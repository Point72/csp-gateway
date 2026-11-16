"""Compare Perspective ingestion pipelines without changing production ingestion."""

import argparse
import json
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, timezone
from importlib.metadata import version
from itertools import zip_longest
from pathlib import Path
from statistics import median

import csp
import orjson
import pyarrow as pa
import pyarrow.json
from packaging.version import Version
from perspective import PerspectiveError, Server
from pydantic import BaseModel, field_serializer

from csp_gateway import GatewayStruct, create_pyarrow_table, psp_schema_to_arrow_schema
from csp_gateway.benchmarks.test_request_performance import _LoadModule
from csp_gateway.server.modules.web.perspective import _serialize_records
from csp_gateway.server.web.routes.shared import _dump_records

PIPELINES = ("custom-arrow", "native-arrow", "custom-json", "native-json", "batch-json", "typed-arrow", "gateway-json")
SHAPES = (
    "flat",
    "nested",
    "lists",
    "empty-lists",
    "maps",
    "nullable",
    "temporal",
    "enums",
    "custom",
    "composite",
    "basket",
    "excluded",
    "serializer",
)
_NOW = datetime(2026, 1, 1, 12, 34, 56, 123000, tzinfo=UTC)


class Trade(GatewayStruct):
    symbol: str
    price: float
    quantity: int
    active: bool
    settlement: date


class Quote(BaseModel):
    bid: float
    ask: float


class NestedTrade(Trade):
    quote: Quote


class ListTrade(Trade):
    venues: list[str]
    levels: list[int]


class MapTrade(Trade):
    attributes: dict[str, str]

    @classmethod
    def psp_schema(cls, excluded_columns=None):
        schema = super().psp_schema(excluded_columns)
        if "attributes" in schema:
            # Declare this fixture's map keys; the generic dict schema is a string column.
            del schema["attributes"]
            schema.update({"attributes.desk": str, "attributes.region": str})
        return schema


class Status(csp.Enum):
    READY = 1
    DONE = 2


class EnumTrade(Trade):
    status: Status


class CustomTrade(Trade):
    def psp_flatten(self, custom_jsonifier=None):
        rows = super().psp_flatten(custom_jsonifier)
        for row in rows:
            row["price"] *= 100
        return rows


class SerializedTrade(Trade):
    @field_serializer("price", when_used="json")
    def serialize_price(self, value):
        return value * 100


@dataclass
class Workload:
    shape: str
    count: int
    indexed: bool

    def __post_init__(self):
        self.model = {
            "nested": NestedTrade,
            "lists": ListTrade,
            "empty-lists": ListTrade,
            "maps": MapTrade,
            "enums": EnumTrade,
            "custom": CustomTrade,
            "excluded": NestedTrade,
            "serializer": SerializedTrade,
        }.get(self.shape, Trade)
        self.key_name = "rates" if self.shape == "basket" else None
        self.computed_index = ("index", ["symbol", "id"]) if self.shape == "composite" else None
        self.schema = self.model.psp_schema({"price": True, "quote": {"ask"}} if self.shape == "excluded" else None)
        if self.key_name:
            self.schema["basket-key"] = str
        if self.computed_index:
            self.schema[self.computed_index[0]] = str
        self.flat_json_schema = psp_schema_to_arrow_schema(self.schema)
        self.dates = {name for name, typ in self.schema.items() if typ is date}
        fields = list(psp_schema_to_arrow_schema(Trade.psp_schema()))
        if self.shape in ("nested", "excluded"):
            fields.append(pa.field("quote", pa.struct([("bid", pa.float64()), ("ask", pa.float64())])))
        elif self.shape in ("lists", "empty-lists"):
            fields.extend([pa.field("venues", pa.list_(pa.string())), pa.field("levels", pa.list_(pa.int64()))])
        elif self.shape == "maps":
            fields.append(pa.field("attributes", pa.struct([("desk", pa.string()), ("region", pa.string())])))
        elif self.shape == "enums":
            fields.append(pa.field("status", pa.string()))
        if self.key_name:
            fields.append(pa.field("basket-key", pa.string()))
        if self.computed_index:
            fields.append(pa.field(self.computed_index[0], pa.string()))
        self.nested_json_schema = pa.schema(fields)
        self.nested_arrow_schema = pa.schema([pa.field(f.name, pa.date32()) if f.name in self.dates else f for f in fields])
        self.generations = [self.records(generation) for generation in range(2)]

    def records(self, generation):
        records = []
        for i in range(self.count):
            values = {
                "id": str(i),
                "timestamp": _NOW,
                "symbol": f"SYM{i % 20}",
                "price": 100.25 + i + generation,
                "quantity": i,
                "active": True,
                "settlement": date(2026, 1, 3),
            }
            if self.shape in ("nested", "excluded"):
                values["quote"] = Quote(bid=values["price"] - 1, ask=values["price"] + 1)
            elif self.shape in ("lists", "empty-lists"):
                values.update(venues=["XNYS", "XNAS"], levels=[1, 2, 3])
                if self.shape == "empty-lists" and generation:
                    values["levels"] = []
            elif self.shape == "maps":
                values["attributes"] = {"desk": "rates", "region": "US"}
            elif self.shape == "enums":
                values["status"] = Status.READY if generation == 0 else Status.DONE
            elif self.shape == "nullable" and generation:
                values.pop("price")
                values.update(timestamp=None, settlement=None)
            elif self.shape == "temporal" and generation:
                values["timestamp"] = _NOW.astimezone(timezone(timedelta(hours=5, minutes=30)))
            records.append(self.model(**values))
        return records

    def table(self, client, pipeline=None):
        schema = self.schema
        index = self.computed_index[0] if self.computed_index else "id"
        if pipeline == "gateway-json" and self.computed_index:
            name, index = self.computed_index
            schema = {key: typ for key, typ in schema.items() if key != name}
        return client.table(
            schema,
            index=index if self.indexed else None,
            limit=None if self.indexed else self.count * (6 if self.shape in ("lists", "empty-lists") else 1),
            list_flatten="cartesian",
            struct_flatten="pivot",
            map_flatten="pivot",
        )


def _metadata(workload, row):
    additions = {}
    if workload.key_name:
        additions["basket-key"] = workload.key_name
    if workload.computed_index:
        name, fields = workload.computed_index
        additions[name] = "-".join(str(row[field]) for field in fields)
    return additions


def _jsonl(workload, records):
    if not workload.key_name and not workload.computed_index:
        return "\n".join(record.to_json() for record in records).encode()
    rows = []
    for record in records:
        # Benchmark the cost of preserving gateway routing/index metadata after serialization.
        # Composite keys must use serialized values, as create_pyarrow_table does.
        row = orjson.loads(record.to_json())
        row.update(_metadata(workload, row))
        rows.append(orjson.dumps(row))
    return b"\n".join(rows)


def _ipc(table):
    stream = pa.BufferOutputStream()
    with pa.ipc.new_stream(stream, table.schema) as writer:
        writer.write_table(table)
    return stream.getvalue().to_pybytes()


def prepare(workload, pipeline, records):
    if pipeline == "gateway-json":
        return _serialize_records(records, workload.key_name), "json"
    if pipeline == "custom-arrow":
        return _ipc(create_pyarrow_table(workload.key_name, records, workload.computed_index, workload.flat_json_schema, workload.dates)), None
    if pipeline == "custom-json":
        if workload.key_name or workload.computed_index:
            rows = []
            for record in records:
                for row in record.psp_flatten():
                    row.update(_metadata(workload, row))
                    rows.append(orjson.dumps(row))
            return b"\n".join(rows), "ndjson"
        return b"\n".join(orjson.dumps(row) for record in records for row in record.psp_flatten()), "ndjson"
    if pipeline == "batch-json":
        payload = _dump_records(records)
        if workload.key_name or workload.computed_index:
            rows = orjson.loads(payload)
            for row in rows:
                row.update(_metadata(workload, row))
            payload = orjson.dumps(rows)
        return payload, "json"
    if pipeline == "typed-arrow":
        stream = pa.BufferOutputStream()
        with pa.ipc.new_stream(stream, workload.nested_arrow_schema) as writer:
            for start in range(0, len(records), 5000):
                rows = [record.to_dict() for record in records[start : start + 5000]]
                if workload.key_name or workload.computed_index:
                    for row in rows:
                        row.update(_metadata(workload, row))
                writer.write_batch(
                    pa.RecordBatch.from_pylist(
                        rows,
                        schema=workload.nested_arrow_schema,
                    )
                )
        return stream.getvalue().to_pybytes(), None
    payload = _jsonl(workload, records)
    if pipeline == "native-json":
        return payload, "ndjson"
    if pipeline != "native-arrow":
        raise ValueError(f"Unknown pipeline: {pipeline}")
    table = pa.json.read_json(
        pa.BufferReader(payload),
        read_options=pa.json.ReadOptions(use_threads=True),
        parse_options=pa.json.ParseOptions(explicit_schema=workload.nested_json_schema, unexpected_field_behavior="ignore"),
    )
    return _ipc(table.cast(workload.nested_arrow_schema)), None


def _rows(view):
    # Ignore engine-dependent row/column order, preserving duplicates and null values.
    return sorted(orjson.dumps(row, option=orjson.OPT_SORT_KEYS) for row in view.to_records())


def check_equivalence(workload, pipeline):
    # Flattening overrides may mutate records; neither path may prepare the other's input.
    baseline_records = [workload.records(generation) for generation in range(2)]
    candidate_records = [workload.records(generation) for generation in range(2)]
    client = Server().new_local_client()
    baseline = workload.table(client)
    candidate = workload.table(client, pipeline)
    expected_view = baseline.view()
    actual_view = candidate.view()
    views = [("rows", expected_view, actual_view)]
    columns = [name for name in ("price", "quantity") if name in workload.schema]
    if "symbol" in workload.schema and columns:
        options = {"group_by": ["symbol"], "columns": columns}
        views.append(("grouped", baseline.view(**options), candidate.view(**options)))
    stage = "baseline"
    try:
        # Start empty, then replace values repeatedly for the same identities.
        for generation in (0, 1, 0):
            stage = "baseline"
            payload, fmt = prepare(workload, "custom-arrow", baseline_records[generation])
            baseline.update(payload, format=fmt)
            stage = "candidate"
            payload, fmt = prepare(workload, pipeline, candidate_records[generation])
            candidate.update(payload, format=fmt)
            if baseline.schema() != candidate.schema():
                return {"status": "mismatch", "generation": generation, "reason": "Different schemas"}
            for name, expected_view, actual_view in views:
                expected, actual = _rows(expected_view), _rows(actual_view)
                if expected != actual:
                    first = next((left, right) for left, right in zip_longest(expected, actual) if left != right)
                    return {
                        "status": "mismatch",
                        "view": name,
                        "generation": generation,
                        "expected_rows": len(expected),
                        "actual_rows": len(actual),
                        "first_difference": [orjson.loads(row) if row is not None else None for row in first],
                    }
        return {"status": "equivalent", "output_rows": baseline.size()}
    except (PerspectiveError, pa.ArrowException, TypeError, ValueError) as error:
        return {"status": "error", "stage": stage, "reason": f"{type(error).__name__}: {error}"}
    finally:
        for _, expected_view, actual_view in views:
            expected_view.delete()
            actual_view.delete()
        baseline.delete()
        candidate.delete()


def measure(workload, pipeline, seconds, grouped):
    client = Server().new_local_client()
    table = workload.table(client, pipeline)
    view = table.view(group_by=["symbol"], columns=[name for name in ("price", "quantity") if name in workload.schema]) if grouped else None
    load = _LoadModule(update_hz=200, cpu_work_ms=0.25, rows=1, measure_engine_lag=True)

    @csp.graph
    def graph():
        csp.add_graph_output("clock", load._work(csp.timer(timedelta(milliseconds=5)), 0.00025))

    runner = None
    try:
        for generation in (0, 1):
            payload, fmt = prepare(workload, pipeline, workload.generations[generation])
            table.update(payload, format=fmt)
        runner = csp.run_on_thread(graph, realtime=True)
        time.sleep(0.1)
        load.lag_metrics()
        time.sleep(0.5)
        idle_lag = load.lag_metrics()
        samples = []
        started = time.perf_counter()
        while time.perf_counter() - started < seconds or len(samples) < 5:
            before = time.perf_counter()
            payload, fmt = prepare(workload, pipeline, workload.generations[len(samples) % 2])
            prepared = time.perf_counter()
            table.update(payload, format=fmt)
            after = time.perf_counter()
            samples.append(((prepared - before) * 1000, (after - prepared) * 1000, (after - before) * 1000))
        elapsed = time.perf_counter() - started
        lag = load.lag_metrics()
        return {
            "batches": len(samples),
            "elapsed_s": elapsed,
            "prepare_ms": median(sample[0] for sample in samples),
            "ingest_ms": median(sample[1] for sample in samples),
            "total_ms": median(sample[2] for sample in samples),
            "input_records_per_s": workload.count * len(samples) / elapsed,
            "payload_bytes": len(payload),
            "table_rows": table.size(),
            "idle_engine_lag": idle_lag,
            "engine_lag": lag,
        }
    finally:
        if runner is not None:
            runner.stop_engine()
            runner.join()
        if view is not None:
            view.delete()
        table.delete()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pipelines", nargs="+", choices=PIPELINES, default=list(PIPELINES[:4]))
    parser.add_argument("--shapes", nargs="+", choices=SHAPES, default=["flat", "nested", "lists"])
    parser.add_argument("--counts", nargs="+", type=int, default=[1000, 10000, 100000])
    parser.add_argument("--seconds", type=float, default=2)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--indexed", action="store_true")
    parser.add_argument("--grouped", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--output", type=Path, default=Path(".benchmarks/perspective-ingestion.json"))
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if min(args.counts) < 1 or args.seconds <= 0 or args.repeats < 1:
        parser.error("counts, seconds, and repeats must be positive")
    if Version(version("perspective-python")) < Version("5.7"):
        parser.error("Perspective >=5.7 is required for native struct/map flattening")
    if args.worker:
        pipeline = args.pipelines[0]
        result = {"pipeline": pipeline, "shape": args.shapes[0], "count": args.counts[0], "indexed": args.indexed, "grouped": args.grouped}
        # Test replacement semantics on a small fixture before allocating large timing datasets.
        result["correctness"] = check_equivalence(Workload(args.shapes[0], 3, args.indexed), pipeline)
        if not args.check_only and result["correctness"]["status"] == "equivalent":
            workload = Workload(args.shapes[0], args.counts[0], args.indexed)
            result["timing"] = measure(workload, pipeline, args.seconds, args.grouped)
        print(json.dumps(result), flush=True)
        return
    report = {
        "versions": {name: version(name) for name in ("csp", "pydantic", "pyarrow", "perspective-python")},
        "python": sys.version,
        "platform": platform.platform(),
        "arrow_threads": pa.cpu_count(),
        "seconds": args.seconds,
        "results": [],
    }
    for repeat in range(args.repeats):
        for shape in args.shapes:
            for count in args.counts:
                for pipeline in args.pipelines if repeat % 2 == 0 else reversed(args.pipelines):
                    command = [
                        sys.executable,
                        "-m",
                        "csp_gateway.benchmarks.perspective",
                        "--worker",
                        "--shapes",
                        shape,
                        "--counts",
                        str(count),
                        "--pipelines",
                        pipeline,
                        "--seconds",
                        str(args.seconds),
                    ]
                    for name in ("indexed", "grouped", "check_only"):
                        if getattr(args, name):
                            command.append("--" + name.replace("_", "-"))
                    completed = subprocess.run(command, capture_output=True, text=True, check=True)
                    result = json.loads(completed.stdout)
                    result["repeat"] = repeat
                    report["results"].append(result)
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(json.dumps(report, indent=2) + "\n")
                    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
