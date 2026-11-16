from importlib.metadata import version
from typing import Any

import pytest
from packaging.version import Version
from perspective import Server

from csp_gateway.benchmarks import perspective as ingestion
from csp_gateway.server.modules.logging.util import MonitoringEvent
from csp_gateway.utils.web.controls import Controls

pytestmark = pytest.mark.skipif(Version(version("perspective-python")) < Version("5.7"), reason="Native flattening requires Perspective >=5.7")


@pytest.mark.parametrize("pipeline", ingestion.PIPELINES[:4])
@pytest.mark.parametrize("shape", ["flat", "nested", "maps", "enums", "temporal", "composite", "basket", "excluded", "serializer"])
@pytest.mark.parametrize("indexed", [False, True])
def test_ingestion_pipeline_equivalence(pipeline, shape, indexed):
    result = ingestion.check_equivalence(ingestion.Workload(shape, 3, indexed), pipeline)
    assert result["status"] == "equivalent", result


@pytest.mark.parametrize("pipeline", ingestion.PIPELINES[:4])
def test_cartesian_expansion_matches_gateway(pipeline):
    workload = ingestion.Workload("lists", 3, False)
    result = ingestion.check_equivalence(workload, pipeline)
    assert result == {"status": "equivalent", "output_rows": 18}


@pytest.mark.parametrize("pipeline", ingestion.PIPELINES[:4])
def test_empty_lists_match_gateway_in_append_tables(pipeline):
    result = ingestion.check_equivalence(ingestion.Workload("empty-lists", 3, False), pipeline)
    assert result["status"] == "equivalent", result


@pytest.mark.parametrize("pipeline", ingestion.PIPELINES[4:])
@pytest.mark.parametrize("shape", ["flat", "nested"])
def test_additional_pipeline_equivalence(pipeline, shape):
    result = ingestion.check_equivalence(ingestion.Workload(shape, 3, True), pipeline)
    assert result["status"] == "equivalent", result


def test_map_fixture_preserves_values():
    workload = ingestion.Workload("maps", 1, False)
    table = workload.table(Server().new_local_client())
    view = table.view()
    try:
        payload, fmt = ingestion.prepare(workload, "custom-arrow", workload.generations[0])
        table.update(payload, format=fmt)
        row = view.to_records()[0]
        assert row["attributes.desk"] == "rates"
        assert row["attributes.region"] == "US"
    finally:
        view.delete()
        table.delete()


@pytest.mark.parametrize("shape", ["composite", "basket", "excluded", "serializer"])
def test_application_fixture_expected_values(shape):
    workload = ingestion.Workload(shape, 1, True)
    table = workload.table(Server().new_local_client())
    view = table.view()
    try:
        payload, fmt = ingestion.prepare(workload, "custom-arrow", workload.generations[0])
        table.update(payload, format=fmt)
        row = view.to_records()[0]
        if shape == "composite":
            assert row["index"] == "SYM0-0"
        elif shape == "basket":
            assert row["basket-key"] == "rates"
        elif shape == "excluded":
            assert "price" not in row and "quote.ask" not in row
            assert row["quote.bid"] == 99.25
        else:
            assert row["price"] == 10025.0
    finally:
        view.delete()
        table.delete()


def test_typed_arrow_detects_json_only_serializer():
    result = ingestion.check_equivalence(ingestion.Workload("serializer", 1, True), "typed-arrow")
    assert result["status"] == "mismatch"
    expected, actual = result["first_difference"]
    assert expected["price"] == actual["price"] * 100


def test_equivalence_detects_custom_flattening_difference():
    result = ingestion.check_equivalence(ingestion.Workload("custom", 1, True), "native-json")
    assert result["status"] == "mismatch"
    expected, actual = result["first_difference"]
    assert expected["price"] == actual["price"] * 100


def test_gateway_json_uses_native_composite_index():
    workload = ingestion.Workload("composite", 3, True)
    table = workload.table(Server().new_local_client(), "gateway-json")
    try:
        for records in workload.generations:
            payload, fmt = ingestion.prepare(workload, "gateway-json", records)
            table.update(payload, format=fmt)
        assert table.size() == 3
        assert "index" not in table.schema()
    finally:
        table.delete()
    assert ingestion.check_equivalence(workload, "gateway-json")["reason"] == "Different schemas"


@pytest.mark.parametrize("indexed", [False, True])
@pytest.mark.parametrize("shape", ingestion.SHAPES)
def test_gateway_json_changes_only_approved_fixture_behavior(indexed, shape):
    result = ingestion.check_equivalence(ingestion.Workload(shape, 3, indexed), "gateway-json")
    changed = shape in ("custom", "composite") or (indexed and shape == "nullable")
    assert result["status"] == ("mismatch" if changed else "equivalent"), result


@pytest.mark.parametrize("pipeline", ingestion.PIPELINES)
@pytest.mark.parametrize("model,source,display", [(Controls, "data", "data_str"), (MonitoringEvent, "tags", "tag_str")])
def test_equivalence_isolates_mutating_application_hooks(monkeypatch, pipeline, model, source, display):
    workload = ingestion.Workload("flat", 1, True)
    workload.schema = model.psp_schema({source: True, "alert_type": True})
    workload.flat_json_schema = ingestion.psp_schema_to_arrow_schema(workload.schema)
    workload.nested_json_schema = workload.flat_json_schema
    workload.nested_arrow_schema = workload.flat_json_schema
    workload.dates = set()

    def records(generation):
        values = {source: {"generation": str(generation)}}
        if model is MonitoringEvent:
            values.update(title="Example", text="Example event", event_type="test")
        return [model(id="0", timestamp=ingestion._NOW, **values)]

    monkeypatch.setattr(workload, "records", records)
    result = ingestion.check_equivalence(workload, pipeline)
    if pipeline in ("custom-arrow", "custom-json", "gateway-json"):
        assert result["status"] == "equivalent", result
    else:
        assert result["status"] == "mismatch", result
        expected, actual = result["first_difference"]
        assert expected[display] == '{"generation":"0"}'
        assert actual[display] in ("", None)


@pytest.mark.parametrize("indexed", [False, True])
@pytest.mark.parametrize("missing", ["parent", "child", "list-child"])
def test_native_arrow_missing_nested_values(monkeypatch, indexed, missing):
    class NestedListTrade(ingestion.Trade):
        quotes: list[ingestion.Quote]

    workload = ingestion.Workload("nested", 3, indexed)
    if missing == "list-child":
        monkeypatch.setattr(workload, "model", NestedListTrade)
        workload.schema = NestedListTrade.psp_schema()
        workload.flat_json_schema = ingestion.psp_schema_to_arrow_schema(workload.schema)
        fields = list(ingestion.psp_schema_to_arrow_schema(ingestion.Trade.psp_schema()))
        fields.append(
            ingestion.pa.field("quotes", ingestion.pa.list_(ingestion.pa.struct([("bid", ingestion.pa.float64()), ("ask", ingestion.pa.float64())])))
        )
        workload.nested_json_schema = ingestion.pa.schema(fields)
        workload.nested_arrow_schema = ingestion.pa.schema(
            [ingestion.pa.field(field.name, ingestion.pa.date32()) if field.name in workload.dates else field for field in fields]
        )

    def records(generation):
        values: dict[str, Any] = {"id": "0", "timestamp": ingestion._NOW, "symbol": "SYM0", "price": 100.0, "quantity": 1, "active": True}
        complete = ingestion.Quote(bid=99.0, ask=101.0)
        partial = ingestion.Quote.model_construct(bid=98.0)
        if missing == "list-child":
            values["quotes"] = [complete, partial if generation else complete]
        elif not generation or missing != "parent":
            values["quote"] = partial if generation else complete
        return [workload.model(**values)]

    monkeypatch.setattr(workload, "records", records)
    result = ingestion.check_equivalence(workload, "native-arrow")
    expected = "error" if indexed and missing == "list-child" else "equivalent"
    assert result["status"] == expected, result


def test_equivalence_reports_conversion_error(monkeypatch):
    def reject(*args):
        raise ValueError("Invalid fixture")

    monkeypatch.setattr(ingestion, "prepare", reject)
    result = ingestion.check_equivalence(ingestion.Workload("flat", 1, True), "native-json")
    assert result == {"status": "error", "stage": "baseline", "reason": "ValueError: Invalid fixture"}


def test_measure_stops_engine_after_failure(monkeypatch):
    original_prepare = ingestion.prepare
    original_run = ingestion.csp.run_on_thread
    runners = []
    calls = 0

    def prepare(*args):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise ValueError("Timed preparation failed")
        return original_prepare(*args)

    def run(*args, **kwargs):
        runner = original_run(*args, **kwargs)
        runners.append(runner)
        return runner

    monkeypatch.setattr(ingestion, "prepare", prepare)
    monkeypatch.setattr(ingestion.csp, "run_on_thread", run)
    with pytest.raises(ValueError, match="Timed preparation failed"):
        ingestion.measure(ingestion.Workload("flat", 1, True), "custom-arrow", 0.01, False)
    assert len(runners) == 1
    assert not runners[0].is_alive()
