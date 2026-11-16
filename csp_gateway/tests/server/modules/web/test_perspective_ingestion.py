import json
from enum import Enum
from unittest.mock import Mock

import numpy as np
import pytest
from csp.typing import Numpy1DArray
from perspective import Server
from pydantic import field_serializer

from csp_gateway import GatewayStruct, MountPerspectiveTables
from csp_gateway.server.modules.web.perspective import _serialize_records, pull_data_thread
from csp_gateway.utils.struct.base import _PRESERVE_TZ


def _feed(table, *batches, key_name=None):
    queue = Mock()
    queue.get.side_effect = [{("records", key_name): batch} for batch in batches] + [KeyboardInterrupt()]
    with pytest.raises(KeyboardInterrupt):
        pull_data_thread(queue, {"records": table})


def _module():
    module = MountPerspectiveTables()
    module._server = Server()
    module._client = module._server.new_local_client()
    return module


def test_feed_uses_native_flattening_and_preserves_omitted_values():
    class Quote(GatewayStruct):
        bid: float
        ask: float

    class Record(GatewayStruct):
        price: float
        quote: Quote
        levels: list[int]

        def psp_flatten(self, custom_jsonifier=None):
            raise AssertionError("The feed must not call custom flattening")

    module = _module()
    module.add_table("records", Record.psp_schema(), index="id")
    table = module._table_insts["records"]
    view = table.view()
    try:
        _feed(
            table,
            [Record(id="a", price=10, quote=Quote(bid=9, ask=11), levels=[1, 2])],
            [Record.model_validate({"id": "a", "quote": {"bid": 8}, "levels": []})],
        )
        row = view.to_records()[0]
        assert row["price"] == 10  # JSON updates leave omitted values alone.
        assert row["quote.bid"] == 8
        assert row["quote.ask"] == 11
        assert row["levels"] is None
        _feed(table, [Record.model_validate({"id": "a", "price": None})])
        assert view.to_records()[0]["price"] is None  # Explicit null still clears a value.
    finally:
        view.delete()
        table.delete()


def test_native_multi_column_indexes_do_not_collide_or_add_a_column():
    class Record(GatewayStruct):
        desk: str
        symbol: str
        quantity: int

    module = _module()
    schema = Record.psp_schema()
    module.add_table("records", schema, index=["desk", "symbol"])
    table = module._table_insts["records"]
    view = table.view()
    try:
        _feed(table, [Record(desk="a-b", symbol="c", quantity=1), Record(desk="a", symbol="b-c", quantity=2)])
        _feed(table, [Record(desk="a-b", symbol="c", quantity=3)])
        assert table.size() == 2
        assert {tuple(row[key] for key in ("desk", "symbol", "quantity")) for row in view.to_records()} == {("a-b", "c", 3), ("a", "b-c", 2)}
        assert "index" not in table.schema()
        assert "index" not in schema
    finally:
        view.delete()
        table.delete()


def test_native_cartesian_expansion_with_enum_arrays_and_basket_metadata():
    class Status(Enum):
        READY = 1
        DONE = 2

    class Record(GatewayStruct):
        statuses: Numpy1DArray[Status]
        levels: list[int]

    module = _module()
    module.add_table("records", Record.psp_schema() | {"basket-key": str})
    table = module._table_insts["records"]
    view = table.view()
    try:
        _feed(table, [Record(statuses=np.array([Status.READY, Status.DONE], dtype=object), levels=[1, 2, 3])], key_name="rates")
        rows = view.to_records()
        assert len(rows) == 6
        assert {(row["statuses"], row["levels"]) for row in rows} == {(status, level) for status in ("READY", "DONE") for level in (1, 2, 3)}
        assert all(row["basket-key"] == "rates" for row in rows)
    finally:
        view.delete()
        table.delete()


def test_feed_serialization_preserves_context_and_explicit_json_override():
    class Record(GatewayStruct):
        value: int = 1

        @field_serializer("value")
        def serialize_value(self, value, info):
            return value * 100 if (info.context or {}).get(_PRESERVE_TZ) else value

    class Custom(Record):
        def to_json(self, default_fn=None):
            return '{"value":42}'

    records = [Record(id="a", timestamp=None), Record(id="b", timestamp=None)]
    assert Record._list_serializers() is not None
    assert json.loads(_serialize_records(records)) == [json.loads(record.to_json()) for record in records]
    assert json.loads(_serialize_records([Custom()])) == [{"value": 42}]
    assert json.loads(_serialize_records([records[0], Custom()]))[-1] == {"value": 42}
    assert _serialize_records([]) == b"[]"


def test_feed_keeps_numpy_json_conversion_without_flattening():
    class Record(GatewayStruct):
        values: np.ndarray

    encoded = json.loads(_serialize_records([Record(values=np.array([1.0, 2.0]))]))
    assert encoded[0]["values"] == [1.0, 2.0]


@pytest.mark.parametrize(
    "options,index,limit",
    [
        ({"default_limit": 100, "indexes": {"records": "id"}}, "id", None),
        ({"default_index": "id", "limits": {"records": 5}}, None, 5),
        ({"default_index": "id", "default_limit": 100, "indexes": {"records": None}}, None, 100),
        ({"default_index": "id", "default_limit": 100}, "id", None),
        ({"default_limit": 100, "tables": {"records": {"index": ["id", "timestamp"]}}}, ["id", "timestamp"], None),
        ({"default_index": "id", "tables": {"records": {"limit": 5}}}, None, 5),
        ({"indexes": {"records": "id"}, "limits": {"records": 5}}, "id", 5),
    ],
)
def test_explicit_index_or_limit_overrides_conflicting_defaults(options, index, limit):
    config = MountPerspectiveTables(**options)._get_effective_config("records")
    assert config.index == index
    assert config.limit == limit


def test_feed_prepares_display_fields_without_custom_flattening():
    from csp_gateway.server.modules.logging.util import MonitoringEvent
    from csp_gateway.utils.web.controls import Controls

    records = [Controls(data={"enabled": True}), MonitoringEvent(title="Example", text="Example event", event_type="test", tags={"desk": "rates"})]
    rows = json.loads(_serialize_records(records))
    assert rows[0]["data_str"] == '{"enabled":true}'
    assert rows[1]["tag_str"] == '{"desk":"rates"}'

    class Prepared(GatewayStruct):
        display: str = ""

        def psp_prepare(self):
            self.display = "prepared"

        def psp_flatten(self, custom_jsonifier=None):
            raise AssertionError("The live feed must use native flattening")

    assert json.loads(_serialize_records([Prepared()]))[0]["display"] == "prepared"


@pytest.mark.parametrize("lists", [False, True])
def test_basket_streams_preserve_each_key_in_primary_and_additional_tables(lists, monkeypatch):
    from datetime import datetime

    import csp
    from csp import ts

    from csp_gateway import Gateway, GatewayChannels, GatewayModule

    class Record(GatewayStruct):
        value: int

        @classmethod
        def psp_schema(cls, excluded_columns=None):
            return super().psp_schema(excluded_columns) | {"basket-key": str}

    class Channels(GatewayChannels):
        records: dict[str, ts[list[Record]]] = None

    class ScalarChannels(GatewayChannels):
        records: dict[str, ts[Record]] = None

    class Feed(GatewayModule):
        def dynamic_keys(self):
            return {"records": ["a", "b"]}

        def connect(self, channels):
            for key, value in [("a", 1), ("b", 2)]:
                record = Record(value=value)
                channels.set_channel("records", csp.const([record] if lists else record), key)

    module = MountPerspectiveTables(tables={"copy": {"channel": "records", "excluded_columns": {"id"}}})
    monkeypatch.setattr(MountPerspectiveTables, "run_perspective", lambda self: None)
    gateway = Gateway(channels=Channels() if lists else ScalarChannels(), modules=[Feed(), module])
    csp.run(gateway.graph, starttime=datetime(2026, 1, 1), endtime=2 * module.update_interval)
    batches = []
    while not module._queue.empty():
        batches.append(module._queue.get_nowait())
    queue = Mock()
    queue.get.side_effect = batches + [KeyboardInterrupt()]
    with pytest.raises(KeyboardInterrupt):
        pull_data_thread(queue, module._table_insts)
    for table in module._table_insts.values():
        view = table.view()
        try:
            assert {(row["basket-key"], row["value"]) for row in view.to_records()} == {("a", 1), ("b", 2)}
        finally:
            view.delete()
            table.delete()
