import gc
import json
import time
from datetime import UTC, date, datetime, timedelta, timezone
from enum import Enum, auto
from typing import Annotated
from unittest.mock import MagicMock

import csp
import numpy as np
import orjson
import polars as pl
import pyarrow
import pytest
from csp import ts
from csp.typing import Numpy1DArray
from perspective import Server
from pydantic import BaseModel, ConfigDict, Field, field_serializer

from csp_gateway import (
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewayStruct,
    MountPerspectiveTables,
    TableConfig,
)
from csp_gateway.server.modules.web.perspective import migrate_perspective_layout
from csp_gateway.testing.harness import GatewayTestHarness


class MyTestEnum(Enum):
    a = auto()
    b = auto()
    c = auto()

    def __lt__(self, other):
        # so csp doesn't complain about memoization
        return self.value < other.value


class MyTestSubStruct(GatewayStruct):
    y: list[int]
    x: int = 1
    z: float


class MyTestStruct(GatewayStruct):
    sub: MyTestSubStruct
    z: MyTestEnum
    ncsp_sub: object


class MyTestOptionalSubStruct(GatewayStruct):
    sub_a: int | None


class MyTestOptionalStruct(GatewayStruct):
    i: int
    i_o: int | None
    ob: object
    ob_op: object | None
    l_i: [int]
    lt_i: list[int]
    lt_i_op: list[int] | None
    s: MyTestSubStruct
    s_op: MyTestSubStruct | None
    e: MyTestEnum
    e_op: MyTestEnum | None
    sub: MyTestOptionalSubStruct
    sub_op: MyTestOptionalSubStruct | None


class MyPyArrowStruct(GatewayStruct):
    d: date


def _table(cls, items, excluded=None, **kwargs):
    """A real Perspective table, built from a struct's encoder the way the module builds its tables."""
    module = _ModuleStub()
    encoder = cls.psp_arrow_encoder(excluded)
    MountPerspectiveTables.add_table(module, "t", encoder, **kwargs)
    table = module._table_insts["t"]
    if items:
        table.update(encoder.encode(items))
    return table


def _records(cls, items, excluded=None):
    return _table(cls, items, excluded).view().to_records()


def _records_with(cls, items, **kwargs):
    return _table(cls, items, **kwargs).view().to_records()


class _ModuleStub:
    """Just enough of the module for `add_table`."""

    def __init__(self):
        self._client = Server().new_local_client()
        self._table_insts = {}


class GWC(GatewayChannels):
    test_channel: ts[MyTestStruct] = None
    list_channel: ts[list[MyTestStruct]] = None
    dict_channel: dict[str, ts[MyTestStruct]] = None
    dict_enum_channel: dict[MyTestEnum, ts[MyTestStruct]] = None
    index_channel: ts[MyTestStruct] = None
    limit_channel: ts[MyTestStruct] = None
    exclude_channel: ts[MyTestStruct] = None

    my_perspective: Server = Field(default_factory=Server)


class GWCUnused(GatewayChannels):
    a: ts[MyTestStruct] = None
    b: ts[MyTestStruct] = None
    c: ts[[MyTestStruct]] = None
    d: ts[[MyTestStruct]] = None
    e: dict[MyTestEnum, ts[MyTestStruct]] = None
    f: dict[MyTestEnum, ts[MyTestStruct]] = None


def test_inherited_container_annotation_schema():
    # Base declares container field
    class BaseModelWithContainer(BaseModel):
        arr: list[int] = None

    # Child has no own annotations for arr; relies on inherited annotation
    class ChildStruct(GatewayStruct, BaseModelWithContainer):
        pass

    schema = ChildStruct.psp_schema()
    # Ensure container element type is preserved as int, not str
    assert schema["arr"] is int


def test_csp_enum_schema():
    class Status(csp.Enum):
        READY = 1

    class StructWithCspEnum(GatewayStruct):
        status: Status

    assert StructWithCspEnum.psp_schema()["status"] is str


def test_annotated_csp_enum_array_schema():
    class Status(csp.Enum):
        READY = 1
        DONE = 2

    class StructWithCspEnumArray(GatewayStruct):
        statuses: Annotated[Numpy1DArray[Status], Field(description="Statuses")]
        values: Annotated[Numpy1DArray[float], Field(description="Values")]

    schema = StructWithCspEnumArray.psp_schema()
    assert schema["statuses"] is str
    assert schema["values"] is float

    value = StructWithCspEnumArray(statuses=np.array([Status.READY, Status.DONE], dtype=object))
    assert [row["statuses"] for row in _records(StructWithCspEnumArray, [value])] == ["READY", "DONE"]


def test_optional_annotated_array_schema():
    class StructWithOptionalArray(GatewayStruct):
        values: Annotated[Numpy1DArray[float], Field(description="Values")] | None = None

    assert StructWithOptionalArray.psp_schema()["values"] is float


def test_inherited_ndarray_annotation_schema():
    # Base declares numpy array field with element type
    class BaseModelWithArray(BaseModel):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        arr_nd: Numpy1DArray[float] = np.array([1.0]).view(Numpy1DArray)

    # Child inherits without redeclaring annotation
    class ChildStruct(GatewayStruct, BaseModelWithArray):
        pass

    schema = ChildStruct.psp_schema()
    # Ensure ndarray element type is preserved as float, not str
    assert schema["arr_nd"] is float


def test_inherited_container_on_gatewaystruct():
    # Parent defines a container field on GatewayStruct
    class ParentGS(GatewayStruct):
        arr: list[int]

    # Child does not redeclare annotations
    class ChildGS(ParentGS):
        pass

    schema = ChildGS.psp_schema()
    assert schema["arr"] is int


def test_inherited_ndarray_on_gatewaystruct():
    class ParentGSArr(GatewayStruct):
        arr_nd: Numpy1DArray[float] = np.array([1.0]).view(Numpy1DArray)

    class ChildGSArr(ParentGSArr):
        pass

    schema = ChildGSArr.psp_schema()
    assert schema["arr_nd"] is float


def test_recursive_perspective_schema():
    schema = MyTestStruct.psp_schema()
    assert isinstance(schema, dict)
    assert schema == {
        "id": str,
        "timestamp": datetime,
        "sub.id": str,
        "sub.y": int,
        "sub.x": int,
        "sub.z": float,
        "sub.timestamp": datetime,
        "z": str,
    }

    schema = MyTestOptionalStruct.psp_schema()
    assert isinstance(schema, dict)
    assert schema == {
        "id": str,
        "timestamp": datetime,
        "i": int,
        "i_o": int,
        "l_i": int,
        "lt_i": int,
        "lt_i_op": int,
        "s.id": str,
        "s.y": int,
        "s.x": int,
        "s.z": float,
        "s.timestamp": datetime,
        "s_op.id": str,
        "s_op.y": int,
        "s_op.x": int,
        "s_op.z": float,
        "s_op.timestamp": datetime,
        "e": str,
        "e_op": str,
        "sub.id": str,
        "sub.sub_a": int,
        "sub.timestamp": datetime,
        "sub_op.id": str,
        "sub_op.sub_a": int,
        "sub_op.timestamp": datetime,
    }


def test_recursive_perspective_flattening():
    now = datetime.now(UTC).replace(tzinfo=UTC)
    now_ms = int(now.timestamp() * 1000)

    def flat(sub: MyTestSubStruct, **kwargs):
        o = MyTestStruct(sub=sub, timestamp=now, **kwargs)
        rows = _records(MyTestStruct, [o])
        return o, rows

    # List with 1 element
    sub = MyTestSubStruct(y=[1], timestamp=now)
    o, rows = flat(sub)
    assert rows == [{"id": o.id, "sub.id": sub.id, "sub.y": 1, "sub.x": 1, "sub.z": None, "sub.timestamp": now_ms, "timestamp": now_ms, "z": None}]

    # List with multiple elements becomes a row each, the parent repeated
    sub = MyTestSubStruct(y=[1, 2, 3], timestamp=now)
    o, rows = flat(sub)
    assert [r["sub.y"] for r in rows] == [1, 2, 3]
    assert {r["id"] for r in rows} == {o.id}
    assert {r["sub.id"] for r in rows} == {sub.id}

    # An empty list keeps the row, with a null
    sub = MyTestSubStruct(y=[], timestamp=now)
    o, rows = flat(sub)
    assert len(rows) == 1 and rows[0]["sub.y"] is None and rows[0]["sub.x"] == 1

    # Perspective reads non-finite floats as null
    for value in (float("nan"), float("inf"), float("-inf")):
        _, rows = flat(MyTestSubStruct(y=[], z=value, timestamp=now))
        assert rows[0]["sub.z"] is None

    # Enums are shown by name
    _, rows = flat(MyTestSubStruct(y=[1], timestamp=now), z=MyTestEnum.b)
    assert rows[0]["z"] == "b"

    # A field with no perspective conversion is left out
    o = MyTestStruct(ncsp_sub=object(), timestamp=now)
    assert "ncsp_sub" not in MyTestStruct.psp_schema()
    assert _records(MyTestStruct, [o])[0]["id"] == o.id


def test_table_columns_match_flattened_schema():
    for cls in (MyTestStruct, MyTestOptionalStruct):
        assert sorted(_table(cls, []).schema()) == sorted(cls.psp_schema())


def test_multiple_lists_combine_as_a_cartesian_product():
    class Two(GatewayStruct):
        a: list[int]
        b: list[str]

    rows = _records(Two, [Two(a=[1, 2], b=["p", "q", "r"])])
    assert sorted((r["a"], r["b"]) for r in rows) == [(a, b) for a in (1, 2) for b in "pqr"]


def test_list_of_structs_flattens_under_the_field_name():
    class Item(GatewayStruct):
        k: str
        v: int

    class Order(GatewayStruct):
        items: list[Item]

    assert Order.psp_schema().keys() >= {"items.k", "items.v"}
    rows = _records(Order, [Order(items=[Item(k="a", v=1), Item(k="b", v=2)])])
    assert [(r["items.k"], r["items.v"]) for r in rows] == [("a", 1), ("b", 2)]


def test_dicts_are_json_strings_and_none_is_null():
    class WithDict(GatewayStruct):
        data: dict = None
        name: str = None

    assert WithDict.psp_schema()["data"] is str
    rows = _records(WithDict, [WithDict(data={"a": 1, "b": [1, 2]}, name="x"), WithDict()])
    assert orjson.loads(rows[0]["data"]) == {"a": 1, "b": [1, 2]}
    assert rows[1]["data"] is None and rows[1]["name"] is None


def test_dicts_of_scalars_are_arrow_maps_shown_as_json():
    class WithMap(GatewayStruct):
        tags: dict[str, int] = None

    encoder = WithMap.psp_arrow_encoder()
    assert encoder.schema.field("tags").type == pyarrow.map_(pyarrow.string(), pyarrow.int64())
    assert WithMap.psp_schema()["tags"] is str
    rows = _records(WithMap, [WithMap(tags={"a": 1, "b": 2}), WithMap()])
    assert orjson.loads(rows[0]["tags"]) == {"a": 1, "b": 2}
    assert rows[1]["tags"] is None


def test_unset_fields_are_null():
    rows = _records(MyTestOptionalStruct, [MyTestOptionalStruct(i=1)])
    assert rows[0]["i"] == 1 and rows[0]["i_o"] is None and rows[0]["s.x"] is None


def test_exclusions_drop_nested_columns():
    excluded = {"sub": {"y"}, "z": True}
    columns = _table(MyTestStruct, [], excluded).schema()
    assert sorted(columns) == sorted(MyTestStruct.psp_schema(excluded))
    assert "sub.y" not in columns and "z" not in columns


def test_exclude_columns_schema():
    res = MyTestStruct.psp_schema()
    assert set(res.keys()) == {"z", "sub.y", "sub.x", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}

    res = MyTestStruct.psp_schema({"z"})
    assert set(res.keys()) == {"sub.y", "sub.x", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}

    res = MyTestStruct.psp_schema({"sub"})
    assert set(res.keys()) == {"z", "id", "timestamp"}

    res = MyTestStruct.psp_schema({"sub": {"x"}})
    assert set(res.keys()) == {"z", "sub.y", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}

    res = MyTestStruct.psp_schema({"sub": {"x"}, "z": True})
    assert set(res.keys()) == {"sub.y", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}


def test_pyarrow_conversion():
    now = datetime.now(UTC)
    now_date = now.date()
    encoder = MyPyArrowStruct.psp_arrow_encoder()
    assert encoder.schema.field("d").type == pyarrow.date32()

    o = MyPyArrowStruct(timestamp=now, d=now_date)
    df = pl.from_arrow(encoder.encode([o]))
    assert df.head()["d"][0] == now_date

    #  Check nones are handled correctly
    o = MyPyArrowStruct(timestamp=None, d=None)
    df = pl.from_arrow(encoder.encode([o]))
    assert df.head()["d"][0] is None
    assert df.head()["timestamp"][0] is None

    #  Naive datetimes are UTC, and others are converted to it
    naive = datetime(2024, 1, 1, 12)
    offset = datetime(2024, 1, 1, 14, tzinfo=timezone(timedelta(hours=2)))
    df = pl.from_arrow(encoder.encode([MyPyArrowStruct(timestamp=naive), MyPyArrowStruct(timestamp=offset)]))
    assert df["timestamp"].to_list() == [datetime(2024, 1, 1, 12, tzinfo=UTC)] * 2


def test_composite_index_keys_rows_by_every_field():
    class Quote(GatewayStruct):
        venue: str
        symbol: str
        px: float

    rows = [Quote(venue="A", symbol="X", px=1.0), Quote(venue="A", symbol="Y", px=2.0), Quote(venue="A", symbol="X", px=3.0)]
    table = _table(Quote, rows, index=["venue", "symbol"])
    assert sorted((r["symbol"], r["px"]) for r in table.view().to_records()) == [("X", 3.0), ("Y", 2.0)]
    # no synthesized key column
    assert sorted(table.schema()) == sorted(Quote.psp_schema())


def test_indexed_table_with_list_columns_is_rejected_at_creation():
    with pytest.raises(Exception, match="expanded list column"):
        MountPerspectiveTables.add_table(_ModuleStub(), "t", MyTestStruct.psp_arrow_encoder(), index="id")


def test_index_on_a_list_column_is_allowed():
    class Item(GatewayStruct):
        k: str
        v: int

    class Order(GatewayStruct):
        items: list[Item]

    module = _ModuleStub()
    MountPerspectiveTables.add_table(module, "orders", Order.psp_arrow_encoder(), index="items.k")
    table = module._table_insts["orders"]
    table.update(Order.psp_arrow_encoder().encode([Order(items=[Item(k="a", v=1), Item(k="b", v=2)])]))
    assert table.size() == 2


class TestListFlatten:
    class Tagged(GatewayStruct):
        name: str = None
        values: list[float] = None

    def _module(self, **kwargs):
        module = _ModuleStub()
        encoder = self.Tagged.psp_arrow_encoder()
        MountPerspectiveTables.add_table(module, "t", encoder, **kwargs)
        return module._table_insts["t"], encoder

    def test_stringify_keeps_a_list_in_one_cell_so_the_table_can_be_indexed(self):
        table, encoder = self._module(index="name", list_flatten="stringify")
        table.update(encoder.encode([self.Tagged(name="a", values=[1.0, 2.5])]))
        assert table.schema()["values"] == "string"
        assert [orjson.loads(r["values"]) for r in table.view().to_records()] == [[1.0, 2.5]]

    def test_cartesian_is_the_default(self):
        table, encoder = self._module()
        table.update(encoder.encode([self.Tagged(name="a", values=[1.0, 2.5])]))
        assert table.size() == 2

    def test_stringify_keeps_a_list_of_structs_in_one_cell(self):
        class Item(GatewayStruct):
            k: str

        class Order(GatewayStruct):
            items: list[Item]

        rows = _records_with(Order, [Order(items=[Item(k="a"), Item(k="b")])], list_flatten="stringify")
        assert [[item["k"] for item in orjson.loads(r["items"])] for r in rows] == [["a", "b"]]

    def test_stringify_formatted_writes_datetimes_as_text(self):
        class Stamped(GatewayStruct):
            when: list[datetime]

        rows = _records_with(Stamped, [Stamped(when=[datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)])], list_flatten="stringify_formatted")
        assert orjson.loads(rows[0]["when"]) == ["2024-01-02 03:04:05.000"]

    def test_table_config_reaches_the_table(self):
        module = MountPerspectiveTables(tables={"a": TableConfig(list_flatten="stringify", map_flatten="pivot")})
        assert (module._get_effective_config("a").list_flatten, module._get_effective_config("a").map_flatten) == ("stringify", "pivot")
        assert (module._get_effective_config("b").list_flatten, module._get_effective_config("b").map_flatten) == (
            "cartesian",
            "stringify_formatted",
        )


class TestIndexAndLimit:
    """Perspective takes an index or a limit for a table, never both."""

    def test_default_limit_gives_way_to_an_index(self):
        module = MountPerspectiveTables(default_limit=100, indexes={"a": "id"})
        assert (module._get_effective_config("a").index, module._get_effective_config("a").limit) == ("id", None)
        assert (module._get_effective_config("b").index, module._get_effective_config("b").limit) == (None, 100)

    def test_default_index_gives_way_to_a_limit(self):
        module = MountPerspectiveTables(default_index="id", limits={"a": 5}, indexes={"c": None})
        assert (module._get_effective_config("a").index, module._get_effective_config("a").limit) == (None, 5)
        assert (module._get_effective_config("b").index, module._get_effective_config("b").limit) == ("id", None)

    def test_opting_out_of_the_default_index_restores_the_default_limit(self):
        module = MountPerspectiveTables(default_index="id", default_limit=10, indexes={"c": None})
        assert (module._get_effective_config("c").index, module._get_effective_config("c").limit) == (None, 10)

    def test_both_on_one_table_is_left_for_perspective_to_reject(self):
        module = MountPerspectiveTables(indexes={"a": "id"}, limits={"a": 5})
        config = module._get_effective_config("a")
        assert (config.index, config.limit) == ("id", 5)
        with pytest.raises(ValueError, match="both `limit` and `index`"):
            MountPerspectiveTables.add_table(_ModuleStub(), "a", MyTestOptionalSubStruct.psp_arrow_encoder(), limit=5, index="id")


@pytest.mark.parametrize("use_external_perspective", [True, False])
def test_MountPerspectiveTables(use_external_perspective):
    module = MountPerspectiveTables(
        tables={"exclude": ["exclude_channel"]},
        limits={"limit_channel": 5},
        indexes={"index_channel": "id", "dict_channel": "id", "exclude_channel": None},
        # Perspective explodes a list into rows, which a table indexed on `id` cannot hold
        excluded_table_columns={"index_channel": {"sub": {"y"}}, "dict_channel": {"sub": {"y"}}},
        layouts={
            "Test Layout": '{"sizes":[1],"detail":{"main":{"type":"split-area","orientation":"horizontal","children":[{"type":"split-area","orientation":"vertical","children":[{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_1"],"currentIndex":0},{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_4"],"currentIndex":0}],"sizes":[0.5,0.5]},{"type":"split-area","orientation":"vertical","children":[{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_3"],"currentIndex":0},{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_5"],"currentIndex":0}],"sizes":[0.5,0.5]}],"sizes":[0.5,0.5]}},"mode":"globalFilters","viewers":{"PERSPECTIVE_GENERATED_ID_1":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"timestamp":"last","x":"last","id":"last","y":"last"},"master":false,"name":"basket","table":"basket","linked":false},"PERSPECTIVE_GENERATED_ID_4":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"timestamp":"last","x":"last","id":"last","y":"last"},"master":false,"name":"example_list","table":"example_list","linked":false},"PERSPECTIVE_GENERATED_ID_3":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"id":"last","x":"last","timestamp":"last","y":"last"},"master":false,"name":"example","table":"example","linked":false},"PERSPECTIVE_GENERATED_ID_5":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"id":"last","timestamp":"last","x":"last","y":"last"},"master":false,"name":"never_ticks","table":"never_ticks","linked":false}}}'
        },
        update_interval=timedelta(seconds=0.5),
    )
    if use_external_perspective:
        module.perspective_field = "my_perspective"

    h = GatewayTestHarness(
        test_channels=[GWC.test_channel, GWC.list_channel, GWC.dict_channel, GWC.dict_enum_channel, GWC.index_channel, GWC.limit_channel],
        test_dynamic_keys={"dict_channel": ["test_key"]},
    )

    now = datetime.now(UTC).replace(tzinfo=UTC)

    # List with 1 element
    o = MyTestStruct(sub=MyTestSubStruct(y=[1], timestamp=now), timestamp=now)

    for _ in range(10):
        h.send(GWC.test_channel, o)
        h.send(GWC.list_channel, [o])
        h.send(GWC.dict_channel, {"test_key": o})
        h.send(GWC.dict_enum_channel, {MyTestEnum.a: o})
        h.send(GWC.limit_channel, o)
        h.send(GWC.index_channel, o)
    h.assert_ticked(GWC.test_channel, 10)
    h.assert_ticked(GWC.list_channel, 10)
    h.assert_ticked((GWC.dict_channel, "test_key"), 10)
    h.assert_ticked((GWC.dict_enum_channel, MyTestEnum.a), 10)
    h.assert_ticked(GWC.limit_channel, 10)
    h.assert_ticked(GWC.index_channel, 10)

    h.delay(2 * module.update_interval)  # So that the buffer is flushed
    channels = GWC()
    gateway = Gateway(modules=[h, module], channels=channels)
    csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(5))

    # The graph runs, which is a good sign. Now look at the contents of the tables more closely

    if use_external_perspective:
        psp = channels.my_perspective  # Confirm we use the manager from the channels in the tests that follow
    else:
        psp = module._server

    assert sorted(psp.new_local_client().get_hosted_table_names()) == sorted(
        [
            GWC.test_channel,
            GWC.list_channel,
            GWC.dict_channel,
            GWC.dict_enum_channel,
            GWC.index_channel,
            GWC.limit_channel,
        ]
    )

    def table_len(name):
        return len(psp.new_local_client().open_table(name).view().to_json())

    assert table_len(GWC.test_channel) == 10
    assert table_len(GWC.list_channel) == 10

    assert table_len(GWC.dict_channel) == 1  # Because of index
    assert table_len(GWC.dict_enum_channel) == 10
    assert table_len(GWC.limit_channel) == 5
    assert table_len(GWC.index_channel) == 1


@pytest.mark.parametrize("exclude_columns", [True, False])
def test_MountPerspectiveTables_exclude_columns(exclude_columns):
    if exclude_columns:
        excluded_table_columns = {"test_channel": {"z"}, "list_channel": {"sub": {"y"}}, "dict_channel": {"sub": {"y": True, "x": True}}}
    else:
        excluded_table_columns = {}

    module = MountPerspectiveTables(
        excluded_table_columns=excluded_table_columns,
        update_interval=timedelta(seconds=0.5),
    )

    h = GatewayTestHarness(
        test_channels=[GWC.test_channel, GWC.list_channel, GWC.dict_channel, GWC.exclude_channel],
        test_dynamic_keys={"dict_channel": ["test_key"]},
    )

    now = datetime.now(UTC).replace(tzinfo=UTC)

    # List with 1 element
    o = MyTestStruct(sub=MyTestSubStruct(y=[1], timestamp=now), timestamp=now)

    h.send(GWC.test_channel, o)
    h.send(GWC.list_channel, [o])
    h.send(GWC.dict_channel, {"test_key": o})
    h.send(GWC.exclude_channel, o)

    h.delay(2 * module.update_interval)  # So that the buffer is flushed
    channels = GWC()
    gateway = Gateway(modules=[h, module], channels=channels)
    csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(5))

    def table_columns(name):
        return set(module._server.new_local_client().open_table(name).columns())

    def table_len(name):
        return len(module._server.new_local_client().open_table(name).view().to_json())

    if exclude_columns:
        assert table_columns(GWC.test_channel) == {"sub.y", "sub.x", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}
        assert table_columns(GWC.list_channel) == {"z", "sub.x", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}
        assert table_columns(GWC.dict_channel) == {"z", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}

    else:
        assert table_columns(GWC.test_channel) == {"z", "sub.y", "sub.x", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}
        assert table_columns(GWC.list_channel) == {"z", "sub.y", "sub.x", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}
        assert table_columns(GWC.dict_channel) == {"z", "sub.y", "sub.x", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}

    assert table_columns(GWC.exclude_channel) == {"z", "sub.y", "sub.x", "sub.z", "id", "timestamp", "sub.id", "sub.timestamp"}

    assert table_len(GWC.test_channel) == 1
    assert table_len(GWC.list_channel) == 1
    assert table_len(GWC.dict_channel) == 1
    assert table_len(GWC.exclude_channel) == 1


def test_exclude_unused_tables():
    channels = GWCUnused()
    psp_module = MountPerspectiveTables()

    class MyTestModule(GatewayModule):
        def connect(self, channels):
            channels.set_channel(GWCUnused.a, csp.const(MyTestStruct()))
            channels.set_channel(GWCUnused.c, csp.const([MyTestStruct()]))
            channels.set_channel(GWCUnused.e, csp.const(MyTestStruct()), MyTestEnum.a)

    gateway = Gateway(modules=[psp_module, MyTestModule()], channels=channels)

    # Build gateway - this will wire unused channels with null_ts
    csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(5))

    # Mock out startup
    gateway.output = MagicMock()
    gateway.graph_build_failed = False
    gateway.running = True
    gateway.output.is_alive.return_value = True

    # Build web to run perspective table pruning
    gateway._build_web(ui=True, timeout=1, _in_test=True)

    # Assert that tables were pruned
    assert sorted(psp_module._unused_tables) == sorted(["b", "d", "f"])


def test_additional_tables():
    """Test that additional_tables creates duplicate tables from the same channel with different config."""
    from csp_gateway.server.modules.web.perspective import AdditionalTableConfig

    module = MountPerspectiveTables(
        tables={"include": ["test_channel", "limit_channel"]},
        indexes={"test_channel": "id"},
        excluded_table_columns={"test_channel": {"sub": {"y"}}},
        limits={"limit_channel": 5},
        additional_tables={
            "test_channel_no_index": AdditionalTableConfig(
                channel="test_channel",
                # no index, no limit - raw append
            ),
            "test_channel_limited": AdditionalTableConfig(
                channel="test_channel",
                limit=3,
            ),
            "limit_channel_full": AdditionalTableConfig(
                channel="limit_channel",
                # no limit override - gets all rows
            ),
        },
        update_interval=timedelta(seconds=0.5),
    )

    h = GatewayTestHarness(
        test_channels=[GWC.test_channel, GWC.limit_channel],
    )

    now = datetime.now(UTC).replace(tzinfo=UTC)
    o = MyTestStruct(sub=MyTestSubStruct(y=[1], timestamp=now), timestamp=now)

    for _ in range(10):
        h.send(GWC.test_channel, o)
        h.send(GWC.limit_channel, o)
    h.assert_ticked(GWC.test_channel, 10)
    h.assert_ticked(GWC.limit_channel, 10)

    h.delay(2 * module.update_interval)  # So that the buffer is flushed
    channels = GWC()
    gateway = Gateway(modules=[h, module], channels=channels)
    csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(5))

    psp = module._server

    # All tables should be registered
    table_names = sorted(psp.new_local_client().get_hosted_table_names())
    assert "test_channel" in table_names
    assert "test_channel_no_index" in table_names
    assert "test_channel_limited" in table_names
    assert "limit_channel" in table_names
    assert "limit_channel_full" in table_names

    def table_len(name):
        return len(psp.new_local_client().open_table(name).view().to_json())

    # test_channel has index="id", so all rows collapse to 1
    assert table_len("test_channel") == 1
    # test_channel_no_index has no index, all 10 rows kept
    assert table_len("test_channel_no_index") == 10
    # test_channel_limited has limit=3, so at most 3 rows
    assert table_len("test_channel_limited") == 3

    # limit_channel has limit=5
    assert table_len("limit_channel") == 5
    # limit_channel_full has no limit, all 10 rows
    assert table_len("limit_channel_full") == 10


def test_additional_tables_with_dict_channel():
    """Test that additional_tables works with dict basket channels."""
    from csp_gateway.server.modules.web.perspective import AdditionalTableConfig

    module = MountPerspectiveTables(
        tables={"include": ["dict_channel"]},
        indexes={"dict_channel": "id"},
        excluded_table_columns={"dict_channel": {"sub": {"y"}}},
        additional_tables={
            "dict_channel_no_index": AdditionalTableConfig(
                channel="dict_channel",
                # no index - keeps all rows
            ),
        },
        update_interval=timedelta(seconds=0.5),
    )

    h = GatewayTestHarness(
        test_channels=[GWC.dict_channel],
        test_dynamic_keys={"dict_channel": ["test_key"]},
    )

    now = datetime.now(UTC).replace(tzinfo=UTC)
    o = MyTestStruct(sub=MyTestSubStruct(y=[1], timestamp=now), timestamp=now)

    for _ in range(5):
        h.send(GWC.dict_channel, {"test_key": o})
    h.assert_ticked((GWC.dict_channel, "test_key"), 5)

    h.delay(2 * module.update_interval)
    channels = GWC()
    gateway = Gateway(modules=[h, module], channels=channels)
    csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(5))

    psp = module._server

    def table_len(name):
        return len(psp.new_local_client().open_table(name).view().to_json())

    # dict_channel has index="id", collapses to 1 row
    assert table_len("dict_channel") == 1
    # dict_channel_no_index has no index, all 5 rows kept
    assert table_len("dict_channel_no_index") == 5


def test_additional_tables_invalid_channel():
    """Test that referencing a non-existent channel raises an error."""
    from csp_gateway.server.modules.web.perspective import AdditionalTableConfig

    module = MountPerspectiveTables(
        tables={"include": ["test_channel"]},
        additional_tables={
            "bogus_table": AdditionalTableConfig(
                channel="nonexistent_channel",
            ),
        },
        update_interval=timedelta(seconds=0.5),
    )

    h = GatewayTestHarness(
        test_channels=[GWC.test_channel],
    )

    now = datetime.now(UTC).replace(tzinfo=UTC)
    o = MyTestStruct(sub=MyTestSubStruct(y=[1], timestamp=now), timestamp=now)
    h.send(GWC.test_channel, o)

    channels = GWC()
    gateway = Gateway(modules=[h, module], channels=channels)
    with pytest.raises(ValueError, match="references channel 'nonexistent_channel'"):
        csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(5))


def test_tables_unified_api():
    """Test the new unified tables API where everything is configured via tables dict."""
    from csp_gateway.server.modules.web.perspective import TableConfig

    module = MountPerspectiveTables(
        tables={
            # Primary table with config override (channel == table_name when omitted)
            "test_channel": TableConfig(index="id", excluded_columns={"sub": {"y"}}),
            # Primary table with limit
            "limit_channel": TableConfig(limit=5),
            # Additional table: same channel, different config
            "test_channel_no_index": TableConfig(channel="test_channel"),
            "test_channel_limited": TableConfig(channel="test_channel", limit=3),
        },
        channel_selection={"exclude": ["dict_channel", "dict_enum_channel", "index_channel", "exclude_channel"]},
        update_interval=timedelta(seconds=0.5),
    )

    h = GatewayTestHarness(
        test_channels=[GWC.test_channel, GWC.limit_channel],
    )

    now = datetime.now(UTC).replace(tzinfo=UTC)
    o = MyTestStruct(sub=MyTestSubStruct(y=[1], timestamp=now), timestamp=now)

    for _ in range(10):
        h.send(GWC.test_channel, o)
        h.send(GWC.limit_channel, o)
    h.assert_ticked(GWC.test_channel, 10)
    h.assert_ticked(GWC.limit_channel, 10)

    h.delay(2 * module.update_interval)
    channels = GWC()
    gateway = Gateway(modules=[h, module], channels=channels)
    csp.run(gateway.graph, starttime=datetime(2023, 1, 1), endtime=timedelta(5))

    psp = module._server

    def table_len(name):
        return len(psp.new_local_client().open_table(name).view().to_json())

    # test_channel has index="id" via TableConfig, collapses to 1
    assert table_len("test_channel") == 1
    # test_channel_no_index has no index, keeps all 10
    assert table_len("test_channel_no_index") == 10
    # test_channel_limited has limit=3
    assert table_len("test_channel_limited") == 3
    # limit_channel has limit=5
    assert table_len("limit_channel") == 5


class TestLayoutMigration:
    """Saved layouts are upgraded by Perspective's own migration, through spaday-perspective.

    The exact shape is Perspective's to decide (its `perspective-migrate` corpus covers it); these
    tests cover what csp-gateway relies on: which layouts change, and that the result is valid.
    """

    V4_LAYOUT = json.dumps(
        {
            "sizes": [0.2, 0.8],
            "detail": {
                "main": {
                    "type": "split-area",
                    "orientation": "vertical",
                    "sizes": [0.3, 0.7],
                    "children": [
                        {"type": "tab-area", "widgets": ["A"], "currentIndex": 0},
                        {"type": "tab-area", "widgets": ["B", "C"], "currentIndex": 1},
                    ],
                }
            },
            "master": {"sizes": [1], "widgets": ["M"]},
            "mode": "globalFilters",
            "viewers": {
                "A": {"table": "example", "plugin": "Datagrid"},
                "B": {"table": "example", "plugin": "Treemap"},
                "C": {"table": "other", "plugin": "Datagrid"},
                "M": {"table": "example", "plugin": "Datagrid", "group_by": ["id"]},
            },
        }
    )

    @staticmethod
    def _tabs(node):
        if node["type"] == "tab-layout":
            return list(node["tabs"])
        return [tab for child in node["children"] for tab in TestLayoutMigration._tabs(child)]

    @staticmethod
    def _assert_valid(layout: str):
        from perspective import validate

        validate(
            "workspace",
            {key: value for key, value in json.loads(layout).items() if key not in ("closed_channels", "retained_panel_configs_by_table")},
        )

    def test_v4_layout_becomes_a_valid_workspace(self):
        migrated = migrate_perspective_layout(self.V4_LAYOUT)
        self._assert_valid(migrated)
        assert {"viewers", "detail", "master", "mode"}.isdisjoint(json.loads(migrated))

    def test_every_placed_panel_is_kept(self):
        migrated = json.loads(migrate_perspective_layout(self.V4_LAYOUT))
        assert sorted(migrated["panels"]) == ["A", "B", "C", "M"]
        assert sorted(self._tabs(migrated["layout"])) == ["A", "B", "C", "M"]
        assert migrated["masters"] == ["M"]
        assert migrated["panels"]["M"]["group_by"] == ["id"]

    def test_panel_configs_are_migrated(self):
        # Perspective's migration upgrades each panel too; a 2.x-era `name` becomes `title`.
        layout = json.loads(self.V4_LAYOUT)
        layout["viewers"]["A"]["name"] = "Named"
        migrated = json.loads(migrate_perspective_layout(json.dumps(layout)))
        assert migrated["panels"]["A"]["title"] == "Named"
        assert "name" not in migrated["panels"]["A"]

    def test_dropped_information_is_logged(self, caplog):
        # A v4 viewer that no layout node shows has no place in a version 5 workspace.
        layout = json.loads(self.V4_LAYOUT)
        layout["viewers"]["orphan"] = {"table": "example", "plugin": "Datagrid"}
        with caplog.at_level("WARNING"):
            migrated = json.loads(migrate_perspective_layout(json.dumps(layout)))
        assert "orphan" not in migrated["panels"]
        assert "Perspective layout migration" in caplog.text

    def test_migration_is_idempotent(self):
        once = migrate_perspective_layout(self.V4_LAYOUT)
        assert json.loads(migrate_perspective_layout(once)) == json.loads(once)

    def test_current_layouts_are_stamped_and_keep_spaday_keys(self):
        # A current-shape layout without a `version` is taken as written by the installed release.
        retained = {"example": {"plugin": "Datagrid", "table": "example"}}
        layout = {"layout": {"type": "tab-layout", "tabs": ["A"]}, "panels": {"A": {"table": "example"}}, "closed_channels": retained}
        migrated = json.loads(migrate_perspective_layout(json.dumps(layout)))
        assert migrated["panels"] == {"A": {"table": "example"}}
        assert migrated["closed_channels"] == retained
        assert "version" in migrated

    def test_v5_layout_with_legacy_metadata_is_left_or_made_valid(self):
        layout = json.dumps({"layout": {"type": "tab-layout", "tabs": ["A"]}, "panels": {"A": {"table": "example"}}, "viewers": {}})
        migrated = migrate_perspective_layout(layout)
        if migrated != layout:
            self._assert_valid(migrated)

    @pytest.mark.parametrize("layout", ["", "not json", "[]", "1"])
    def test_non_layout_input_passes_through(self, layout):
        assert migrate_perspective_layout(layout) == layout

    @pytest.mark.parametrize(
        "root",
        ["invalid", {"type": "split-area", "children": [None]}, {"type": "split-area", "children": 1}],
    )
    def test_malformed_legacy_layout_does_not_break_configuration(self, root):
        layout = json.dumps({"viewers": {}, "detail": {"main": root}})
        module = MountPerspectiveTables(layouts={"Malformed": layout})
        # Left as is when Perspective cannot migrate it, and otherwise migrated to something valid.
        if module.layouts["Malformed"] != layout:
            self._assert_valid(module.layouts["Malformed"])

    def test_configured_layouts_are_migrated_on_validation(self):
        module = MountPerspectiveTables(layouts={"Server Defined Layout": self.V4_LAYOUT})
        migrated = json.loads(module.layouts["Server Defined Layout"])
        assert {"layout", "masters", "panels"} <= migrated.keys()

    def test_demo_layout_migrates_to_a_valid_workspace(self):
        # The viewer rejects keys a workspace does not define, so the demo's 3.3.4-era layout must migrate cleanly.
        from pathlib import Path

        from omegaconf import OmegaConf

        import csp_gateway

        config = OmegaConf.load(Path(csp_gateway.__file__).parent / "server/config/gateway/omnibus.yaml")
        layout = config.modules.mount_perspective_tables.layouts["Server Defined Layout"]
        self._assert_valid(migrate_perspective_layout(layout))


class TestServerViews:
    """Server views are pre-calculated tables, which client-server replicas must be able to follow."""

    FLAT = {"table": "base", "group_by": ["g"], "columns": ["v"], "aggregates": {"v": "sum"}, "group_rollup_mode": "flat"}

    @staticmethod
    def _module(**config):
        module = MountPerspectiveTables(**config)
        module._server = Server()
        module._client = module._server.new_local_client()
        module._table_insts = {}
        source = module._client.table({"k": "string", "g": "string", "v": "float"}, index="k", name="base")
        source.update([{"k": "1", "g": "x", "v": 1.0}, {"k": "2", "g": "y", "v": 2.0}])
        module._add_server_views()
        return module, source

    def test_any_perspective_view_setting_is_accepted(self):
        module = MountPerspectiveTables(server_views={"by_g": self.FLAT})
        assert module.server_views["by_g"]["group_rollup_mode"] == "flat"

    def test_configs_are_left_as_given(self):
        # Perspective's defaults apply; nothing is added, so this view keeps its total and subtotal rows.
        module = MountPerspectiveTables(server_views={"by_g": {"table": "base", "group_by": ["g"]}})
        assert module.server_views["by_g"] == {"table": "base", "group_by": ["g"]}

    @pytest.mark.parametrize(
        ("config", "match"),
        [
            ({"group_by": ["g"]}, "must specify a base 'table'"),
            ({"table": "base"}, "at least one view operation"),
            ({"table": "base", "row_pivots": ["g"]}, "not a valid Perspective view"),
        ],
    )
    def test_invalid_configs_are_rejected(self, config, match):
        with pytest.raises(ValueError, match=match):
            MountPerspectiveTables(server_views={"bad": config})

    def test_flat_grouped_view_is_indexed_by_its_groups(self):
        module, _ = self._module(server_views={"by_g": self.FLAT})
        assert module._table_insts["by_g"].get_index() == "g"

    def test_replica_of_a_flat_grouped_view_follows_groups_that_empty(self):
        module, source = self._module(server_views={"by_g": self.FLAT})
        derived = module._table_insts["by_g"]
        # As spaday-perspective's mirror does: a view opened through one client (the websocket's) is
        # copied into a table on another (the browser worker's), which Perspective keeps in step.
        view = module._server.new_local_client().open_table("by_g").view()
        replica = module._server.new_local_client().table(view)
        assert replica.get_index() == "g"

        source.update([{"k": "1", "g": "y", "v": 10.0}])
        source.remove(["2"])
        source.update([{"k": "3", "g": "z", "v": 5.0}])
        expected = sorted(derived.view().to_records(), key=lambda row: row["g"])
        assert expected == [{"g": "y", "v": 10.0}, {"g": "z", "v": 5.0}]

        def replica_rows():
            return sorted(replica.view().to_records(), key=lambda row: row["g"])

        # Cross-client updates may be delivered after `update` returns.
        deadline = time.monotonic() + 2
        while replica_rows() != expected and time.monotonic() < deadline:
            time.sleep(0.05)
        assert replica_rows() == expected

    def test_unindexed_grouped_view_warns_in_client_server_mode(self, caplog):
        config = {**self.FLAT, "group_rollup_mode": "rollup"}
        with caplog.at_level("WARNING"):
            module, _ = self._module(server_views={"by_g": config})
        assert module._table_insts["by_g"].get_index() is None
        assert "keep groups that empty" in caplog.text

    def test_unindexed_grouped_view_does_not_warn_in_server_mode(self, caplog):
        config = {**self.FLAT, "group_rollup_mode": "rollup"}
        with caplog.at_level("WARNING"):
            self._module(server_views={"by_g": config}, architectures={"by_g": "server"})
        assert "keep groups that empty" not in caplog.text


class _Color(Enum):
    RED = 1
    BLUE = 2


class _CspColor(csp.Enum):
    RED = 1
    BLUE = 2


class _Leaf(GatewayStruct):
    n: int
    when: datetime


class _HoldsLeaf(GatewayStruct):
    x: int
    leaf: _Leaf


class _Wide(GatewayStruct):
    """One of every column kind the encoder builds from attributes."""

    i: int
    f: float
    s: str
    flag: bool
    d: date
    opt: int | None = None
    color: _Color
    csp_color: _CspColor
    colors: list[_Color] = []
    leaf: _Leaf
    leaves: list[_Leaf] = []
    ints: list[int] = []
    arr: Numpy1DArray[float] = np.array([])
    tags: dict[str, int] = {}
    blob: dict = {}
    nested_blob: dict[str, list[int]] = {}


class _Serialized(GatewayStruct):
    x: int

    @field_serializer("x")
    def _double(self, value: int) -> int:
        return value * 2


class _HoldsSerialized(GatewayStruct):
    inner: _Serialized


class _Prepared(GatewayStruct):
    data: dict = {}
    data_str: str = ""

    def psp_prepare(self):
        self.data_str = orjson.dumps(self.data).decode()


def _wide_records():
    now = datetime(2026, 11, 16, 12, 0, 0)
    leaf = _Leaf(n=1, when=now)
    return [
        _Wide(
            i=1,
            f=1.5,
            s="a",
            flag=True,
            d=date(2026, 11, 16),
            opt=3,
            color=_Color.RED,
            csp_color=_CspColor.BLUE,
            colors=[_Color.RED, _Color.BLUE],
            leaf=leaf,
            leaves=[leaf, _Leaf(n=2, when=now.replace(tzinfo=UTC))],
            ints=[1, 2, 3],
            arr=np.array([0.5, 1.5]),
            tags={"a": 1, "b": 2},
            blob={"k": [1, {"x": now}]},
            nested_blob={"a": [1, 2]},
            timestamp=now,
        ),
        # Fields never set: implicitly unset ones are null, a struct included.
        _Wide(i=2, s="b", color=_Color.BLUE),
        # Explicit empties and an explicit None.
        _Wide(i=3, opt=None, colors=[], leaves=[], ints=[], arr=np.array([]), tags={}, blob={}, nested_blob={}),
    ]


class TestAttributeEncoder:
    """The column-by-column encoder gives exactly what the `model_dump` path gives."""

    @staticmethod
    def _both(struct_type, records, excluded=None):
        encoder = struct_type.psp_arrow_encoder(excluded)
        return encoder, encoder.encode(records).to_pylist(), encoder._encode_dumped(records).to_pylist()

    def test_every_column_kind_matches_model_dump(self):
        encoder, fast, dumped = self._both(_Wide, _wide_records())
        assert encoder._attributes is not None
        assert fast == dumped

    def test_exclusions_match_model_dump(self):
        encoder, fast, dumped = self._both(_Wide, _wide_records(), {"leaf": {"n"}, "blob": True, "arr": True})
        assert encoder._attributes is not None
        assert fast == dumped
        assert "blob" not in encoder.schema.names

    def test_existing_test_structs_match_model_dump(self):
        now = datetime.now(UTC)
        records = [
            MyTestStruct(sub=MyTestSubStruct(y=[1, 2], z=1.0, timestamp=now), z=MyTestEnum.b, timestamp=now),
            MyTestStruct(sub=MyTestSubStruct(y=[], z=2.0), timestamp=now),
            MyTestStruct(timestamp=now),
        ]
        encoder, fast, dumped = self._both(MyTestStruct, records)
        assert encoder._attributes is not None
        assert fast == dumped

    def test_csp_enum_arrays_match_model_dump(self):
        class Status(csp.Enum):
            READY = 1
            DONE = 2

        class WithStatuses(GatewayStruct):
            statuses: Numpy1DArray[Status]
            values: Numpy1DArray[float]

        records = [WithStatuses(statuses=np.array([Status.READY, Status.DONE], dtype=object), values=np.array([1.0, 2.0])), WithStatuses()]
        _, fast, dumped = self._both(WithStatuses, records)
        assert fast == dumped

    @pytest.mark.parametrize("cls", [_Serialized, _HoldsSerialized])
    def test_python_serializers_fall_back_to_model_dump(self, cls):
        encoder = cls.psp_arrow_encoder()
        assert encoder._attributes is None
        record = _Serialized(x=2) if cls is _Serialized else _HoldsSerialized(inner=_Serialized(x=2))
        column = encoder.encode([record]).to_pylist()[0]
        assert (column["x"] if cls is _Serialized else column["inner"]["x"]) == 4

    def test_encoding_makes_no_per_record_objects_for_the_garbage_collector(self):
        # Container objects made per record and alive until the batch is encoded get promoted to the
        # collector's oldest generation and set off full collections. Those hold the GIL while they sweep
        # every live object (~300 ms at 100k records per batch), stalling the csp engine.
        now = datetime(2026, 11, 16, 12, 0, 0)
        # Half the records leave every field implicitly unset, at both levels: unset fields are checked per record.
        records = [_HoldsLeaf(x=i, leaf=_Leaf(n=i, when=now)) for i in range(5_000)] + [_HoldsLeaf(leaf=_Leaf()) for _ in range(5_000)]
        encoder = _HoldsLeaf.psp_arrow_encoder()
        assert encoder._attributes is not None
        collections = []

        def on_collect(phase, info):
            if phase == "start":
                collections.append(info["generation"])

        enabled, threshold = gc.isenabled(), gc.get_threshold()
        gc.collect()
        gc.enable()
        # A collection per 100 objects alive at once: one object per record would set off ~200 here.
        gc.set_threshold(100, 10, 10)
        gc.callbacks.append(on_collect)
        try:
            encoder.encode_ipc(records)
        finally:
            gc.callbacks.remove(on_collect)
            gc.set_threshold(*threshold)
            if not enabled:
                gc.disable()
        assert len(collections) < 10, collections
        assert encoder.encode(records).to_pylist() == encoder._encode_dumped(records).to_pylist()

    def test_psp_prepare_runs_before_attributes_are_read(self):
        encoder = _Prepared.psp_arrow_encoder()
        assert encoder._attributes is not None
        assert encoder.encode([_Prepared(data={"a": 1})]).to_pylist()[0]["data_str"] == '{"a":1}'

    def test_perspective_tables_match(self):
        encoder = _Wide.psp_arrow_encoder()
        client = Server().new_local_client()
        # csp-gateway's table defaults: several lists in one row expand as their product.
        options = {"list_flatten": "cartesian", "map_flatten": "stringify_formatted"}
        # The same records for both: each construction generates its own ids and timestamps.
        records = _wide_records()
        fast = client.table(encoder.empty_ipc(), **options)
        fast.update(encoder.encode_ipc(records))
        dumped = client.table(encoder.empty_ipc(), **options)
        dumped.update(encoder._encode_dumped(records))
        assert fast.view().to_columns() == dumped.view().to_columns()


class TestEncodeOncePerChannel:
    """A channel feeding several tables is encoded once per encoder those tables use."""

    def test_tables_sharing_an_encoder_are_grouped(self):
        shared = MyTestOptionalSubStruct.psp_arrow_encoder()
        other = MyTestOptionalSubStruct.psp_arrow_encoder({"sub_a"})
        module = MountPerspectiveTables()
        module._feed("channel", "a", shared)
        module._feed("channel", "b", shared)
        module._feed("channel", "c", other)
        assert module._channel_groups == {"channel": [(shared, ["a", "b"]), (other, ["c"])]}
        assert module._encoders == {"a": shared, "b": shared, "c": other}

    def test_each_encoder_encodes_a_batch_once(self, monkeypatch):
        from csp_gateway.server.modules.web.perspective import apply_batch

        shared = MyTestOptionalSubStruct.psp_arrow_encoder()
        other = MyTestOptionalSubStruct.psp_arrow_encoder({"sub_a"})
        calls = []
        for encoder in (shared, other):
            original = encoder.encode_ipc
            monkeypatch.setattr(encoder, "encode_ipc", lambda items, encoder=encoder, original=original: calls.append(encoder) or original(items))
        client = Server().new_local_client()
        tables = {name: client.table(encoder.empty_ipc(), name=name) for name, encoder in (("a", shared), ("b", shared), ("c", other))}

        apply_batch({"channel": [MyTestOptionalSubStruct(sub_a=1)]}, {"channel": [(shared, ["a", "b"]), (other, ["c"])]}, tables)

        assert calls == [shared, other]
        assert [tables[name].size() for name in ("a", "b", "c")] == [1, 1, 1]
        assert "sub_a" in tables["a"].columns()
        assert "sub_a" not in tables["c"].columns()


class TestDefaultLayoutTables:
    """Which tables the generated default layout opens."""

    AVAILABLE = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf"]

    @staticmethod
    def _module(**kwargs) -> MountPerspectiveTables:
        return MountPerspectiveTables(**kwargs)

    def test_caps_at_five_in_name_order_by_default(self):
        module = self._module()
        assert module._select_default_layout_tables(self.AVAILABLE) == ["alpha", "bravo", "charlie", "delta", "echo"]

    def test_max_is_configurable(self):
        module = self._module(default_layout_max_tables=2)
        assert module._select_default_layout_tables(self.AVAILABLE) == ["alpha", "bravo"]

    def test_explicit_tables_win_and_keep_their_order(self):
        module = self._module(default_layout_tables=["golf", "alpha"], default_layout_max_tables=1)
        assert module._select_default_layout_tables(self.AVAILABLE) == ["golf", "alpha"]

    def test_unknown_table_names_are_dropped(self):
        module = self._module(default_layout_tables=["golf", "not_a_table"])
        assert module._select_default_layout_tables(self.AVAILABLE) == ["golf"]
