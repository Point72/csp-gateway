import json
from datetime import UTC, date, datetime, timedelta
from enum import Enum, auto
from typing import Annotated
from unittest.mock import MagicMock

import csp
import numpy as np
import polars as pl
import pytest
from csp import ts
from csp.typing import Numpy1DArray
from perspective import Server
from pydantic import BaseModel, ConfigDict, Field

from csp_gateway import (
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewayStruct,
    MountPerspectiveTables,
    create_pyarrow_table,
    psp_schema_to_arrow_schema,
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

    class StructWithCspEnumArray(GatewayStruct):
        statuses: Annotated[Numpy1DArray[Status], Field(description="Statuses")]
        values: Annotated[Numpy1DArray[float], Field(description="Values")]

    schema = StructWithCspEnumArray.psp_schema()
    assert schema["statuses"] is str
    assert schema["values"] is float


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

    # List with 1 element
    o = MyTestStruct(sub=MyTestSubStruct(y=[1], timestamp=now), timestamp=now)
    # Use the actual id from the object, not the counter (which is now global)
    sub_id = o.sub.id
    id = o.id

    assert isinstance(o.sub.psp_flatten(), list)
    sub_flat = o.sub.psp_flatten()
    for d in sub_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
    assert sub_flat == [
        {"id": sub_id, "y": 1, "x": 1, "timestamp": now},
    ]

    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": id,
            "sub.id": sub_id,
            "sub.y": 1,
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    o = MyTestStruct(sub=MyTestSubStruct(y=[], z=float("nan"), timestamp=now), timestamp=now)
    o2_sub_id = o.sub.id
    o2_id = o.id
    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": o2_id,
            "sub.id": o2_sub_id,
            "sub.x": 1,
            "sub.z": None,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    o = MyTestStruct(sub=MyTestSubStruct(y=[], z=float("inf"), timestamp=now), timestamp=now)
    o3_sub_id = o.sub.id
    o3_id = o.id
    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": o3_id,
            "sub.id": o3_sub_id,
            "sub.x": 1,
            "sub.z": None,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    o = MyTestStruct(sub=MyTestSubStruct(y=[], z=float("-inf"), timestamp=now), timestamp=now)
    o4_sub_id = o.sub.id
    o4_id = o.id
    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": o4_id,
            "sub.id": o4_sub_id,
            "sub.x": 1,
            "sub.z": None,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    # List with multiple elements
    o = MyTestStruct(sub=MyTestSubStruct(y=[1, 2, 3], timestamp=now), timestamp=now)
    o5_sub_id = o.sub.id
    o5_id = o.id

    assert isinstance(o.sub.psp_flatten(), list)
    sub_flat = o.sub.psp_flatten()
    for d in sub_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
    assert sub_flat == [
        {"id": o5_sub_id, "y": 1, "x": 1, "timestamp": now},
        {"id": o5_sub_id, "y": 2, "x": 1, "timestamp": now},
        {"id": o5_sub_id, "y": 3, "x": 1, "timestamp": now},
    ]

    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": o5_id,
            "sub.id": o5_sub_id,
            "sub.y": 1,
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
        {
            "id": o5_id,
            "sub.id": o5_sub_id,
            "sub.y": 2,
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
        {
            "id": o5_id,
            "sub.id": o5_sub_id,
            "sub.y": 3,
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    # Empty list removed
    o = MyTestStruct(sub=MyTestSubStruct(y=[], timestamp=now), timestamp=now)
    o6_sub_id = o.sub.id
    o6_id = o.id
    assert isinstance(o.sub.psp_flatten(), list)
    sub_flat = o.sub.psp_flatten()
    for d in sub_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
    assert sub_flat == [
        {"id": o6_sub_id, "x": 1, "timestamp": now},
    ]

    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": o6_id,
            "sub.id": o6_sub_id,
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    # Non json serializable object passed
    o = MyTestStruct(ncsp_sub=object(), timestamp=now)
    o7_id = o.id
    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
    assert o_flat == [
        {
            "id": o7_id,
            "ncsp_sub": "",
            "timestamp": now,
        },
    ]


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
    schema = MyPyArrowStruct.psp_schema()
    arrow_schema = psp_schema_to_arrow_schema(schema)
    date_key_set = set()
    date_key_set.add("d")
    datetime_key_set = set()
    datetime_key_set.add("timestamp")

    o = MyPyArrowStruct(timestamp=now, d=now_date)
    table = create_pyarrow_table(None, [o], None, arrow_schema, date_key_set)
    df = pl.from_arrow(table)
    assert df.head()["d"][0] == now_date

    #  Check nones are handled correctly
    o = MyPyArrowStruct(timestamp=None, d=None)
    table = create_pyarrow_table(None, [o], None, arrow_schema, date_key_set)
    df = pl.from_arrow(table)
    assert df.head()["d"][0] is None
    assert df.head()["timestamp"][0] is None


@pytest.mark.parametrize("use_external_perspective", [True, False])
def test_MountPerspectiveTables(use_external_perspective):
    module = MountPerspectiveTables(
        tables={"exclude": ["exclude_channel"]},
        limits={"limit_channel": 5},
        indexes={"index_channel": "id", "dict_channel": "id", "exclude_channel": None},
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
            "test_channel": TableConfig(index="id"),
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
    """Perspective 4 workspace layouts are rewritten to the Perspective 5 shape."""

    V4_LAYOUT = json.dumps(
        {
            "sizes": [1],
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
            "master": {"sizes": [], "widgets": ["A"]},
            "mode": "globalFilters",
            "viewers": {
                "A": {"table": "example", "plugin": "Datagrid"},
                "B": {"table": "example", "plugin": "Treemap"},
                "C": {"table": "other", "plugin": "Datagrid"},
            },
        }
    )

    def test_widget_tree_becomes_layout_tree(self):
        migrated = json.loads(migrate_perspective_layout(self.V4_LAYOUT))
        assert migrated["layout"] == {
            "type": "split-layout",
            "orientation": "vertical",
            "sizes": [0.3, 0.7],
            "children": [
                {"type": "tab-layout", "tabs": ["A"], "selected": 0},
                {"type": "tab-layout", "tabs": ["B", "C"], "selected": 1},
            ],
        }

    def test_viewers_become_panels_and_masters_are_kept(self):
        migrated = json.loads(migrate_perspective_layout(self.V4_LAYOUT))
        assert sorted(migrated["panels"]) == ["A", "B", "C"]
        assert migrated["panels"]["B"] == {"table": "example", "plugin": "Treemap"}
        assert migrated["masters"] == ["A"]
        # The v4-only envelope keys do not survive.
        assert "viewers" not in migrated
        assert "detail" not in migrated

    def test_already_migrated_layout_is_untouched(self):
        once = migrate_perspective_layout(self.V4_LAYOUT)
        assert migrate_perspective_layout(once) == once

    @pytest.mark.parametrize("layout", ["", "not json", "[]", '{"panels": {}}'])
    def test_non_v4_input_passes_through(self, layout):
        assert migrate_perspective_layout(layout) == layout

    def test_configured_layouts_are_migrated_on_validation(self):
        module = MountPerspectiveTables(layouts={"Server Defined Layout": self.V4_LAYOUT})
        migrated = json.loads(module.layouts["Server Defined Layout"])
        assert sorted(migrated) == ["layout", "masters", "panels"]


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
