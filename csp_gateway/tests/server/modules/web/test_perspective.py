from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional

import csp
import numpy as np
import polars as pl
import pytest
from csp import Enum, ts
from csp.typing import Numpy1DArray
from perspective import Server
from pydantic import Field

from csp_gateway import Gateway, GatewayChannels, GatewayStruct, MountPerspectiveTables, create_pyarrow_table, psp_schema_to_arrow_schema
from csp_gateway.testing.harness import GatewayTestHarness
from csp_gateway.utils.struct import GatewayStructMixins


class MyTestEnum(Enum):
    a = Enum.auto()
    b = Enum.auto()


class MyTestSubStruct(GatewayStruct):
    y: List[int]
    x: int = 1
    z: float


class MyTestStruct(GatewayStruct):
    sub: MyTestSubStruct
    z: MyTestEnum
    ncsp_sub: object


class MyTestOptionalSubStruct(GatewayStruct):
    sub_a: Optional[int]


class MyTestOptionalStruct(GatewayStruct):
    i: int
    i_o: Optional[int]
    ob: object
    ob_op: Optional[object]
    l_i: [int]
    lt_i: List[int]
    lt_i_op: Optional[List[int]]
    s: MyTestSubStruct
    s_op: Optional[MyTestSubStruct]
    e: MyTestEnum
    e_op: Optional[MyTestEnum]
    sub: MyTestOptionalSubStruct
    sub_op: Optional[MyTestOptionalSubStruct]


class MyPyArrowStruct(GatewayStruct):
    d: date


def test_inherited_container_annotation_schema():
    # Base declares container field
    from csp import Struct

    class BaseStruct(Struct):
        arr: List[int]

    # Child has no own annotations for arr; relies on inherited annotation
    class ChildStruct(*GatewayStructMixins, BaseStruct):
        # explicit id/timestamp, like typical mixin usage
        id: str
        timestamp: datetime

    schema = ChildStruct.psp_schema()
    # Ensure container element type is preserved as int, not str
    assert schema["arr"] is int


def test_inherited_ndarray_annotation_schema():
    from csp import Struct

    # Base declares numpy array field with element type
    class BaseStruct(Struct):
        arr_nd: Numpy1DArray[float] = np.array([1.0]).view(Numpy1DArray)

    # Child inherits without redeclaring annotation
    class ChildStruct(*GatewayStructMixins, BaseStruct):
        id: str
        timestamp: datetime

    schema = ChildStruct.psp_schema()
    # Ensure ndarray element type is preserved as float, not str
    assert schema["arr_nd"] is float


def test_inherited_container_on_gatewaystruct():
    # Parent defines a container field on GatewayStruct
    class ParentGS(GatewayStruct):
        arr: List[int]

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
    now = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)

    # List with 1 element
    o = MyTestStruct(sub=MyTestSubStruct(y=[1], timestamp=now), timestamp=now)
    sub_id = MyTestSubStruct.id_generator.current()
    id = MyTestStruct.id_generator.current()

    assert isinstance(o.sub.psp_flatten(), list)
    sub_flat = o.sub.psp_flatten()
    for d in sub_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
    assert sub_flat == [
        {"id": str(sub_id), "y": 1, "x": 1, "timestamp": now},
    ]

    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": str(id),
            "sub.id": str(sub_id),
            "sub.y": 1,
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    o = MyTestStruct(sub=MyTestSubStruct(y=[], z=float("nan"), timestamp=now), timestamp=now)
    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": str(id + 1),
            "sub.id": str(sub_id + 1),
            "sub.x": 1,
            "sub.z": None,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    o = MyTestStruct(sub=MyTestSubStruct(y=[], z=float("inf"), timestamp=now), timestamp=now)
    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": str(id + 2),
            "sub.id": str(sub_id + 2),
            "sub.x": 1,
            "sub.z": None,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    o = MyTestStruct(sub=MyTestSubStruct(y=[], z=float("-inf"), timestamp=now), timestamp=now)
    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": str(id + 3),
            "sub.id": str(sub_id + 3),
            "sub.x": 1,
            "sub.z": None,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    # List with multiple elements
    o = MyTestStruct(sub=MyTestSubStruct(y=[1, 2, 3], timestamp=now), timestamp=now)

    assert isinstance(o.sub.psp_flatten(), list)
    sub_flat = o.sub.psp_flatten()
    for d in sub_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
    assert sub_flat == [
        {"id": str(sub_id + 4), "y": 1, "x": 1, "timestamp": now},
        {"id": str(sub_id + 4), "y": 2, "x": 1, "timestamp": now},
        {"id": str(sub_id + 4), "y": 3, "x": 1, "timestamp": now},
    ]

    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": str(id + 4),
            "sub.id": str(sub_id + 4),
            "sub.y": 1,
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
        {
            "id": str(id + 4),
            "sub.id": str(sub_id + 4),
            "sub.y": 2,
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
        {
            "id": str(id + 4),
            "sub.id": str(sub_id + 4),
            "sub.y": 3,
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    # Empty list removed
    o = MyTestStruct(sub=MyTestSubStruct(y=[], timestamp=now), timestamp=now)
    assert isinstance(o.sub.psp_flatten(), list)
    sub_flat = o.sub.psp_flatten()
    for d in sub_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
    assert sub_flat == [
        {"id": str(sub_id + 5), "x": 1, "timestamp": now},
    ]

    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["sub.timestamp"] = datetime.fromisoformat(d["sub.timestamp"])
    assert o_flat == [
        {
            "id": str(id + 5),
            "sub.id": str(sub_id + 5),
            "sub.x": 1,
            "sub.timestamp": now,
            "timestamp": now,
        },
    ]

    # Non json serializable object passed
    o = MyTestStruct(ncsp_sub=object(), timestamp=now)
    assert isinstance(o.psp_flatten(), list)
    o_flat = o.psp_flatten()
    for d in o_flat:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
    assert o_flat == [
        {
            "id": str(id + 6),
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
    now = datetime.now(timezone.utc)
    now_date = now.date()
    schema = MyPyArrowStruct.psp_schema()
    arrow_schema = psp_schema_to_arrow_schema(schema)
    date_key_set = set()
    date_key_set.add("d")
    datetime_key_set = set()
    datetime_key_set.add("timestamp")

    o = MyPyArrowStruct(timestamp=now, d=now_date)
    table = create_pyarrow_table(None, [o], arrow_schema, date_key_set)
    df = pl.from_arrow(table)
    assert df.head()["d"][0] == now_date

    #  Check nones are handled correctly
    o = MyPyArrowStruct(timestamp=None, d=None)
    table = create_pyarrow_table(None, [o], arrow_schema, date_key_set)
    df = pl.from_arrow(table)
    assert df.head()["d"][0] is None
    assert df.head()["timestamp"][0] is None


class ExampleEnum(Enum):
    A = 1
    B = 2
    C = 3


class GWC(GatewayChannels):
    test_channel: ts[MyTestStruct] = None
    list_channel: ts[List[MyTestStruct]] = None
    dict_channel: Dict[str, ts[MyTestStruct]] = None
    dict_enum_channel: Dict[ExampleEnum, ts[MyTestStruct]] = None
    index_channel: ts[MyTestStruct] = None
    limit_channel: ts[MyTestStruct] = None
    exclude_channel: ts[MyTestStruct] = None

    my_perspective: Server = Field(default_factory=Server)


@pytest.mark.parametrize("use_external_perspective", [True, False])
def test_MountPerspectiveTables(use_external_perspective):
    module = MountPerspectiveTables(
        tables={"exclude": ["exclude_channel"]},
        limits={"limit_channel": 5},
        indexes={"index_channel": "id", "dict_channel": "id", "exclude_channel": None},
        layouts={
            "Test Layout": '{"sizes":[1],"detail":{"main":{"type":"split-area","orientation":"horizontal","children":[{"type":"split-area","orientation":"vertical","children":[{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_1"],"currentIndex":0},{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_4"],"currentIndex":0}],"sizes":[0.5,0.5]},{"type":"split-area","orientation":"vertical","children":[{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_3"],"currentIndex":0},{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_5"],"currentIndex":0}],"sizes":[0.5,0.5]}],"sizes":[0.5,0.5]}},"mode":"globalFilters","viewers":{"PERSPECTIVE_GENERATED_ID_1":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"timestamp":"last","x":"last","id":"last","y":"last"},"master":false,"name":"basket","table":"basket","linked":false},"PERSPECTIVE_GENERATED_ID_4":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"timestamp":"last","x":"last","id":"last","y":"last"},"master":false,"name":"example_list","table":"example_list","linked":false},"PERSPECTIVE_GENERATED_ID_3":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"id":"last","x":"last","timestamp":"last","y":"last"},"master":false,"name":"example","table":"example","linked":false},"PERSPECTIVE_GENERATED_ID_5":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"id":"last","timestamp":"last","x":"last","y":"last"},"master":false,"name":"never_ticks","table":"never_ticks","linked":false}}}'  # noqa: E501
        },
        update_interval=timedelta(seconds=0.5),
    )
    if use_external_perspective:
        module.perspective_field = "my_perspective"

    h = GatewayTestHarness(
        test_channels=[GWC.test_channel, GWC.list_channel, GWC.dict_channel, GWC.dict_enum_channel, GWC.index_channel, GWC.limit_channel],
        test_dynamic_keys={"dict_channel": ["test_key"]},
    )

    now = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)

    # List with 1 element
    o = MyTestStruct(sub=MyTestSubStruct(y=[1], timestamp=now), timestamp=now)

    for _ in range(10):
        h.send(GWC.test_channel, o)
        h.send(GWC.list_channel, [o])
        h.send(GWC.dict_channel, {"test_key": o})
        h.send(GWC.dict_enum_channel, {ExampleEnum.A: o})
        h.send(GWC.limit_channel, o)
        h.send(GWC.index_channel, o)
    h.assert_ticked(GWC.test_channel, 10)
    h.assert_ticked(GWC.list_channel, 10)
    h.assert_ticked((GWC.dict_channel, "test_key"), 10)
    h.assert_ticked((GWC.dict_enum_channel, ExampleEnum.A), 10)
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

    now = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)

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
