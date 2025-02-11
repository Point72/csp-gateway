from datetime import datetime, timedelta

import csp
import pytest

from csp_gateway.server import Initialize
from csp_gateway.testing import (
    GatewayTestHarness,
    MyEnum,
    MyGateway,
    MyGatewayChannels,
    MyStruct,
)


@pytest.mark.parametrize("unroll", [True, False])
@pytest.mark.parametrize("offset", [0, 30])
def test_initializer(offset, unroll):
    offset_ts = timedelta(seconds=offset)
    start_dt = datetime(2023, 1, 1)
    target_dt = start_dt + offset_ts

    goal_struct = MyStruct(foo=1.0, my_flag=True, time=timedelta(seconds=10), id="test", timestamp=target_dt)
    val = {"foo": 1.0, "time": 10, "id": "test", "timestamp": target_dt}
    if unroll:
        val = [val.copy(), val.copy()]

    init = Initialize(
        channel=MyGatewayChannels.my_channel,
        seconds_offset=offset,
        value=val,
        unroll=unroll,
    )
    h = GatewayTestHarness(test_channels=[MyGatewayChannels.my_channel])
    if offset > 0:
        h.advance(delay=offset_ts)
    elif unroll:
        h.delay(delay=timedelta(microseconds=1))  # we have to wait for the unrolling

    def assert_func(vals):
        goal_len = 1 if not unroll else 2
        assert len(vals) == goal_len
        for dt, val in vals:
            assert dt == target_dt
            assert val.to_dict() == goal_struct.to_dict()

    h.assert_ticked_values(MyGatewayChannels.my_channel, assert_func)
    gw = MyGateway(modules=[h, init], channels=MyGatewayChannels())

    csp.run(gw.graph, starttime=start_dt, endtime=timedelta(1))


@pytest.mark.parametrize("unroll", [True, False])
@pytest.mark.parametrize("offset", [0, 30])
def test_initializer_list(offset, unroll):
    offset_ts = timedelta(seconds=offset)
    start_dt = datetime(2023, 1, 1)
    target_dt = start_dt + offset_ts
    val = [{"foo": 1.0, "time": 10, "id": "test", "timestamp": target_dt}]
    if unroll:
        val = [val.copy(), val.copy()]  # we unroll 2 lists
    goal_struct = MyStruct(foo=1.0, my_flag=True, time=timedelta(seconds=10), id="test", timestamp=target_dt)
    init = Initialize(
        channel=MyGatewayChannels.my_list_channel,
        unroll=unroll,
        seconds_offset=offset,
        value=val,
    )
    h = GatewayTestHarness(test_channels=[MyGatewayChannels.my_list_channel])
    if offset > 0:
        h.advance(delay=offset_ts)
    elif unroll:
        h.delay(delay=timedelta(microseconds=1))  # we have to wait for the unrolling

    def assert_func(vals):
        goal_len = 1 if not unroll else 2
        assert len(vals) == goal_len
        for dt, val in vals:
            assert dt == target_dt
            assert len(val) == 1
            assert val[0].to_dict() == goal_struct.to_dict()

    h.assert_ticked_values(MyGatewayChannels.my_list_channel, assert_func)
    gw = MyGateway(modules=[h, init], channels=MyGatewayChannels())

    csp.run(gw.graph, starttime=start_dt, endtime=timedelta(1))


@pytest.mark.parametrize("offset", [0, 30])
def test_initializer_dict_basket(offset):
    offset_ts = timedelta(seconds=offset)
    start_dt = datetime(2023, 1, 1)
    target_dt = start_dt + offset_ts

    goal_struct = MyStruct(foo=1.0, my_flag=True, time=timedelta(seconds=10), id="test", timestamp=target_dt)
    init = Initialize(
        channel=MyGatewayChannels.my_enum_basket,
        seconds_offset=offset,
        value={
            "ONE": {"foo": 1.0, "time": 10, "id": "test", "timestamp": target_dt},
            "TWO": {"foo": 1.0, "time": 0, "id": "test", "timestamp": target_dt},
        },
    )
    h = GatewayTestHarness(test_channels=[MyGatewayChannels.my_enum_basket])
    h.delay(delay=offset_ts)

    def assert_value_one(val):
        assert val.to_dict() == goal_struct.to_dict()

    def assert_value_two(val):
        goal_dict = goal_struct.to_dict()
        goal_dict["time"] = timedelta(seconds=0)
        assert val.to_dict() == goal_dict

    h.assert_value(
        (MyGatewayChannels.my_enum_basket, MyEnum.ONE),
        assert_value_one,
    )
    h.assert_value(
        (MyGatewayChannels.my_enum_basket, MyEnum.TWO),
        assert_value_two,
    )
    gw = MyGateway(modules=[h, init], channels=MyGatewayChannels())

    csp.run(gw.graph, starttime=start_dt, endtime=timedelta(1))
