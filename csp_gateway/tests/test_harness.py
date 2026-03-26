from datetime import datetime, timedelta

import csp
import pytest

from csp_gateway.server.modules import AddChannelsToGraphOutput
from csp_gateway.testing import GatewayTestHarness
from csp_gateway.testing.shared_helpful_classes import MyGateway, MyGatewayChannels, MyStruct


@pytest.mark.parametrize("make_invalid", (True, False))
def test_delay(make_invalid):
    channels = [
        MyGatewayChannels.my_channel,
    ]
    h = GatewayTestHarness(test_channels=channels)

    # Engine start
    h.send(MyGatewayChannels.my_channel, MyStruct())
    h.assert_ticked(MyGatewayChannels.my_channel, 1)

    # timedelta delay
    h.advance(delay=timedelta(seconds=1))
    h.send(MyGatewayChannels.my_channel, MyStruct())

    # timedelta delay on timedelta delay
    h.advance(delay=timedelta(seconds=2))
    h.send(MyGatewayChannels.my_channel, MyStruct())

    # datetime delay
    h.advance(delay=datetime(2020, 1, 2))
    h.send(MyGatewayChannels.my_channel, MyStruct())

    # timedelta delay on datetime delay
    h.advance(delay=timedelta(seconds=5))
    h.send(MyGatewayChannels.my_channel, MyStruct())

    if make_invalid:
        # Jumping back in time.
        h.advance(delay=datetime(2020, 1, 2, 0, 0, 1))

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )

    if make_invalid:
        with pytest.raises(ValueError):
            csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(3))
    else:
        res = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(3))

        assert "my_channel" in res
        assert len(res["my_channel"]) == 5
        expected_times = [
            datetime(2020, 1, 1),
            datetime(2020, 1, 1, 0, 0, 1),
            datetime(2020, 1, 1, 0, 0, 3),
            datetime(2020, 1, 2),
            datetime(2020, 1, 2, 0, 0, 5),
        ]
        for (actual_time, _), expected_time in zip(res["my_channel"], expected_times):
            assert actual_time == expected_time


def test_delay_jump_straight_away():
    channels = [
        MyGatewayChannels.my_channel,
    ]
    h = GatewayTestHarness(test_channels=channels)

    # datetime delay
    h.advance(delay=datetime(2020, 1, 2))
    h.send(MyGatewayChannels.my_channel, MyStruct())

    # timedelta delay on datetime delay
    h.advance(delay=timedelta(seconds=5))
    h.send(MyGatewayChannels.my_channel, MyStruct())

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    res = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(3))

    assert "my_channel" in res
    assert len(res["my_channel"]) == 2
    expected_times = [
        datetime(2020, 1, 2),
        datetime(2020, 1, 2, 0, 0, 5),
    ]
    for (actual_time, _), expected_time in zip(res["my_channel"], expected_times):
        assert actual_time == expected_time


def test_assert_equal():
    """Test assert_equal with attributes since MyStruct has auto-generated id/timestamp"""
    channels = [MyGatewayChannels.my_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(MyGatewayChannels.my_channel, MyStruct(foo=1.0, time=timedelta(seconds=1)))
    h.assert_ticked(MyGatewayChannels.my_channel, 1)
    # Can't use assert_equal for full struct due to auto-generated fields, use attrs instead
    h.assert_attrs_equal(MyGatewayChannels.my_channel, {"foo": 1.0, "time": timedelta(seconds=1), "my_flag": True})

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_type():
    channels = [MyGatewayChannels.my_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(MyGatewayChannels.my_channel, MyStruct(foo=1.0, time=timedelta(seconds=1)))
    h.assert_ticked(MyGatewayChannels.my_channel, 1)
    h.assert_type(MyGatewayChannels.my_channel, MyStruct)

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_attr_equal():
    channels = [MyGatewayChannels.my_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(MyGatewayChannels.my_channel, MyStruct(foo=1.5, time=timedelta(seconds=2)))
    h.assert_ticked(MyGatewayChannels.my_channel, 1)
    h.assert_attr_equal(MyGatewayChannels.my_channel, "foo", 1.5)
    h.assert_attr_equal(MyGatewayChannels.my_channel, "time", timedelta(seconds=2))
    h.assert_attr_equal(MyGatewayChannels.my_channel, "my_flag", True)

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_attrs_equal():
    channels = [MyGatewayChannels.my_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(MyGatewayChannels.my_channel, MyStruct(foo=2.5, time=timedelta(seconds=3)))
    h.assert_ticked(MyGatewayChannels.my_channel, 1)
    h.assert_attrs_equal(MyGatewayChannels.my_channel, {"foo": 2.5, "time": timedelta(seconds=3), "my_flag": True})

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_attr_not_equal():
    channels = [MyGatewayChannels.my_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(MyGatewayChannels.my_channel, MyStruct(foo=1.5, time=timedelta(seconds=2)))
    h.assert_ticked(MyGatewayChannels.my_channel, 1)
    h.assert_attr_not_equal(MyGatewayChannels.my_channel, "foo", 2.5)
    h.assert_attr_not_equal(MyGatewayChannels.my_channel, "time", timedelta(seconds=5))

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_len():
    channels = [MyGatewayChannels.my_list_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(
        MyGatewayChannels.my_list_channel,
        [MyStruct(foo=1.0, time=timedelta(seconds=1)), MyStruct(foo=2.0, time=timedelta(seconds=2))],
    )
    h.assert_ticked(MyGatewayChannels.my_list_channel, 1)
    h.assert_len(MyGatewayChannels.my_list_channel, 2)

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_idx_type():
    channels = [MyGatewayChannels.my_list_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(
        MyGatewayChannels.my_list_channel,
        [MyStruct(foo=1.0, time=timedelta(seconds=1)), MyStruct(foo=2.0, time=timedelta(seconds=2))],
    )
    h.assert_ticked(MyGatewayChannels.my_list_channel, 1)
    h.assert_idx_type(MyGatewayChannels.my_list_channel, 0, MyStruct)
    h.assert_idx_type(MyGatewayChannels.my_list_channel, 1, MyStruct)

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_idx_attr_equal():
    channels = [MyGatewayChannels.my_list_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(
        MyGatewayChannels.my_list_channel,
        [MyStruct(foo=1.0, time=timedelta(seconds=1)), MyStruct(foo=2.0, time=timedelta(seconds=2))],
    )
    h.assert_ticked(MyGatewayChannels.my_list_channel, 1)
    h.assert_idx_attr_equal(MyGatewayChannels.my_list_channel, 0, "foo", 1.0)
    h.assert_idx_attr_equal(MyGatewayChannels.my_list_channel, 1, "foo", 2.0)
    h.assert_idx_attr_equal(MyGatewayChannels.my_list_channel, 0, "time", timedelta(seconds=1))

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_idx_attrs_equal():
    channels = [MyGatewayChannels.my_list_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(
        MyGatewayChannels.my_list_channel,
        [MyStruct(foo=1.0, time=timedelta(seconds=1)), MyStruct(foo=2.0, time=timedelta(seconds=2))],
    )
    h.assert_ticked(MyGatewayChannels.my_list_channel, 1)
    h.assert_idx_attrs_equal(MyGatewayChannels.my_list_channel, 0, {"foo": 1.0, "time": timedelta(seconds=1)})
    h.assert_idx_attrs_equal(MyGatewayChannels.my_list_channel, 1, {"foo": 2.0, "time": timedelta(seconds=2)})

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_idx_attr_not_equal():
    channels = [MyGatewayChannels.my_list_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(
        MyGatewayChannels.my_list_channel,
        [MyStruct(foo=1.0, time=timedelta(seconds=1)), MyStruct(foo=2.0, time=timedelta(seconds=2))],
    )
    h.assert_ticked(MyGatewayChannels.my_list_channel, 1)
    h.assert_idx_attr_not_equal(MyGatewayChannels.my_list_channel, 0, "foo", 2.0)
    h.assert_idx_attr_not_equal(MyGatewayChannels.my_list_channel, 1, "foo", 1.0)

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_reset():
    channels = [MyGatewayChannels.my_channel]
    h = GatewayTestHarness(test_channels=channels)

    # First tick
    h.send(MyGatewayChannels.my_channel, MyStruct())
    h.assert_ticked(MyGatewayChannels.my_channel, 1)

    # Reset and send another
    h.reset()
    h.advance(delay=timedelta(seconds=1))
    h.send(MyGatewayChannels.my_channel, MyStruct())
    # After reset, tick count should be 1 again
    h.assert_ticked(MyGatewayChannels.my_channel, 1)

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(2))


def test_assert_value():
    channels = [MyGatewayChannels.my_channel]
    h = GatewayTestHarness(test_channels=channels)

    h.send(MyGatewayChannels.my_channel, MyStruct(foo=3.14, time=timedelta(seconds=1)))
    h.assert_ticked(MyGatewayChannels.my_channel, 1)
    h.assert_value(MyGatewayChannels.my_channel, lambda v: v.foo == 3.14)
    h.assert_value(MyGatewayChannels.my_channel, lambda v: isinstance(v, MyStruct))

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_assert_ticked_values():
    channels = [MyGatewayChannels.my_channel]
    h = GatewayTestHarness(test_channels=channels)

    # Send multiple values without reset (don't use advance which resets)
    h.send(MyGatewayChannels.my_channel, MyStruct(foo=1.0, time=timedelta(seconds=1)))
    h.delay(timedelta(seconds=1))
    h.send(MyGatewayChannels.my_channel, MyStruct(foo=2.0, time=timedelta(seconds=2)))
    h.delay(timedelta(seconds=1))
    h.send(MyGatewayChannels.my_channel, MyStruct(foo=3.0, time=timedelta(seconds=3)))

    # Check all ticked values
    def check_ticks(ticked_values):
        assert len(ticked_values) == 3
        assert ticked_values[0][1].foo == 1.0
        assert ticked_values[1][1].foo == 2.0
        assert ticked_values[2][1].foo == 3.0

    h.assert_ticked_values(MyGatewayChannels.my_channel, check_ticks)

    gateway = MyGateway(
        modules=[h, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(5))
