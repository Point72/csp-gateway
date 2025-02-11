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
