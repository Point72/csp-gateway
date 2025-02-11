from datetime import datetime, timedelta, timezone
from typing import List
from unittest import mock
from unittest.mock import Mock

import csp
import opsgenie_sdk
from csp import Enum, ts

from csp_gateway.server.gateway import Gateway, GatewayChannels, GatewayModule
from csp_gateway.server.modules.logging.opsgenie import PublishOpsGenie
from csp_gateway.server.modules.logging.util import (
    MonitoringEvent,
    MonitoringMetric,
    OpsGenieLevel,
)
from csp_gateway.testing import GatewayTestHarness


class EventTestEnum(Enum):
    GOOD = Enum.auto()
    BAD = Enum.auto()


class EventTestChannels(GatewayChannels):
    event: ts[List[MonitoringEvent]] = None
    metric: ts[List[MonitoringMetric]] = None


class EventTestModule(GatewayModule):
    interval: timedelta = timedelta(seconds=1)

    @csp.node
    def subscribe_events(
        self,
        trigger: ts[bool],
    ) -> ts[List[MonitoringEvent]]:
        with csp.state():
            last_x = 0
        if csp.ticked(trigger):
            last_x += 1
            return [
                MonitoringEvent(
                    title=f"Event #{last_x}",
                    text=f"Disconnected {last_x}",
                    alert_type=MonitoringEvent.AlertType.error,
                    event_type="disconnect error",
                ),
                MonitoringEvent(
                    title=f"Event #{last_x}",
                    text=f"Cancel order {last_x}",
                    alert_type=MonitoringEvent.AlertType.warning,
                    event_type="cancel order",
                ),
                MonitoringEvent(
                    title=f"Event #{last_x}",
                    text=f"Completed order {last_x}",
                    alert_type=MonitoringEvent.AlertType.success,
                    event_type="completed order",
                ),
                MonitoringEvent(
                    title=f"Event #{last_x}",
                    text=f"Restricted list request {last_x}",
                    alert_type=MonitoringEvent.AlertType.info,
                    event_type="restricted list",
                    tags={"restricted event": f"{last_x}"},
                ),
            ]

    @csp.node
    def subscribe_metrics(
        self,
        trigger: ts[bool],
    ) -> ts[List[MonitoringMetric]]:
        with csp.state():
            last_x = 1.0
        if csp.ticked(trigger):
            last_x += 1
            return [
                MonitoringMetric(
                    metric="cancelled.orders",
                    metric_type=MonitoringMetric.MetricType.count,
                    value=1,
                    tags={"cancelled order": f"{last_x}"},
                ),
                MonitoringMetric(
                    metric="submitted.orders",
                    metric_type=MonitoringMetric.MetricType.gauge,
                    value=10,
                    tags={"submitted order": f"{last_x}"},
                ),
                MonitoringMetric(
                    metric="rejected.orders",
                    metric_type=MonitoringMetric.MetricType.rate,
                    value=100,
                    tags={"rejected order": f"{last_x}"},
                ),
                MonitoringMetric(
                    metric="_heartbeat",
                    metric_type=MonitoringMetric.MetricType.rate,
                    value=1,
                    tags={"event_group": "heartbeat"},
                ),
            ]

    def connect(self, channels: EventTestChannels):
        # Create some CSP data streams
        events = self.subscribe_events(csp.timer(interval=self.interval, value=True))
        metrics = self.subscribe_metrics(csp.timer(interval=self.interval, value=True))
        # Channels set via `set_channel`
        channels.set_channel(EventTestChannels.event, events)
        channels.set_channel(EventTestChannels.metric, metrics)


@mock.patch("opsgenie_sdk.AlertApi.create_alert")
@mock.patch("opsgenie_sdk.CreateHeartbeatPayload")
@mock.patch("opsgenie_sdk.HeartbeatApi.get_heartbeat")
@mock.patch("opsgenie_sdk.HeartbeatApi.create_heartbeat")
@mock.patch("opsgenie_sdk.HeartbeatApi.update_heartbeat")
@mock.patch.object(opsgenie_sdk.HeartbeatApi, "ping")
@mock.patch("logging.Logger.trace")
def test_opsgenie(
    mock_trace,
    mock_ping,
    mock_update_heartbeat,
    mock_create_heartbeat,
    mock_get_heartbeat,
    mock_create_heartbeat_payload,
    mock_event_create,
):
    def assert_func(event_ticks):
        assert len(event_ticks) > 0
        for _, events in event_ticks:
            for e in events:
                assert "monitoring_id" in e.tags

    # Mock the response of the HeartbeatApi.ping method
    mock_ping_response = Mock()
    mock_ping_response.ready.return_value = True
    mock_ping_response.get.return_value = Mock(result="PONG - Heartbeat received")
    mock_ping.return_value = mock_ping_response

    h = GatewayTestHarness(test_channels=["event", "metric"])
    gateway = Gateway(
        modules=[
            h,
            EventTestModule(),
            PublishOpsGenie(
                ops_api_key="foo123",
                ops_heartbeat_name="test_heartbeat",
                ops_tags={"user": "test0123", "trading_area": "ABCD"},
                ops_alert_min_level=OpsGenieLevel.P3,
                ops_async_delay_sec=3.0,
                events_channel="event",
                metrics_channel="metric",
            ),
        ],
        channels=EventTestChannels(),
    )
    h.delay(timedelta(seconds=1))
    csp.run(
        gateway.graph,
        starttime=datetime.now(timezone.utc),
        endtime=timedelta(seconds=5),
    )

    # assert OpsGenmie alerts
    # on level OpsGenieLevel.P3 there should be 10 events created
    assert mock_event_create.call_count == 10
    test_events = mock_event_create.call_args_list
    assert len(test_events) == 10

    for res in test_events:
        res_dict = res.kwargs["create_alert_payload"].to_dict()
        assert res_dict["entity"] in (
            "cancel order",
            "completed order",
            "disconnect error",
            "restricted list",
        )
        assert res_dict["source"] == "python"
        assert res_dict["message"].startswith("Event #")
        assert res_dict["description"].startswith(
            (
                "Cancel order",
                "Completed order",
                "Disconnected",
                "Restricted list request",
            )
        )
        tags = dict(x.split(":") for x in res_dict.pop("tags"))
        assert "monitoring_id" in tags
        assert "user" in tags
        assert "trading_area" in tags
        assert tags["monitoring_id"] == res_dict["alias"]

    mock_trace.assert_any_call("Setting alarm to check alert queue in %s seconds", 3.0)
    mock_trace.assert_any_call("Alert submission successful")
    mock_trace.assert_any_call("Done processing alert queue, %s object(s) remaining", mock.ANY)
    mock_trace.assert_any_call("Resetting alarm to check alert queue in %s seconds", 3.0)

    # assert heartbeat payload creation
    assert mock_create_heartbeat_payload.call_count == 1
    payload_kwargs = mock_create_heartbeat_payload.call_args_list[0].kwargs
    expected_payload = opsgenie_sdk.CreateHeartbeatPayload(
        name="test_heartbeat",
        description="test_heartbeat generated by csp_gateway",
        interval=1,
        interval_unit="minutes",
        enabled=True,
        alert_message="test_heartbeat heartbeat not received in 1 minutes",
        alert_tags=["user:test0123", "trading_area:ABCD"],
        alert_priority="P2",
    )

    assert payload_kwargs == {
        "name": "test_heartbeat",
        "description": "test_heartbeat generated by csp_gateway",
        "interval": 1,
        "interval_unit": "minutes",
        "enabled": True,
        "alert_message": "test_heartbeat heartbeat not received in 1 minutes",
        "alert_tags": ["user:test0123", "trading_area:ABCD"],
        "alert_priority": "P2",
    }

    assert mock_get_heartbeat.call_count == 1
    args = mock_get_heartbeat.call_args_list[0].args
    kwargs = mock_get_heartbeat.call_args_list[0].kwargs
    assert args == ("test_heartbeat",)
    assert kwargs == {"async_req": False, "_request_timeout": 5.0}

    assert mock_update_heartbeat.call_count == 1
    update_heartbeat_kwargs = mock_update_heartbeat.call_args_list[0].kwargs
    assert update_heartbeat_kwargs["update_heartbeat_payload"].to_dict() == expected_payload.to_dict()

    assert mock_create_heartbeat.call_count == 0
