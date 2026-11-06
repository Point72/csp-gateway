from datetime import UTC, datetime, timedelta
from enum import Enum
from queue import Queue
from threading import Thread
from unittest import mock

import csp
import datadog
import pytest
from csp import ts

from csp_gateway.server.gateway import Gateway, GatewayChannels, GatewayModule
from csp_gateway.server.modules.logging.datadog import PublishDatadog
from csp_gateway.server.modules.logging.util import (
    MonitoringEvent,
    MonitoringMetric,
)
from csp_gateway.testing import GatewayTestHarness


class DatadogTestEnum(str, Enum):
    GOOD = "GOOD"
    BAD = "BAD"


class DatadogTestChannels(GatewayChannels):
    event: ts[list[MonitoringEvent]] = None
    metric: ts[list[MonitoringMetric]] = None


class DatadogTestModule(GatewayModule):
    interval: timedelta = timedelta(seconds=1)

    @csp.node
    def subscribe_events(
        self,
        trigger: ts[bool],
    ) -> ts[list[MonitoringEvent]]:
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
    ) -> ts[list[MonitoringMetric]]:
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
            ]

    def connect(self, channels: DatadogTestChannels):
        # Create some CSP data streams
        events = self.subscribe_events(csp.timer(interval=self.interval, value=True))
        metrics = self.subscribe_metrics(csp.timer(interval=self.interval, value=True))
        # Channels set via `set_channel`
        channels.set_channel(DatadogTestChannels.event, events)
        channels.set_channel(DatadogTestChannels.metric, metrics)


def test_monitoring_init():
    event = MonitoringEvent(
        title="Event #1",
        text="Restricted list request 1",
        alert_type=MonitoringEvent.AlertType.info,
        event_type="restricted list",
        tags={"fav number": 10.27},
    )
    assert event.tags["fav number"] == "10.27"

    metric = MonitoringMetric(
        metric="rejected.orders",
        metric_type=MonitoringMetric.MetricType.rate,
        value=100,
        tags={"enum": DatadogTestEnum.GOOD},
    )
    assert isinstance(metric.tags["enum"], str)


@pytest.mark.parametrize("metric_type", list(MonitoringMetric.MetricType))
@pytest.mark.parametrize("include_monitoring_id", [False, True])
@pytest.mark.parametrize("dd_tags", [None, {"monitoring_id": "global_id"}])
@pytest.mark.parametrize("include_tags", [False, True])
def test_datadog_metric_tags(metric_type, include_monitoring_id, dd_tags, include_tags):
    class CustomMetric(MonitoringMetric):
        def to_datadog(self, extra_tags=None):
            payload = super().to_datadog(extra_tags)
            payload["host"] = "test-host"
            if not include_tags:
                payload.pop("tags")
            return payload

    metrics = [
        CustomMetric(id="first_id", metric="test.metric", metric_type=metric_type, value=1.0, tags={"env": "test"}),
        CustomMetric(id="second_id", metric="test.metric", metric_type=metric_type, value=2.0, tags={"env": "test"}),
    ]
    for metric in metrics:
        metric_dict = metric.to_dict()
        if include_tags:
            assert metric_dict["tags"] == ["env:test", f"monitoring_id:{metric.id}"]
        else:
            assert "tags" not in metric_dict

    dd_queue = Queue()
    dd_thread = Thread()
    dd_thread.start()

    def graph():
        PublishDatadog._publish_datadog(
            csp.null_ts([MonitoringEvent]),
            csp.const(metrics),
            dd_queue,
            dd_thread,
            dd_tags,
            include_monitoring_id,
        )

    csp.run(graph, starttime=datetime.now(UTC), endtime=timedelta(seconds=1))

    dd_queue.get_nowait()
    submissions = dd_queue.get_nowait()
    assert len(submissions) == 2
    for metric, (submitted_type, payload) in zip(metrics, submissions, strict=True):
        assert submitted_type is CustomMetric
        assert payload["metric"] == "test.metric"
        assert payload["host"] == "test-host"
        if include_tags:
            expected_tags = ["env:test"]
            if include_monitoring_id:
                expected_tags.append(f"monitoring_id:{'global_id' if dd_tags else metric.id}")
            assert payload["tags"] == expected_tags
        else:
            assert "tags" not in payload
        assert "monitoring_id" in metric.tags
    assert [payload["points"][0][1] for _, payload in submissions] == [1.0, 2.0]
    assert dd_queue.get_nowait() is None
    assert dd_queue.empty()


def test_datadog_bad_connection():
    # no connection provided should raise API error
    h = GatewayTestHarness(test_channels=["event", "metric"])
    gateway = Gateway(
        modules=[
            h,
            DatadogTestModule(),
            PublishDatadog(
                dd_tags={"user": "test0123", "trading_area": "ABCD"},
                events_channel="event",
                metrics_channel="metric",
            ),
        ],
        channels=DatadogTestChannels(),
    )
    h.delay(timedelta(seconds=1))
    csp.run(
        gateway.graph,
        starttime=datetime.now(UTC),
        endtime=timedelta(seconds=5),
    )


@pytest.mark.parametrize(
    ("datadog_options", "include_monitoring_id"),
    [({}, False), ({"include_monitoring_id": False}, False), ({"include_monitoring_id": True}, True)],
)
@mock.patch("datadog.initialize")
@mock.patch.object(datadog.api.Event, "create")
@mock.patch.object(datadog.api.Metric, "send")
def test_datadog(mock_send_metric, mock_event_create, mock_initialize, datadog_options, include_monitoring_id):
    mock_event_create.return_value = {"status": "ok"}

    h = GatewayTestHarness(test_channels=["event", "metric"])
    gateway = Gateway(
        modules=[
            h,
            DatadogTestModule(),
            PublishDatadog(
                dd_tags={"user": "test0123", "trading_area": "ABCD"},
                events_channel="event",
                metrics_channel="metric",
                **datadog_options,
            ),
        ],
        channels=DatadogTestChannels(),
    )
    h.delay(timedelta(seconds=1))

    def assert_func(event_ticks):
        assert len(event_ticks) > 0
        for _, events in event_ticks:
            for e in events:
                # We are asserting here that to_datadog() has been called on the event. to_datadog() mutates the
                # MonitoringBase. There are tests in downstream libraries (e.g. cubist-trading) that expects to_datadog()
                # to be called in the main graph thread. If this assertion fails, the unit tests in downstream libraries
                # might be broken.
                assert "monitoring_id" in e.tags

    h.assert_ticked_values("event", assert_func)
    csp.run(
        gateway.graph,
        starttime=datetime.now(UTC),
        endtime=timedelta(seconds=5),
    )

    event_keys = (
        "title",
        "text",
        "alert_type",
        "aggregation_key",
        "date_happened",
        "source_type_name",
        "user",
        "trading_area",
        "monitoring_id",
    )

    init_event = mock_event_create.call_args_list[0]
    init_dict = init_event.kwargs
    tags = dict(x.split(":") for x in init_dict.pop("tags"))
    init_dict.update(tags)
    for key in event_keys:
        assert key in init_dict
    del init_dict["date_happened"]
    del init_dict["monitoring_id"]
    assert init_dict == {
        "title": "PublishDatadog started",
        "text": "PublishDatadog started",
        "alert_type": "success",
        "aggregation_key": "connection init",
        "source_type_name": "python",
        "user": "test0123",
        "trading_area": "ABCD",
    }

    test_events = mock_event_create.call_args_list[1:]

    # assert event submissions
    # 15 ticks * 4 types of events = 20
    assert len(test_events) == 20
    event_map = {}
    for res in test_events:
        res_dict = res.kwargs
        tags = dict(x.split(":") for x in res_dict.pop("tags"))
        res_dict.update(tags)

        # assert all keys are in the list
        assert [key in res_dict for key in event_keys] == [True] * 9
        if res_dict["aggregation_key"] == "restricted list":
            assert "restricted event" in res_dict

        # count tag values
        for v in res_dict.values():
            if v not in event_map:
                event_map[v] = 0
            event_map[v] += 1

    for i in range(1, 6):
        assert event_map[f"Event #{i}"] == 4

    for v in MonitoringEvent.AlertType:
        assert event_map[v.value] == 5

    for v in ("python", "test0123", "ABCD"):
        assert event_map[v] == 20

    for v in ("disconnect error", "restricted list", "cancel order", "completed order"):
        assert event_map[v] == 5

    # assert metric submissions
    # 5 ticks * 3 types of metrics = 15
    assert mock_send_metric.call_count == 15
    metric_keys = (
        "metric",
        "type",
        "points",
        "user",
        "trading_area",
    )
    metric_map = {}
    sum = 0
    for res in mock_send_metric.call_args_list:
        res_dict = res.kwargs
        tags = dict(x.split(":") for x in res_dict.pop("tags"))
        res_dict.update(tags)

        # assert all keys are in the list
        assert [key in res_dict for key in metric_keys] == [True] * 5
        assert ("monitoring_id" in res_dict) == include_monitoring_id

        # count tag values
        for v in res_dict.values():
            if isinstance(v, list):
                sum += int(v[0][1])
                continue
            else:
                if v not in metric_map:
                    metric_map[v] = 0
                metric_map[v] += 1

    # assert values
    assert sum == 555

    for v in (
        "cancelled.orders",
        "submitted.orders",
        "rejected.orders",
        "count",
        "gauge",
        "rate",
    ):
        assert metric_map[v] == 5

    for v in ("test0123", "ABCD"):
        assert metric_map[v] == 15
