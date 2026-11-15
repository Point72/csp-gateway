from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import csp
import datadog
import opsgenie_sdk
import pytest
from hydra.utils import instantiate
from pydantic import ValidationError

from csp_gateway import (
    Gateway,
    GatewayModule,
    PublishAlertsOpsGenie,
    PublishDatadog,
    PublishEventsDatadog,
    PublishHeartbeatsOpsGenie,
    PublishMetricsDatadog,
    PublishOpsGenie,
)
from csp_gateway.server.modules._backends import datadog as _datadog, opsgenie as _opsgenie
from csp_gateway.server.modules.logging.util import DatadogLevel, MonitoringEvent, MonitoringMetric


class PublisherSource(GatewayModule):
    def dynamic_channels(self):
        return {"events": list[MonitoringEvent], "metrics": list[MonitoringMetric]}

    def connect(self, channels):
        events = [
            MonitoringEvent(
                title="error",
                text="error",
                event_type="test",
                alert_type=DatadogLevel.error,
                tags={"event_group": "test", "symbol": "ABC"},
            ),
            MonitoringEvent(title="info", text="info", event_type="test"),
        ]
        metrics = [
            MonitoringMetric(metric="heartbeat", metric_type=MonitoringMetric.MetricType.gauge, value=1),
            MonitoringMetric(metric="orders", metric_type=MonitoringMetric.MetricType.count, value=2),
        ]
        channels.set_channel("events", csp.const(events))
        channels.set_channel("metrics", csp.const(metrics))


def run_publisher(*publishers):
    gateway = Gateway(modules=[PublisherSource(), *publishers])
    csp.run(gateway.graph, starttime=datetime.now(UTC), endtime=timedelta(seconds=1))


@pytest.fixture
def datadog_api(monkeypatch):
    api = Mock()
    api.event.return_value = {"status": "ok"}
    api.metric.return_value = {"status": "ok"}
    monkeypatch.setattr(datadog.api.Event, "create", api.event)
    monkeypatch.setattr(datadog.api.Metric, "send", api.metric)
    return api


@pytest.fixture
def opsgenie_api(monkeypatch):
    client = Mock()
    alerts = Mock()
    heartbeats = Mock()
    alerts.create_alert.return_value.ready.return_value = True
    heartbeats.ping.return_value.ready.return_value = True
    client_factory = Mock(return_value=client)
    alerts_factory = Mock(return_value=alerts)
    heartbeats_factory = Mock(return_value=heartbeats)
    monkeypatch.setattr(opsgenie_sdk.api_client, "ApiClient", client_factory)
    monkeypatch.setattr(opsgenie_sdk, "AlertApi", alerts_factory)
    monkeypatch.setattr(opsgenie_sdk, "HeartbeatApi", heartbeats_factory)
    return SimpleNamespace(
        client=client,
        alerts=alerts,
        heartbeats=heartbeats,
        client_factory=client_factory,
        alerts_factory=alerts_factory,
        heartbeats_factory=heartbeats_factory,
    )


@pytest.mark.parametrize("include_monitoring_id", [False, True])
def test_datadog_metrics_only(datadog_api, include_monitoring_id):
    run_publisher(
        PublishMetricsDatadog(
            metrics_channel="metrics",
            dd_tags={"service": "test"},
            include_monitoring_id=include_monitoring_id,
        )
    )

    datadog_api.event.assert_not_called()
    assert datadog_api.metric.call_count == 2
    for submission in datadog_api.metric.call_args_list:
        tags = submission.kwargs["tags"]
        assert "service:test" in tags
        assert any(tag.startswith("monitoring_id:") for tag in tags) == include_monitoring_id


def test_datadog_events_only(datadog_api):
    run_publisher(PublishEventsDatadog(events_channel="events", dd_tags={"service": "test"}))

    datadog_api.metric.assert_not_called()
    assert [call.kwargs["title"] for call in datadog_api.event.call_args_list] == ["PublishDatadog started", "error", "info"]
    assert all("service:test" in call.kwargs["tags"] for call in datadog_api.event.call_args_list)


def test_standalone_datadog_publishers_can_share_a_gateway(datadog_api):
    with patch.object(_datadog, "get_thread", wraps=_datadog.get_thread) as thread_factory:
        run_publisher(PublishMetricsDatadog(metrics_channel="metrics"), PublishEventsDatadog(events_channel="events"))

    assert thread_factory.call_count == 2
    assert datadog_api.event.call_count == 3
    assert datadog_api.metric.call_count == 2


@pytest.mark.parametrize("events_enabled", [False, True])
@pytest.mark.parametrize("metrics_enabled", [False, True])
def test_datadog_combined_shares_worker_and_preserves_order(datadog_api, events_enabled, metrics_enabled):
    publisher = PublishDatadog(
        events_channel="events" if events_enabled else None,
        metrics_channel="metrics" if metrics_enabled else None,
    )
    with patch.object(_datadog, "get_thread", wraps=_datadog.get_thread) as thread_factory:
        run_publisher(publisher)

    active = events_enabled or metrics_enabled
    assert thread_factory.call_count == int(active)
    expected_order = ["event"] * (int(active) + 2 * events_enabled) + ["metric"] * (2 * metrics_enabled)
    assert [call[0] for call in datadog_api.mock_calls] == expected_order


@pytest.mark.parametrize("publisher", [PublishMetricsDatadog, PublishEventsDatadog])
def test_datadog_unconfigured_publisher_does_not_start_worker(datadog_api, publisher):
    with patch.object(_datadog, "get_thread", wraps=_datadog.get_thread) as thread_factory:
        run_publisher(publisher())

    thread_factory.assert_not_called()
    datadog_api.event.assert_not_called()
    datadog_api.metric.assert_not_called()


def test_datadog_legacy_node_override_signature(datadog_api):
    node_calls = []
    original_node = PublishDatadog._publish_datadog

    class CustomDatadog(PublishDatadog):
        pass

    def legacy_node(events, metrics, queue, thread, tags, include_monitoring_id=False):
        node_calls.append(include_monitoring_id)
        original_node(events, metrics, queue, thread, tags, include_monitoring_id)

    with patch.object(CustomDatadog, "_publish_datadog", staticmethod(legacy_node)):
        run_publisher(CustomDatadog(events_channel="events", metrics_channel="metrics"))

    assert node_calls == [False]
    assert datadog_api.event.call_count == 3
    assert datadog_api.metric.call_count == 2


def test_datadog_metrics_delivery_failure_is_logged(datadog_api, caplog):
    datadog_api.metric.side_effect = RuntimeError("offline")

    run_publisher(PublishMetricsDatadog(metrics_channel="metrics"))

    assert "Error sending monitoring data to Datadog" in caplog.text
    assert "offline" in caplog.text


def test_opsgenie_alerts_without_heartbeat_configuration(opsgenie_api):
    publisher = PublishAlertsOpsGenie(
        ops_api_key="test",
        events_channel="events",
        ops_tags={"service": "test"},
        ops_alias_tags={"test": ["symbol"]},
    )
    run_publisher(publisher)

    opsgenie_api.client_factory.assert_called_once()
    opsgenie_api.alerts_factory.assert_called_once_with(api_client=opsgenie_api.client)
    opsgenie_api.heartbeats_factory.assert_not_called()
    opsgenie_api.alerts.create_alert.assert_called_once()
    payload = opsgenie_api.alerts.create_alert.call_args.kwargs["create_alert_payload"]
    assert payload.alias == "ABC"
    assert payload.priority == "P2"
    assert "service:test" in payload.tags


def test_standalone_opsgenie_publishers_can_share_a_gateway(opsgenie_api):
    run_publisher(
        PublishAlertsOpsGenie(ops_api_key="test", events_channel="events"),
        PublishHeartbeatsOpsGenie(ops_api_key="test", ops_heartbeat_name="test", metrics_channel="metrics"),
    )

    assert opsgenie_api.client_factory.call_count == 2
    opsgenie_api.alerts.create_alert.assert_called_once()
    opsgenie_api.heartbeats.ping.assert_called_once()
    opsgenie_api.heartbeats.disable_heartbeat.assert_called_once()


def test_opsgenie_heartbeats_without_alert_configuration_or_tags(opsgenie_api):
    run_publisher(
        PublishHeartbeatsOpsGenie(
            ops_api_key="test",
            ops_heartbeat_name="test-heartbeat",
            metrics_channel="metrics",
        )
    )

    opsgenie_api.client_factory.assert_called_once()
    opsgenie_api.alerts_factory.assert_not_called()
    opsgenie_api.heartbeats_factory.assert_called_once_with(api_client=opsgenie_api.client)
    opsgenie_api.heartbeats.get_heartbeat.assert_called_once()
    opsgenie_api.heartbeats.update_heartbeat.assert_called_once()
    opsgenie_api.heartbeats.ping.assert_called_once_with("test-heartbeat", async_req=True)
    opsgenie_api.heartbeats.disable_heartbeat.assert_called_once_with("test-heartbeat", async_req=False, _request_timeout=5.0)
    payload = opsgenie_api.heartbeats.update_heartbeat.call_args.kwargs["update_heartbeat_payload"]
    assert payload.alert_tags == []


def test_opsgenie_heartbeat_creation_when_missing(opsgenie_api):
    error = opsgenie_sdk.exceptions.ApiException(status=404)
    error.body = '{"message": "not found"}'
    opsgenie_api.heartbeats.get_heartbeat.side_effect = error

    run_publisher(PublishHeartbeatsOpsGenie(ops_api_key="test", ops_heartbeat_name="new", metrics_channel="metrics"))

    opsgenie_api.heartbeats.create_heartbeat.assert_called_once()
    opsgenie_api.heartbeats.update_heartbeat.assert_not_called()
    opsgenie_api.heartbeats.ping.assert_called_once_with("new", async_req=True)


def test_opsgenie_standalone_heartbeat_shutdown_failure_is_logged(opsgenie_api, caplog):
    opsgenie_api.heartbeats.disable_heartbeat.side_effect = RuntimeError("offline")

    run_publisher(PublishHeartbeatsOpsGenie(ops_api_key="test", ops_heartbeat_name="test", metrics_channel="metrics"))

    assert "Failed to disable heartbeat 'test' on shutdown: offline" in caplog.text


def test_opsgenie_legacy_heartbeat_override(opsgenie_api):
    initialized = []

    class CustomOpsGenie(PublishOpsGenie):
        def _init_heartbeat(self, heartbeat_api):
            initialized.append(heartbeat_api)
            super()._init_heartbeat(heartbeat_api)

    run_publisher(CustomOpsGenie(ops_api_key="test", ops_heartbeat_name="test", metrics_channel="metrics"))

    assert initialized == [opsgenie_api.heartbeats]
    opsgenie_api.heartbeats.update_heartbeat.assert_called_once()


@pytest.mark.parametrize("events_enabled", [False, True])
@pytest.mark.parametrize("heartbeats_enabled", [False, True])
def test_opsgenie_combined_shares_client(opsgenie_api, events_enabled, heartbeats_enabled):
    run_publisher(
        PublishOpsGenie(
            ops_api_key="test",
            ops_heartbeat_name="test-heartbeat",
            events_channel="events" if events_enabled else None,
            metrics_channel="metrics" if heartbeats_enabled else None,
        )
    )

    opsgenie_api.client_factory.assert_called_once()
    assert opsgenie_api.alerts_factory.call_count == int(events_enabled)
    assert opsgenie_api.heartbeats_factory.call_count == int(heartbeats_enabled)
    if events_enabled:
        opsgenie_api.alerts_factory.assert_called_once_with(api_client=opsgenie_api.client)
        opsgenie_api.alerts.create_alert.assert_called_once()
    if heartbeats_enabled:
        opsgenie_api.heartbeats_factory.assert_called_once_with(api_client=opsgenie_api.client)
        opsgenie_api.heartbeats.ping.assert_called_once()
        opsgenie_api.heartbeats.disable_heartbeat.assert_called_once()


@pytest.mark.parametrize("publisher", [PublishHeartbeatsOpsGenie, PublishOpsGenie])
def test_opsgenie_heartbeat_name_still_required(publisher):
    with pytest.raises(ValidationError):
        publisher(ops_api_key="test", metrics_channel="metrics")


def test_opsgenie_combined_events_only_still_requires_legacy_heartbeat_name():
    with pytest.raises(ValidationError):
        PublishOpsGenie(ops_api_key="test", events_channel="events")


@pytest.mark.parametrize(
    ("publisher", "supported", "unsupported"),
    [
        (PublishMetricsDatadog, "metrics_channel", "events_channel"),
        (PublishEventsDatadog, "events_channel", "metrics_channel"),
        (PublishAlertsOpsGenie, "events_channel", "ops_heartbeat_name"),
        (PublishHeartbeatsOpsGenie, "metrics_channel", "ops_alert_min_level"),
    ],
)
def test_standalone_configuration_only_exposes_its_capability(publisher, supported, unsupported):
    assert supported in publisher.model_fields
    assert unsupported not in publisher.model_fields
    values = {}
    if "ops_api_key" in publisher.model_fields:
        values["ops_api_key"] = "test"
    if "ops_heartbeat_name" in publisher.model_fields:
        values["ops_heartbeat_name"] = "test"
    values[unsupported] = "unused"
    with pytest.raises(ValidationError) as error:
        publisher(**values)
    assert any(item["loc"] == (unsupported,) and item["type"] == "extra_forbidden" for item in error.value.errors())


@pytest.mark.parametrize(
    ("publisher", "dependency"),
    [
        (PublishDatadog, "datadog"),
        (PublishMetricsDatadog, "datadog"),
        (PublishEventsDatadog, "datadog"),
        (PublishOpsGenie, "opsgenie"),
        (PublishAlertsOpsGenie, "opsgenie"),
        (PublishHeartbeatsOpsGenie, "opsgenie"),
    ],
)
def test_missing_sdk_validation_names_the_publisher(monkeypatch, publisher, dependency):
    if dependency == "datadog":
        monkeypatch.setattr(_datadog, "api", None)
    else:
        monkeypatch.setattr(_opsgenie, "opsgenie_sdk", None)

    with pytest.raises(ImportError, match=publisher.__name__):
        publisher(ops_api_key="test", ops_heartbeat_name="test")


@pytest.mark.parametrize(
    ("publisher", "config"),
    [
        (PublishDatadog, {"events_channel": "events", "metrics_channel": "metrics"}),
        (PublishMetricsDatadog, {"metrics_channel": "metrics"}),
        (PublishEventsDatadog, {"events_channel": "events"}),
        (PublishOpsGenie, {"ops_api_key": "test", "ops_heartbeat_name": "test", "events_channel": "events", "metrics_channel": "metrics"}),
        (PublishAlertsOpsGenie, {"ops_api_key": "test", "events_channel": "events"}),
        (PublishHeartbeatsOpsGenie, {"ops_api_key": "test", "ops_heartbeat_name": "test", "metrics_channel": "metrics"}),
    ],
)
def test_publisher_configuration_round_trip(publisher, config):
    configured = instantiate({"_target_": f"csp_gateway.{publisher.__name__}", **config})
    restored = GatewayModule.model_validate(configured.model_dump(mode="json"))

    assert type(restored) is publisher
    assert restored.model_dump(mode="json") == configured.model_dump(mode="json")
