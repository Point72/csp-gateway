import logging
import timeit
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from csp_gateway.server.modules.logging.util import (
    DatadogLevel,
    MonitoringBase,
    MonitoringEvent,
    MonitoringLevelMapping,
    MonitoringMetric,
    MonitoringSystem,
    OpsGenieLevel,
)
from csp_gateway.utils.struct.base import GatewayStruct


# Mocking GatewayStruct for simplicity
class MockGatewayStruct(GatewayStruct):
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "test_id")
        self.timestamp = kwargs.get("timestamp", datetime.now(timezone.utc))


@pytest.fixture
def monitoring_event():
    return MonitoringEvent(
        id="event_id",
        timestamp=datetime.now(timezone.utc),
        title="Test Event",
        text="This is a test event",
        event_type="test_event",
        alert_type=DatadogLevel.error,
        source="test_source",
        tags={
            "env": "test",
            "event_group": "group1",
            "tag1": "value1",
            "tag2": "value2",
        },
    )


@pytest.fixture
def monitoring_metric():
    return MonitoringMetric(
        id="metric_id",
        timestamp=datetime.now(timezone.utc),
        metric="test_metric",
        metric_type=MonitoringMetric.MetricType.gauge,
        value=1.0,
        tags={"env": "test"},
    )


def test_monitoring_system_enum():
    assert MonitoringSystem.DATADOG.value == "datadog"
    assert MonitoringSystem.OPSGENIE.value == "opsgenie"
    assert MonitoringSystem.LOGGING.value == "logging"


def test_datadog_level_enum():
    assert DatadogLevel.error.value == "error"
    assert DatadogLevel.warning.value == "warning"
    assert DatadogLevel.info.value == "info"
    assert DatadogLevel.success.value == "success"


def test_opsgenie_level_enum():
    assert OpsGenieLevel.P1.value == "P1"
    assert OpsGenieLevel.P2.value == "P2"
    assert OpsGenieLevel.P3.value == "P3"
    assert OpsGenieLevel.P4.value == "P4"
    assert OpsGenieLevel.P5.value == "P5"


def test_monitoring_base_init():
    base = MonitoringBase(id="base_id", timestamp=datetime.now(timezone.utc), tags={"env": "test"})
    assert base.id == "base_id"
    assert base.tags == {"env": "test"}


def test_monitoring_base_get_tags(monitoring_event):
    tags = monitoring_event.get_tags()
    assert "env:test" in tags
    assert "monitoring_id:event_id" in tags


def test_monitoring_base_get_datadog_timestamp(monitoring_event):
    timestamp = monitoring_event.get_datadog_timestamp()
    assert isinstance(timestamp, float)


def test_monitoring_event_to_datadog(monitoring_event):
    payload = monitoring_event.to_datadog()
    assert payload["title"] == "Test Event"
    assert payload["text"] == "This is a test event"
    assert payload["alert_type"] == "error"


def test_monitoring_metric_to_datadog(monitoring_metric):
    payload = monitoring_metric.to_datadog()
    assert payload["metric"] == "test_metric"
    assert payload["type"] == "gauge"
    assert isinstance(payload["points"], list)


@patch("opsgenie_sdk.CreateAlertPayload")
def test_monitoring_event_to_opsgenie(mock_create_alert_payload, monitoring_event):
    # Set up the mock return value
    mock_payload_instance = MagicMock()
    mock_payload_instance.source = "test_source"
    mock_payload_instance.message = "Test Event"
    mock_create_alert_payload.return_value = mock_payload_instance

    payload = monitoring_event.to_opsgenie()
    assert mock_create_alert_payload.called
    assert payload.source == "test_source"
    assert payload.message == "Test Event"


@patch("opsgenie_sdk.CreateAlertPayload")
def test_monitoring_metric_to_opsgenie(mock_create_alert_payload, monitoring_metric):
    # Set up the mock return value
    mock_payload_instance = MagicMock()
    mock_payload_instance.source = "python"
    mock_payload_instance.message = "Test Metric Alert"
    mock_create_alert_payload.return_value = mock_payload_instance

    payload = monitoring_metric.to_opsgenie(
        title="Test Metric Alert",
        alert_type=MonitoringLevelMapping.info,
    )
    assert mock_create_alert_payload.called
    assert payload.source == "python"
    assert payload.message == "Test Metric Alert"


def test_monitoring_event_to_dict(monitoring_event):
    event_dict = monitoring_event.to_dict()
    assert event_dict["title"] == "Test Event"
    assert event_dict["text"] == "This is a test event"
    assert event_dict["event_type"] == "test_event"
    assert event_dict["alert_type"] == DatadogLevel.error
    assert event_dict["source"] == "test_source"
    assert event_dict["tags"] == [
        "env:test",
        "event_group:group1",
        "tag1:value1",
        "tag2:value2",
        "monitoring_id:event_id",
    ]
    assert "timestamp" in event_dict


def test_monitoring_metric_to_dict(monitoring_metric):
    metric_dict = monitoring_metric.to_dict()
    assert metric_dict["metric"] == "test_metric"
    assert metric_dict["type"] == "gauge"
    assert metric_dict["points"][0][1] == 1.0
    assert metric_dict["tags"] == ["env:test", "monitoring_id:metric_id"]


def test_monitoring_level_mapping_from_event(monitoring_event):
    mapping = MonitoringLevelMapping.from_event(monitoring_event)
    assert mapping == MonitoringLevelMapping.error
    assert mapping.value.datadog == DatadogLevel.error
    assert mapping.value.opsgenie == OpsGenieLevel.P2
    assert mapping.value.logging == logging.ERROR

    with pytest.raises(ValueError):

        class Foo:
            def __init__(self):
                self.alert_type = "foo"

        MonitoringLevelMapping.from_event(Foo())


def test_monitoring_levels():
    assert MonitoringLevelMapping.get_opsgenie_levels() == (
        "P1",
        "P2",
        "P3",
        "P4",
        "P5",
    )
    assert MonitoringLevelMapping.get_datadog_levels() == (
        "error",
        "error",
        "warning",
        "info",
        "success",
    )
    assert MonitoringLevelMapping.get_logging_levels() == (
        50,
        40,
        30,
        20,
        10,
    )


def test_monitoring_level_mapping_from_alert_type():
    # Datadog has no "critical" level alert
    for level in (OpsGenieLevel.P1, "P1", 50):
        mapping = MonitoringLevelMapping.from_alert_type(level)
        assert mapping == MonitoringLevelMapping.critical
        assert mapping.value.level == "critical"
        assert mapping.value.datadog == DatadogLevel.error
        assert mapping.value.logging == 50

    for level in (OpsGenieLevel.P2, DatadogLevel.error, "error", "P2", 40):
        mapping = MonitoringLevelMapping.from_alert_type(level)
        assert mapping == MonitoringLevelMapping.error
        assert mapping.value.level == "error"
        assert mapping.value.datadog == DatadogLevel.error
        assert mapping.value.logging == 40

    for level in (OpsGenieLevel.P3, DatadogLevel.warning, "warning", "P3", 30):
        mapping = MonitoringLevelMapping.from_alert_type(level)
        assert mapping == MonitoringLevelMapping.warning
        assert mapping.value.level == "warning"
        assert mapping.value.datadog == DatadogLevel.warning
        assert mapping.value.logging == 30

    for level in (OpsGenieLevel.P4, DatadogLevel.info, "info", "P4", 20):
        mapping = MonitoringLevelMapping.from_alert_type(level)
        assert mapping == MonitoringLevelMapping.info
        assert mapping.value.level == "info"
        assert mapping.value.datadog == DatadogLevel.info
        assert mapping.value.logging == 20

    for level in (OpsGenieLevel.P5, DatadogLevel.success, "success", "P5", 10):
        mapping = MonitoringLevelMapping.from_alert_type(level)
        assert mapping == MonitoringLevelMapping.debug
        assert mapping.value.level == "debug"
        assert mapping.value.datadog == DatadogLevel.success
        assert mapping.value.logging == 10

    with pytest.raises(ValueError):
        MonitoringLevelMapping.from_alert_type("foo")

    with pytest.raises(ValueError):
        MonitoringLevelMapping.from_alert_type(42)


def test_monitoring_event_class_methods():
    event = MonitoringEvent(
        id="event_id",
        timestamp=datetime.now(timezone.utc),
        title="Test Event",
        text="This is a test event",
        event_type="test_event",
        alert_type=DatadogLevel.error,
        source="test_source",
        tags={"env": "test"},
    )
    event_dict = event.to_dict()
    assert event_dict["title"] == "Test Event"
    assert event_dict["text"] == "This is a test event"
    flatten_data = event.psp_flatten()[0]
    assert '{"env":"test","monitoring_id":"event_id"}' == flatten_data["tag_str"]


def test_monitoring_metric_class_methods():
    metric = MonitoringMetric(
        id="metric_id",
        timestamp=datetime.now(timezone.utc),
        metric="test_metric",
        metric_type=MonitoringMetric.MetricType.gauge,
        value=1.0,
        tags={"env": "test"},
    )
    metric_dict = metric.to_dict()
    assert metric_dict["metric"] == "test_metric"
    assert metric_dict["type"] == "gauge"
    assert metric_dict["points"][0][1] == 1.0
    flatten_data = metric.psp_flatten()[0]
    assert '{"env":"test","monitoring_id":"metric_id"}' == flatten_data["tag_str"]


@patch("opsgenie_sdk.CreateAlertPayload")
def test_monitoring_event_alias(mock_create_alert_payload, monitoring_event):
    # Set up the mock return value
    mock_payload_instance = MagicMock()
    mock_payload_instance.source = "test_source"
    mock_payload_instance.message = "Test Event"
    mock_create_alert_payload.return_value = mock_payload_instance

    # Test case where alias is generated
    alias_tags = {"group1": ["tag2", "tag1"]}
    monitoring_event.to_opsgenie(alias_tags=alias_tags)
    assert mock_create_alert_payload.called

    # Verify the alias is correctly generated
    expected_tags = {
        "env:test",
        "monitoring_id:event_id",
        "event_group:group1",
        "tag1:value1",
        "tag2:value2",
    }
    actual_call_args = mock_create_alert_payload.call_args[1]
    assert set(actual_call_args["tags"]) == expected_tags
    assert actual_call_args["alias"] == "value2:value1"

    # Reset the mock for the next test
    mock_create_alert_payload.reset_mock()

    # Test case where alias is empty, and id is used instead
    alias_tags = {"group2": ["tag1", "tag2"]}
    monitoring_event.to_opsgenie(alias_tags=alias_tags)
    assert mock_create_alert_payload.called

    # Verify the alias is set to the event id
    actual_call_args = mock_create_alert_payload.call_args[1]
    assert set(actual_call_args["tags"]) == expected_tags
    assert actual_call_args["alias"] == "event_id"


def test_alias(monitoring_event):
    # Test default values
    result = monitoring_event.get_event_alias()
    assert result == "", "Default values should return an empty string"

    # Test successful execution with valid inputs
    alias_tags = {"group1": ["tag1", "tag2"]}
    result = monitoring_event.get_event_alias(alias_tags=alias_tags)
    assert result == "value1:value2", "Expected 'value1:value2'"

    # Test that the order of tags is preserved as defined in the config
    alias_tags = {"group1": ["tag2", "tag1"]}
    result = monitoring_event.get_event_alias(alias_tags=alias_tags)
    assert result == "value2:value1", "Expected 'value2:value1'"

    # Test when alias_tags is None
    result = monitoring_event.get_event_alias(alias_tags=None)
    assert result == "", "alias_tags=None should return an empty string"

    # Test when category_tag does not match any tags
    alias_tags = {"group2": ["tag1", "tag2"]}
    result = monitoring_event.get_event_alias(alias_tags=alias_tags)
    assert result == "", "Non-matching category_tag should return an empty string"

    # Test when none of the alias requested is found
    alias_tags = {"group1": ["non_existent_tag1", "non_existent_tag2"]}
    result = monitoring_event.get_event_alias(alias_tags=alias_tags)
    assert result == "", "None of the requested alias tags found should return an empty string"

    # Test when there are no tags
    monitoring_event.tags = {}
    alias_tags = {"group1": ["tag1", "tag2"]}
    result = monitoring_event.get_event_alias(alias_tags=alias_tags)
    assert result == "", "No tags should return an empty string"
    monitoring_event.tags = {
        "env": "test",
        "event_group": "group1",
        "tag1": "value1",
        "tag2": "value2",
    }  # Reset tags for further tests

    # Test when the category tag is not found
    alias_tags = {"group1": ["tag1", "tag2"]}
    result = monitoring_event.get_event_alias(category_tag="non_existent_category", alias_tags=alias_tags)
    assert result == "", "Non-existent category tag should return an empty string"

    # Test when extra_tags are included
    alias_tags = {"group1": ["tag1", "tag2", "extra_tag"]}
    extra_tags = {"extra_tag": "extra_value"}
    result = monitoring_event.get_event_alias(alias_tags=alias_tags, extra_tags=extra_tags)
    assert result == "value1:value2:extra_value", "Expected 'value1:value2:extra_value'"

    # Test with different separator
    alias_tags = {"group1": ["tag1", "tag2"]}
    result = monitoring_event.get_event_alias(alias_tags=alias_tags, separator="-")
    assert result == "value1-value2", "Expected 'value1-value2'"

    # Test the speed of execution for the function
    alias_tags = {"group1": ["tag1", "tag2"]}
    execution_time = timeit.timeit(lambda: monitoring_event.get_event_alias(alias_tags=alias_tags), number=1000)
    print(f"Execution time for 1000 runs: {execution_time} seconds")
