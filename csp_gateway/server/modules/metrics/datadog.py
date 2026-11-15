from pydantic import Field

from csp_gateway.server.modules._backends.datadog import (
    _DatadogPublisher,
    log as log,  # noqa: PLC0414 -- preserve the module's logger export
)
from csp_gateway.server.modules.logging.datadog_events import _DatadogEvents

__all__ = ("PublishDatadog", "PublishMetricsDatadog")


class _DatadogMetrics(_DatadogPublisher):
    metrics_channel: str | None = Field(default=None, description="Channel for metrics.")
    include_monitoring_id: bool = Field(default=False, description="Include the monitoring_id tag in Datadog metric submissions.")


class PublishMetricsDatadog(_DatadogMetrics):
    """Publish Datadog metrics without emitting native events."""

    def connect(self, channels):
        self._connect_datadog(
            channels,
            metrics_channel=self.metrics_channel,
            include_monitoring_id=self.include_monitoring_id,
            emit_startup_event=False,
        )


class PublishDatadog(_DatadogMetrics, _DatadogEvents):
    """Publish Datadog metrics and native events with shared queued delivery."""

    def connect(self, channels):
        self._connect_datadog(
            channels,
            events_channel=self.events_channel,
            metrics_channel=self.metrics_channel,
            include_monitoring_id=self.include_monitoring_id,
        )
