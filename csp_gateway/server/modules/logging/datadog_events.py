from pydantic import Field

from csp_gateway.server.modules._backends.datadog import _DatadogPublisher

__all__ = ("PublishEventsDatadog",)


class _DatadogEvents(_DatadogPublisher):
    events_channel: str | None = Field(default=None, description="Channel for events.")


class PublishEventsDatadog(_DatadogEvents):
    """Publish native Datadog events, including the startup notification."""

    def connect(self, channels):
        self._connect_datadog(channels, events_channel=self.events_channel)
