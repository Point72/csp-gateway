import logging
from datetime import UTC, datetime
from queue import Queue
from threading import Thread

import csp
from csp import ts
from pydantic import Field, model_validator

from csp_gateway.server import ChannelSelection, GatewayModule
from csp_gateway.server.modules.logging.util import (
    MonitoringEvent,
    MonitoringMetric,
)
from csp_gateway.utils import get_thread

try:
    from datadog import api
except ImportError:
    # Hold and raise in model validator
    api = None

log = logging.getLogger("csp_gateway.server.modules.logging.datadog")
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
logging.getLogger("datadog.api").setLevel(logging.ERROR)

# define TRACE level logging below DEBUG to investigate Datadog submission
# without polluting DEBUG level file log
TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")


def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL):
        self._log(TRACE_LEVEL, message, args, **kwargs)


logging.Logger.trace = trace


def _log_result(
    data_type: str,
    payload: dict[str, str | list[str]],
    res: dict[str, str | list[str]],
) -> None:
    """Logger for Datadog submission replies.

    Args:
        data_type: type of the submission i.e. event or metric
        payload:  Datadog submission payload
        res: Datadog submission response
    """
    if not res or "status" not in res or res["status"] != "ok":
        log.error(f"Datadog {data_type} submission failure {res} for {payload}")
    else:
        log.trace(res)


def _send_to_datadog(queue: Queue, dd_latency_log_threshold_seconds: int) -> None:
    while True:
        data = queue.get()
        if data is None:
            return

        for event_or_metric_type, event_or_metric_body in data:
            try:
                start_time = datetime.now(UTC)
                if issubclass(event_or_metric_type, MonitoringEvent):
                    res = api.Event.create(**event_or_metric_body)
                elif issubclass(event_or_metric_type, MonitoringMetric):
                    res = api.Metric.send(**event_or_metric_body)
                else:
                    raise TypeError(f"Unknown monitor type {event_or_metric_type.__name__}.")
            except Exception:
                log.exception("Error sending monitoring data to Datadog")
            else:
                end_time = datetime.now(UTC)
                _log_result(event_or_metric_type.__name__, event_or_metric_body, res)
                elapsed_seconds = (end_time - start_time).total_seconds()
                if elapsed_seconds > dd_latency_log_threshold_seconds:
                    log.warning(
                        f"Sending data to datadog took {elapsed_seconds} seconds, which is longer than expected ({dd_latency_log_threshold_seconds} seconds)!"
                    )


class _DatadogPublisher(GatewayModule):
    """Shared Datadog configuration and queued delivery."""

    # None of the channels are required
    requires: ChannelSelection | None = Field(default=[], description="List of required channels.")
    dd_latency_log_threshold_seconds: int = Field(
        default=30,
        description="Maximum time sending events/metrics to datadog can take before a warning is logged.",
    )

    dd_tags: dict[str, str] | None = Field(default=None, description="Tags to be included with Datadog submissions.")

    @model_validator(mode="before")
    def check_import(cls, values):
        if api is None:
            raise ImportError(f"datadog is required for {cls.__name__}. Install it with: pip install datadog")
        return values

    def _connect_datadog(
        self,
        channels,
        events_channel: str | None = None,
        metrics_channel: str | None = None,
        include_monitoring_id: bool = False,
        emit_startup_event: bool = True,
    ):
        if not events_channel and not metrics_channel:
            return

        dd_queue = Queue()

        if events_channel:
            events = channels.get_channel(events_channel)
        else:
            events = csp.null_ts([MonitoringEvent])

        if metrics_channel:
            metrics = channels.get_channel(metrics_channel)
        else:
            metrics = csp.null_ts([MonitoringMetric])

        dd_thread = get_thread(
            target=_send_to_datadog,
            args=(dd_queue, self.dd_latency_log_threshold_seconds),
        )
        dd_thread.start()
        if emit_startup_event:
            # Keep the existing call signature for subclasses overriding the legacy node.
            self._publish_datadog(events, metrics, dd_queue, dd_thread, self.dd_tags, include_monitoring_id)
        else:
            self._publish_datadog(events, metrics, dd_queue, dd_thread, self.dd_tags, include_monitoring_id, False)

    @staticmethod
    @csp.node
    def _publish_datadog(
        events: ts[list[MonitoringEvent]],
        metrics: ts[list[MonitoringMetric]],
        dd_queue: Queue,
        dd_thread: Thread,
        dd_tags: dict[str, str],
        include_monitoring_id: bool = False,
        emit_startup_event: bool = True,
    ):
        with csp.start():
            if emit_startup_event:
                init_event = MonitoringEvent(
                    title="PublishDatadog started",
                    text="PublishDatadog started",
                    alert_type=MonitoringEvent.AlertType.success,
                    event_type="connection init",
                )
                dd_queue.put([(type(init_event), init_event.to_datadog(dd_tags))])

        with csp.stop():
            dd_queue.put(None)
            dd_thread.join()

        new_events_or_metrics = []

        if csp.ticked(events):
            new_events_or_metrics.extend(events)

        if csp.ticked(metrics):
            new_events_or_metrics.extend(metrics)

        if new_events_or_metrics:
            new_events_or_metrics_and_body = []
            for item in new_events_or_metrics:
                body = item.to_datadog(dd_tags)
                if isinstance(item, MonitoringMetric) and not include_monitoring_id and "tags" in body:
                    body["tags"] = [tag for tag in body["tags"] if not tag.startswith("monitoring_id:")]
                new_events_or_metrics_and_body.append((type(item), body))
            dd_queue.put(new_events_or_metrics_and_body)
