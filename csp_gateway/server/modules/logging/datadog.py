import logging
from datetime import datetime, timezone
from queue import Queue
from threading import Thread
from typing import Dict, List, Optional, Union

import csp
from csp import ts
from pydantic import Field

from csp_gateway.server import ChannelSelection, GatewayModule
from csp_gateway.server.modules.logging.util import (
    MonitoringEvent,
    MonitoringMetric,
)

log = logging.getLogger(__name__)
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

__all__ = ("PublishDatadog",)


def _log_result(
    data_type: str,
    payload: Dict[str, Union[str, List[str]]],
    res: Dict[str, Union[str, List[str]]],
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
    from datadog import api

    while True:
        data = queue.get()
        if data is None:
            return

        for event_or_metric_type, event_or_metric_body in data:
            try:
                start_time = datetime.now(timezone.utc)
                if issubclass(event_or_metric_type, MonitoringEvent):
                    res = api.Event.create(**event_or_metric_body)
                elif issubclass(event_or_metric_type, MonitoringMetric):
                    res = api.Metric.send(**event_or_metric_body)
                else:
                    raise ValueError(f"Unknown monitor type {event_or_metric_type.__name__}.")
            except Exception as e:
                log.error(e, exc_info=True)
            else:
                end_time = datetime.now(timezone.utc)
                _log_result(event_or_metric_type.__name__, event_or_metric_body, res)
                elapsed_seconds = (end_time - start_time).total_seconds()
                if elapsed_seconds > dd_latency_log_threshold_seconds:
                    log.warning(
                        f"Sending data to datadog took {elapsed_seconds} seconds, which is longer than expected ({dd_latency_log_threshold_seconds} seconds)!"
                    )


class PublishDatadog(GatewayModule):
    """
    Gateway Module for emiting Datadog API events and/or metrics
    """

    # None of the channels are required
    requires: Optional[ChannelSelection] = Field(default=[], description="List of required channels.")
    events_channel: Optional[str] = Field(default=None, description="Channel for events.")
    metrics_channel: Optional[str] = Field(default=None, description="Channel for metrics.")
    dd_latency_log_threshold_seconds: int = Field(
        default=30,
        description="Maximum time sending events/metrics to datadog can take before a warning is logged.",
    )

    dd_tags: Optional[Dict[str, str]] = Field(default=None, description="Tags to be included with Datadog submissions.")

    def connect(self, channels):
        """
        Channels to be connected to graph
        """
        if not self.events_channel and not self.metrics_channel:
            return

        dd_queue = Queue()

        if self.events_channel:
            events = channels.get_channel(self.events_channel)
        else:
            events = csp.null_ts([[MonitoringEvent]])

        if self.metrics_channel:
            metrics = channels.get_channel(self.metrics_channel)
        else:
            metrics = csp.null_ts([[MonitoringMetric]])

        dd_thread = Thread(
            target=_send_to_datadog,
            args=(dd_queue, self.dd_latency_log_threshold_seconds),
            daemon=True,
        )
        dd_thread.start()
        self._publish_datadog(events, metrics, dd_queue, dd_thread, self.dd_tags)

    @staticmethod
    @csp.node
    def _publish_datadog(
        events: ts[List[MonitoringEvent]],
        metrics: ts[List[MonitoringMetric]],
        dd_queue: Queue,
        dd_thread: Thread,
        dd_tags: Dict[str, str],
    ):
        with csp.start():
            # send starting event to Datadog
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
            new_events_or_metrics_and_body = [(type(x), x.to_datadog(dd_tags)) for x in new_events_or_metrics]
            dd_queue.put(new_events_or_metrics_and_body)
