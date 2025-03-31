import json
import logging
from collections import deque
from datetime import timedelta
from typing import Dict, List, Literal, Optional

import csp
import opsgenie_sdk
from csp import ts
from pydantic import Field, PrivateAttr, model_validator

from csp_gateway.server import ChannelSelection, GatewayModule
from csp_gateway.server.modules.logging.util import (
    MonitoringEvent,
    MonitoringLevelMapping,
    MonitoringMetric,
    OpsGenieLevel,
)

log = logging.getLogger(__name__)

# define TRACE level logging below DEBUG to investigate OpsGenie submission
# without polluting DEBUG level file log
TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")


def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL):
        self._log(TRACE_LEVEL, message, args, **kwargs)


logging.Logger.trace = trace

__all__ = ("PublishOpsGenie",)


class PublishOpsGenie(GatewayModule):
    """
    PublishOpsGenie class is responsible for interfacing with OpsGenie to send alerts and
    manage heartbeats and heartbeat lags. It includes configurations for API keys, tags,
    delays, and heartbeat settings.
    """

    ops_api_key: str = Field(description="The API key for OpsGenie.")

    # None of the channels are required
    requires: Optional[ChannelSelection] = Field(default=[], description="List of required channels.")
    events_channel: Optional[str] = Field(default=None, description="Channel for events.")
    metrics_channel: Optional[str] = Field(default=None, description="Channel for metrics.")
    _api_client: opsgenie_sdk.api_client.ApiClient = PrivateAttr()

    ops_tags: Optional[Dict[str, str]] = Field(default=None, description="Tags to be included with OpsGenie alerts.")
    ops_async_delay_sec: Optional[float] = Field(default=5.0, description="Delay in seconds for asynchronous operations.")
    ops_sync_delay_sec: Optional[float] = Field(default=5.0, description="Delay in seconds for synchronous operations.")

    # heartbeat related
    ops_heartbeat_name: str = Field(description="The name of the heartbeat.")
    ops_heartbeat_interval: Optional[int] = Field(default=1, description="The interval at which heartbeats are sent.")
    ops_heartbeat_interval_unit: Optional[Literal["minutes", "hours", "days"]] = Field(
        default="minutes", description="The unit of the heartbeat interval."
    )
    ops_heartbeat_alert_level: Optional[OpsGenieLevel] = Field(default=OpsGenieLevel.P2, description="The alert level for heartbeat issues.")
    ops_heartbeat_metric_name: Optional[str] = Field(default="heartbeat", description="The metric name for heartbeat.")
    ops_alert_min_level: Optional[OpsGenieLevel] = Field(
        default=OpsGenieLevel.P3,
        description="The minimum alert level for OpsGenie alerts.",
    )
    ops_alias_tags: Dict[str, List[str]] = Field(default={}, description="Tags to be used as OpsGenie alis for event_agregation")
    ops_alias_separator: str = Field(default=":", description="Separator to build OpsGenie alias.")
    ops_category_tag: str = Field(default="event_group", description="Tag that identifies event type.")

    @model_validator(mode="before")
    def check_metrics_channel_and_heartbeat(cls, values):
        if values.get("metrics_channel") and not values.get("ops_heartbeat_name"):
            raise ValueError("'ops_heartbeat_name' is required if 'metrics_channel' is provided")
        return values

    def _init_heartbeat(self, heartbeat_api):
        # we specifically want to run heartbeat initialization in async_req=False with timeout
        # then each ping will be run in async_req=True mode
        payload = opsgenie_sdk.CreateHeartbeatPayload(
            name=self.ops_heartbeat_name,
            description=f"{self.ops_heartbeat_name} generated by csp_gateway",
            interval=self.ops_heartbeat_interval,
            interval_unit=self.ops_heartbeat_interval_unit,
            enabled=True,
            alert_message=(
                f"{self.ops_heartbeat_name} heartbeat not received in " + f"{self.ops_heartbeat_interval} {self.ops_heartbeat_interval_unit}"
            ),
            alert_tags=[f"{k}:{v}" for k, v in self.ops_tags.items()],
            alert_priority=self.ops_heartbeat_alert_level.value,
        )
        try:
            # heartbeats must have unique name
            # check if the heartbeat with this name already exists
            res = heartbeat_api.get_heartbeat(
                self.ops_heartbeat_name,
                async_req=False,
                _request_timeout=self.ops_sync_delay_sec,
            )
            log.info(
                "Heartbeat '%s' already exists: %s",
                self.ops_heartbeat_name,
                res.data.to_dict(),
            )
            # update heartbeat in case if payload parameters changed (i.e. tags, intervals, etc.)
            heartbeat_api.update_heartbeat(
                name=self.ops_heartbeat_name,
                update_heartbeat_payload=payload,
                async_req=False,
                _request_timeout=self.ops_sync_delay_sec,
            )
            log.info(
                "Updated heartbeat '%s' with the payload: %s",
                self.ops_heartbeat_name,
                res.data.to_dict(),
            )
        except opsgenie_sdk.exceptions.ApiException as e:
            # try to create a heartbeat if one does not exist
            message = json.loads(e.body)
            log.info(
                "Failed to retrieve heartbeat '%s': %s",
                self.ops_heartbeat_name,
                message,
            )
            res = heartbeat_api.create_heartbeat(
                create_heartbeat_payload=payload,
                async_req=False,
                _request_timeout=self.ops_sync_delay_sec,
            )
            log.info(
                "Created heartbeat '%s' with the payload: %s",
                self.ops_heartbeat_name,
                res.data.to_dict(),
            )

    def connect(self, channels):
        """
        Channels to be connected to graph
        """
        # this just creates an object and does not perform any calls or connections to OpsGenie
        config = opsgenie_sdk.configuration.Configuration()
        config.api_key["Authorization"] = self.ops_api_key
        self._api_client = opsgenie_sdk.api_client.ApiClient(configuration=config)

        if self.events_channel:
            events = channels.get_channel(self.events_channel)
            self._publish_alerts(events)

        if self.metrics_channel:
            metrics = channels.get_channel(self.metrics_channel)
            self._publish_heartbeat(metrics)

    @csp.node
    def _publish_heartbeat(self, data: ts[List[MonitoringMetric]]):
        with csp.alarms():
            alarm = csp.alarm(bool)

        with csp.state():
            s_alarm_scheduled = False
            # s_heartbeat queue to store and process async replies from OpsGenie
            s_heartbeat_queue = deque()
            s_heartbeat_api = opsgenie_sdk.HeartbeatApi(api_client=self._api_client)

        with csp.start():
            # init heartbeat object in synchronous mode
            self._init_heartbeat(heartbeat_api=s_heartbeat_api)

        if csp.ticked(data):
            for metric in data:
                log.trace("Received metric %s", metric.metric)
                if metric.metric == self.ops_heartbeat_metric_name:
                    try:
                        # heartbeat received, send ping
                        log.trace("Processing heartbeat %s", metric.to_dict())
                        res = s_heartbeat_api.ping(self.ops_heartbeat_name, async_req=True)
                        # append to the asynch queue to check status later
                        s_heartbeat_queue.append((csp.now(), res))
                        if not s_alarm_scheduled:
                            log.trace(
                                "Setting alarm to check heartbeat queue in %s seconds",
                                self.ops_async_delay_sec,
                            )
                            csp.schedule_alarm(alarm, timedelta(seconds=self.ops_async_delay_sec), True)
                            s_alarm_scheduled = True
                    except opsgenie_sdk.exceptions.ApiException as e:
                        log.error(
                            "Failed to send heartbeat for metric %s : %s",
                            metric.to_dict(self.ops_tags),
                            e,
                        )

        if csp.ticked(alarm):
            # keep processing the first element in the queue until the queue is either empty
            # or the timestamp of the first element is less than ops_async_delay_sec in the past
            while s_heartbeat_queue and (csp.now() - s_heartbeat_queue[0][0]).total_seconds() >= self.ops_async_delay_sec:
                log.trace(
                    "Processing heartbeat queue, %s object(s) remaining",
                    len(s_heartbeat_queue),
                )
                (_, res) = s_heartbeat_queue.popleft()
                if res.ready():
                    log.trace("Heartbeat submission successful")
                else:
                    log.error(
                        "Heartbeat submission is not ready in %s seconds",
                        self.ops_async_delay_sec,
                    )
            log.trace(
                "Done processing heartbeat queue, %s object(s) remaining",
                len(s_heartbeat_queue),
            )
        # if more items remaining reschedule the alarm
        if s_heartbeat_queue:
            log.trace(
                "Resetting alarm to check heartbeat queue in %s seconds",
                self.ops_async_delay_sec,
            )
            csp.schedule_alarm(alarm, timedelta(seconds=self.ops_async_delay_sec), True)
            s_alarm_scheduled = True
        else:
            log.trace("Heartbeat queue is empty")
            s_alarm_scheduled = False

    @csp.node
    def _publish_alerts(self, data: ts[List[MonitoringEvent]]):
        """ """
        with csp.alarms():
            alarm = csp.alarm(bool)

        with csp.state():
            s_alarm_scheduled = False
            # s_alert queue to store and process async replies from OpsGenie
            s_alert_queue = deque()
            s_alert_api = opsgenie_sdk.AlertApi(api_client=self._api_client)
            s_min_alert_level = MonitoringLevelMapping.from_alert_type(
                level=self.ops_alert_min_level,
            )

        if csp.ticked(data):
            for event in data:
                log.trace("Received MonitoringEvent: %s", event.to_dict())
                event_level = MonitoringLevelMapping.from_event(event)
                # check if the event at or above min reported level
                if event_level.logging >= s_min_alert_level.logging:
                    try:
                        payload = event.to_opsgenie(
                            extra_tags=self.ops_tags,
                            alias_tags=self.ops_alias_tags,
                            category_tag=self.ops_category_tag,
                            separator=self.ops_alias_separator,
                        )
                        log.trace("Processing alert: %s", payload)
                        res = s_alert_api.create_alert(
                            create_alert_payload=payload,
                            async_req=True,
                        )
                        s_alert_queue.append((csp.now(), res))
                        if not s_alarm_scheduled:
                            log.trace(
                                "Setting alarm to check alert queue in %s seconds",
                                self.ops_async_delay_sec,
                            )
                            csp.schedule_alarm(
                                alarm,
                                timedelta(seconds=self.ops_async_delay_sec),
                                True,
                            )
                            s_alarm_scheduled = True
                    except Exception as e:
                        log.error(e, exc_info=True)
                else:
                    log.trace(
                        "Ignoring MonitoringEvent alert level %s (logging level %s) below threshold %s",
                        event.alert_type,
                        event_level,
                        s_min_alert_level,
                    )

        if csp.ticked(alarm):
            # keep processing the first element in the queue until the queue is either empty
            # or the timestamp of the first element is less than ops_async_delay_sec in the past
            while s_alert_queue and (csp.now() - s_alert_queue[0][0]).total_seconds() >= self.ops_async_delay_sec:
                log.trace(
                    "Processing alert queue, %s object(s) remaining",
                    len(s_alert_queue),
                )
                (_, res) = s_alert_queue.popleft()
                if res.ready():
                    log.trace("Alert submission successful")
                else:
                    log.error(
                        "Alert submission is not ready in %s seconds",
                        self.ops_async_delay_sec,
                    )
            log.trace(
                "Done processing alert queue, %s object(s) remaining",
                len(s_alert_queue),
            )
            # if more items remaining reschedule the alarm
            if s_alert_queue:
                log.trace(
                    "Resetting alarm to check alert queue in %s seconds",
                    self.ops_async_delay_sec,
                )
                csp.schedule_alarm(alarm, timedelta(seconds=self.ops_async_delay_sec), True)
                s_alarm_scheduled = True
            else:
                log.trace("Alert queue is empty")
                s_alarm_scheduled = False
