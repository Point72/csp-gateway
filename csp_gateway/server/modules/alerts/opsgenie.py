from collections import deque
from datetime import timedelta

import csp
from csp import ts
from pydantic import Field

from csp_gateway.server.modules._backends.opsgenie import _OpsGeniePublisher, log, opsgenie_sdk
from csp_gateway.server.modules.heartbeats.opsgenie import _OpsGenieHeartbeats
from csp_gateway.server.modules.logging.util import MonitoringEvent, MonitoringLevelMapping, OpsGenieLevel

__all__ = ("PublishAlertsOpsGenie", "PublishOpsGenie")


class _OpsGenieAlerts(_OpsGeniePublisher):
    events_channel: str | None = Field(default=None, description="Channel for events.")
    ops_alert_min_level: OpsGenieLevel | None = Field(
        default=OpsGenieLevel.P3,
        description="The minimum alert level for OpsGenie alerts.",
    )
    ops_alias_tags: dict[str, list[str]] = Field(default={}, description="Tags to be used as OpsGenie alis for event_agregation")
    ops_alias_separator: str = Field(default=":", description="Separator to build OpsGenie alias.")
    ops_category_tag: str = Field(default="event_group", description="Tag that identifies event type.")

    def _connect_alerts(self, channels):
        if self.events_channel:
            events = channels.get_channel(self.events_channel)
            self._publish_alerts(events)

    @csp.node
    def _publish_alerts(self, data: ts[list[MonitoringEvent]]):
        with csp.alarms():
            alarm = csp.alarm(bool)

        with csp.state():
            s_alarm_scheduled = False
            s_alert_queue = deque()
            s_alert_api = opsgenie_sdk.AlertApi(api_client=self._api_client)
            s_min_alert_level = MonitoringLevelMapping.from_alert_type(
                level=self.ops_alert_min_level,
            )

        if csp.ticked(data):
            for event in data:
                log.trace("Received MonitoringEvent: %s", event.to_dict())
                event_level = MonitoringLevelMapping.from_event(event)
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
                    except Exception:  # noqa: BLE001 -- isolate alert delivery failures from the CSP engine
                        log.exception("Error creating OpsGenie alert")
                else:
                    log.trace(
                        "Ignoring MonitoringEvent alert level %s (logging level %s) below threshold %s",
                        event.alert_type,
                        event_level,
                        s_min_alert_level,
                    )

        if csp.ticked(alarm):
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


class PublishAlertsOpsGenie(_OpsGenieAlerts):
    """Publish OpsGenie alerts without requiring or managing a heartbeat."""

    def connect(self, channels):
        self._connect_client()
        self._connect_alerts(channels)


class PublishOpsGenie(_OpsGenieAlerts, _OpsGenieHeartbeats):
    """Publish OpsGenie alerts and heartbeats using a shared API client."""

    def connect(self, channels):
        self._connect_client()
        self._connect_alerts(channels)
        self._connect_heartbeats(channels)
