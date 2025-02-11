import logging
from abc import abstractmethod
from datetime import timezone
from enum import Enum
from typing import Dict, List, Tuple, Union

import orjson
from pydantic import BaseModel
from typing_extensions import override

from csp_gateway.utils.struct.base import GatewayStruct

log = logging.getLogger(__name__)

__all__ = (
    "DatadogLevel",
    "MonitoringBase",
    "MonitoringEvent",
    "MonitoringLevel",
    "MonitoringLevelMapping",
    "MonitoringMetric",
    "MonitoringSystem",
    "OpsGenieLevel",
)


class MonitoringSystem(Enum):
    """List of monitoring systems."""

    DATADOG = "datadog"
    OPSGENIE = "opsgenie"
    LOGGING = "logging"


class DatadogLevel(Enum):
    """Datadog alert levels."""

    error = "error"
    warning = "warning"
    info = "info"
    success = "success"


class OpsGenieLevel(Enum):
    """OpsGenie alert levels."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"


class MonitoringBase(GatewayStruct):
    """
    Monitoring base class.

    Attributes:
        tags (Dict[str, str]): Monitoring tags.
        tag_str (str): String representation of tags.
    """

    tags: Dict[str, str] = {}
    tag_str: str = ""

    def __init__(self, **kwargs):
        # We add override __init__ here since csp does not currently
        # provide type validation for dict typing so we
        # perform it here manually using csp's internal typing
        # validation
        super().__init__(**kwargs)
        obj_type = self.__class__
        # based on from csp
        for field, value in kwargs.items():
            expected_type = obj_type.__full_metadata_typed__.get(field, None)
            if expected_type is None:
                raise KeyError(f"Unexpected field `{field}` for type {obj_type}")
            setattr(self, field, obj_type._obj_from_python(value, expected_type))

    def get_tags(self, extra_tags: Dict[str, str] = None) -> List[str]:
        """
        Appends extra (i.e., global) tags if supplied to event or metric specific tags.
        Transforms dictionary of monitoring tags into Datadog compliant List format.
        i.e., {'foo':'bar', 'baz': 'qux'} transformed into ['foo:bar', 'baz:qux'].

        Args:
            extra_tags (Optional[Dict[str, str]]): Extra tags to be appended.

        Returns:
            List[str]: Datadog tags list.
        """
        if extra_tags:
            self.tags.update(extra_tags)
        if "monitoring_id" not in self.tags:
            self.tags["monitoring_id"] = self.id
        return [f"{k}:{v}" for k, v in self.tags.items()]

    def get_datadog_timestamp(self, from_tz: timezone = timezone.utc, to_tz: timezone = None) -> float:
        """
        Provides Datadog timestamp.
        Optionally converts timestamp time zone into Datadog instance time zone.
        This is needed as Datadog does not recognize future timestamps.

        Args:
            from_tz (timezone, optional): The original time zone of the timestamp. Defaults to timezone.utc.
            to_tz (Optional[timezone]): The target time zone for conversion. Defaults to None.

        Returns:
            float: Datadog timestamp.
        """
        return self.timestamp.replace(tzinfo=from_tz).astimezone(tz=to_tz).timestamp()

    @abstractmethod
    def to_datadog(extra_tags: List[str] = None) -> Dict[str, Union[str, List[str]]]:
        """
        Abstract method to implement conversion to Datadog payload.

        Args:
            extra_tags (Optional[List[str]]): Metric extra tags.

        Returns:
            Dict[str, Union[str, List[str]]]: Datadog metric payload.
        """
        raise NotImplementedError

    @abstractmethod
    def to_dict(self, extra_tags: Dict[str, str] = None) -> Dict[str, str]:
        """
        Abstract method to convert to dictionary.

        Args:
            extra_tags (Optional[Dict[str, str]]): Extra tags to be appended.

        Returns:
            Dict[str, str]: Dictionary representation.
        """
        raise NotImplementedError

    @abstractmethod
    def to_opsgenie(self, extra_tags: Dict[str, str] = None) -> "opsgenie_sdk.CloseAlertPayload":  # noqa: F821
        """
        Abstract method to convert to OpsGenie payload.

        Args:
            extra_tags (Optional[Dict[str, str]]): Extra tags to be appended.

        Returns:
            opsgenie_sdk.CloseAlertPayload: OpsGenie payload.
        """
        raise NotImplementedError

    @override
    def psp_flatten(self, custom_jsonifier=None):
        """
        Flattens the object for PSP.

        Args:
            custom_jsonifier (optional): Custom JSON serializer.

        Returns:
            The flattened object.
        """
        self.tag_str = orjson.dumps(self.tags).decode()
        return super().psp_flatten(custom_jsonifier)


class MonitoringEvent(MonitoringBase):
    """
    Monitoring event for Datadog.

    Attributes:
        title (str): Datadog event title.
        text (str): Datadog event text.
        event_type (str): Datadog key by which to group events in the event stream.
        alert_type (DatadogLevel): Datadog alert type, e.g., error, warning, etc.
        source (str): Source type of the event.
    """

    DEFAULT_SOURCE = "python"

    # leave for backward compatibility
    AlertType = DatadogLevel

    title: str
    text: str
    event_type: str
    alert_type: Union[AlertType, DatadogLevel] = DatadogLevel.info
    source: str = DEFAULT_SOURCE

    def get_event_alias(
        self,
        category_tag: str = "event_group",
        alias_tags: Dict[str, str] = None,
        extra_tags: Dict[str, str] = None,
        separator: str = ":",
    ) -> str:
        """
        Formats alias string from specified tags.
        This functionality is useful to aggregate OpsGenie events under the same alias.

        Args:
            category_tag (str): Name of the tag used to categorize the evnet. Default is "event_group".
            alias_tags (Optional[Dict[str, str]]): Event tags used to build an alias.
            extra_tags (Optional[Dict[str, str]]): Event extra tags.
            separator (str): Separator to build alias. Default is ":".
        Returns:
            (str): Aggregator alias
        """
        if alias_tags:
            if not extra_tags:
                extra_tags = {}
            tags = self.tags | extra_tags
            alias = []
            if category_tag in tags and tags[category_tag] in alias_tags:
                for alias_tag in alias_tags[tags[category_tag]]:
                    if alias_tag in tags:
                        alias.append(tags[alias_tag])
            if alias:
                return separator.join(alias)
        return ""

    def to_datadog(self, extra_tags: Dict[str, str] = None) -> Dict[str, Union[str, List[str]]]:
        """
        Formats Datadog event payload.

        Args:
            extra_tags (Optional[Dict[str, str]]): Metric extra tags.

        Returns:
            Dict[str, Union[str, List[str]]]: Datadog event payload.
        """
        return {
            "title": self.title,
            "text": self.text,
            "alert_type": self.alert_type.value,
            "aggregation_key": self.event_type,
            "date_happened": self.get_datadog_timestamp(),
            "source_type_name": self.source,
            "tags": self.get_tags(extra_tags),
        }

    def to_dict(self, extra_tags: Dict[str, str] = None) -> Dict[str, str]:
        """
        Converts the event to a dictionary.

        Args:
            extra_tags (Optional[Dict[str, str]]): Extra tags to be appended.

        Returns:
            Dict[str, str]: Dictionary representation of the event.
        """
        attrs = (
            "title",
            "text",
            "source",
            "alert_type",
            "event_type",
            "id",
            "timestamp",
        )
        attrs_dict = {attr: getattr(self, attr) for attr in attrs}
        attrs_dict["tags"] = self.get_tags(extra_tags=extra_tags)
        return attrs_dict

    def to_opsgenie(
        self,
        category_tag: str = "event_group",
        alias_tags: Dict[str, str] = None,
        extra_tags: Dict[str, str] = None,
        separator: str = ":",
    ) -> "opsgenie_sdk.CloseAlertPayload":  # noqa: F821
        """
        Converts the event to an OpsGenie payload.

        Args:
            category_tag (str): Name of the tag used to categorize the evnet. Default is "event_group".
            alias_tags (Optional[Dict[str, str]]): Event tags used to build an alias.
            extra_tags (Optional[Dict[str, str]]): Event extra tags.
            separator (str): Separator to build alias. Default is ":".
        Returns:
            opsgenie_sdk.CloseAlertPayload: OpsGenie payload.
        """
        import opsgenie_sdk

        if not extra_tags:
            extra_tags = {}
        alias = self.get_event_alias(
            category_tag=category_tag,
            alias_tags=alias_tags,
            extra_tags=extra_tags,
            separator=separator,
        )
        return opsgenie_sdk.CreateAlertPayload(
            source=self.source,
            message=self.title,
            alias=alias or self.id,
            description=self.text,
            tags=self.get_tags(extra_tags=extra_tags),
            entity=self.event_type,
            details=self.tags | extra_tags,
            priority=MonitoringLevelMapping.from_event(self).opsgenie,
        )


class MonitoringLevel(BaseModel):
    """Dataclass used for level mapping accross systems"""

    level: str
    datadog: DatadogLevel
    opsgenie: OpsGenieLevel
    logging: int


class MonitoringLevelMapping(Enum):
    """
    MonitoringLevelMapping provides mapping between Datadog, OpsGenie, and logging levels.

    Attributes:
        critical (MonitoringLevel): Critical level mapping.
        error (MonitoringLevel): Error level mapping.
        warning (MonitoringLevel): Warning level mapping.
        info (MonitoringLevel): Info level mapping.
        debug (MonitoringLevel): Debug level mapping.
    """

    critical = MonitoringLevel(
        level="critical",
        datadog=DatadogLevel.error,
        opsgenie=OpsGenieLevel.P1,
        logging=50,
    )
    error = MonitoringLevel(level="error", datadog=DatadogLevel.error, opsgenie=OpsGenieLevel.P2, logging=40)
    warning = MonitoringLevel(
        level="warning",
        datadog=DatadogLevel.warning,
        opsgenie=OpsGenieLevel.P3,
        logging=30,
    )
    info = MonitoringLevel(level="info", datadog=DatadogLevel.info, opsgenie=OpsGenieLevel.P4, logging=20)
    debug = MonitoringLevel(
        level="debug",
        datadog=DatadogLevel.success,
        opsgenie=OpsGenieLevel.P5,
        logging=10,
    )

    @property
    def opsgenie(self) -> str:
        """Gets the OpsGenie level value."""
        return self.value.opsgenie.value

    @property
    def datadog(self) -> str:
        """Gets the Datadog level value."""
        return self.value.datadog.value

    @property
    def logging(self) -> str:
        """Gets the logging level."""
        return self.value.logging

    @classmethod
    def from_event(cls, event: MonitoringEvent) -> "MonitoringLevelMapping":
        """
        Gets the monitoring level mapping from a MonitoringEvent.

        Args:
            event (MonitoringEvent): The monitoring event.

        Returns:
            MonitoringLevelMapping: The corresponding monitoring level mapping.

        Raises:
            ValueError: If no mapping is found for the event.
        """
        mapping: Dict[str, MonitoringLevelMapping] = {member.value.datadog: member for member in cls}
        if event.alert_type in mapping:
            return mapping[event.alert_type]
        raise ValueError(f"No MonitoringLevelMapping found for {event}")

    @classmethod
    def from_alert_type(cls, level: Union[int, str, DatadogLevel, OpsGenieLevel]) -> "MonitoringLevelMapping":
        """
        Gets the monitoring level mapping from an alert type.

        Args:
            level Union[int, str, DatadogLevel, OpsGenieLevel]: The alert level.

        Returns:
            MonitoringLevelMapping: The corresponding monitoring level mapping.

        Raises:
            ValueError: If no mapping is found for the level.DatadogLevel
        """
        if isinstance(level, str):
            try:
                level = DatadogLevel(level)
            except ValueError:
                try:
                    level = OpsGenieLevel(level)
                except ValueError:
                    raise ValueError(f"No alert level {level} found")
        if isinstance(level, DatadogLevel):
            # Datadog has no critical level
            if level == DatadogLevel.error:
                return cls.error
            for alert_level in cls:
                if getattr(alert_level, MonitoringSystem.DATADOG.value) == level.value:
                    return alert_level
        elif isinstance(level, OpsGenieLevel):
            for alert_level in cls:
                if getattr(alert_level, MonitoringSystem.OPSGENIE.value) == level.value:
                    return alert_level
        elif isinstance(level, int):
            for alert_level in cls:
                if getattr(alert_level, MonitoringSystem.LOGGING.value) == level:
                    return alert_level
        raise ValueError(f"No alert level {level} found ---")

    @classmethod
    def get_opsgenie_levels(cls) -> Tuple[str]:
        """
        Gets all OpsGenie levels.

        Returns:
            Tuple[str]: All OpsGenie levels.
        """
        return tuple(member.opsgenie for member in cls)

    @classmethod
    def get_datadog_levels(cls) -> Tuple[str]:
        """
        Gets all Datadog levels.

        Returns:
            Tuple[str]: All Datadog levels.
        """
        return tuple(member.datadog for member in cls)

    @classmethod
    def get_logging_levels(cls) -> Tuple[str]:
        """
        Gets all logging levels.

        Returns:
            Tuple[str]: All logging levels.
        """
        return tuple(member.logging for member in cls)


class MonitoringMetric(MonitoringBase):
    """
    Monitoring metric for Datadog.

    Attributes:
        metric (str): Datadog metric name.
        metric_type (MetricType): Datadog metric type, i.e., count, rate, gauge.
        value (Union[int, float]): Numeric metric value.
    """

    class MetricType(Enum):
        """
        Metric type struct
        """

        gauge = "gauge"
        count = "count"
        rate = "rate"

    metric: str
    metric_type: MetricType
    value: float

    def to_datadog(self, extra_tags: Dict[str, str] = None) -> Dict[str, Union[str, List[str]]]:
        """
        Formats Datadog metric payload.

        Args:
            extra_tags (Optional[Dict[str, str]]): Metric extra tags.

        Returns:
            Dict[str, Union[str, List[str]]]: Datadog metric payload.
        """
        return {
            "metric": self.metric,
            "type": self.metric_type.value,
            "points": [(self.get_datadog_timestamp(), self.value)],
            "tags": self.get_tags(extra_tags),
        }

    def to_dict(self, extra_tags: Dict[str, str] = None) -> Dict[str, Union[str, List[str]]]:
        """
        Converts the metric to a dictionary.

        Args:
            extra_tags (Optional[Dict[str, str]]): Extra tags to be appended.

        Returns:
            Dict[str, Union[str, List[str]]]: Dictionary representation of the metric.
        """
        return self.to_datadog(extra_tags=extra_tags)

    def to_opsgenie(
        self,
        title: str,
        alert_type: MonitoringLevelMapping,
        text: str = None,
        source: str = None,
        extra_tags: Dict[str, str] = None,
    ) -> "opsgenie_sdk.CloseAlertPayload":  # noqa: F821
        """
        Converts the metric to an OpsGenie payload.

        Args:
            title (str): Alert title.
            alert_type (MonitoringLevelMapping): Alert type mapping.
            text (Optional[str]): Alert text. Defaults to None.
            source (Optional[str]): Source of the alert. Defaults to None.
            extra_tags (Optional[Dict[str, str]]): Extra tags to be appended. Defaults to None.

        Returns:
            opsgenie_sdk.CloseAlertPayload: OpsGenie payload.
        """
        import opsgenie_sdk

        if not extra_tags:
            extra_tags = {}
        return opsgenie_sdk.CreateAlertPayload(
            source=source or MonitoringEvent.DEFAULT_SOURCE,
            message=title,
            alias=self.id,
            description=text or title,
            tags=self.get_tags(extra_tags=extra_tags),
            entity=self.metric,
            details=self.tags | extra_tags,
            priority=alert_type.opsgenie,
            note=text or title,
        )
