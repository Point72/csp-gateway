from datetime import UTC, datetime, timedelta
from typing import Any, get_args, get_origin

import csp
import orjson
from ccflow import BaseModel
from csp import ts
from csp.adapters.kafka import (
    DateTimeType,
    JSONTextMessageMapper,
    KafkaStartOffset,
    RawTextMessageMapper,
)
from csp.adapters.status import Status
from csp.impl.types.container_type_normalizer import ContainerTypeNormalizer
from deprecation import deprecated
from pydantic import Field, FilePath, PrivateAttr, field_validator, model_validator
from typing_extensions import override

from csp_gateway.server import (
    ChannelSelection,
    EncodedEngineCycle,
    GatewayChannels,
    GatewayModule,
)
from csp_gateway.server.shared.engine_replay import EngineReplay
from csp_gateway.server.shared.json_converter import _convert_orjson_compatible

from .utils import KafkaChannelProcessor

__all__ = (
    "KafkaConfiguration",
    "KafkaStartOffset",
    "ReadWriteKafka",
    "ReplayEngineKafka",
)

#: Wire field names of the envelope a message is wrapped in when engine timestamps are included.
_ENVELOPE_ENCODING_FIELD = "encoding"
_ENVELOPE_TIMESTAMP_FIELD = "csp_timestamp"


class _EngineCycleEnvelope(csp.Struct):
    """The envelope as csp's Kafka adapter sees it, for the one case that needs csp to parse it.

    Subscribing with ``tick_timestamp_from_field`` makes csp replay each message at the engine time
    recorded in it, which means csp -- not us -- has to read that field out of the payload. It can
    only do that into a ``csp.Struct``, so this is the last one in the package. Everything else,
    including the publish side, reads and writes the same wire format through `EncodedEngineCycle`.
    """

    encoding: str
    csp_timestamp: datetime


def _encode_envelope(encoding: str, csp_timestamp: datetime) -> str:
    """Serialize the envelope exactly as csp's ``JSONTextMessageMapper`` would.

    csp writes ``DateTimeType.UINT64_MILLIS`` as epoch milliseconds and reads it back the same way,
    so a subscriber using the mapper parses this unchanged.
    """
    return orjson.dumps(
        {
            _ENVELOPE_ENCODING_FIELD: encoding,
            _ENVELOPE_TIMESTAMP_FIELD: int(csp_timestamp.replace(tzinfo=UTC).timestamp() * 1000),
        }
    ).decode()


def _decode_envelope(message: str) -> EncodedEngineCycle:
    """Read an envelope written by `_encode_envelope` or by csp's ``JSONTextMessageMapper``."""
    raw = orjson.loads(message)
    timestamp = raw.get(_ENVELOPE_TIMESTAMP_FIELD)
    return EncodedEngineCycle(
        encoding=raw[_ENVELOPE_ENCODING_FIELD],
        csp_timestamp=datetime.fromtimestamp(timestamp / 1000, tz=UTC).replace(tzinfo=None) if timestamp is not None else None,
    )


# NOTE: If the authorization parameters are not correct, the graph may hang indefinitely
class KafkaConfiguration(BaseModel):
    """
    For more information regarding Kafka, see here:
    https://kafka.apache.org/documentation/#introduction
    """

    broker: str = Field(description="broker URL")
    start_offset: KafkaStartOffset | timedelta | datetime | None = Field(
        None,
        description="""Signifies where to start the stream playback from (defaults to KafkaStartOffset.LATEST ). Can be
                             one of the KafkaStartOffset enum types,
                             datetime - to replay from the given absolute time
                             timedelta - this will be taken as an absolute offset from starttime to playback from""",
    )

    @field_validator("start_offset", mode="before")
    @classmethod
    def _coerce_start_offset(cls, value):
        # Coerce
        if isinstance(value, str) and value in KafkaStartOffset.__members__:
            return KafkaStartOffset[value]
        return value

    debug: bool = Field(
        False,
        description="Whether to be in debug mode. If True, start_offset is set to None",
    )
    group_id: str | None = Field(
        None,
        description="""
        If set, will cause the adapter to behave as a consume-once consumer.
        start_offset may not be set in this case since the adapter will
        always replay from the last consumed offset.""",
    )
    group_id_prefix: str = Field(
        "",
        description="""When not passing an explicit group_id, a prefix can be supplied that will be
        used to prefix the UUID generated for the group_id""",
    )
    max_threads: int = 4
    max_queue_size: int = 1000000
    poll_timeout: timedelta = Field(
        timedelta(seconds=1),
        description="""
        Amount of time to wait if data is not available in the broker
        to consume.""",
    )

    auth: bool = Field(False, description="Determines whether to use authentication")
    security_protocol: str = Field("SASL_SSL", description="Security protocol, only used if auth is set to True")
    sasl_kerberos_keytab: FilePath | None = Field(
        None,
        description="""
        Location of the Kerberos keytab for Kerberos authentication.
        Only used if auth is set to True
        """,
    )
    sasl_kerberos_principal: str = Field("", description="Name of kerberos principal, only used if auth is set to True")
    ssl_ca_location: FilePath | None = Field(
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        description="""
        Location of the PEM key for broker validation.
        Only used if auth is set to True. Defaults to a file location many linux machines
        have access to.""",
    )
    sasl_kerberos_service_name: str = Field("kafka", description="Kerberos service name, only used if auth is set to True")

    rd_kafka_conf_options: dict | None = Field(
        None,
        description="""
        Extra configuration options that will be directly passed to the C++ Kafka consumers and producers.
        For example, if you want to change maximum amount of time the Kafka broker will block before
        answering the fetch request if there isn't sufficient data to immediately satisfy the requirement
        given by fetch.min.bytes, you can set:
        rd_kafka_conf_options={'fetch.wait.max.ms' : '10' }
        """,
    )


# TODO: Does not work with dict baskets
class ReadWriteKafka(GatewayModule):
    """
    This class is designed to:
    1. Publish Gateway channel ticks to Kafka.
    2. Read Gateway channel ticks from Kafka to instantiate
       those ticks on the corresponding channel.

    Custom serialization and deserialization logic can be provided by
    inheriting from this class and overriding the following function:
    * `serialize`
    * `deserialize`

    However, since the defaults provide helpful functionality, other functions can be
    overriden in order to still utilize some of this default behavior.

    * `serialize_to_python` transforms an object into a form compatible with being written to json.

    *`deserialize_to_python` takes a parsed json object, and an expected type, and can then transform the object before being parsed to the appropriate type

    *`deserialize_to_target` takes a python object, and transforms it to the target type

    Caveats:
    - Dict baskets are not supported.
    """

    config: KafkaConfiguration
    requires: ChannelSelection | None = []
    publish_channel_to_topic_and_key: dict[str, dict[str, str]] = {}
    subscribe_channel_to_topic_and_key: dict[str, dict[str, str]] = {}

    publish_channel_processors: dict[str, KafkaChannelProcessor] = Field(
        default={},
        description=(
            "Dictionary mapping channel to KafkaChannelProcessor that "
            "performs a transformation on the incoming tick before publishing "
            "to Kafka. "
            "If the procesing function returns None for a tick, that tick is not published to Kafka"
        ),
    )
    publish_elements: bool = Field(
        default=False,
        description=(
            "Whether list-valued publish channels emit one Kafka message per element. Publish processors receive individual elements when enabled."
        ),
    )
    subscribe_channel_processors: dict[str, KafkaChannelProcessor] = Field(
        default={},
        description=(
            "Dictionary mapping channel to KafkaChannelProcessor processor that "
            "performs a transformation on the incoming tick before pushing the "
            "tick to the gateway. "
            "If the procesing function returns None for a tick, that tick is not pushed into the corresponding channel."
        ),
    )

    encoding_with_engine_timestamps: bool = Field(
        default=False,
        description=("Determines whether the encodings to and from Kafka include the csp engine timestamp."),
    )
    subscribe_with_csp_engine_timestamp: bool = Field(
        default=False,
        description=(
            "Determines whether the timestamp used when subscribing is the "
            "timestamp Kafka received the message, or the timestamp included on the encoding."
        ),
    )
    subscribe_with_struct_id: bool = Field(
        default=False,
        description=("If False, replaces the id field on GatewayStructs from Kafka with one autogenerated by the current Gateway."),
    )
    subscribe_with_struct_timestamp: bool = Field(
        default=False,
        description=("If False, replaces the timestamp field on the GatewayStruct with a timestamp autogenerated by the current Gateway."),
    )
    include_subscribe_messages_before_engine_start: bool = Field(
        default=False,
        description="Based on the Kafka offset, if Kafka messages are read in with timestamps before engine start time (either the Kafka timestamp or the message on the struct), whether these messages will get dropped or included in the graph. The default is False, only pulling in messages into the csp graph that are at or after the engine starttime. If True, these messages will be pulled in with timestamp equal to engine starttime.",
    )
    _kafkaadapter: csp.adapters.kafka.KafkaAdapterManager = PrivateAttr(default=None)

    @model_validator(mode="after")
    def check_parameters_consistent(self):
        if self.subscribe_with_csp_engine_timestamp and not self.encoding_with_engine_timestamps:
            raise ValueError("If `subscribe_with_csp_engine_timestamp` is True, you must set `encoding_with_engine_timestamp` to be True as well")
        return self

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._kafkaadapter = csp.adapters.kafka.KafkaAdapterManager(
            broker=self.config.broker,
            start_offset=self.config.start_offset,
            group_id=self.config.group_id,
            group_id_prefix=self.config.group_id_prefix,
            max_threads=self.config.max_threads,
            max_queue_size=self.config.max_queue_size,
            auth=self.config.auth,
            security_protocol=self.config.security_protocol,
            sasl_kerberos_keytab=str(self.config.sasl_kerberos_keytab),
            sasl_kerberos_principal=self.config.sasl_kerberos_principal,
            ssl_ca_location=str(self.config.ssl_ca_location),
            sasl_kerberos_service_name=self.config.sasl_kerberos_service_name,
            rd_kafka_conf_options=self.config.rd_kafka_conf_options,
            debug=self.config.debug,
            poll_timeout=self.config.poll_timeout,
        )

    def deserialize_to_python(self, obj: object, ts_typ: object) -> object:
        """Intercepts encoding from Kafka before conversion to to target type.
        This can be overwritten to implement custom logic to alter the object before it is passed onto the `deserialize_to_target` to create the csp struct
        """
        return obj

    def deserialize_to_target(self, obj: object, ts_typ: object) -> object:
        """Receives a python object loaded from json, and converts it to an object of type `ts_type`"""
        normalized_type = ContainerTypeNormalizer.normalize_type(ts_typ)
        is_list = get_origin(normalized_type) is list

        context = {}
        if not self.subscribe_with_struct_id:
            context["force_new_id"] = True
        if not self.subscribe_with_struct_timestamp:
            context["force_new_timestamp"] = True
        if is_list:
            inner_type = get_args(normalized_type)[0]
            type_adapter = inner_type.type_adapter()
            return [type_adapter.validate_python(v, context=context) for v in obj]
        return ts_typ.type_adapter().validate_python(obj, context=context)

    def deserialize(self, encoding: str, ts_typ: object):
        """Receives the encoded string from Kafka and
        deserializes it appropriately to convert into an object
        of type specified by `ts_typ`.
        """
        encoding_obj = orjson.loads(encoding)

        json_dict = self.deserialize_to_python(encoding_obj, ts_typ=ts_typ)

        return self.deserialize_to_target(json_dict, ts_typ=ts_typ)

    @deprecated(details="Use serialize_to_python instead.")
    def serialize_to_dict(self, x: Any) -> dict[str, Any]:
        """Serializes an object to a dictionary compatible with
        orjson for encoding to json."""
        return self.serialize_to_python(x)

    def serialize(self, x: Any) -> str:
        """Serializes an object to json"""
        encoding_for_orjson = self.serialize_to_python(x)
        return orjson.dumps(
            encoding_for_orjson,
            option=orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_NAIVE_UTC,
        ).decode()

    def serialize_to_python(self, obj: Any) -> Any:
        """Serializes an object to a format compatible with being transformed into json"""
        return _convert_orjson_compatible(obj)

    @csp.node
    def deserialize_csp(self, encoding: ts[str], ts_typ: "T") -> ts["T"]:  # noqa
        if csp.ticked(encoding):
            return self.deserialize(encoding, ts_typ)

    @csp.node
    def serialize_csp(self, x: ts[object]) -> ts[str]:
        return self.serialize(x)

    @csp.node
    def serialize_with_engine_timestamp_csp(self, x: ts[object]) -> ts[str]:
        return _encode_envelope(self.serialize(x), csp.now())

    def connect(self, channels: GatewayChannels):
        # Published messages are always written by us as raw text. Only the subscribe side of the
        # engine-timestamp path needs csp's JSON mapper, to read csp_timestamp back out for
        # tick_timestamp_from_field.
        if self.encoding_with_engine_timestamps:
            subscribe_msg_mapper = JSONTextMessageMapper(datetime_type=DateTimeType.UINT64_MILLIS)
            subscribe_ts_type = _EngineCycleEnvelope
            subscribe_field_map = {
                _ENVELOPE_ENCODING_FIELD: _ENVELOPE_ENCODING_FIELD,
                _ENVELOPE_TIMESTAMP_FIELD: _ENVELOPE_TIMESTAMP_FIELD,
            }
        else:
            subscribe_msg_mapper = RawTextMessageMapper()
            subscribe_ts_type = str
            subscribe_field_map = None

        for channel_name, topic_to_key in self.publish_channel_to_topic_and_key.items():
            channel = channels.get_channel(channel_name)
            channel_type = channels.get_outer_type(channel_name).typ
            normalized_type = ContainerTypeNormalizer.normalize_type(channel_type)

            publish_value = channel
            publish_type = channel_type
            if self.publish_elements and get_origin(normalized_type) is list:
                publish_type = get_args(normalized_type)[0]
                publish_value = csp.unroll(channel)

            channel_processor = self.publish_channel_processors.get(channel_name)

            for topic, key in topic_to_key.items():
                if channel_processor is not None:
                    raw_value = channel_processor.apply_process(publish_type, publish_value, topic, key)
                else:
                    raw_value = publish_value

                if self.encoding_with_engine_timestamps:
                    encoded_value = self.serialize_with_engine_timestamp_csp(raw_value)
                else:
                    encoded_value = self.serialize_csp(raw_value)
                self._kafkaadapter.publish(
                    msg_mapper=RawTextMessageMapper(),
                    topic=topic,
                    key=key,
                    x=encoded_value,
                )

        tick_timestamp_from_field = _ENVELOPE_TIMESTAMP_FIELD if self.subscribe_with_csp_engine_timestamp else None

        for (
            channel_name,
            topic_to_key,
        ) in self.subscribe_channel_to_topic_and_key.items():
            values_to_tick = []
            for topic, key in topic_to_key.items():
                sub = self._kafkaadapter.subscribe(
                    ts_type=subscribe_ts_type,
                    topic=topic,
                    msg_mapper=subscribe_msg_mapper,
                    key=key,
                    field_map=subscribe_field_map,
                    tick_timestamp_from_field=tick_timestamp_from_field,
                    adjust_out_of_order_time=True,
                    include_msg_before_start_time=self.include_subscribe_messages_before_engine_start,
                    push_mode=csp.PushMode.NON_COLLAPSING,
                )
                if self.encoding_with_engine_timestamps:
                    sub = sub.encoding
                channel_type = channels.get_outer_type(channel_name).typ
                deserialized_sub = self.deserialize_csp(encoding=sub, ts_typ=channel_type)
                channel_processor = self.subscribe_channel_processors.get(channel_name)

                if channel_processor is not None:
                    val_to_tick = channel_processor.apply_process(channel_type, deserialized_sub, topic, key)
                else:
                    val_to_tick = deserialized_sub
                values_to_tick.append(val_to_tick)

            channels.set_channel(
                channel_name,
                csp.flatten(values_to_tick),
            )

    def status(self) -> ts[Status]:
        """Returns a ticking edge of the Status updates from the underlying csp Kafka adapter."""
        return self._kafkaadapter.status()


class ReplayEngineKafka(EngineReplay):
    key: str = Field(
        description="""
        The key within a topic. Events published on the same topic with the same key go to the same partition.
        Kafka guarantees that any consumer of a given topic-partition will always read that
        partition's events in exactly the same order as they were written."""
    )
    topic: str = Field(description="Kafka topic")
    config: KafkaConfiguration
    _kafkaadapter: Any = PrivateAttr(default=None)

    # backwards compatibility, if the config is set make sure nothing from it is
    @model_validator(mode="before")
    @classmethod
    def validate_kafka(cls, values):
        config_fields = [
            "broker",
            "start_offset",
            "debug",
            "group_id",
            "group_id_prefix",
            "max_threads",
            "max_queue_size",
            "poll_timeout",
            "auth",
            "security_protocol",
            "sasl_kerberos_keytab",
            "sasl_kerberos_principal",
            "ssl_ca_location",
            "sasl_kerberos_service_name",
            "rd_kafka_conf_options",
        ]
        if "config" in values:
            if duplicate_values := [name for name in config_fields if name in values]:
                raise ValueError(f"Config is set, these attributes should be on the Config: {duplicate_values}")
        else:
            config_args = {}
            # we set the values on the config
            for field in config_fields:
                if field in values:
                    config_args[field] = values.pop(field)
            values["config"] = config_args
        return values

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._kafkaadapter = csp.adapters.kafka.KafkaAdapterManager(
            broker=self.config.broker,
            start_offset=self.config.start_offset,
            group_id=self.config.group_id,
            group_id_prefix=self.config.group_id_prefix,
            max_threads=self.config.max_threads,
            max_queue_size=self.config.max_queue_size,
            auth=self.config.auth,
            security_protocol=self.config.security_protocol,
            sasl_kerberos_keytab=str(self.config.sasl_kerberos_keytab),
            sasl_kerberos_principal=self.config.sasl_kerberos_principal,
            ssl_ca_location=str(self.config.ssl_ca_location),
            sasl_kerberos_service_name=self.config.sasl_kerberos_service_name,
            rd_kafka_conf_options=self.config.rd_kafka_conf_options,
            debug=self.config.debug,
            poll_timeout=self.config.poll_timeout,
        )

    @csp.node
    def _extract_encoding(self, message: ts[str]) -> ts[str]:
        if csp.ticked(message):
            return _decode_envelope(message).encoding

    @csp.node
    def _to_envelope(self, cycle: ts[EncodedEngineCycle]) -> ts[str]:
        if csp.ticked(cycle):
            return _encode_envelope(cycle.encoding, cycle.csp_timestamp)

    @override
    def subscribe(self):
        message = self._kafkaadapter.subscribe(
            ts_type=str,
            msg_mapper=RawTextMessageMapper(),
            topic=self.topic,
            key=self.key,
            push_mode=csp.PushMode.NON_COLLAPSING,
        )
        return self._extract_encoding(message)

    @override
    def publish(self, encoded_channels: ts[EncodedEngineCycle]):
        self._kafkaadapter.publish(
            msg_mapper=RawTextMessageMapper(),
            topic=self.topic,
            key=self.key,
            x=self._to_envelope(encoded_channels),
        )

    @override
    def status(self) -> ts[Status]:
        """Returns a ticking edge of the Status updates from the underlying csp Kafka adapter."""
        return self._kafkaadapter.status()
