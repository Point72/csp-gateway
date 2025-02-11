from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, List, Union
from unittest import mock

import csp
import numpy as np
import orjson
import pytest
from csp import ts
from csp.adapters.kafka import KafkaStartOffset as KafkaStartOffsetCsp
from csp.typing import Numpy1DArray
from pydantic import ValidationError

from csp_gateway import (
    AddChannelsToGraphOutput,
    ChannelSelection,
    EncodedEngineCycle,
    GatewayStruct,
    KafkaChannelProcessor,
    KafkaConfiguration,
    ReadWriteKafka,
    ReadWriteMode,
    ReplayEngineKafka,
)
from csp_gateway.testing.shared_helpful_classes import (
    MyGateway,
    MyGatewayChannels,
    MySetModule,
    MyStruct,
)


class MyNumpyStruct(MyStruct):
    arr: Numpy1DArray[float]


class MyGatewayChannelsWithNumpyStruct(MyGatewayChannels):
    my_numpy_struct_channel: ts[MyNumpyStruct] = None


class ProcessMyFlagTrue(KafkaChannelProcessor):
    def process(self, obj: Union[List[GatewayStruct], GatewayStruct], topic: str, key: str) -> Any:
        if isinstance(obj, list):
            return obj if all(getattr(val, "my_flag", False) is True for val in obj) else None
        return obj if getattr(obj, "my_flag", False) is True else None


class FloatKafkaChannelProcessor(KafkaChannelProcessor):
    goal_float: float
    key: str

    def process(self, obj: Union[List[GatewayStruct], GatewayStruct], topic: str, key: str) -> bool:
        if key == self.key:
            obj.foo = self.goal_float
            return obj
        return obj


def create_kafka_engine_replay(selection: ChannelSelection, read_write_mode: ReadWriteMode):
    broker = "kafka-broker:9093"
    topic = "topic_test"
    key = "test_kafka_gateway_module"
    config = KafkaConfiguration(broker=broker)
    return ReplayEngineKafka(
        selection=selection,
        config=config,
        topic=topic,
        key=key,
        read_write_mode=read_write_mode,
    )


def test_config_validation_fails():
    broker = "kafka-broker:9093"
    with pytest.raises(ValidationError):
        KafkaConfiguration(broker=broker, sasl_kerberos_keytab="Fake/location")


def test_config_pydantic_validation():
    broker = "kafka-broker:9093"
    for offset_name, val in KafkaStartOffsetCsp.__members__.items():
        config = KafkaConfiguration(broker=broker, start_offset=offset_name)
        assert config.start_offset.name == offset_name
        config = KafkaConfiguration(broker=broker, start_offset=val)
        assert config.start_offset.name == offset_name


@mock.patch("csp.adapters.kafka.KafkaAdapterManager", autospec=True)
@pytest.mark.parametrize("by_key", [True, False])
def test_kafka_engine_replay_write(mock_object, by_key):
    mock_publish = mock.MagicMock()
    mock_subscribe = mock.MagicMock()
    mock_object.return_value.subscribe = mock_subscribe
    mock_object.return_value.publish = mock_publish

    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    channels = MyGatewayChannels.fields()
    kafka_engine_replay_write = create_kafka_engine_replay(ChannelSelection.model_validate(channels), ReadWriteMode.WRITE)

    gateway_writing = MyGateway(
        modules=[setter, kafka_engine_replay_write, AddChannelsToGraphOutput()],
        channels=MyGatewayChannels(),
    )
    out = csp.run(gateway_writing.graph, starttime=datetime.utcnow(), endtime=timedelta(seconds=5))
    assert mock_publish.call_count == 1
    assert mock_subscribe.call_count == 0

    # Does not interfere with graph
    assert len(out["my_channel"]) == 1
    assert len(out["my_list_channel"]) == 1
    assert len(out["my_list_channel"][0][1]) == 2
    assert len(out["my_array_channel"]) == 1
    assert len(out["my_array_channel"][0][1]) == 2
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 1
    assert len(out["my_str_basket[my_key]"]) == 1
    assert len(out["my_str_basket[my_key2]"]) == 1
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 1
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 1
    assert len(out["my_str_basket[my_key]"]) == 1
    assert len(out["my_str_basket[my_key2]"]) == 1


@mock.patch("csp.adapters.kafka.KafkaAdapterManager", autospec=True)
@pytest.mark.parametrize("read_write_mode", [ReadWriteMode.READ, ReadWriteMode.READ_AND_WRITE])
def test_kafka_engine_replay_read_and_write_read(mock_object, read_write_mode):
    mock_publish = mock.MagicMock()

    def mock_subscribe(*a, **kw):
        return csp.null_ts(EncodedEngineCycle)

    mock_object.return_value.subscribe.side_effect = mock_subscribe
    mock_object.return_value.publish = mock_publish

    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    kafka_engine_replay_write = create_kafka_engine_replay(ChannelSelection.model_validate(channels), read_write_mode)

    gateway_writing = MyGateway(
        modules=[setter, kafka_engine_replay_write, setter],
        channels=MyGatewayChannels(),
    )
    csp.run(gateway_writing.graph, starttime=datetime.utcnow(), endtime=timedelta(seconds=5))
    if read_write_mode is ReadWriteMode.READ_AND_WRITE:
        assert mock_publish.call_count == 1
    else:
        assert mock_publish.call_count == 0


@mock.patch("csp.adapters.kafka.KafkaAdapterManager", autospec=True)
def test_kafka_read_write_fails_with_dict_basket(mock_object):
    mock_publish = mock.MagicMock()

    def mock_subscribe(*a, **kw):
        return csp.null_ts(EncodedEngineCycle)

    mock_object.return_value.subscribe.side_effect = mock_subscribe
    mock_object.return_value.publish = mock_publish

    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    broker = "kafka-broker:9093"
    config = KafkaConfiguration(broker=broker)

    kafka_writer = ReadWriteKafka(
        config=config,
        publish_channel_to_topic_and_key={
            MyGatewayChannels.my_channel: {"topic1": "key"},
            MyGatewayChannels.my_str_basket: {"topic1": "key2"},
            MyGatewayChannels.my_enum_basket: {"topic2": "key"},
        },
    )

    gateway_writing = MyGateway(
        modules=[setter, kafka_writer, setter],
        channels=MyGatewayChannels(),
    )
    with pytest.raises((TypeError, AttributeError)):
        csp.run(
            gateway_writing.graph,
            starttime=datetime.utcnow(),
            endtime=timedelta(seconds=5),
        )


@mock.patch("csp.adapters.kafka.KafkaAdapterManager", autospec=True)
@pytest.mark.parametrize("encoding_with_engine_timestamps", [True, False])
def test_kafka_read_write_read(mock_object, encoding_with_engine_timestamps, capsys):
    def mock_publish_action(*a, **kw):
        if kw["topic"] == "kafka_topic1" and kw["key"] == "kafka_key2":
            # If Kafka publishes to this key on this topic, we capture it
            # with a print statement.
            if encoding_with_engine_timestamps:
                csp.print("val_check", kw["x"].encoding)
            else:
                csp.print("val_check", kw["x"])

    mock_publish = mock.MagicMock(side_effect=mock_publish_action)
    # mock_publish = mock.MagicMock()

    def mock_subscribe(*a, **kw):
        return csp.null_ts(EncodedEngineCycle)

    mock_object.return_value.subscribe.side_effect = mock_subscribe
    mock_object.return_value.publish = mock_publish

    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    broker = "kafka-broker:9093"
    config = KafkaConfiguration(broker=broker)

    kafka_reader = ReadWriteKafka(
        config=config,
        publish_channel_to_topic_and_key={
            MyGatewayChannelsWithNumpyStruct.my_channel: {"kafka_topic1": "kafka_key"},
            MyGatewayChannelsWithNumpyStruct.my_array_channel: {"kafka_topic1": "kafka_key2"},
            MyGatewayChannelsWithNumpyStruct.my_numpy_struct_channel: {"kafka_topic2": "kafka_key"},
        },
        encoding_with_engine_timestamps=encoding_with_engine_timestamps,
    )

    gateway_writing = MyGateway(
        channels_model=MyGatewayChannelsWithNumpyStruct,
        modules=[setter, kafka_reader, setter],
        channels=MyGatewayChannelsWithNumpyStruct(),
    )
    csp.run(gateway_writing.graph, starttime=datetime.utcnow(), endtime=timedelta(seconds=5))
    calls = mock_publish.call_args_list
    topic_and_call_args = defaultdict(lambda *a, **kw: defaultdict(int))
    for call in calls:
        kwargs = call.kwargs
        key = kwargs["key"]
        topic = kwargs["topic"]
        topic_and_call_args["key"][key] += 1
        topic_and_call_args["topic"][topic] += 1

    assert topic_and_call_args["key"]["kafka_key"] == 2
    assert topic_and_call_args["key"]["kafka_key2"] == 1
    assert topic_and_call_args["topic"]["kafka_topic1"] == 2
    assert topic_and_call_args["topic"]["kafka_topic2"] == 1
    captured = capsys.readouterr()
    assert len(captured.out) > 0


@mock.patch("csp.adapters.kafka.KafkaAdapterManager", autospec=True)
def test_kafka_read_write_write(mock_object):
    mock_publish = mock.MagicMock()

    def mock_subscribe(*a, **kw):
        if kw["topic"] == "kafka_topic1" and kw["key"] == "kafka_key":
            encoding = orjson.dumps({"foo": 9.1}).decode()
            return csp.const(EncodedEngineCycle(encoding=encoding))
        elif kw["topic"] == "kafka_topic1" and kw["key"] == "kafka_key2":
            encoding = orjson.dumps([{"foo": 0.1}, {"my_flag": False}]).decode()
            return csp.const(EncodedEngineCycle(encoding=encoding), timedelta(seconds=1))
        elif kw["topic"] == "kafka_topic2" and kw["key"] == "kafka_key":
            encoding = orjson.dumps({"arr": [7.2, -1001.3]}).decode()
            return csp.const(EncodedEngineCycle(encoding=encoding), timedelta(seconds=1))
        else:
            raise ValueError("This should never be hit")

    mock_object.return_value.subscribe.side_effect = mock_subscribe
    mock_object.return_value.publish = mock_publish

    broker = "kafka-broker:9093"
    config = KafkaConfiguration(broker=broker)

    kafka_writer = ReadWriteKafka(
        config=config,
        subscribe_channel_to_topic_and_key={
            MyGatewayChannelsWithNumpyStruct.my_channel: {"kafka_topic1": "kafka_key"},
            MyGatewayChannelsWithNumpyStruct.my_list_channel: {"kafka_topic1": "kafka_key2"},
            MyGatewayChannelsWithNumpyStruct.my_numpy_struct_channel: {"kafka_topic2": "kafka_key"},
        },
    )

    gateway_writing = MyGateway(
        channels_model=MyGatewayChannelsWithNumpyStruct,
        modules=[kafka_writer, AddChannelsToGraphOutput()],
        channels=MyGatewayChannelsWithNumpyStruct(),
    )
    out = csp.run(gateway_writing.graph, starttime=datetime.utcnow(), endtime=timedelta(seconds=5))
    assert not mock_publish.call_args_list
    assert len(out[MyGatewayChannelsWithNumpyStruct.my_channel]) == 1
    assert out[MyGatewayChannelsWithNumpyStruct.my_channel][0][1].foo == 9.1

    assert len(out[MyGatewayChannelsWithNumpyStruct.my_list_channel]) == 1
    assert len(out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1]) == 2
    assert out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1][0].foo == 0.1
    assert out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1][1].my_flag is False

    assert len(out[MyGatewayChannelsWithNumpyStruct.my_numpy_struct_channel]) == 1
    my_numpy_struct = out[MyGatewayChannelsWithNumpyStruct.my_numpy_struct_channel][0][1]
    np.testing.assert_array_almost_equal(my_numpy_struct.arr, np.array([7.2, -1001.3]))


@mock.patch("csp.adapters.kafka.KafkaAdapterManager", autospec=True)
@pytest.mark.parametrize("use_struct_id", [True, False])
@pytest.mark.parametrize("use_struct_timestamp", [True, False])
def test_kafka_read_write_write_overwrite_id_timestamp(mock_object, use_struct_id, use_struct_timestamp):
    mock_publish = mock.MagicMock()

    def mock_subscribe(*a, **kw):
        if kw["topic"] == "kafka_topic1" and kw["key"] == "kafka_key":
            encoding = orjson.dumps({"foo": 9.1, "id": "howdy"}).decode()
            return csp.const(EncodedEngineCycle(encoding=encoding))
        elif kw["topic"] == "kafka_topic1" and kw["key"] == "kafka_key2":
            encoding = orjson.dumps([{"foo": 0.1, "timestamp": datetime(2021, 1, 1)}, {"my_flag": False}]).decode()
            return csp.const(EncodedEngineCycle(encoding=encoding), timedelta(seconds=1))
        else:
            raise ValueError("This should never be hit")

    mock_object.return_value.subscribe.side_effect = mock_subscribe
    mock_object.return_value.publish = mock_publish

    broker = "kafka-broker:9093"
    config = KafkaConfiguration(broker=broker)

    kafka_writer = ReadWriteKafka(
        config=config,
        subscribe_with_struct_id=use_struct_id,
        subscribe_with_struct_timestamp=use_struct_timestamp,
        subscribe_channel_to_topic_and_key={
            MyGatewayChannelsWithNumpyStruct.my_channel: {"kafka_topic1": "kafka_key"},
            MyGatewayChannelsWithNumpyStruct.my_list_channel: {"kafka_topic1": "kafka_key2"},
        },
    )

    gateway_writing = MyGateway(
        channels_model=MyGatewayChannelsWithNumpyStruct,
        modules=[kafka_writer, AddChannelsToGraphOutput()],
        channels=MyGatewayChannelsWithNumpyStruct(),
    )
    out = csp.run(gateway_writing.graph, starttime=datetime.utcnow(), endtime=timedelta(seconds=5))
    assert not mock_publish.call_args_list
    assert len(out[MyGatewayChannelsWithNumpyStruct.my_channel]) == 1
    assert out[MyGatewayChannelsWithNumpyStruct.my_channel][0][1].foo == 9.1
    if use_struct_id:
        assert out[MyGatewayChannelsWithNumpyStruct.my_channel][0][1].id == "howdy"
    else:
        assert out[MyGatewayChannelsWithNumpyStruct.my_channel][0][1].id != "howdy"

    assert len(out[MyGatewayChannelsWithNumpyStruct.my_list_channel]) == 1
    assert len(out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1]) == 2
    assert out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1][0].foo == 0.1
    if use_struct_timestamp:
        assert out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1][0].timestamp == datetime(2021, 1, 1)
    else:
        # this is in the future, so we know the datetime is past the current date
        assert out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1][0].timestamp > datetime(2023, 1, 1)
    assert out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1][1].my_flag is False


@mock.patch("csp.adapters.kafka.KafkaAdapterManager", autospec=True)
@pytest.mark.parametrize("my_flag", [True, False])
def test_kafka_read_write_filter_write(mock_object, my_flag):
    mock_publish = mock.MagicMock()

    def mock_subscribe(*a, **kw):
        if kw["topic"] == "kafka_topic1" and kw["key"] == "kafka_key":
            encoding = orjson.dumps({"foo": 9.1}).decode()
            return csp.const(EncodedEngineCycle(encoding=encoding))
        elif kw["topic"] == "kafka_topic1" and kw["key"] == "kafka_key2":
            encoding = orjson.dumps([{"foo": 0.1}, {"my_flag": my_flag}]).decode()
            return csp.const(EncodedEngineCycle(encoding=encoding), timedelta(seconds=1))
        elif kw["topic"] == "kafka_topic2" and kw["key"] == "kafka_key":
            encoding = orjson.dumps({"arr": [7.2, -1001.3]}).decode()
            return csp.const(EncodedEngineCycle(encoding=encoding), timedelta(seconds=1))
        else:
            raise ValueError("This should never be hit")

    mock_object.return_value.subscribe.side_effect = mock_subscribe
    mock_object.return_value.publish = mock_publish

    broker = "kafka-broker:9093"
    config = KafkaConfiguration(broker=broker)

    my_list_channel_processor = ProcessMyFlagTrue()
    kafka_writer = ReadWriteKafka(
        config=config,
        subscribe_channel_to_topic_and_key={
            MyGatewayChannelsWithNumpyStruct.my_channel: {"kafka_topic1": "kafka_key"},
            MyGatewayChannelsWithNumpyStruct.my_list_channel: {"kafka_topic1": "kafka_key2"},
            MyGatewayChannelsWithNumpyStruct.my_numpy_struct_channel: {"kafka_topic2": "kafka_key"},
        },
        subscribe_channel_processors={MyGatewayChannelsWithNumpyStruct.my_list_channel: my_list_channel_processor},
    )

    gateway_writing = MyGateway(
        channels_model=MyGatewayChannelsWithNumpyStruct,
        modules=[kafka_writer, AddChannelsToGraphOutput()],
        channels=MyGatewayChannelsWithNumpyStruct(),
    )
    out = csp.run(gateway_writing.graph, starttime=datetime.utcnow(), endtime=timedelta(seconds=5))
    assert not mock_publish.call_args_list
    assert len(out[MyGatewayChannelsWithNumpyStruct.my_channel]) == 1
    assert out[MyGatewayChannelsWithNumpyStruct.my_channel][0][1].foo == 9.1

    # in `my_list_channel` structs get filtered out if `my_flag` is set to
    # False.
    if not my_flag:
        assert len(out[MyGatewayChannelsWithNumpyStruct.my_list_channel]) == 0
    else:
        assert len(out[MyGatewayChannelsWithNumpyStruct.my_list_channel]) == 1
        assert len(out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1]) == 2
        assert out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1][0].foo == 0.1
        assert out[MyGatewayChannelsWithNumpyStruct.my_list_channel][0][1][1].my_flag is True

    assert len(out[MyGatewayChannelsWithNumpyStruct.my_numpy_struct_channel]) == 1
    my_numpy_struct = out[MyGatewayChannelsWithNumpyStruct.my_numpy_struct_channel][0][1]
    np.testing.assert_array_almost_equal(my_numpy_struct.arr, np.array([7.2, -1001.3]))


@mock.patch("csp.adapters.kafka.KafkaAdapterManager", autospec=True)
@pytest.mark.parametrize("encoding_with_engine_timestamps", [True, False])
@pytest.mark.parametrize("filter_key", ["kafka_key", "non_existent_key"])
def test_kafka_read_write_filter_read(mock_object, encoding_with_engine_timestamps, filter_key, capsys):
    def mock_publish_action(*a, **kw):
        if kw["topic"] == "kafka_topic1" and kw["key"] == "kafka_key":
            # If Kafka publishes to this key on this topic, we capture it
            # with a print statement.
            if encoding_with_engine_timestamps:
                csp.print("val_check", kw["x"].encoding)
            else:
                csp.print("val_check", kw["x"])

    mock_publish = mock.MagicMock(side_effect=mock_publish_action)

    def mock_subscribe(*a, **kw):
        return csp.null_ts(EncodedEngineCycle)

    mock_object.return_value.subscribe.side_effect = mock_subscribe
    mock_object.return_value.publish = mock_publish

    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=99.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    broker = "kafka-broker:9093"
    config = KafkaConfiguration(broker=broker)

    my_channel_processor = FloatKafkaChannelProcessor(goal_float=1.0, key=filter_key)

    kafka_writer = ReadWriteKafka(
        config=config,
        publish_channel_to_topic_and_key={
            MyGatewayChannelsWithNumpyStruct.my_channel: {"kafka_topic1": "kafka_key"},
            MyGatewayChannelsWithNumpyStruct.my_array_channel: {"kafka_topic1": "kafka_key2"},
            MyGatewayChannelsWithNumpyStruct.my_numpy_struct_channel: {"kafka_topic2": "kafka_key"},
        },
        publish_channel_processors={MyGatewayChannelsWithNumpyStruct.my_channel: my_channel_processor},
        encoding_with_engine_timestamps=encoding_with_engine_timestamps,
    )

    gateway_writing = MyGateway(
        channels_model=MyGatewayChannelsWithNumpyStruct,
        modules=[setter, kafka_writer, setter],
        channels=MyGatewayChannelsWithNumpyStruct(),
    )
    csp.run(gateway_writing.graph, starttime=datetime.utcnow(), endtime=timedelta(seconds=5))
    calls = mock_publish.call_args_list
    topic_and_call_args = defaultdict(lambda *a, **kw: defaultdict(int))
    for call in calls:
        kwargs = call.kwargs
        key = kwargs["key"]
        topic = kwargs["topic"]
        topic_and_call_args["key"][key] += 1
        topic_and_call_args["topic"][topic] += 1

    assert topic_and_call_args["key"]["kafka_key"] == 2
    assert topic_and_call_args["key"]["kafka_key2"] == 1
    assert topic_and_call_args["topic"]["kafka_topic1"] == 2
    assert topic_and_call_args["topic"]["kafka_topic2"] == 1
    captured = capsys.readouterr()
    if filter_key == "kafka_key":
        assert captured.out.count('"foo":1.0') == 2
        assert captured.out.count('"foo":99.0') == 0
    else:
        assert captured.out.count('"foo":1.0') == 0
        assert captured.out.count('"foo":99.0') == 2
