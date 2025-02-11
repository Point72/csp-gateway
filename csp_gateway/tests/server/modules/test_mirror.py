import time
from datetime import datetime, timedelta
from unittest import mock

import csp
import orjson
import pytest

from csp_gateway import ReadWriteMode, State
from csp_gateway.server import (
    ChannelSelection,
    EncodedEngineCycle,
    Mirror,
    ReplayEngineJSON,
)
from csp_gateway.server.gateway.csp.channels import _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD
from csp_gateway.testing.shared_helpful_classes import (
    MyGateway,
    MyGatewayChannels,
    MySetModule,
    MyStruct,
)

from .kafka.test_kafka import create_kafka_engine_replay


@mock.patch("csp_gateway.ReplayEngineKafka", autospec=True)
def test_mirror_same_channels(mock_object):
    requires = ChannelSelection(include=["test_channel1"])
    selection = ChannelSelection(include=["test_channel2"])

    mirror = Mirror(mirror_source=mock_object, requires=requires, selection=selection)

    assert mirror.mirror_source.requires == requires
    assert mirror.mirror_source.selection == selection


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

    mirror = Mirror(
        mirror_source=kafka_engine_replay_write,
        selection=kafka_engine_replay_write.selection,
    )
    gateway_writing = MyGateway(modules=[setter, mirror, setter], channels=MyGatewayChannels())
    csp.run(gateway_writing.graph, starttime=datetime.utcnow(), endtime=timedelta(seconds=5))
    assert mock_publish.call_count == 0


@pytest.mark.parametrize("read_write_mode", [ReadWriteMode.WRITE, ReadWriteMode.READ])
def test_overwrite_json(read_write_mode, tmpdir):
    file = str(tmpdir.join("json_test_data.json"))
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    setup_json_module = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.WRITE,
    )
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    gateway = MyGateway(modules=[setup_json_module, setter], channels=MyGatewayChannels())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    with open(file, "r") as json_file:
        assert len(list(json_file)) == 1

    # start_writing doesnt matter since Mirror is only in READ mode
    json_module = ReplayEngineJSON(
        selection=channels,
        filename=file,
        start_writing=datetime(2020, 12, 12),
        read_write_mode=read_write_mode,
        overwrite_if_writing=True,
    )
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0), timedelta(days=365)),
        my_data2=csp.const(MyStruct(foo=2.0), timedelta(days=365)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)], timedelta(days=365)),
    )
    mirror = Mirror(mirror_source=json_module, selection=json_module.selection)
    new_gateway = MyGateway(modules=[mirror, setter], channels=MyGatewayChannels())
    csp.run(new_gateway.graph, starttime=datetime(2020, 1, 1))
    with open(file, "r") as json_file:
        items = list(json_file)
        assert len(items) == 1
        json_dict = orjson.loads(items[0])
        actual_date = datetime.fromisoformat(json_dict[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD]).replace(tzinfo=None)
        assert actual_date == datetime(2020, 1, 1)


@pytest.mark.parametrize("by_key", [True, False])
def test_mirror_state(by_key, tmpdir):
    file = str(tmpdir.join("json_test_data.json"))
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    setup_json_module = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.WRITE,
    )
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    gateway = MyGateway(modules=[setup_json_module, setter], channels=MyGatewayChannels())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    with open(file, "r") as json_file:
        assert len(list(json_file)) == 1

    json_module = ReplayEngineJSON(
        selection=channels,
        filename=file,
        start_writing=datetime(2020, 12, 12),
        read_write_mode=ReadWriteMode.READ,
        overwrite_if_writing=True,
    )
    state_channels = {
        MyGatewayChannels.my_channel: "id",
        MyGatewayChannels.my_list_channel: "id",
    }
    mirror = Mirror(
        mirror_source=json_module,
        selection=json_module.selection,
        state_channels=state_channels,
    )
    new_gateway = MyGateway(modules=[mirror], channels=MyGatewayChannels())
    new_gateway.start(block=False, realtime=True, rest=False, starttime=datetime(2020, 1, 1))
    try:
        time.sleep(0.5)
        state = new_gateway.channels.state("my_channel")
        assert isinstance(state, State)
        assert len(state.query()) == 1
        state = new_gateway.channels.state("my_list_channel")
        assert isinstance(state, State)
        assert len(state.query()) == 2
    finally:
        with mock.patch("os._exit"), mock.patch("os.kill"):
            new_gateway.stop()
