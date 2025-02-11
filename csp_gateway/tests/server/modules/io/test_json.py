from datetime import datetime, timedelta
from typing import Dict, Type

import csp
import orjson
import pytest
from csp import ts

from csp_gateway import (
    AddChannelsToGraphOutput,
    Channels,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewayStruct,
    ReadWriteMode,
    ReplayEngineJSON,
    State,
)
from csp_gateway.server.gateway.csp.channels import _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD
from csp_gateway.testing.shared_helpful_classes import (
    MyGateway,
    MyGatewayChannels,
    MySetModule,
    MyStruct,
)


class MyStrStruct(GatewayStruct):
    foo: str


class MySmallGatewayChannels(GatewayChannels):
    example: ts[int] = None
    struct_with_str: ts[MyStrStruct] = None
    s_example: ts[State[int]] = None
    my_str_basket: Dict[str, ts[float]] = None


class MySmallGateway(Gateway):
    channels_model: Type[Channels] = MySmallGatewayChannels


class MySetStrStructModule(GatewayModule):
    my_data: ts[MyStrStruct]

    def connect(self, channels: MySmallGatewayChannels) -> None:
        channels.set_channel(MySmallGatewayChannels.struct_with_str, self.my_data)


class MyReplayEngineJSON(ReplayEngineJSON):
    def dynamic_keys(self):
        return {MyGatewayChannels.my_str_basket: ["my_key", "my_key2"]}


class MyModuleTestSameTimeDifferentCycle(GatewayModule):
    my_data: ts[MyStruct]
    my_data2: ts[MyStruct]

    def connect(self, channels: MyGatewayChannels) -> None:
        # Build a set of inputs based on the test cases
        channels.set_channel(MyGatewayChannels.my_channel, self.my_data)
        my_list_data = csp.collect([self.my_data, self.my_data2])
        channels.set_channel(
            MyGatewayChannels.my_list_channel,
            my_list_data,
        )


@pytest.mark.parametrize("by_key", [True, False])
def test_json_module_output(tmpdir, by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    file = str(tmpdir.join("json_test_data.json"))
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    json_module = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.WRITE,
    )
    gateway_writing = MyGateway(modules=[setter, json_module, setter, setter], channels=MyGatewayChannels())
    csp.run(gateway_writing.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))

    json_module_read = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.READ,
        start_writing=datetime(2099, 1, 1),  # far in the future to never stop reading
    )
    gateway_reading = MyGateway(
        modules=[
            setter,
            json_module_read,
            AddChannelsToGraphOutput(selection=channels),
        ],
        channels=MyGatewayChannels(),
    )
    out = csp.run(gateway_reading.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    # TODO: encode/decode Numpy1DArray
    assert len(out["my_channel"]) == 4
    assert len(out["my_list_channel"]) == 4
    assert len(out["my_list_channel"][0][1]) == 2
    assert len(out["my_list_channel"][1][1]) == 2
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 4
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 4
    assert len(out["my_str_basket[my_key]"]) == 4
    assert len(out["my_str_basket[my_key2]"]) == 4
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 4
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 4


@pytest.mark.parametrize("by_key", [True, False])
def test_json_module_nested_directory(tmpdir, by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    file = str(tmpdir.join("/non_existent_dir/json_test_data.json"))
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    json_module = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.WRITE,
    )
    gateway_writing = MyGateway(modules=[setter, json_module, setter, setter], channels=MyGatewayChannels())
    csp.run(gateway_writing.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))

    json_module_read = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.READ,
        start_writing=datetime(2099, 1, 1),  # far in the future to never stop reading
    )
    gateway_reading = MyGateway(
        modules=[
            setter,
            json_module_read,
            AddChannelsToGraphOutput(selection=channels),
        ],
        channels=MyGatewayChannels(),
    )
    out = csp.run(gateway_reading.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    # TODO: encode/decode Numpy1DArray
    assert len(out["my_channel"]) == 4
    assert len(out["my_list_channel"]) == 4
    assert len(out["my_list_channel"][0][1]) == 2
    assert len(out["my_list_channel"][1][1]) == 2
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 4
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 4
    assert len(out["my_str_basket[my_key]"]) == 4
    assert len(out["my_str_basket[my_key2]"]) == 4
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 4
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 4


@pytest.mark.parametrize("by_key", [True, False])
def test_custom_json_module_output(tmpdir, by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    file = str(tmpdir.join("json_test_data.json"))
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    json_module = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.WRITE,
    )
    gateway_writing = MyGateway(modules=[setter, json_module, setter, setter], channels=MyGatewayChannels())
    csp.run(gateway_writing.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))

    # we can make our own custom ReplayEngineJSON class that specifies dynamic keys
    json_module_read = MyReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.READ,
        start_writing=datetime(2099, 1, 1),  # far in the future to never stop reading
    )
    gateway_reading = MyGateway(
        modules=[json_module_read, AddChannelsToGraphOutput(selection=channels)],
        channels=MyGatewayChannels(),
    )
    out = csp.run(gateway_reading.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    # TODO: encode/decode Numpy1DArray
    assert len(out["my_channel"]) == 3
    assert len(out["my_list_channel"]) == 3
    assert len(out["my_list_channel"][0][1]) == 2
    assert len(out["my_list_channel"][1][1]) == 2
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 3
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 3
    assert len(out["my_str_basket[my_key]"]) == 3
    assert len(out["my_str_basket[my_key2]"]) == 3
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 3
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 3


def test_json_module_output_diff_timestamp_tick(tmpdir):
    setter = MyModuleTestSameTimeDifferentCycle(
        my_data=csp.curve(
            MyStruct,
            [(timedelta(), MyStruct(foo=1.0)), (timedelta(), MyStruct(foo=3.0))],
        ),
        my_data2=csp.curve(
            MyStruct,
            [
                (timedelta(), MyStruct(foo=2.0)),
            ],
        ),
    )
    file = str(tmpdir.join("json_test_data.json"))
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
    ]
    json_module = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.WRITE,
    )
    gateway_writing = MyGateway(modules=[setter, json_module], channels=MyGatewayChannels())
    csp.run(gateway_writing.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))

    json_module_read = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.READ,
        start_writing=datetime(2099, 1, 1),  # far in the future to never stop reading
    )
    gateway_reading = MyGateway(
        modules=[json_module_read, AddChannelsToGraphOutput(selection=channels)],
        channels=MyGatewayChannels(),
    )
    out = csp.run(gateway_reading.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    # TODO: encode/decode Numpy1DArray
    assert len(out["my_channel"]) == 2
    assert len(out["my_list_channel"]) == 2
    assert len(out["my_list_channel"][0][1]) == 2
    # on the second tick of my_data, my_data2 does not
    # tick so our list is just of length 1
    assert len(out["my_list_channel"][1][1]) == 1
    assert out["my_list_channel"][1][1][0].foo == 3.0


def test_json_module_delimiter(tmpdir):
    file = str(tmpdir.join("json_test_data.json"))
    setter = MySetStrStructModule(my_data=csp.const(MyStrStruct(foo="\nis\nthe\ndelimiter\n")))
    json_module = ReplayEngineJSON(
        selection=[MySmallGatewayChannels.struct_with_str],
        filename=file,
        read_write_mode=ReadWriteMode.WRITE,
    )
    gateway_writing = MySmallGateway(modules=[setter, json_module], channels=MySmallGatewayChannels())
    csp.run(gateway_writing.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    json_module_read = ReplayEngineJSON(
        selection=[MySmallGatewayChannels.struct_with_str],
        filename=file,
        read_write_mode=ReadWriteMode.READ,
        start_writing=datetime(2099, 1, 1),  # far in the future to never stop reading
    )
    output_module = AddChannelsToGraphOutput(selection=[MySmallGatewayChannels.struct_with_str])
    gateway_reading = MySmallGateway(modules=[json_module_read, output_module], channels=MySmallGatewayChannels())
    out = csp.run(gateway_reading.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert out["struct_with_str"][0][1].foo == "\nis\nthe\ndelimiter\n"
    assert len(out["struct_with_str"]) == 1


@pytest.mark.parametrize("exclude", [True, False])
def test_json_module_all_channels(tmpdir, exclude):
    file = str(tmpdir.join("json_test_data.json"))
    my_struct = MyStrStruct(foo="|is|the|delimiter|", id="test")
    setter = MySetStrStructModule(my_data=csp.const(my_struct))
    json_module = ReplayEngineJSON(
        filename=file,
        read_write_mode=ReadWriteMode.WRITE,
    )
    gateway_writing = MySmallGateway(modules=[setter, json_module], channels=MySmallGatewayChannels())
    csp.run(gateway_writing.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    json_module_read = ReplayEngineJSON(
        selection=[MySmallGatewayChannels.struct_with_str],
        filename=file,
        read_write_mode=ReadWriteMode.READ,
        start_writing=datetime(2099, 1, 1),  # far in the future to never stop reading
    )
    if exclude:
        json_module_read.subscribe_with_struct_id = False
        json_module_read.subscribe_with_struct_timestamp = False
    output_module = AddChannelsToGraphOutput(selection=[MySmallGatewayChannels.struct_with_str])
    gateway_reading = MySmallGateway(modules=[json_module_read, output_module], channels=MySmallGatewayChannels())
    out = csp.run(gateway_reading.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert out["struct_with_str"][0][1].foo == "|is|the|delimiter|"
    assert len(out["struct_with_str"]) == 1
    if exclude:
        assert out["struct_with_str"][0][1].id != my_struct.id
        assert out["struct_with_str"][0][1].timestamp != my_struct.timestamp
    else:
        assert out["struct_with_str"][0][1].id == my_struct.id
        assert out["struct_with_str"][0][1].timestamp == my_struct.timestamp


@pytest.mark.parametrize("writing_start_type", ["datetime", "timedelta"])
def test_switch_automatically_to_write(writing_start_type, tmpdir):
    if writing_start_type == "datetime":
        start_writing = datetime(2020, 12, 12)
    elif writing_start_type == "timedelta":
        start_writing = timedelta(days=364)
    file = str(tmpdir.join("json_test_data.json"))
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    json_module = ReplayEngineJSON(
        selection=channels,
        filename=file,
        read_write_mode=ReadWriteMode.WRITE,
    )
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    gateway = MyGateway(modules=[json_module, setter], channels=MyGatewayChannels())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    with open(file, "r") as json_file:
        assert len(list(json_file)) == 1

    json_module_read_and_write = ReplayEngineJSON(selection=channels, filename=file, start_writing=start_writing)
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0), timedelta(days=365)),
        my_data2=csp.const(MyStruct(foo=2.0), timedelta(days=365)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)], timedelta(days=365)),
    )
    new_gateway = MyGateway(modules=[json_module_read_and_write, setter], channels=MyGatewayChannels())
    csp.run(new_gateway.graph, starttime=datetime(2020, 1, 1))
    with open(file, "r") as json_file:
        items = list(json_file)
        assert len(items) == 2
        json_dict_0 = orjson.loads(items[0])
        first_date = datetime.fromisoformat(json_dict_0[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD]).replace(tzinfo=None)
        assert first_date == datetime(2020, 1, 1)

        json_dict_1 = orjson.loads(items[1])
        second_date = datetime.fromisoformat(json_dict_1[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD]).replace(tzinfo=None)
        assert second_date == (datetime(2020, 1, 1) + timedelta(days=365))


@pytest.mark.parametrize("read_write_mode", [ReadWriteMode.READ_AND_WRITE, ReadWriteMode.READ])
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
    new_gateway = MyGateway(modules=[json_module, setter], channels=MyGatewayChannels())
    csp.run(new_gateway.graph, starttime=datetime(2020, 1, 1))
    with open(file, "r") as json_file:
        items = list(json_file)
        assert len(items) == 1
        json_dict = orjson.loads(items[0])
        actual_date = datetime.fromisoformat(json_dict[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD]).replace(tzinfo=None)

        if read_write_mode is ReadWriteMode.READ_AND_WRITE:
            assert actual_date == datetime(2020, 1, 1) + timedelta(days=365)
        elif read_write_mode is ReadWriteMode.READ:
            assert actual_date == datetime(2020, 1, 1)
        else:
            raise TypeError(f"read_write_mode should be a ReadWriteMode enum, got {read_write_mode}")
