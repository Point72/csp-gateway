from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List, Optional, Tuple, Type

import csp
import orjson
import pytest
from csp import ts
from pydantic import GetPydanticSchema, PrivateAttr
from pydantic_core import core_schema

from csp_gateway import (
    AddChannelsToGraphOutput,
    Channels,
    ChannelSelection,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewayStruct,
    JSONConverter,
)
from csp_gateway.server.gateway.csp.channels import _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD
from csp_gateway.server.shared.json_converter import (
    ChannelValueModel as CVM,
    _convert_orjson_compatible,
    _create_snapshot_dict,
)
from csp_gateway.testing.shared_helpful_classes import (
    MyEnum,
    MyGateway,
    MyGatewayChannels,
    MySetModule,
    MyStruct,
)


class MysteryClass: ...


# This is an example on how to annotate a new, custom class, for validation and ser/der via pydantic
# GatewayStructs will pick this up and allow users to use their own defined serializtion and deserialization
ValidatedMysteryClass = Annotated[
    MysteryClass,  # our own special class Pydantic is not aware of
    GetPydanticSchema(
        lambda tp, handler: core_schema.no_info_before_validator_function(
            lambda x: MysteryClass() if x == "A" else "SHOULD_NEVER_HIT",
            schema=core_schema.any_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda x: "A", info_arg=False, return_schema=core_schema.str_schema(), when_used="json"
            ),  # this defines how to serialize the class. This will be used for serialization to str, such as for saving to json
        )  # outer level definition of schema, here, we say that "the schema can be anything, but before you apply the schema, run this validator function"
    ),
]


class MyPrivateAttrStruct(MyStruct):
    _private: str = "unset"


class MySelectiveSetModule(GatewayModule):
    requires: Optional[ChannelSelection] = []
    my_data: ts[MyStruct]
    my_data2: ts[MyStruct]
    my_list_data: ts[List[MyStruct]]
    by_key: bool = True

    def dynamic_keys(self):
        return {MyGatewayChannels.my_str_basket: ["my_key", "my_key2"]}

    def connect(self, channels: MyGatewayChannels) -> None:
        # Build a set of inputs based on the test cases
        channels.set_channel(MyGatewayChannels.my_channel, self.my_data)
        channels.set_channel(
            MyGatewayChannels.my_list_channel,
            self.my_list_data,
        )
        channels.add_send_channel(MyGatewayChannels.my_channel)
        channels.set_state(MyGatewayChannels.my_channel, "id")
        channels.add_send_channel(MyGatewayChannels.my_list_channel)
        channels.set_state(MyGatewayChannels.my_list_channel, "id")

        if self.by_key:
            channels.set_channel(MyGatewayChannels.my_enum_basket, self.my_data, MyEnum.ONE)
            channels.set_channel(MyGatewayChannels.my_enum_basket, self.my_data2, MyEnum.TWO)
            channels.set_channel(MyGatewayChannels.my_str_basket, self.my_data, "my_key")
            channels.set_channel(MyGatewayChannels.my_str_basket, self.my_data2, "my_key2")
        else:
            channels.set_channel(
                MyGatewayChannels.my_enum_basket,
                {
                    MyEnum.ONE: self.my_data,
                    MyEnum.TWO: self.my_data2,
                },
            )
            channels.set_channel(
                MyGatewayChannels.my_str_basket,
                {
                    "my_key": self.my_data,
                    "my_key2": self.my_data2,
                },
            )


class MyCustomStruct(GatewayStruct):
    mystery_val: List[ValidatedMysteryClass]


class MyFatPipeChannels(MyGatewayChannels):
    fat_pipe: ts[str] = None
    custom_struct: ts[MyCustomStruct] = None


class SetMysteryClassModule(GatewayModule):
    custom_struct: ts[MyCustomStruct]

    def connect(self, channels):
        channels.set_channel(MyFatPipeChannels.custom_struct, self.custom_struct)


class MyFatPipeChannelsGateway(Gateway):
    channels_model: Type[Channels] = MyFatPipeChannels


class MyFatPipeSetter(GatewayModule):
    to_fat_pipe: ts[str]

    def connect(self, channels: MyFatPipeChannels):
        channels.set_channel(MyFatPipeChannels.fat_pipe, self.to_fat_pipe)


class MyJsonEncoder(GatewayModule):
    requires: Optional[ChannelSelection] = []
    channels_list: List[str]
    _dict_basket_keys: Dict[str, Any] = PrivateAttr(default=None)

    def dynamic_keys(self):
        self._dict_basket_keys = {
            MyGatewayChannels.my_str_basket: ["my_key", "my_key2"],
            MyGatewayChannels.my_enum_basket: list(MyEnum),
            MyGatewayChannels.my_enum_basket_list: list(MyEnum),
        }
        return self._dict_basket_keys

    def connect(self, channels: MyGatewayChannels):
        json_connector = JSONConverter(
            decode_channels=self.channels_list,
            encode_channels=self.channels_list,
            channels=channels,
        )

        csp.add_graph_output("encoded_snapshot_model", json_connector.encode())


class MyJsonDecoder(GatewayModule):
    requires: Optional[ChannelSelection] = []
    channels_list: List[str]
    _dict_basket_keys: Dict[str, Any] = PrivateAttr(default=None)
    flag_updates: Dict[str, List[Tuple[str, bool]]] = None

    def dynamic_keys(self):
        self._dict_basket_keys = {
            MyFatPipeChannels.my_str_basket: ["my_key", "my_key2"],
            MyFatPipeChannels.my_enum_basket: list(MyEnum),
            MyFatPipeChannels.my_enum_basket_list: list(MyEnum),
        }
        return self._dict_basket_keys

    def connect(self, channels: MyFatPipeChannels):
        json_connector = JSONConverter(
            decode_channels=self.channels_list,
            encode_channels=self.channels_list,
            channels=channels,
            flag_updates=self.flag_updates or {},
        )
        json_connector.decode(channels.get_channel(MyFatPipeChannels.fat_pipe))


class MyJsonEncoderDecoder(GatewayModule):
    requires: Optional[ChannelSelection] = []
    decode_channels: List[str]
    encode_channels: List[str]
    _dict_basket_keys: Dict[str, Any] = PrivateAttr(default=None)
    flag_updates: Dict[str, List[Tuple[str, bool]]] = None
    encode: bool

    def dynamic_keys(self):
        self._dict_basket_keys = {
            MyFatPipeChannels.my_str_basket: ["my_key", "my_key2"],
            MyFatPipeChannels.my_enum_basket: list(MyEnum),
            MyFatPipeChannels.my_enum_basket_list: list(MyEnum),
        }
        return self._dict_basket_keys

    def connect(self, channels: MyFatPipeChannels):
        json_connector = JSONConverter(
            decode_channels=self.decode_channels,
            encode_channels=self.encode_channels,
            channels=channels,
            flag_updates=self.flag_updates or {},
        )
        if self.encode:
            csp.add_graph_output("encoded_snapshot_model", json_connector.encode())
        else:
            json_connector.decode(channels.get_channel(MyFatPipeChannels.fat_pipe))


class MyJsonChecker(GatewayModule):
    requires: Optional[ChannelSelection] = []
    timestamp: datetime

    @csp.node
    def check_time(self, t: ts[datetime]) -> ts[bool]:
        if csp.ticked(t):
            return t == self.timestamp

    def connect(self, channels: MyFatPipeChannels):
        struct = channels.get_channel(MyFatPipeChannels.my_channel)
        csp.add_graph_output("engine_times_align", self.check_time(csp.times(struct)))


# This function is tested and used in other tests so it was factored out
def create_snapshot_dict(timestamp, dummy_id):
    channel_values_list = [
        CVM(
            channel=MyGatewayChannels.my_channel,
            value=MyStruct(foo=3.0, timestamp=timestamp, id=dummy_id),
            timestamp=timestamp,
        ),
        CVM(
            channel=MyGatewayChannels.my_list_channel,
            value=[
                MyStruct(foo=4.0, timestamp=timestamp, id=dummy_id),
                MyStruct(foo=5.0, timestamp=timestamp, id=dummy_id),
            ],
            timestamp=timestamp,
        ),
        CVM(
            channel=MyGatewayChannels.my_enum_basket,
            value=MyStruct(foo=6.0, timestamp=timestamp, id=dummy_id),
            dict_basket_key=MyEnum.ONE,
            timestamp=timestamp,
        ),
        CVM(
            channel=MyGatewayChannels.my_enum_basket,
            value=MyStruct(foo=7.0, timestamp=timestamp, id=dummy_id),
            dict_basket_key=MyEnum.TWO,
            timestamp=timestamp,
        ),
        CVM(
            channel=MyGatewayChannels.my_str_basket,
            value=MyStruct(foo=8.0, timestamp=timestamp, id=dummy_id),
            dict_basket_key="key1",
            timestamp=timestamp,
        ),
        CVM(
            channel=MyGatewayChannels.my_str_basket,
            value=MyStruct(foo=9.0, timestamp=timestamp, id=dummy_id),
            dict_basket_key="key2",
            timestamp=timestamp,
        ),
        CVM(
            channel=MyGatewayChannels.my_enum_basket_list,
            value=[
                MyStruct(foo=10.0, timestamp=timestamp, id=dummy_id),
                MyStruct(foo=11.0, timestamp=timestamp, id=dummy_id),
            ],
            dict_basket_key=MyEnum.ONE,
            timestamp=timestamp,
        ),
    ]
    snapshot_dict = _create_snapshot_dict(channel_values_list)
    return snapshot_dict


def test_convert_orjson_compatible():
    gateway_struct_list = [MyStruct(foo=3.0, time=timedelta(days=4, microseconds=11)), MyStruct(foo=2.9)]
    pydantic_list = _convert_orjson_compatible(gateway_struct_list)
    for pydantic_x, x in zip(pydantic_list, gateway_struct_list):
        target = x.type_adapter().dump_python(x, mode="json")
        target["timestamp"] = datetime.fromisoformat(target["timestamp"])
        assert pydantic_x == target
    # To avoid json encoding issues with these custom enum types
    # _convert_orjson_compatible converts them to their name for encoding
    enum = MyEnum.ONE
    assert _convert_orjson_compatible(enum) == enum.name

    my_str = "hai"
    assert _convert_orjson_compatible(my_str) == my_str


def test_parse_snapshot_dict():
    timestamp = datetime(2020, 1, 1)
    dummy_id = "9"
    snapshot_dict = create_snapshot_dict(timestamp, dummy_id)
    decoded_obj = MyGatewayChannels._snapshot_model.model_validate(snapshot_dict)

    assert decoded_obj.my_list_channel == [
        MyStruct(foo=4.0, timestamp=timestamp, id=dummy_id),
        MyStruct(foo=5.0, timestamp=timestamp, id=dummy_id),
    ]
    assert decoded_obj.my_channel == MyStruct(foo=3.0, timestamp=timestamp, id=dummy_id)
    assert decoded_obj.my_enum_basket[MyEnum.ONE] == MyStruct(foo=6.0, timestamp=timestamp, id=dummy_id)
    assert decoded_obj.my_enum_basket[MyEnum.TWO] == MyStruct(foo=7.0, timestamp=timestamp, id=dummy_id)
    assert decoded_obj.my_str_basket["key1"] == MyStruct(foo=8.0, timestamp=timestamp, id=dummy_id)
    assert decoded_obj.my_str_basket["key2"] == MyStruct(foo=9.0, timestamp=timestamp, id=dummy_id)
    assert decoded_obj.my_enum_basket_list[MyEnum.ONE] == [
        MyStruct(foo=10.0, timestamp=timestamp, id=dummy_id),
        MyStruct(foo=11.0, timestamp=timestamp, id=dummy_id),
    ]


def test_parse_snapshot_dict_with_private_fields():
    class MyPrivateAttrGatewayChannels(GatewayChannels):
        my_channel: ts[MyPrivateAttrStruct] = None

    channel_values_list = [
        CVM(
            channel=MyPrivateAttrGatewayChannels.my_channel,
            value=MyPrivateAttrStruct(foo=3.0, _private="howdy"),
            timestamp=datetime(2020, 1, 1),
        )
    ]
    snapshot_dict = _create_snapshot_dict(channel_values_list)
    assert "_private" not in snapshot_dict[MyPrivateAttrGatewayChannels.my_channel]

    # When we decode to csp, the underscore field comes back and is set to its default value
    snapshot_model = MyPrivateAttrGatewayChannels._snapshot_model.model_validate(snapshot_dict)
    assert snapshot_model.my_channel._private == "unset"


# NOTE: This test relies on the format of the json encoding to not change
def test_json_snapshot():
    timestamp = datetime(2020, 1, 1)
    dummy_id = "9"
    snapshot_dict = create_snapshot_dict(timestamp, dummy_id)
    model = MyGatewayChannels._snapshot_model.model_validate(snapshot_dict)
    target = '{"my_channel":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":3.0,"my_flag":true},"my_list_channel":[{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":4.0,"my_flag":true},{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":5.0,"my_flag":true}],"my_enum_basket":{"ONE":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":6.0,"my_flag":true},"TWO":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":7.0,"my_flag":true}},"my_str_basket":{"key1":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":8.0,"my_flag":true},"key2":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":9.0,"my_flag":true}},"my_enum_basket_list":{"ONE":[{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":10.0,"my_flag":true},{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":11.0,"my_flag":true}]},"csp_engine_timestamp":"2020-01-01T00:00:00+00:00"}'  # noqa
    target = target.replace("+00:00", "")
    print(model.model_dump_json())
    assert orjson.loads(model.model_dump_json()) == orjson.loads(target)


# NOTE: This test relies on the format of the json encoding to not change
def test_parse_snapshot_json():
    timestamp = datetime(2020, 1, 1, 5, tzinfo=timezone(timedelta(hours=5)))
    dummy_id = "9"
    snapshot_str = '{"my_channel":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":3.0},"my_list_channel":[{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":4.0},{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":5.0}],"my_enum_basket":{"ONE":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":6.0},"TWO":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":7.0}},"my_str_basket":{"key1":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":8.0},"key2":{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":9.0}},"my_enum_basket_list":{"ONE":[{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":10.0},{"id":"9","timestamp":"2020-01-01T00:00:00+00:00","foo":11.0}]}}'  # noqa: E501
    model = MyGatewayChannels._snapshot_model.model_validate_json(snapshot_str)
    exp_model = MyGatewayChannels._snapshot_model(
        my_channel=MyStruct(foo=3.0, timestamp=timestamp, id=dummy_id),
        my_list_channel=[
            MyStruct(foo=4.0, timestamp=timestamp, id=dummy_id),
            MyStruct(foo=5.0, timestamp=timestamp, id=dummy_id),
        ],
        my_enum_basket={
            MyEnum.ONE: MyStruct(foo=6.0, timestamp=timestamp, id=dummy_id),
            MyEnum.TWO: MyStruct(foo=7.0, timestamp=timestamp, id=dummy_id),
        },
        my_str_basket={
            "key1": MyStruct(foo=8.0, timestamp=timestamp, id=dummy_id),
            "key2": MyStruct(foo=9.0, timestamp=timestamp, id=dummy_id),
        },
        my_enum_basket_list={
            MyEnum.ONE: [
                MyStruct(foo=10.0, timestamp=timestamp, id=dummy_id),
                MyStruct(foo=11.0, timestamp=timestamp, id=dummy_id),
            ]
        },
    )
    # The models align once we get back to the csp version of the structs
    assert model.my_channel == exp_model.my_channel
    assert model.my_list_channel == exp_model.my_list_channel
    assert model.my_str_basket["key1"] == exp_model.my_str_basket["key1"]
    assert model.my_str_basket["key2"] == exp_model.my_str_basket["key2"]
    assert model.my_enum_basket[MyEnum.ONE] == exp_model.my_enum_basket[MyEnum.ONE]
    assert model.my_enum_basket[MyEnum.TWO] == exp_model.my_enum_basket[MyEnum.TWO]
    assert model.my_enum_basket_list[MyEnum.ONE] == exp_model.my_enum_basket_list[MyEnum.ONE]


@pytest.mark.parametrize("by_key", [True, False])
def test_encode(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0, time=timedelta(days=4, microseconds=11))),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    json_encoder = MyJsonEncoder(channels_list=channels)
    gateway = MyGateway(modules=[setter, json_encoder], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    encoded_snapshot_model = out["encoded_snapshot_model"][0][1]
    snapshot_model = MyGatewayChannels._snapshot_model.model_validate_json(encoded_snapshot_model.encoding)
    assert snapshot_model.my_channel.foo == 1.0
    assert snapshot_model.my_channel.time == timedelta(days=4, microseconds=11)
    assert snapshot_model.my_list_channel[1].foo == 2.0
    assert snapshot_model.my_str_basket["my_key"].foo == 1.0
    assert snapshot_model.my_str_basket["my_key2"].foo == 2.0
    assert snapshot_model.my_enum_basket[MyEnum.ONE].foo == 1.0
    assert snapshot_model.my_enum_basket[MyEnum.TWO].foo == 2.0
    assert snapshot_model.my_enum_basket_list[MyEnum.ONE] == snapshot_model.my_enum_basket_list[MyEnum.TWO]


@pytest.mark.parametrize("by_key", [True, False])
def test_encode_filter_channels(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    channels = list(MyGatewayChannels.model_fields.keys())
    assert MyGatewayChannels.s_my_channel in channels
    assert MyGatewayChannels.my_array_channel in channels
    json_encoder = MyJsonEncoder(channels_list=channels)
    gateway = MyGateway(modules=[setter, json_encoder], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    encoded_snapshot_model = out["encoded_snapshot_model"][0][1]
    snapshot_model = MyGatewayChannels._snapshot_model.model_validate_json(encoded_snapshot_model.encoding)
    assert snapshot_model.my_channel.foo == 1.0
    assert snapshot_model.my_list_channel[1].foo == 2.0
    assert snapshot_model.my_str_basket["my_key"].foo == 1.0
    assert snapshot_model.my_str_basket["my_key2"].foo == 2.0
    assert snapshot_model.my_enum_basket[MyEnum.ONE].foo == 1.0
    assert snapshot_model.my_enum_basket[MyEnum.TWO].foo == 2.0
    assert snapshot_model.my_enum_basket_list[MyEnum.ONE] == snapshot_model.my_enum_basket_list[MyEnum.TWO]
    assert MyGatewayChannels.s_my_channel not in snapshot_model.model_fields
    assert getattr(snapshot_model, _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD) == datetime(2020, 1, 1)


@pytest.mark.parametrize("by_key", [True, False])
def test_encode_twice_same_timestamp(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=3.0), MyStruct(foo=9.0)]),
        by_key=by_key,
    )
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    json_encoder = MyJsonEncoder(channels_list=channels)
    gateway = MyGateway(modules=[setter, setter, json_encoder], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    assert len(out) == 1
    assert len(out["encoded_snapshot_model"]) == 2
    assert out["encoded_snapshot_model"][0][0] == out["encoded_snapshot_model"][1][0]

    for _, encoding in out["encoded_snapshot_model"]:
        snapshot_model = MyGatewayChannels._snapshot_model.model_validate_json(encoding.encoding)
        assert snapshot_model.my_channel.foo == 1.0
        assert snapshot_model.my_list_channel[1].foo == 9.0
        assert snapshot_model.my_str_basket["my_key"].foo == 1.0
        assert snapshot_model.my_str_basket["my_key2"].foo == 2.0
        assert snapshot_model.my_enum_basket[MyEnum.ONE].foo == 1.0
        assert snapshot_model.my_enum_basket[MyEnum.TWO].foo == 2.0
        assert snapshot_model.my_enum_basket_list[MyEnum.ONE] == snapshot_model.my_enum_basket_list[MyEnum.TWO]


@pytest.mark.parametrize("by_key", [True, False])
def test_encode_decode(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    raw_custom_struct = MyCustomStruct.type_adapter().validate_python(dict(mystery_val=["A", "A"]))  # must be A for serialization
    setter_mystery = SetMysteryClassModule(custom_struct=csp.const(raw_custom_struct))
    channels = [
        MyFatPipeChannels.my_channel,
        MyFatPipeChannels.my_list_channel,
        MyFatPipeChannels.my_str_basket,
        MyFatPipeChannels.my_enum_basket,
        MyFatPipeChannels.my_enum_basket_list,
        MyFatPipeChannels.custom_struct,
    ]
    json_encoder = MyJsonEncoder(channels_list=channels)
    gateway = MyGateway(modules=[setter, json_encoder, setter_mystery], channels=MyFatPipeChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    encoded_snapshot_model = out["encoded_snapshot_model"][0][1]

    fat_pipe_module = MyFatPipeSetter(to_fat_pipe=csp.const(encoded_snapshot_model.encoding))
    getter = AddChannelsToGraphOutput(selection=channels)
    json_decoder = MyJsonDecoder(channels_list=channels)
    gateway = MyFatPipeChannelsGateway(modules=[fat_pipe_module, json_decoder, getter], channels=MyFatPipeChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=5))
    assert len(out["my_channel"]) == 1
    assert len(out["my_list_channel"]) == 1
    assert len(out["my_list_channel"][0][1]) == 2
    assert out["my_list_channel"][0][1][1].foo == 2.0
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
    assert isinstance(out["custom_struct"][0][1].mystery_val[0], MysteryClass)  # custom serialization worked!
    assert len(out["custom_struct"][0][1].mystery_val) == 2


@pytest.mark.parametrize("delay", [timedelta(seconds=1), timedelta(seconds=5)])
def test_encode_decode_timestamp(delay):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0), delay=delay),
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
    json_encoder = MyJsonEncoder(channels_list=channels)
    gateway = MyGateway(modules=[setter, json_encoder], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    encoded_snapshot_model = out["encoded_snapshot_model"][1][1]

    fat_pipe_module = MyFatPipeSetter(to_fat_pipe=csp.const(encoded_snapshot_model.encoding))
    getter = AddChannelsToGraphOutput(selection=channels)
    json_decoder = MyJsonDecoder(channels_list=channels)
    json_checker = MyJsonChecker(timestamp=datetime(2020, 1, 1) + delay)
    gateway = MyFatPipeChannelsGateway(
        modules=[fat_pipe_module, json_decoder, getter, json_checker],
        channels=MyFatPipeChannels(),
    )
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=6))
    assert out["engine_times_align"] == [(datetime(2020, 1, 1) + delay, True)]


@pytest.mark.parametrize("by_key", [True, False])
def test_encode_decode_missing_channels(by_key):
    setter = MySelectiveSetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    json_encoder = MyJsonEncoder(channels_list=channels)
    gateway = MyGateway(modules=[setter, json_encoder], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    encoded_snapshot_model = out["encoded_snapshot_model"][0][1]

    fat_pipe_module = MyFatPipeSetter(to_fat_pipe=csp.const(encoded_snapshot_model.encoding))
    getter = AddChannelsToGraphOutput(selection=channels)
    json_decoder = MyJsonDecoder(channels_list=channels)
    gateway = MyFatPipeChannelsGateway(modules=[fat_pipe_module, json_decoder, getter], channels=MyFatPipeChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=5))
    assert len(out["my_channel"]) == 1
    assert len(out["my_list_channel"]) == 1
    assert len(out["my_list_channel"][0][1]) == 2
    assert out["my_list_channel"][0][1][1].foo == 2.0
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 1
    assert len(out["my_str_basket[my_key]"]) == 1
    assert len(out["my_str_basket[my_key2]"]) == 1
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 0
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 0
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 1
    assert len(out["my_str_basket[my_key]"]) == 1
    assert len(out["my_str_basket[my_key2]"]) == 1


@pytest.mark.parametrize("by_key", [True, False])
def test_encode_decode_some_channels(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    encode_channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
        MyGatewayChannels.my_enum_basket_list,
    ]
    decode_channels = [
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_list_channel,
        MyGatewayChannels.my_str_basket,
        MyGatewayChannels.my_enum_basket,
    ]
    json_encoder = MyJsonEncoderDecoder(encode_channels=encode_channels, decode_channels=decode_channels, encode=True)
    gateway = MyGateway(modules=[setter, json_encoder], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    encoded_snapshot_model = out["encoded_snapshot_model"][0][1]

    fat_pipe_module = MyFatPipeSetter(to_fat_pipe=csp.const(encoded_snapshot_model.encoding))
    getter = AddChannelsToGraphOutput(selection=encode_channels)
    json_decoder = MyJsonEncoderDecoder(encode_channels=encode_channels, decode_channels=decode_channels, encode=False)
    gateway = MyFatPipeChannelsGateway(modules=[fat_pipe_module, json_decoder, getter], channels=MyFatPipeChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=5))
    assert len(out["my_channel"]) == 1
    assert len(out["my_list_channel"]) == 1
    assert len(out["my_list_channel"][0][1]) == 2
    assert out["my_list_channel"][0][1][1].foo == 2.0
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 1
    assert len(out["my_str_basket[my_key]"]) == 1
    assert len(out["my_str_basket[my_key2]"]) == 1
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 0
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 0
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 1
    assert len(out["my_str_basket[my_key]"]) == 1
    assert len(out["my_str_basket[my_key2]"]) == 1


@pytest.mark.parametrize("include_list_channel", [True, False])
def test_encode_decode_flag_updates(include_list_channel):
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
    json_encoder = MyJsonEncoder(channels_list=channels)
    gateway = MyGateway(modules=[setter, json_encoder], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
    encoded_snapshot_model = out["encoded_snapshot_model"][0][1]

    fat_pipe_module = MyFatPipeSetter(to_fat_pipe=csp.const(encoded_snapshot_model.encoding))
    getter = AddChannelsToGraphOutput(selection=channels)
    if include_list_channel:
        json_decoder = MyJsonDecoder(
            channels_list=channels,
            flag_updates={
                "my_channel": [("_new", False), ("my_flag", False)],
                "my_list_channel": [("_new", False)],
            },
        )
    else:
        json_decoder = MyJsonDecoder(
            channels_list=channels,
            flag_updates={"my_channel": [("_new", False), ("my_flag", False)]},
        )
    gateway = MyFatPipeChannelsGateway(modules=[fat_pipe_module, json_decoder, getter], channels=MyFatPipeChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=5))
    assert len(out["my_channel"]) == 1
    assert len(out["my_list_channel"]) == 1
    assert len(out["my_list_channel"][0][1]) == 2
    assert out["my_list_channel"][0][1][1].foo == 2.0
    assert out["my_channel"][0][1]._new is False
    assert out["my_channel"][0][1].my_flag is False
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


# NOTE: This test relies on the format of the json encoding to not change
@pytest.mark.parametrize("after_graph_ends", [True, False])
def test_decode(after_graph_ends):
    raw_encoding = """{"csp_engine_timestamp":"2020-01-01T00:00:00.000000+00:00","my_channel":{"id":"2319507561549660168","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":1.0},"my_list_channel":[{"id":"2319507561549660168","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":1.0},{"id":"2319507561549660169","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":2.0}],"my_enum_basket":{"ONE":{"id":"2319507561549660168","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":1.0},"TWO":{"id":"2319507561549660169","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":2.0}},"my_str_basket":{"my_key":{"id":"2319507561549660168","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":1.0},"my_key2":{"id":"2319507561549660169","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":2.0}},"my_enum_basket_list":{"TWO":[{"id":"2319507561549660168","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":1.0},{"id":"2319507561549660169","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":2.0}],"ONE":[{"id":"2319507561549660168","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":1.0},{"id":"2319507561549660169","timestamp":"2023-03-28T14:11:46.074000+00:00","foo":2.0}]}}"""  # noqa: E501

    if after_graph_ends:
        delay = timedelta(seconds=100)
    else:
        delay = timedelta()
    fat_pipe_module = MyFatPipeSetter(to_fat_pipe=csp.const(raw_encoding, delay=delay))
    channels = [
        MyFatPipeChannels.my_channel,
        MyFatPipeChannels.my_list_channel,
        MyFatPipeChannels.my_str_basket,
        MyFatPipeChannels.my_enum_basket,
        MyFatPipeChannels.my_enum_basket_list,
    ]
    getter = AddChannelsToGraphOutput(selection=channels)
    json_decoder = MyJsonDecoder(channels_list=channels)
    gateway = MyFatPipeChannelsGateway(modules=[fat_pipe_module, json_decoder, getter], channels=MyFatPipeChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=5))

    if after_graph_ends:
        for v in out.values():
            assert not v

    else:
        assert len(out["my_channel"]) == 1
        assert len(out["my_list_channel"]) == 1
        assert len(out["my_list_channel"][0][1]) == 2
        assert out["my_list_channel"][0][1][1].foo == 2.0
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
