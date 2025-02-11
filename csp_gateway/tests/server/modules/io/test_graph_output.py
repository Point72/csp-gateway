from datetime import datetime, timedelta

import csp
import pytest

from csp_gateway import AddChannelsToGraphOutput
from csp_gateway.testing.shared_helpful_classes import (
    MyGateway,
    MyGatewayChannels,
    MySetModule,
    MyStruct,
)


@pytest.mark.parametrize("by_key", [True, False])
def test_get_set_AddChannelsToGraphOutput(by_key, caplog):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = AddChannelsToGraphOutput()
    gateway = MyGateway(modules=[getter, setter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
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


@pytest.mark.parametrize("by_key", [True, False])
def test_set_get_AddChannelsToGraphOutput(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = AddChannelsToGraphOutput()
    gateway = MyGateway(modules=[setter, getter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
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


@pytest.mark.parametrize("by_key", [True, False])
def test_set_get_AddChannelsToGraphOutput_not_all_channels(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = AddChannelsToGraphOutput(
        selection=[
            MyGatewayChannels.my_channel,
            MyGatewayChannels.my_str_basket,
            MyGatewayChannels.my_list_channel,
        ],
    )
    gateway = MyGateway(modules=[setter, getter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert len(out["my_channel"]) == 1
    assert len(out["my_list_channel"]) == 1
    assert len(out["my_list_channel"][0][1]) == 2
    assert len(out["my_str_basket[my_key]"]) == 1
    assert len(out["my_str_basket[my_key2]"]) == 1

    assert not out.get("my_array_channel", [])
    assert not out.get("my_array_channel", [])
    assert not out.get("my_enum_basket[MyEnum.ONE]", [])
    assert not out.get("my_enum_basket[MyEnum.TWO]", [])
    assert not out.get("my_enum_basket_list[MyEnum.ONE]", [])
    assert not out.get("my_enum_basket_list[MyEnum.TWO]", [])


@pytest.mark.parametrize("by_key", [True, False])
def test_get_set_set_AddChannelsToGraphOutput(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = AddChannelsToGraphOutput()
    gateway = MyGateway(modules=[getter, setter, setter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert len(out["my_channel"]) == 2
    assert len(out["my_list_channel"]) == 2
    assert len(out["my_list_channel"][0][1]) == 2
    assert len(out["my_list_channel"][1][1]) == 2
    assert len(out["my_array_channel"]) == 2
    assert len(out["my_array_channel"][0][1]) == 2
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 2
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 2
    assert len(out["my_str_basket[my_key]"]) == 2
    assert len(out["my_str_basket[my_key2]"]) == 2
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 2
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 2
