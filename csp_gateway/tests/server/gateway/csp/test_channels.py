from datetime import date, datetime
from typing import Dict, List, Optional, get_type_hints

import csp
import numpy as np
import pytest
from csp import Enum, Struct, ts
from csp.typing import Numpy1DArray
from pydantic import ValidationError

from csp_gateway import GatewayChannels, GatewayStruct as _Base, State
from csp_gateway.server.gateway.csp.channels import _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD


class Symbology(Enum):
    ID = Enum.auto()


class SimpleOrder(_Base):
    _private: str
    symbol: str
    symbology: Symbology = Symbology.ID
    price: float
    quantity: int
    filled: float = 0  # Note that default is an int
    settlement_date: date
    notes: str = ""
    algo_params: dict


class SimpleOrderChild(SimpleOrder):
    new_field: float


class MyCompositeStruct(_Base):
    order: SimpleOrder
    order_list: List[SimpleOrder]


class MyEnum(Enum):
    ONE = 1
    TWO = 2


class MyCspStruct(Struct):
    a: int
    csp_np_array: Numpy1DArray[float] = np.array([13.0]).view(Numpy1DArray)


class MyStruct(_Base):
    foo: float
    fav_num: int = 68
    my_np_array: Numpy1DArray[float] = np.array([6.0]).view(Numpy1DArray)
    my_csp_struct: MyCspStruct = MyCspStruct(a=9)


class MyGatewayChannels(GatewayChannels):
    my_static: float = 0.0
    my_static_dict: Dict[str, float] = {}
    my_static_list: List[str] = []
    my_channel: ts[MyStruct] = None
    s_my_channel: ts[State[MyStruct]] = None
    my_list_channel: ts[List[MyStruct]] = None
    s_my_list_channel: ts[State[MyStruct]] = None
    my_enum_basket: Dict[MyEnum, ts[MyStruct]] = None
    my_str_basket: Dict[str, ts[MyStruct]] = None
    my_enum_basket_list: Dict[MyEnum, ts[List[MyStruct]]] = None
    my_array_channel: ts[Numpy1DArray[float]] = None


class DerivedChannels(MyGatewayChannels):
    pass


class DerivedDerivedChannels(DerivedChannels):
    pass


class DerivedDerivedDerivedChannels(DerivedDerivedChannels):
    pass


def test_construction():
    channels = MyGatewayChannels()
    assert MyGatewayChannels.my_static == "my_static"
    assert channels.my_static == 0.0
    assert MyGatewayChannels.my_channel == "my_channel"
    assert channels.my_channel is None
    channels.my_static = 1.0
    channels.my_channel = csp.null_ts(MyStruct)


def test_construction_derived():
    # Seems innocuous, but has broken before
    channelss = [
        DerivedChannels(),
        DerivedDerivedChannels(),
        DerivedDerivedDerivedChannels(),
    ]
    for channels in channelss:
        assert MyGatewayChannels.my_static == "my_static"
        assert channels.my_static == 0.0
        assert MyGatewayChannels.my_channel == "my_channel"
        assert channels.my_channel is None
        channels.my_static = 1.0
        channels.my_channel = csp.null_ts(MyStruct)


def test_snapshot_model_type_hints():
    snapshot_model = MyGatewayChannels._snapshot_model
    type_hints = get_type_hints(snapshot_model)
    assert len(type_hints) == 6
    assert type_hints["my_channel"] == Optional[MyStruct]
    assert type_hints["my_list_channel"] == Optional[List[MyStruct]]
    assert type_hints["my_enum_basket"] == Optional[Dict[MyEnum, MyStruct]]
    assert type_hints["my_str_basket"] == Optional[Dict[str, MyStruct]]
    assert type_hints["my_enum_basket_list"] == Optional[Dict[MyEnum, List[MyStruct]]]
    assert type_hints[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD] == Optional[datetime]


def test_snapshot_model_instantiation():
    snapshot_model = MyGatewayChannels._snapshot_model
    pass_through = {
        "my_channel": MyStruct(foo=3.0),
        "my_list_channel": [
            MyStruct(foo=3.0),
            MyStruct(foo=2.0),
        ],
        "my_enum_basket": {MyEnum.ONE: MyStruct(foo=3.0)},
    }
    new_model = snapshot_model(**pass_through)
    assert np.array_equal(new_model.my_channel.my_np_array, np.array([6.0]))
    assert new_model.my_channel.foo == 3.0
    assert new_model.my_list_channel[1].foo == 2.0
    assert new_model.my_str_basket is None


def test_snapshot_model_parse_obj():
    snapshot_model = MyGatewayChannels._snapshot_model
    pass_through = {
        "my_channel": {"foo": 3.0},
        "my_list_channel": [
            {"foo": 3.0},
            {
                "foo": 2.0,
                "fav_num": 70,
                "my_np_array": np.array([5.0, 7.0]).view(Numpy1DArray),
            },
        ],
        "my_enum_basket": {MyEnum.ONE: {"foo": 3.0}},
        "my_str_basket": {"my_key": {"foo": 9.0}, "my_key2": {"foo": 11.3}},
        "my_enum_basket_list": {
            MyEnum.TWO: [{"foo": 3.0}, {"foo": 6.89}],
            MyEnum.ONE: [{"foo": 0.0}],
        },
    }
    new_model = snapshot_model.model_validate(pass_through)
    assert isinstance(new_model.my_channel, MyStruct)
    assert new_model.my_channel.foo == 3.0
    assert new_model.my_list_channel[0].foo == 3.0
    assert new_model.my_list_channel[1].fav_num == 70
    assert np.array_equal(new_model.my_list_channel[1].my_np_array, np.array([5.0, 7.0]))
    assert new_model.my_str_basket["my_key"].foo == 9.0
    assert new_model.my_str_basket["my_key2"].fav_num == 68
    assert len(new_model.my_enum_basket_list[MyEnum.TWO]) == 2


def test_snapshot_fails_on_improper_dict():
    snapshot_model = MyGatewayChannels._snapshot_model
    pass_nonexistant_attribute = {"my_channel": {"bad_attr": 68}}
    with pytest.raises(ValidationError):
        snapshot_model.model_validate(pass_nonexistant_attribute)
    with pytest.raises(ValidationError):
        snapshot_model.model_validate({"missing_channel": {"random": 11}})

    pass_non_list_to_list_channel = {"my_list_channel": {"foo": 3.0}}
    with pytest.raises(ValidationError):
        snapshot_model.model_validate(pass_non_list_to_list_channel)
