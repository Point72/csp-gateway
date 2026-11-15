import asyncio
from concurrent.futures import Future
from datetime import date, datetime
from types import SimpleNamespace
from typing import Annotated, get_type_hints

import csp
import numpy as np
import pytest
from csp import Enum, Struct, ts
from csp.typing import Numpy1DArray
from pydantic import ValidationError

from csp_gateway import GatewayChannels, GatewayStruct as _Base, NoProviderException, State
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
    order_list: list[SimpleOrder]


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
    my_static_dict: dict[str, float] = {}
    my_static_list: list[str] = []
    my_channel: Annotated[ts[MyStruct], State(keyby="id")] = None
    my_list_channel: Annotated[ts[list[MyStruct]], State(keyby="id")] = None
    my_enum_basket: dict[MyEnum, ts[MyStruct]] = None
    my_str_basket: dict[str, ts[MyStruct]] = None
    my_enum_basket_list: dict[MyEnum, ts[list[MyStruct]]] = None
    my_array_channel: ts[Numpy1DArray[float]] = None


@pytest.fixture
def last_request():
    channels = MyGatewayChannels()
    future = Future()
    submitted = asyncio.Event()

    def push_tick():
        submitted.set()
        return future

    channels._last_requests["my_channel", None] = SimpleNamespace(push_tick=push_tick)
    return channels, future, submitted


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value, key, expected",
    [
        pytest.param(7, None, 7, id="scalar"),
        pytest.param([1, 2], None, [1, 2], id="list"),
        pytest.param(None, None, None, id="unticked"),
        pytest.param({"one": [1, 2]}, None, {"one": [1, 2]}, id="basket"),
        pytest.param({"one": [1, 2]}, "one", [1, 2], id="basket-key"),
        pytest.param({0: 7}, 0, 7, id="zero-key"),
    ],
)
async def test_last_async_matches_last_values(last_request, value, key, expected):
    channels, future, _ = last_request
    future.set_result(value)
    assert await channels.last_async("my_channel", key) == expected
    assert channels.last("my_channel", key) == expected


@pytest.mark.asyncio
async def test_last_async_cancellation_keeps_engine_future_pending(last_request):
    channels, future, submitted = last_request
    pending = asyncio.create_task(channels.last_async("my_channel"))
    await asyncio.wait_for(submitted.wait(), timeout=1)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert not future.done()
    future.set_result(7)
    assert future.result() == 7


@pytest.mark.asyncio
async def test_last_async_timeout_keeps_engine_future_pending(last_request):
    channels, future, _ = last_request
    with pytest.raises(TimeoutError):
        await channels.last_async("my_channel", timeout=0.01)
    assert not future.done()
    future.set_result(7)
    assert future.result() == 7


@pytest.mark.asyncio
async def test_last_async_missing_provider():
    with pytest.raises(NoProviderException):
        await MyGatewayChannels().last_async("my_channel")


def test_csp_enum_dict_basket_has_static_keys():
    channels = MyGatewayChannels()

    assert set(channels._keys_for_channel("my_enum_basket")) == set(MyEnum)


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
    assert type_hints["my_channel"] == MyStruct | None
    assert type_hints["my_list_channel"] == list[MyStruct] | None
    assert type_hints["my_enum_basket"] == dict[MyEnum, MyStruct] | None
    assert type_hints["my_str_basket"] == dict[str, MyStruct] | None
    assert type_hints["my_enum_basket_list"] == dict[MyEnum, list[MyStruct]] | None
    assert type_hints[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD] == datetime | None


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
