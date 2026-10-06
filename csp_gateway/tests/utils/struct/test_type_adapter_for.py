"""Serializing channel structs that are not GatewayStructs."""

import json

import pytest
from pydantic import BaseModel

from csp_gateway.utils import GatewayStruct
from csp_gateway.utils.struct.base import type_adapter_for


class PlainModel(BaseModel):
    """A channel is free to carry any pydantic model, not only a GatewayStruct."""

    content: str = ""
    count: int = 0


class AStruct(GatewayStruct):
    content: str = ""


def test_plain_pydantic_model_can_be_serialized():
    """Regression: the REST layer called obj.type_adapter() unconditionally.

    A plain pydantic model has no such method, so every read, send, and stage
    of a channel carrying one failed with AttributeError inside the response
    path rather than returning the data.
    """
    model = PlainModel(content="hello", count=2)

    payload = json.loads(type_adapter_for(model).dump_json(model))

    assert payload == {"content": "hello", "count": 2}


def test_gateway_struct_keeps_using_its_own_adapter():
    struct = AStruct(content="hello")

    assert type_adapter_for(struct) is struct.type_adapter()


def test_adapters_are_cached_per_type():
    first = type_adapter_for(PlainModel())
    second = type_adapter_for(PlainModel(content="other"))

    assert first is second


def test_distinct_types_get_distinct_adapters():
    class OtherModel(BaseModel):
        value: int = 0

    assert type_adapter_for(PlainModel()) is not type_adapter_for(OtherModel())


@pytest.mark.parametrize("value", [PlainModel(content="x"), AStruct(content="x")])
def test_round_trips_either_kind(value):
    dumped = type_adapter_for(value).dump_json(value)

    assert json.loads(dumped)["content"] == "x"


def test_non_models_still_raise():
    """Reaching here with a non-model means a caller mishandled a container.

    `prepare_response` iterates a dict when it was not told the channel is a
    dict basket, which yields the string keys. That used to raise, and must
    keep raising rather than serializing the key as if it were the data.
    """
    for value in ("foo", 1, None, ["a"], {"a": 1}):
        with pytest.raises(AttributeError, match="type_adapter"):
            type_adapter_for(value)
