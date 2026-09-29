import gc
import json
import weakref
from datetime import datetime

import pytest
from pydantic import BaseModel, Field, ValidationError

from csp_gateway import GatewayStruct as Base
from csp_gateway.utils.struct import (
    GatewayLookupMixin,
    GatewayPydanticMixin,
    global_lookup,
)


class LookupModel(Base):
    foo: int = 9


class NoLookupModel(Base):
    foo: int = 10


NoLookupModel.omit_from_lookup(True)


@pytest.mark.parametrize("identity", [{}, {"id": None, "timestamp": None}, {"id": "stream-only", "timestamp": datetime(2020, 1, 1)}])
def test_stream_fields_validate_without_identity_or_lookup(identity):
    class Message(Base):
        quantity: int = Field(gt=0)
        label: str = "default"

    message = Message.from_stream_fields(quantity="2", **identity)
    assert message.quantity == 2
    expected = {"quantity": 2, "label": "default", **identity}
    assert message.to_dict() == expected
    json_expected = {**expected}
    if isinstance(json_expected.get("timestamp"), datetime):
        json_expected["timestamp"] = json_expected["timestamp"].isoformat()
    assert json.loads(message.to_json()) == json_expected
    assert message.model_fields_set == {"quantity", *identity}
    assert Message.lookup(message.id) is None
    assert global_lookup(message.id) is None

    # Copying preserves omission; later assignment makes the supplied field visible.
    copied = message.copy()
    assert copied.to_dict() == expected
    copied.id = "assigned"
    assert copied.to_dict()["id"] == "assigned"

    with pytest.raises(ValidationError):
        Message.from_stream_fields(quantity=-1)
    ordinary = Message(quantity=3)
    assert ordinary.id is not None and ordinary.timestamp is not None
    assert Message.lookup(ordinary.id) is ordinary

    reference = weakref.ref(message)
    del message
    gc.collect()
    assert reference() is None


def test_stream_fields_nested_messages_and_declared_identity_defaults():
    class Child(Base):
        quantity: int

    class Parent(Base):
        child: Child

    message = Parent.from_stream_fields(child={"quantity": "2"})
    assert message.to_dict() == {"child": {"quantity": 2}}
    assert message.child.id is None
    assert message.child.quantity == 2

    class NamedMessage(Base):
        id: str = "default-id"

    named = NamedMessage.from_stream_fields()
    assert named.to_dict() == {"id": "default-id"}
    assert NamedMessage.lookup(named.id) is None
    ordinary_child = Child(quantity=3)
    assert Child.lookup(ordinary_child.id) is ordinary_child
    parent = Parent.from_stream_fields(child=ordinary_child)
    assert parent.child is ordinary_child
    assert Child.lookup(ordinary_child.id) is ordinary_child
    fields = {"id": "same-fields", "timestamp": datetime(2020, 1, 1), "quantity": 3}
    ordinary = Child(**fields)
    assert Child.from_stream_fields(**fields) == ordinary
    assert Child.lookup(ordinary.id) is ordinary
    assert Child.model_construct(quantity=2).to_dict() == {"quantity": 2}


def test_automatic_id_generation():
    """Test that IDs are auto-generated and unique across all classes (global generator)."""
    for Model in [LookupModel, NoLookupModel]:
        o1 = Model()
        # IDs should be strings
        assert isinstance(o1.id, str)

        o2 = Model()
        # Each new instance gets a unique ID
        assert o2.id != o1.id
        # IDs are sequential (global counter)
        assert int(o2.id) > int(o1.id)

        if Model == LookupModel:
            assert Model.lookup(o1.id) == o1
            assert Model.lookup(o2.id) == o2


def test_lookup_fails():
    o1 = LookupModel()
    assert isinstance(o1.id, str)

    o2 = LookupModel()
    assert o2.id != o1.id

    assert LookupModel.lookup(o1.id) == o1
    assert LookupModel.lookup(o2.id) == o2

    o1 = NoLookupModel()
    assert isinstance(o1.id, str)

    o2 = NoLookupModel()
    assert o2.id != o1.id

    # NoLookupModel has lookup disabled
    assert NoLookupModel.lookup(o1.id) is None
    assert NoLookupModel.lookup(o2.id) is None


def test_add_lookup_mixin_in_subclass():
    class MyBase(BaseModel):
        a: int = None
        id: str = None
        timestamp: datetime = None

    # Start with only Pydantic mixin (no lookup or id generator)
    class PydOnly(GatewayPydanticMixin, MyBase):
        pass

    # Provide explicit id/timestamp since no lookup mixin exists to default them
    now = datetime.now()
    p = PydOnly(a=1, id="explicit", timestamp=now)
    # TypeAdapter works without lookup mixin
    p2 = PydOnly.type_adapter().validate_python(p.model_dump(exclude_unset=True))
    assert p2.id == "explicit"
    assert p2.timestamp == now

    # Add lookup mixin later via subclassing
    class WithLookup(GatewayLookupMixin, PydOnly):
        pass

    w = WithLookup(a=2)
    assert isinstance(w.id, str)
    assert isinstance(w.timestamp, datetime)
    assert WithLookup.lookup(w.id) == w
    # generate_id available now
    nid = WithLookup.generate_id()
    assert isinstance(nid, str)


def test_lookup_toggle_isolated_across_inheritance():
    class MyBase(BaseModel):
        a: int = None
        id: str = None
        timestamp: datetime = None

    class Parent(GatewayLookupMixin, MyBase):
        pass

    # Disable lookup on Parent
    Parent.omit_from_lookup(True)
    p = Parent(a=1)
    assert Parent.lookup(p.id) is None

    # Child inherits mixin; __init_subclass__ should reset include to True
    class Child(Parent):
        pass

    c = Child(a=2)
    assert c.a == 2
    assert Child.lookup(c.id) == c
    # Ensure Parent still disabled
    p2 = Parent(a=3)
    assert p2.a == 3
    assert Parent.lookup(p2.id) is None


def test_lookup_only_mixin_without_fields_mixin():
    class BaseStruct(BaseModel):
        a: int = None
        # No fields mixin, declare fields on class
        id: str = None
        timestamp: datetime = None

    class LookupOnly(GatewayLookupMixin, BaseStruct):
        pass

    # Defaults applied
    x = LookupOnly(a=5)
    assert isinstance(x.id, str)
    assert isinstance(x.timestamp, datetime)
    assert LookupOnly.lookup(x.id) == x

    # Toggle off lookup
    LookupOnly.omit_from_lookup(True)
    y = LookupOnly(a=6)
    assert LookupOnly.lookup(y.id) is None

    # Toggle back on lookup
    LookupOnly.omit_from_lookup(False)
    z = LookupOnly(a=7)
    assert LookupOnly.lookup(z.id) == z


def test_separate_lookup_registries():
    """Test that class-scoped lookup is isolated between classes."""

    class StructA(BaseModel):
        a: int = None
        id: str = None
        timestamp: datetime = None

    class StructB(BaseModel):
        b: int = None
        id: str = None
        timestamp: datetime = None

    class LookupA(GatewayLookupMixin, StructA):
        pass

    class LookupB(GatewayLookupMixin, StructB):
        pass

    a1 = LookupA(a=1)
    b1 = LookupB(b=1)

    # Class-scoped lookup finds own instances
    assert LookupA.lookup(a1.id) == a1
    assert LookupB.lookup(b1.id) == b1

    # Cross-lookups via class method are still isolated
    assert LookupA.lookup(b1.id) is None
    assert LookupB.lookup(a1.id) is None

    # But global_lookup can find both without class filter
    assert global_lookup(a1.id) == a1
    assert global_lookup(b1.id) == b1

    # global_lookup with class filter works too
    assert global_lookup(a1.id, LookupA) == a1
    assert global_lookup(b1.id, LookupB) == b1
    assert global_lookup(a1.id, LookupB) is None
    assert global_lookup(b1.id, LookupA) is None

    # Global generator means all IDs are unique
    a_id1 = LookupA.generate_id()
    a_id2 = LookupA.generate_id()
    b_id1 = LookupB.generate_id()
    b_id2 = LookupB.generate_id()
    # All IDs are unique (global counter)
    assert len({a_id1, a_id2, b_id1, b_id2}) == 4


def test_global_lookup_function():
    """Test the global_lookup function for looking up instances by ID."""

    class TestStructA(BaseModel):
        a: int = None
        id: str = None
        timestamp: datetime = None

    class TestStructB(BaseModel):
        b: int = None
        id: str = None
        timestamp: datetime = None

    class GlobalLookupA(GatewayLookupMixin, TestStructA):
        pass

    class GlobalLookupB(GatewayLookupMixin, TestStructB):
        pass

    a1 = GlobalLookupA(a=100)
    b1 = GlobalLookupB(b=200)

    # Global lookup without class filter finds any instance
    assert global_lookup(a1.id) == a1
    assert global_lookup(b1.id) == b1

    # Global lookup with class filter only finds instances of that class
    assert global_lookup(a1.id, GlobalLookupA) == a1
    assert global_lookup(a1.id, GlobalLookupB) is None
    assert global_lookup(b1.id, GlobalLookupB) == b1
    assert global_lookup(b1.id, GlobalLookupA) is None

    # Non-existent ID returns None
    assert global_lookup("nonexistent") is None
    assert global_lookup("nonexistent", GlobalLookupA) is None


def test_global_id_generator_shared():
    """Test that all classes share the same global ID generator."""

    class SharedGenA(BaseModel):
        a: int = None
        id: str = None
        timestamp: datetime = None

    class SharedGenB(BaseModel):
        b: int = None
        id: str = None
        timestamp: datetime = None

    class LookupSharedA(GatewayLookupMixin, SharedGenA):
        pass

    class LookupSharedB(GatewayLookupMixin, SharedGenB):
        pass

    # Both classes use the same generator
    assert LookupSharedA.id_generator is LookupSharedB.id_generator

    # Generate IDs from different classes - they should be strictly increasing
    id1 = LookupSharedA.generate_id()
    id2 = LookupSharedB.generate_id()
    id3 = LookupSharedA.generate_id()
    id4 = LookupSharedB.generate_id()

    assert int(id1) < int(id2) < int(id3) < int(id4)

    # Instance creation also uses the global generator
    a1 = LookupSharedA(a=1)
    b1 = LookupSharedB(b=1)
    a2 = LookupSharedA(a=2)

    assert int(a1.id) < int(b1.id) < int(a2.id)
