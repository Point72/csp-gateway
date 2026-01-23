from datetime import datetime

from csp import Struct

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
    class MyBase(Struct):
        a: int
        id: str
        timestamp: datetime

    # Start with only Pydantic mixin (no lookup or id generator)
    class PydOnly(GatewayPydanticMixin, MyBase):
        pass

    # Provide explicit id/timestamp since no lookup mixin exists to default them
    now = datetime.now()
    p = PydOnly(a=1, id="explicit", timestamp=now)
    # TypeAdapter works without lookup mixin
    p2 = PydOnly.type_adapter().validate_python(p.to_dict())
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
    class MyBase(Struct):
        a: int
        id: str
        timestamp: datetime

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
    class BaseStruct(Struct):
        a: int
        # No fields mixin, declare fields on class
        id: str
        timestamp: datetime

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

    class StructA(Struct):
        a: int
        id: str
        timestamp: datetime

    class StructB(Struct):
        b: int
        id: str
        timestamp: datetime

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

    class TestStructA(Struct):
        a: int
        id: str
        timestamp: datetime

    class TestStructB(Struct):
        b: int
        id: str
        timestamp: datetime

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

    class SharedGenA(Struct):
        a: int
        id: str
        timestamp: datetime

    class SharedGenB(Struct):
        b: int
        id: str
        timestamp: datetime

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
