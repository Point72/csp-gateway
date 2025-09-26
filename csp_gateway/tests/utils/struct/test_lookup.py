from datetime import datetime

from csp import Struct

from csp_gateway import GatewayStruct as Base
from csp_gateway.utils.struct import (
    GatewayLookupMixin,
    GatewayPydanticMixin,
)


class LookupModel(Base):
    foo: int = 9


class NoLookupModel(Base):
    foo: int = 10


NoLookupModel.omit_from_lookup(True)


def test_automatic_id_generation():
    for Model in [LookupModel, NoLookupModel]:
        o1 = Model()
        value1 = str(Model.id_generator.current())
        assert o1.id == value1

        o2 = Model()
        value2 = str(Model.id_generator.current())
        assert o2.id == value2
        assert o2.id == str(int(o1.id) + 1)

        if Model == LookupModel:
            assert Model.lookup(value1) == o1
            assert Model.lookup(value2) == o2


def test_lookup_fails():
    o1 = LookupModel()
    value1 = str(LookupModel.id_generator.current())
    assert o1.id == value1

    o2 = LookupModel()
    value2 = str(LookupModel.id_generator.current())
    assert o2.id == value2
    assert o2.id == str(int(o1.id) + 1)

    assert LookupModel.lookup(value1) == o1
    assert LookupModel.lookup(value2) == o2

    o1 = NoLookupModel()
    value1 = str(NoLookupModel.id_generator.current())
    assert o1.id == value1

    o2 = NoLookupModel()
    value2 = str(NoLookupModel.id_generator.current())
    assert o2.id == value2
    assert o2.id == str(int(o1.id) + 1)

    assert NoLookupModel.lookup(value1) is None
    assert NoLookupModel.lookup(value2) is None


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

    assert LookupA.lookup(a1.id) == a1
    assert LookupB.lookup(b1.id) == b1

    # Cross-lookups must be isolated
    assert LookupA.lookup(b1.id) is None
    assert LookupB.lookup(a1.id) is None

    # Generators are per-class
    a_id1 = LookupA.generate_id()
    a_id2 = LookupA.generate_id()
    b_id1 = LookupB.generate_id()
    b_id2 = LookupB.generate_id()
    assert a_id1 != a_id2
    assert b_id1 != b_id2
    # Not guaranteed, but overwhelmingly likely that sequences don't collide
    assert a_id1 != b_id1
