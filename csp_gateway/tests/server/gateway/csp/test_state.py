import typing
from datetime import datetime, timedelta

from csp import Enum, Struct

from csp_gateway import (
    Filter,
    FilterCondition,
    Query,
    State,
    StateType,
    disable_duckdb_state,
    enable_duckdb_state,
)


class MyEnum(Enum):
    A = 1
    B = 2
    C = 3


class CspSubStruct(Struct):
    suba: int = 1
    subb: str = "b"
    subc: datetime = datetime.now()
    subd: str
    sube: typing.Dict[str, str]
    subf: MyEnum = MyEnum.A


class NonCspStruct(object):
    a: int = 0
    b: str
    c: datetime = datetime.now()
    d: str = ""
    e: typing.Dict[str, str] = {"A": "hhello", "B": "bbye"}
    f: MyEnum = MyEnum.A
    g: CspSubStruct = CspSubStruct()

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class CspStruct(Struct):
    a: int = 0
    b: str
    c: datetime = datetime.now()
    d: str = ""
    e: typing.Dict[str, str] = {"A": "hhello", "B": "bbye"}
    f: MyEnum = MyEnum.A
    h: typing.List[int] = [1, 2, 4]
    i: list = [1, 2, 4]
    j: dict = {"a": "b"}
    g: CspSubStruct = CspSubStruct()


_STATES = [StateType.DUCKDB, StateType.DEFAULT]
_STRUCTS = [CspStruct, NonCspStruct]


def test_state():
    for specialization, struct_type in zip(_STATES, _STRUCTS):
        s = State[struct_type]()
        assert s.state_type() == specialization
        res = s.query()
        assert res == []


def test_state_keyby():
    for specialization, struct_type in zip(_STATES, _STRUCTS):
        s = State[struct_type](keyby="a")
        assert s.state_type() == specialization
        ts = struct_type(b="hello")
        s.insert(ts)
        res = s.query()
        #  assert s.query() == {0: ts}
        assert res == [ts]
        ts2 = struct_type(b="hello2")
        s.insert(ts2)
        res = s.query()
        #  assert s.query() == {0: ts}
        assert res == [ts2]


def test_state_keyby_unset():
    for specialization, struct_type in zip(_STATES, _STRUCTS):
        s = State[struct_type](keyby="d")
        assert s.state_type() == specialization
        ts = struct_type()
        s.insert(ts)
        res = s.query()
        assert res == [ts]


def test_state_keyby_two():
    for specialization, struct_type in zip(_STATES, _STRUCTS):
        s = State[struct_type](keyby=("a", "b"))
        assert s.state_type() == specialization
        ts1 = struct_type(a=0, b="hello")
        s.insert(ts1)
        #  assert s.query() == {0: {"0": ts1}}
        res = s.query()
        assert res == [ts1]

        ts2 = struct_type(a=1, b="bye", g=CspSubStruct(suba=5, subb="good", subf=MyEnum.A))
        s.insert(ts2)
        #  assert s.query() == {0: {"0": ts1}, 1: {"1": ts2}}
        fil = Filter(attr="a", by=FilterCondition(value=1, where="=="))
        query = Query(filters=[fil])
        res = s.query(query)
        assert res == [ts2]
        query = Query(filters=[fil, fil, fil])
        res = s.query(query)
        assert res == [ts2]
        res = s.query()
        assert res == [ts1, ts2]


def test_duckdb_nested_filter():
    s = State[CspStruct](keyby=("a", "b"))
    assert s.state_type() == StateType.DUCKDB
    ts1 = CspStruct(a=0, b="hello")
    s.insert(ts1)
    ts2 = CspStruct(a=1, b="bye", g=CspSubStruct(suba=5, subb="good", subf=MyEnum.A))
    s.insert(ts2)
    fil2 = Filter(attr="g.suba", by=FilterCondition(value=5, where="=="))
    query2 = Query(filters=[fil2])
    res2 = s.query(query2)
    assert res2 == [ts2]


def test_many_inserts():
    s = State[CspStruct](keyby=("a", "b", "f"))
    csp_l = []
    csp_l.append(CspStruct(a=1, b="b1", f=MyEnum.A))
    csp_l.append(CspStruct(a=2, b="b2", f=MyEnum.A))
    csp_l.append(CspStruct(a=3, b="b3", f=MyEnum.A))
    csp_l.append(CspStruct(a=4, b="b4", f=MyEnum.A))
    csp_l.append(CspStruct(a=5, b="b5", f=MyEnum.A))
    csp_l.append(CspStruct(a=6, b="b6", f=MyEnum.A))
    csp_l.append(CspStruct(a=7, b="b7", f=MyEnum.A))
    csp_l.append(CspStruct(a=8, b="b8", f=MyEnum.A))
    csp_l.append(CspStruct(a=9, b="b9", f=MyEnum.A))
    csp_l.append(CspStruct(a=10, b="b10", f=MyEnum.A))
    csp_l.append(CspStruct(a=11, b="b11", f=MyEnum.A))
    csp_l.append(CspStruct(a=12, b="b12", f=MyEnum.A))
    csp_l.append(CspStruct(a=13, b="b13", f=MyEnum.A))
    csp_l.append(CspStruct(a=14, b="b14", f=MyEnum.A))
    csp_l.append(CspStruct(a=15, b="b15", f=MyEnum.A))
    csp_l.append(CspStruct(a=16, b="b16", f=MyEnum.A))
    csp_l.append(CspStruct(a=17, b="b17", f=MyEnum.A))
    rev_csp_l = reversed(csp_l)
    for c in rev_csp_l:
        s.insert(c)
    for i in range(300000):
        s.insert(csp_l[i % len(csp_l)])
        if i % 1000 == 0:
            assert csp_l == s.query()


def test_state_query_timestamp():
    for specialization, struct_type in zip(_STATES, _STRUCTS):
        dt = datetime.now()
        dt_old = dt - timedelta(5)
        s = State[struct_type](keyby=("a", "b"))
        assert s.state_type() == specialization
        ts1 = struct_type(a=0, b="hello", c=dt)
        s.insert(ts1)
        #  assert s.query() == {0: {"0": ts1}}
        res = s.query()
        assert res == [ts1]

        ts2 = struct_type(a=1, b="bye", g=CspSubStruct(suba=5, subb="good", subf=MyEnum.A), c=dt_old)
        s.insert(ts2)

        res = s.query()
        assert res == [ts1, ts2]

        fil = Filter(attr="c", by=FilterCondition(when=str(dt_old), where=">"))
        query = Query(filters=[fil])
        res = s.query(query)
        assert res == [ts1]

        fil = Filter(attr="c", by=FilterCondition(when=str(dt), where="<"))
        query = Query(filters=[fil])
        res = s.query(query)
        assert res == [ts2]

        fil = Filter(attr="c", by=FilterCondition(when=str(dt), where="<="))
        query = Query(filters=[fil])
        res = s.query(query)
        assert res == [ts1, ts2]

        fil = Filter(attr="c", by=FilterCondition(when=str(dt), where=">="))
        query = Query(filters=[fil])
        res = s.query(query)
        assert res == [ts1]


def test_state_query_attr():
    for specialization, struct_type in zip(_STATES, _STRUCTS):
        s = State[struct_type](keyby=("a", "b"))
        assert s.state_type() == specialization
        ts1 = struct_type(a=0, b="hello", g=CspSubStruct(suba=1, subb="good"))
        s.insert(ts1)
        ts2 = struct_type(a=1, b="bye", g=CspSubStruct(suba=1, subb="good"))
        s.insert(ts2)

        res = s.query()
        assert res == [ts1, ts2]

        fil = Filter(attr="a", by=FilterCondition(attr="a", where="<"))
        query = Query(filters=[fil])
        res = s.query(query)
        assert res == []

        fil = Filter(attr="a", by=FilterCondition(attr="a", where=">="))
        query = Query(filters=[fil])
        res = s.query(query)
        assert res == [ts1, ts2]


def test_duckdb_query_attr():
    struct_type = CspStruct
    specialization = StateType.DUCKDB
    s = State[struct_type](keyby=("a", "b"))
    assert s.state_type() == specialization
    ts1 = struct_type(a=0, b="hello", g=CspSubStruct(suba=1, subb="good"))
    s.insert(ts1)
    ts2 = struct_type(a=1, b="bye", g=CspSubStruct(suba=1, subb="good"))
    s.insert(ts2)

    res = s.query()
    assert res == [ts1, ts2]

    fil = Filter(attr="a", by=FilterCondition(attr="g.suba", where="=="))
    query = Query(filters=[fil])
    res = s.query(query)
    assert res == [ts2]

    fil = Filter(attr="f", by=FilterCondition(attr="g.subf", where="=="))
    query = Query(filters=[fil])
    res = s.query(query)
    assert res == [ts1, ts2]


def test_set_duckdb_config():
    enable_duckdb_state()
    s = State[CspStruct](keyby=("a", "b", "f"))
    assert s.state_type() == StateType.DUCKDB
    disable_duckdb_state()
    s = State[CspStruct](keyby=("a", "b", "f"))
    assert s.state_type() == StateType.DEFAULT
