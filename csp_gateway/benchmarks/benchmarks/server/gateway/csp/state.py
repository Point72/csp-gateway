import typing
from datetime import datetime

from csp import Enum, Struct

from csp_gateway import Filter, FilterCondition, Query, State, StateType, disable_duckdb_state, enable_duckdb_state, modify_buffer_threshold

_STATES = [StateType.DUCKDB, StateType.DEFAULT]
_BUFFER_THRESHOLD = 10000
_BUFFER_SIZES = [int(_BUFFER_THRESHOLD / 10), _BUFFER_THRESHOLD - 1, _BUFFER_THRESHOLD, _BUFFER_THRESHOLD + 1, _BUFFER_THRESHOLD * 10]
_FILTER = Filter(attr="a", by=FilterCondition(value=int(_BUFFER_THRESHOLD / 10), where="<="))
_QUERY = Query(filters=[_FILTER, _FILTER])


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


class StateInitialize:
    params = _STATES
    param_names = ["StateType"]

    def setup(self, state_typ):
        if state_typ == StateType.DEFAULT:
            disable_duckdb_state()
        elif state_typ == StateType.DUCKDB:
            enable_duckdb_state()
        return None

    def time_create(self, state_typ):
        _ = State[CspStruct](keyby="a")


class StateInsert:
    params = [_STATES, _BUFFER_SIZES]
    param_names = ["StateType", "#Inserts"]
    timeout = 300

    def setup(self, state_typ, _):
        if state_typ == StateType.DEFAULT:
            disable_duckdb_state()
        elif state_typ == StateType.DUCKDB:
            enable_duckdb_state()
        self.s = State[CspStruct]()
        modify_buffer_threshold(_BUFFER_THRESHOLD)

    def time_insert(self, state_typ, threshold):
        for i in range(threshold):
            ts = CspStruct(a=i, b=f"{i}", f=MyEnum.A, h=[i, i, i], j={i: i}, g=CspSubStruct(suba=i + 1, subb=f"{i + 1}"))
            self.s.insert(ts)


class StateInsertKeyBy:
    params = [_STATES, _BUFFER_SIZES]
    param_names = ["StateType", "#Inserts"]
    timeout = 300

    def setup(self, state_typ, _):
        if state_typ == StateType.DEFAULT:
            disable_duckdb_state()
        elif state_typ == StateType.DUCKDB:
            enable_duckdb_state()
        self.s = State[CspStruct](keyby="a")
        modify_buffer_threshold(_BUFFER_THRESHOLD)

    def time_insert(self, state_typ, threshold):
        for i in range(threshold):
            # Have the keyby value repeat
            ts = CspStruct(a=i % 100, b=f"{i}", f=MyEnum.A, h=[i, i, i], j={i: i}, g=CspSubStruct(suba=i + 1, subb=f"{i + 1}"))
            self.s.insert(ts)


class StateFirstQueryAll:
    params = [_STATES, _BUFFER_SIZES]
    param_names = ["StateType", "#Queries"]
    timeout = 300

    def setup(self, state_typ, threshold):
        if state_typ == StateType.DEFAULT:
            disable_duckdb_state()
        elif state_typ == StateType.DUCKDB:
            enable_duckdb_state()
        self.s = State[CspStruct](keyby="a")
        modify_buffer_threshold(_BUFFER_THRESHOLD)
        for i in range(threshold):
            ts = CspStruct(a=i, b=f"{i}", f=MyEnum.A, h=[i, i, i], j={i: i}, g=CspSubStruct(suba=i + 1, subb=f"{i + 1}"))
            self.s.insert(ts)

    def time_query(self, state_typ, _):
        self.s.query()

    time_query.number = 1


class StateMultiQueryAll:
    params = [_STATES, _BUFFER_SIZES]
    param_names = ["StateType", "#Queries"]
    timeout = 300

    def setup(self, state_typ, threshold):
        if state_typ == StateType.DEFAULT:
            disable_duckdb_state()
        elif state_typ == StateType.DUCKDB:
            enable_duckdb_state()
        self.s = State[CspStruct](keyby="a")
        modify_buffer_threshold(_BUFFER_THRESHOLD)
        for i in range(threshold):
            ts = CspStruct(a=i, b=f"{i}", f=MyEnum.A, h=[i, i, i], j={i: i}, g=CspSubStruct(suba=i + 1, subb=f"{i + 1}"))
            self.s.insert(ts)

    def time_query(self, state_typ, _):
        self.s.query()


class StateFirstQueryFilter:
    params = [_STATES, _BUFFER_SIZES]
    param_names = ["StateType", "#Queries"]
    timeout = 300

    def setup(self, state_typ, threshold):
        if state_typ == StateType.DEFAULT:
            disable_duckdb_state()
        elif state_typ == StateType.DUCKDB:
            enable_duckdb_state()
        self.s = State[CspStruct](keyby="a")
        modify_buffer_threshold(_BUFFER_THRESHOLD)
        for i in range(threshold):
            ts = CspStruct(a=i, b=f"{i}", f=MyEnum.A, h=[i, i, i], j={i: i}, g=CspSubStruct(suba=i + 1, subb=f"{i + 1}"))
            self.s.insert(ts)

    def time_query(self, state_typ, _):
        self.s.query(_QUERY)

    time_query.number = 1


class StateMultiQueryFilter:
    params = [_STATES, _BUFFER_SIZES]
    param_names = ["StateType", "#Queries"]
    timeout = 300

    def setup(self, state_typ, threshold):
        if state_typ == StateType.DEFAULT:
            disable_duckdb_state()
        elif state_typ == StateType.DUCKDB:
            enable_duckdb_state()
        self.s = State[CspStruct](keyby="a")
        modify_buffer_threshold(_BUFFER_THRESHOLD)
        for i in range(threshold):
            ts = CspStruct(a=i, b=f"{i}", f=MyEnum.A, h=[i, i, i], j={i: i}, g=CspSubStruct(suba=i + 1, subb=f"{i + 1}"))
            self.s.insert(ts)

    def time_query(self, state_typ, _):
        self.s.query(_QUERY)
