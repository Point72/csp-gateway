import time
import typing
from datetime import datetime, timedelta

import pytest
from csp import Enum, Struct

from csp_gateway import (
    Filter,
    FilterCondition,
    Query,
    State,
    StateType,
    disable_duckdb_state,
    enable_duckdb_state,
    modify_duckdb_threads,
    restore_duckdb_threads,
)
from csp_gateway.server.gateway.csp import state as state_module


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


class DeepLeaf(Struct):
    x: int = 0
    y: str = "y"
    unset_leaf: str  # intentionally left unset by default


class DeepMid(Struct):
    leaf: DeepLeaf = DeepLeaf()
    mid_val: int = 0
    unset_mid: DeepLeaf  # intentionally unset nested struct


class DeepRoot(Struct):
    mid: DeepMid = DeepMid()
    root_val: int = 0
    unset_root: DeepMid  # intentionally unset nested struct


@pytest.mark.parametrize("use_duckdb", [True, False])
def test_state_query_filter_string_with_single_quote(use_duckdb):
    """A string filter value containing a single quote must be handled identically on both backends
    (DuckDB SQL-escapes it) rather than silently dropped by a DuckDB parser error."""
    (enable_duckdb_state if use_duckdb else disable_duckdb_state)()
    try:
        s = State[CspStruct](keyby=("a",))
        s.insert(CspStruct(a=1, b="O'Brien"))
        s.insert(CspStruct(a=2, b="Smith"))
        q = Query(filters=[Filter(attr="b", by=FilterCondition(value="O'Brien", where="=="))])
        res = s.query(q)
        assert [r.a for r in res] == [1]
    finally:
        enable_duckdb_state()


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


def test_state_keyby_nested():
    """keyby on a dotted path into a nested struct must resolve per-record (no collapse)."""
    for specialization, struct_type in zip(_STATES, _STRUCTS):
        s = State[struct_type](keyby=("g.suba",))
        assert s.state_type() == specialization
        ts1 = struct_type(a=0, b="hello", g=CspSubStruct(suba=1, subb="one"))
        ts2 = struct_type(a=1, b="bye", g=CspSubStruct(suba=2, subb="two"))
        # ts3 shares g.suba with ts1, so it should replace ts1 rather than create a new slot.
        ts3 = struct_type(a=2, b="later", g=CspSubStruct(suba=1, subb="one-updated"))
        s.insert(ts1)
        s.insert(ts2)
        s.insert(ts3)
        res = s.query()
        assert len(res) == 2
        by_suba = {r.g.suba: r for r in res}
        assert by_suba[1] is ts3
        assert by_suba[2] is ts2


def test_get_keyby_value_paths():
    """Unit-test the dotted-path keyby resolver: depth, missing segments, and edge cases."""
    gkv = state_module._get_keyby_value
    root = DeepRoot(root_val=7, mid=DeepMid(mid_val=3, leaf=DeepLeaf(x=5, y="hi")))

    # flat and increasingly deep valid paths
    assert gkv(root, "root_val") == 7
    assert gkv(root, "mid.mid_val") == 3
    assert gkv(root, "mid.leaf.x") == 5
    assert gkv(root, "mid.leaf.y") == "hi"

    # a falsy-but-present leaf value must be preserved (not treated as missing)
    assert gkv(DeepRoot(mid=DeepMid(leaf=DeepLeaf(x=0))), "mid.leaf.x") == 0

    # missing top-level attribute
    assert gkv(root, "nope") is None
    # missing leaf attribute on an otherwise-valid intermediate
    assert gkv(root, "mid.leaf.nope") is None
    # declared but unset scalar leaf
    assert gkv(root, "mid.leaf.unset_leaf") is None
    # unset intermediate struct short-circuits (does not raise)
    assert gkv(root, "unset_root.mid_val") is None
    assert gkv(root, "mid.unset_mid.x") is None
    # attempting to descend into a scalar returns None (does not raise)
    assert gkv(root, "mid.mid_val.x") is None


@pytest.mark.parametrize("use_duckdb", [True, False])
def test_state_keyby_deeply_nested(use_duckdb):
    """keyby on a 3-level dotted path resolves per-record on both state backends."""
    (enable_duckdb_state if use_duckdb else disable_duckdb_state)()
    try:
        s = State[DeepRoot](keyby=("mid.leaf.x",))
        assert s.state_type() == (StateType.DUCKDB if use_duckdb else StateType.DEFAULT)
        r1 = DeepRoot(root_val=1, mid=DeepMid(leaf=DeepLeaf(x=10)))
        r2 = DeepRoot(root_val=2, mid=DeepMid(leaf=DeepLeaf(x=20)))
        # r3 shares mid.leaf.x with r1, so it must replace r1 rather than create a new slot.
        r3 = DeepRoot(root_val=3, mid=DeepMid(leaf=DeepLeaf(x=10)))
        s.insert(r1)
        s.insert(r2)
        s.insert(r3)
        res = s.query()
        assert len(res) == 2
        by_x = {r.mid.leaf.x: r for r in res}
        assert by_x[10] is r3
        assert by_x[20] is r2
    finally:
        enable_duckdb_state()


@pytest.mark.parametrize("use_duckdb", [True, False])
@pytest.mark.parametrize(
    "missing_key",
    [
        "nope",  # missing top-level attribute
        "mid.leaf.nope",  # missing leaf attribute on a valid intermediate
        "mid.leaf.unset_leaf",  # declared but unset scalar leaf
        "unset_root.mid_val",  # unset intermediate struct
        "mid.unset_mid.x",  # deep path through an unset intermediate struct
        "mid.mid_val.x",  # descending into a scalar
    ],
)
def test_state_keyby_unresolvable_path_collapses(use_duckdb, missing_key):
    """A keyby path that cannot be resolved keys every record under None (last write wins),
    matching the behaviour of an unset flat key -- and never raises."""
    (enable_duckdb_state if use_duckdb else disable_duckdb_state)()
    try:
        s = State[DeepRoot](keyby=(missing_key,))
        r1 = DeepRoot(root_val=1, mid=DeepMid(leaf=DeepLeaf(x=10)))
        r2 = DeepRoot(root_val=2, mid=DeepMid(leaf=DeepLeaf(x=20)))
        s.insert(r1)
        s.insert(r2)
        res = s.query()
        assert len(res) == 1
        assert res[0] is r2
    finally:
        enable_duckdb_state()


@pytest.mark.parametrize("use_duckdb", [True, False])
def test_state_query_nested_filter(use_duckdb):
    """State.query filtering by a dotted path into a nested struct works on both backends."""
    (enable_duckdb_state if use_duckdb else disable_duckdb_state)()
    try:
        s = State[DeepRoot](keyby=("root_val",))
        r1 = DeepRoot(root_val=1, mid=DeepMid(leaf=DeepLeaf(x=10)))
        r2 = DeepRoot(root_val=2, mid=DeepMid(leaf=DeepLeaf(x=20)))
        r3 = DeepRoot(root_val=3, mid=DeepMid(leaf=DeepLeaf(x=10)))
        for r in (r1, r2, r3):
            s.insert(r)
        q = Query(filters=[Filter(attr="mid.leaf.x", by=FilterCondition(value=10, where="=="))])
        res = s.query(q)
        assert sorted(r.root_val for r in res) == [1, 3]
    finally:
        enable_duckdb_state()


@pytest.mark.parametrize("use_duckdb", [True, False])
@pytest.mark.parametrize(
    "where, value, expected",
    [
        ("==", 30, [3]),
        ("!=", 30, [1, 2, 4, 5]),
        (">", 25, [3, 4, 5]),
        (">=", 30, [3, 4, 5]),
        ("<", 25, [1, 2]),
        ("<=", 20, [1, 2]),
    ],
)
def test_state_query_nested_filter_operators(use_duckdb, where, value, expected):
    """Every comparison operator on a nested attr returns the correct (possibly multiple) rows,
    identically on both backends. Expected sets are non-empty, so a silently-failing DuckDB query
    (State.query swallows exceptions to []) would fail the assertion rather than pass."""
    (enable_duckdb_state if use_duckdb else disable_duckdb_state)()
    try:
        s = State[DeepRoot](keyby=("root_val",))
        for rv, x in zip(range(1, 6), [10, 20, 30, 40, 50]):
            s.insert(DeepRoot(root_val=rv, mid=DeepMid(leaf=DeepLeaf(x=x))))
        q = Query(filters=[Filter(attr="mid.leaf.x", by=FilterCondition(value=value, where=where))])
        res = s.query(q)
        assert sorted(r.root_val for r in res) == expected
    finally:
        enable_duckdb_state()


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


def test_duckdb_states_share_single_connection():
    # All DuckDBState objects must operate on cursors of one shared DuckDB instance so that the
    # worker-thread pool is created once for the process instead of once per Struct channel.
    enable_duckdb_state()
    states = [State[CspStruct](keyby=("a",)) for _ in range(5)]
    for s in states:
        assert s.state_type() == StateType.DUCKDB

    shared = state_module._DUCKDB_SHARED_CONNECTION
    assert shared is not None
    # Every state gets its own cursor (needed to avoid pending-result errors), but they all share
    # one underlying DuckDB instance. Prove the instance -- and therefore its catalog and worker
    # pool -- is shared by reading one state's table through another state's cursor.
    for s in states:
        assert s._state_impl._con is not shared
    table0 = states[0]._state_impl._table_name
    assert states[1]._state_impl._con.sql(f"SELECT count(*) FROM '{table0}'").fetchall() == [(0,)]

    # Interleaved inserts/queries across states return correct, isolated results.
    for i, s in enumerate(states):
        s.insert(CspStruct(a=i, b=f"v{i}"))
    for i, s in enumerate(reversed(states)):
        idx = len(states) - 1 - i
        res = s.query()
        assert res == [CspStruct(a=idx, b=f"v{idx}")]


def test_modify_and_restore_duckdb_threads():
    enable_duckdb_state()
    try:
        # Create a state so the shared instance exists.
        State[CspStruct](keyby=("a",))
        shared = state_module._DUCKDB_SHARED_CONNECTION
        assert shared is not None

        def current_threads():
            return shared.sql("SELECT current_setting('threads')").fetchall()[0][0]

        assert current_threads() == state_module._DUCKDB_THREADS_ORIGINAL

        modify_duckdb_threads(4)
        assert state_module._DUCKDB_THREADS_CURRENT == 4
        assert current_threads() == 4

        restore_duckdb_threads()
        assert state_module._DUCKDB_THREADS_CURRENT == state_module._DUCKDB_THREADS_ORIGINAL
        assert current_threads() == state_module._DUCKDB_THREADS_ORIGINAL

        try:
            modify_duckdb_threads(0)
            raise AssertionError("expected ValueError for non-positive thread count")
        except ValueError:
            pass
    finally:
        restore_duckdb_threads()


def test_duckdb_threads_spawn_expected_os_threads():
    # Verify two properties against real OS threads:
    #   1. DuckDBState objects share one DuckDB instance, so creating many state tables adds zero
    #      extra threads.
    #   2. The thread knob spawns exactly (threads - 1) background workers on that shared instance.
    psutil = pytest.importorskip("psutil")
    enable_duckdb_state()
    proc = psutil.Process()

    def settled_num_threads(timeout=5.0):
        # DuckDB reaps/spawns workers slightly asynchronously on some platforms; return the OS thread
        # count once it has stopped changing so the baseline is stable.
        deadline = time.monotonic() + timeout
        prev = proc.num_threads()
        time.sleep(0.05)
        cur = proc.num_threads()
        while cur != prev and time.monotonic() < deadline:
            prev = cur
            time.sleep(0.05)
            cur = proc.num_threads()
        return cur

    def wait_for_delta(base, expected, timeout=10.0):
        # Poll until the OS thread delta settles at the expected value to tolerate slow machines.
        deadline = time.monotonic() + timeout
        delta = proc.num_threads() - base
        while delta != expected and time.monotonic() < deadline:
            time.sleep(0.02)
            delta = proc.num_threads() - base
        return delta

    try:
        # Establish the zero-worker baseline before creating any state objects. The shared instance
        # persists for the process, so pin it to threads=1 (0 background workers) and let the OS thread
        # count settle before snapshotting.
        modify_duckdb_threads(1)
        base = settled_num_threads()

        # Property 1: state tables share one instance and so add zero extra OS threads.
        states = [State[CspStruct](keyby=("a",)) for _ in range(8)]
        assert all(s.state_type() == StateType.DUCKDB for s in states)
        assert wait_for_delta(base, 0) == 0, "creating state tables must not spawn per-state worker pools"

        # Property 2: the knob spawns exactly (threads - 1) background workers, regardless of how many
        # state tables exist.
        for num_threads in (2, 4, 8):
            modify_duckdb_threads(num_threads)
            delta = wait_for_delta(base, num_threads - 1)
            assert delta == num_threads - 1, f"threads={num_threads}: expected {num_threads - 1} extra OS threads, saw {delta}"

        # Lowering the knob reaps the workers back down to the baseline.
        modify_duckdb_threads(1)
        assert wait_for_delta(base, 0) == 0
    finally:
        restore_duckdb_threads()
