import json
import threading
import time
from datetime import UTC, datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any

import pytest
import starlette.responses
from pydantic import BaseModel, ConfigDict, Field, PlainSerializer, TypeAdapter, computed_field, field_serializer
from pydantic_core import PydanticSerializationError, SchemaSerializer

from csp_gateway import GatewayStruct
from csp_gateway.server.demo import ExampleData
from csp_gateway.server.web import prepare_response
from csp_gateway.server.web.routes.shared import get_fully_qualified_type_name
from csp_gateway.utils.struct import base
from csp_gateway.utils.struct.base import type_adapter_for


def test_prepare_response():
    data = ExampleData()
    response = prepare_response(res=data, is_list_model=False, is_dict_basket=False, wrap_in_response=True)
    assert isinstance(response, starlette.responses.Response)
    response = prepare_response(res=data, is_list_model=False, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]


def test_prepare_response_list():
    data = ExampleData()
    response = prepare_response(res=[data], is_list_model=False, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]
    response = prepare_response(res=[data], is_list_model=True, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]
    response = prepare_response(res=(data,), is_list_model=True, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]


def test_prepare_response_dict():
    data = ExampleData()
    with pytest.raises(AttributeError):
        prepare_response(res={"foo": data}, is_list_model=False, is_dict_basket=False, wrap_in_response=False)

    response = prepare_response(res={"foo": data}, is_list_model=False, is_dict_basket=True, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]


def test_get_fully_qualified_type_name_with_model():
    """Test that get_fully_qualified_type_name returns the correct fully qualified type name."""
    fq_name = get_fully_qualified_type_name(ExampleData)
    assert fq_name == "csp_gateway.server.demo.omnibus.ExampleData"


def test_get_fully_qualified_type_name_with_list_model():
    """Test that get_fully_qualified_type_name extracts the type from a List."""
    fq_name = get_fully_qualified_type_name(list[ExampleData])
    assert fq_name == "csp_gateway.server.demo.omnibus.ExampleData"


def test_get_fully_qualified_type_name_with_none():
    """Test that get_fully_qualified_type_name returns empty string for None."""
    fq_name = get_fully_qualified_type_name(None)
    assert fq_name == ""


class _Color(Enum):
    RED = 1
    BLUE = 2


class _Inner(GatewayStruct):
    label: str = ""
    values: list[float] = []


class _Record(GatewayStruct):
    x: int = 0
    f: float = 0.0
    color: _Color = _Color.RED
    maybe: str | None = None
    aware: datetime = datetime(2026, 1, 1, tzinfo=UTC)
    naive: datetime = datetime(2026, 1, 1)
    inner: _Inner = _Inner()
    inners: list[_Inner] = []


class _SubRecord(_Record):
    extra: str = "sub"


class _Model(BaseModel):
    a: int = 1


def _old_dump(res):
    """The per-record serialization prepare_response used before batching."""
    return b"[" + b",".join(type_adapter_for(r).dump_json(r) for r in res) + b"]"


def _records():
    floats = [1.5, float("nan"), float("inf"), float("-inf"), -0.0]
    return [
        _Record(
            x=i,
            f=floats[i % len(floats)],
            color=_Color.BLUE if i % 2 else _Color.RED,
            maybe=None if i % 3 else f"m{i}",
            aware=datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=-5))) + timedelta(seconds=i),
            naive=datetime(2026, 1, 1) + timedelta(microseconds=i),
            inner=_Inner(label=f"in{i}", values=[float(i), float("nan")]),
            inners=[_Inner(label=str(j)) for j in range(i % 3)],
        )
        for i in range(20)
    ]


@pytest.mark.parametrize(
    "res",
    [
        pytest.param(_records(), id="same_type"),
        pytest.param([_Record()], id="single"),
        pytest.param([_Record(), _SubRecord(extra="x"), _Record()], id="mixed_subclass"),
        pytest.param([_SubRecord(), _SubRecord()], id="all_subclass"),
        pytest.param([_Model(a=1), _Model(a=2)], id="plain_pydantic"),
        pytest.param([ExampleData(x=1), ExampleData(x=2)], id="example_data"),
    ],
)
def test_prepare_response_bytes_match_per_record(res):
    expected = _old_dump(res)
    response = prepare_response(res=res, is_list_model=True)
    assert response.body == expected
    assert prepare_response(res=res, is_list_model=True, wrap_in_response=False) == expected.decode()


def test_prepare_response_mixed_subclass_keeps_subclass_fields():
    body = json.loads(prepare_response(res=[_Record(), _SubRecord(extra="x")], is_list_model=True).body)
    assert "extra" not in body[0]
    assert body[1]["extra"] == "x"


def test_prepare_response_empty():
    assert prepare_response(res=[], is_list_model=True).body == b"[]"
    assert prepare_response(res=None, wrap_in_response=False) == "[]"


class _Child(GatewayStruct):
    q: int


class _Aliased(GatewayStruct):
    model_config = ConfigDict(serialize_by_alias=True)
    id: str = Field(default=None, alias="record_id")
    timestamp: datetime | None = Field(default=None, serialization_alias="event_time")
    a: int
    b: str = "x"
    child: _Child = None


class _Required(GatewayStruct):
    a: int
    child: _Child = None


class _OwnUnset(GatewayStruct):
    a: int

    def _implicitly_unset(self):
        return set()


class _EpochTimestamps(GatewayStruct):
    model_config = ConfigDict(ser_json_temporal="seconds")


class _InfNan(GatewayStruct):
    model_config = ConfigDict(ser_json_inf_nan="strings")
    f: float = float("inf")


class _Untyped(GatewayStruct):
    # Values in an untyped field are serialized by inspection, which is where the struct's config
    # (ser_json_timedelta="float") is easy to lose.
    data: Any = None
    deltas: list[timedelta] = []


class _OwnTimestamp(GatewayStruct):
    timestamp: Annotated[datetime | None, PlainSerializer(lambda v: "own", when_used="json")] = None


class _OwnSetTimestamp(GatewayStruct):
    # Always set, so its serializer never sees an unset None; only the timestamp shape check keeps it.
    timestamp: Annotated[datetime, PlainSerializer(lambda v: "own", when_used="json")] = datetime(2020, 1, 1)


class _UnsetSerializer(GatewayStruct):
    a: int

    @field_serializer("a")
    def _double(self, value):
        return value * 2


class _SharedKey(GatewayStruct):
    model_config = ConfigDict(serialize_by_alias=True)
    a: int = Field(default=None, serialization_alias="b")
    b: int = 3


class _Extra(GatewayStruct):
    model_config = ConfigDict(extra="allow")
    a: int


class _IsoDatetime(datetime):
    def isoformat(self, *args, **kwargs):
        return "custom"


def _cases():
    aware = datetime(2020, 1, 1, tzinfo=timezone(timedelta(hours=5)))
    return [
        pytest.param(_records(), id="record"),
        pytest.param([_Required(a=1), _Required.from_field_values(a=2), _Required.from_field_values()], id="implicitly_unset"),
        pytest.param([_Required.from_field_values(timestamp=None), _Required.from_field_values(id=None)], id="explicit_none_identity"),
        pytest.param(
            [
                _Required(a=1, child=_Child(q=1)),
                _Required.from_field_values(child={"q": 2}),
                _Required.from_field_values(child=_Child.from_field_values()),
            ],
            id="nested_unset",
        ),
        pytest.param([_Aliased(a=1), _Aliased.from_field_values(), _Aliased(a=2, timestamp=aware)], id="aliased_aware"),
        pytest.param([_Required(a=i, timestamp=datetime(2020, 1, 1, 0, 0, i)) for i in range(3)], id="naive"),
        pytest.param([_Required(a=1), _Required(a=2, timestamp=datetime(2020, 1, 1, tzinfo=UTC)), _Required(a=3)], id="naive_aware_naive"),
        pytest.param([_Required.model_construct(a=1)], id="model_construct"),
        pytest.param([GatewayStruct(), GatewayStruct.from_field_values()], id="bare"),
        pytest.param([_OwnUnset(a=1)], id="overridden_implicitly_unset"),
        pytest.param([_EpochTimestamps()], id="non_iso_temporal"),
        pytest.param([_InfNan(), _InfNan(f=float("nan"))], id="inf_nan_config"),
        pytest.param(
            [_Untyped(data={"now": datetime(2026, 1, 1), "delta": timedelta(seconds=3)}, deltas=[timedelta(days=1)])],
            id="untyped_temporal_config",
        ),
        pytest.param([_OwnTimestamp(timestamp=datetime(2020, 1, 1))], id="own_timestamp_serializer"),
        pytest.param([_Required(a=1, timestamp=_IsoDatetime(2020, 1, 1))], id="datetime_subclass"),
        pytest.param([_OwnSetTimestamp(id="1")], id="own_timestamp_serializer_always_set"),
        pytest.param([_UnsetSerializer(a=1), _UnsetSerializer.from_field_values()], id="serializer_on_unset_field"),
        pytest.param([_SharedKey.from_field_values(b=3)], id="alias_shares_key"),
        pytest.param([_Extra(a=1, z=2)], id="extra_fields"),
    ]


def _outcome(dump, res):
    """The bytes ``dump`` produces, or the type of what it raises."""
    try:
        return dump(res)
    except Exception as err:  # noqa: BLE001
        return type(err)


@pytest.mark.parametrize("res", _cases())
def test_prepare_response_list_fast_path_matches_per_record(res):
    assert _outcome(lambda r: prepare_response(res=r, is_list_model=True).body, res) == _outcome(_old_dump, res)


def test_prepare_response_pandas_timestamps_match_per_record():
    pd = pytest.importorskip("pandas")
    res = [_Required(a=1, timestamp=pd.Timestamp("2020-01-01 00:00:00.123456789")), _Required(a=2, timestamp=pd.NaT), _Required(a=3)]
    assert prepare_response(res=res, is_list_model=True).body == _old_dump(res)


def test_prepare_response_bad_timestamp_still_raises():
    record = _Required(a=1)
    record.timestamp = "2020-01-01"
    with pytest.raises(PydanticSerializationError):
        _old_dump([record])
    with pytest.raises(PydanticSerializationError):
        prepare_response(res=[record], is_list_model=True)


def test_list_serializers_fall_back_where_output_could_differ():
    assert _Required._list_serializers() is not None
    # A serializer that would see an unset field's None (here `_OwnTimestamp`'s own on `timestamp`),
    # a key two fields share, extra fields, or an overridden `_implicitly_unset`.
    for cls in (_OwnUnset, _UnsetSerializer, _OwnTimestamp, _SharedKey, _Extra):
        assert cls._list_serializers() is None, cls
    # A non-ISO temporal config keeps the timestamp serializer on every run.
    serializers = _EpochTimestamps._list_serializers()
    assert serializers is not None and serializers[True] is serializers[False]


class _Node(GatewayStruct):
    label: str = ""
    parent: "_Node" = None


class _Holder(GatewayStruct):
    child: _Record = None


class _UncopyableDefault(GatewayStruct):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    a: int = 0
    # A plain default lives in the core schema itself, and a lock cannot be deep-copied.
    lock: Any = Field(default=threading.Lock(), exclude=True)


@pytest.mark.parametrize(
    "res",
    [
        pytest.param([_Node(label="a", parent=_Node(label="b")), _Node.from_field_values(label="c")], id="self_referential"),
        pytest.param([_Holder(child=_Record(aware=datetime(2020, 1, 1, tzinfo=UTC))), _Holder.from_field_values()], id="nested_aware_child"),
        pytest.param(
            [_Holder(timestamp=datetime(2020, 1, 1), child=_Record(timestamp=datetime(2020, 1, 1, tzinfo=timezone(timedelta(hours=3)))))],
            id="naive_parent_aware_child_timestamp",
        ),
        pytest.param([_UncopyableDefault(a=1), _UncopyableDefault(a=2)], id="uncopyable_default"),
    ],
)
def test_prepare_response_list_fast_path_nested(res):
    assert prepare_response(res=res, is_list_model=True).body == _old_dump(res)


def test_list_serializers_leave_class_schema_untouched():
    before = repr(_Required.__pydantic_core_schema__)
    _Required._list_serializers()
    assert repr(_Required.__pydantic_core_schema__) == before
    assert _Required(a=1).model_dump_json().startswith('{"id":')


def test_list_fast_path_runs_and_chunks(monkeypatch):
    # More records than one chunk, with the unset fields changing midway, so runs split both ways.
    monkeypatch.setattr(base, "_DUMP_CHUNK", 7)
    calls = []
    to_json = base._BoundSerializer.to_json
    monkeypatch.setattr(
        base._BoundSerializer, "to_json", lambda self, records, exclude: calls.append(len(records)) or to_json(self, records, exclude)
    )
    res = [_Required.from_field_values(id=str(i)) for i in range(20)] + [_Required(a=i) for i in range(20)]
    assert _Required._dump_json_list(res) == _old_dump(res)
    assert calls == [7, 7, 6, 7, 7, 6]


def test_list_fast_path_ignores_core_by_alias_default(monkeypatch):
    # Older pydantic-core defaults `to_json(by_alias=...)` to True; the fast path must not inherit that.
    class _AliasByDefault:
        def __init__(self, *args):
            self._serializer = SchemaSerializer(*args)

        def to_json(self, value, by_alias=True, **kwargs):
            return self._serializer.to_json(value, by_alias=by_alias, **kwargs)

    class _Renamed(GatewayStruct):
        a: int = Field(default=None, serialization_alias="renamed")

    monkeypatch.setattr(base, "SchemaSerializer", _AliasByDefault)
    res = [_Renamed(a=1)]
    assert _Renamed._dump_json_list(res) == _old_dump(res)
    assert b"renamed" not in _old_dump(res)


class _RedactingAdapter(TypeAdapter):
    def dump_json(self, instance, **kwargs):
        return super().dump_json(instance, exclude={"secret"}, **kwargs)


class _OwnAdapter(GatewayStruct):
    public: str = "visible"
    secret: str = "private"

    @classmethod
    def type_adapter(cls):
        return _RedactingAdapter(cls)


def test_list_fast_path_keeps_model_owned_adapter():
    # A struct's own `type_adapter` is what per-record dumping uses, so the batch must not bypass it.
    res = [_OwnAdapter.from_field_values()]
    assert _OwnAdapter._list_serializers() is None
    assert prepare_response(res=res, is_list_model=True).body == _old_dump(res) == b'[{"public":"visible"}]'


class _AliasedChild(GatewayStruct):
    model_config = ConfigDict(serialize_by_alias=True)
    value: int = Field(default=1, serialization_alias="renamed")


class _UnaliasedChild(GatewayStruct):
    value: int = Field(default=1, serialization_alias="renamed")


class _AliasedParent(GatewayStruct):
    model_config = ConfigDict(serialize_by_alias=True)
    child: _UnaliasedChild
    value: int = Field(default=1, serialization_alias="mine")


class _ParentOfAliased(GatewayStruct):
    child: _AliasedChild


@pytest.mark.parametrize(
    "res",
    [
        pytest.param([_ParentOfAliased.from_field_values(child=_AliasedChild.from_field_values())], id="child_by_alias"),
        pytest.param([_AliasedParent.from_field_values(child=_UnaliasedChild.from_field_values())], id="parent_by_alias"),
    ],
)
def test_list_fast_path_keeps_nested_alias_config(res):
    # Each model applies its own `serialize_by_alias`; the parent's must not be forced onto its children.
    assert _list_serializers_of(res) is not None
    assert prepare_response(res=res, is_list_model=True).body == _old_dump(res)


class _ComputedSharesKey(GatewayStruct):
    model_config = ConfigDict(serialize_by_alias=True)
    value: int

    @computed_field(alias="value")
    @property
    def computed(self) -> int:
        return 42


class _ComputedOwnKey(GatewayStruct):
    value: int

    @computed_field
    @property
    def computed(self) -> int:
        return 42


def test_list_fast_path_guards_computed_field_keys():
    # Popping an unset field's key also drops a computed field emitted under that key; excluding it does not.
    res = [_ComputedSharesKey.from_field_values()]
    assert _ComputedSharesKey._list_serializers() is None
    assert prepare_response(res=res, is_list_model=True).body == _old_dump(res) == b"[{}]"
    # A computed field under its own key keeps the fast path.
    res = [_ComputedOwnKey.from_field_values(), _ComputedOwnKey(value=1)]
    assert _ComputedOwnKey._list_serializers() is not None
    assert prepare_response(res=res, is_list_model=True).body == _old_dump(res)


def _list_serializers_of(res):
    return type(res[0])._list_serializers()


def test_list_fast_path_shared_unset_scales_linearly():
    # Every record leaves `a` and `child` unset. A per-index exclude made this quadratic in pydantic-core.
    res = [_Required.from_field_values(id=str(i)) for i in range(20_000)]
    start = time.perf_counter()
    body = prepare_response(res=res, is_list_model=True).body
    assert time.perf_counter() - start < 2
    assert body == _old_dump(res)
