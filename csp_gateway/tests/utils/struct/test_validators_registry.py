"""Tests for the unified GatewayStruct validator registry (``add_validator`` / ``clear_validators``).

Validators run automatically during pydantic validation (REST ``/send``,
``type_adapter().validate_python``, JSON snapshot replay, Kafka and filedrop ingestion) and for nested
structs when a containing struct is validated. A validator ``fn(value) -> value`` returns the (possibly
transformed) value and raises ``ValueError`` to reject it; ``mode="before"`` (alias ``"pre"``) runs on the
raw input prior to construction, ``mode="after"`` (alias ``"post"``, default) on the constructed struct.
They do NOT run on native ``MyStruct(...)`` construction.
"""

import pytest
from pydantic import TypeAdapter, ValidationError

from csp_gateway.utils.struct import GatewayStruct


def _bump(s, by=10):
    s2 = s.copy()
    s2.a = s.a + by
    return s2


def _set_a(s, a):
    s2 = s.copy()
    s2.a = a
    return s2


def _set_v(c, v):
    c2 = c.copy()
    c2.v = v
    return c2


def test_after_validator_can_transform_during_validation():
    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda s: _set_a(s, s.a * 10), mode="after")
    assert TypeAdapter(S).validate_python({"a": 5}).a == 50


def test_before_validator_reshapes_raw_input():
    class S(GatewayStruct):
        a: int = 0

    # A "before" validator that accepts a legacy key `old_a` and folds it into `a` (like coercion).
    S.add_validator(lambda d: {**{k: v for k, v in d.items() if k != "old_a"}, "a": d["old_a"]} if "old_a" in d else d, mode="before")
    assert TypeAdapter(S).validate_python({"old_a": 7}).a == 7


def test_after_is_the_default_mode():
    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda s: _bump(s))  # no mode -> "after"
    assert TypeAdapter(S).validate_python({"a": 1}).a == 11


def test_validator_rejects_by_raising():
    class S(GatewayStruct):
        a: int = 0

    def _reject_neg(s):
        if s.a < 0:
            raise ValueError("a<0")
        return s

    S.add_validator(_reject_neg)
    assert TypeAdapter(S).validate_python({"a": 1}).a == 1
    with pytest.raises(ValidationError, match="a<0"):
        TypeAdapter(S).validate_python({"a": -1})


def test_before_validator_rejects_by_raising():
    class S(GatewayStruct):
        a: int = 0

    def _reject(d):
        if isinstance(d, dict) and d.get("a", 0) < 0:
            raise ValueError("pre-reject")
        return d

    S.add_validator(_reject, mode="before")
    assert TypeAdapter(S).validate_python({"a": 1}).a == 1
    with pytest.raises(ValidationError, match="pre-reject"):
        TypeAdapter(S).validate_python({"a": -1})


def test_runs_on_pydantic_path_only_not_native_construction():
    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda s: _set_a(s, 999), mode="after")
    assert TypeAdapter(S).validate_python({"a": 1}).a == 999  # pydantic path
    assert S(a=1).a == 1  # native construction bypasses validators


def test_pre_and_post_are_aliases_for_before_and_after():
    calls = []

    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda d: (calls.append("pre"), d)[1], mode="pre")
    S.add_validator(lambda s: (calls.append("post"), s)[1], mode="post")
    TypeAdapter(S).validate_python({"a": 1})
    assert calls == ["pre", "post"]  # pre==before (pre-construction), post==after


def test_mro_aggregation_before_then_after_base_then_child():
    calls = []

    class Base(GatewayStruct):
        a: int = 0

    class Child(Base):
        b: int = 0

    Base.add_validator(lambda d: (calls.append("pre-base"), d)[1], mode="before")
    Child.add_validator(lambda d: (calls.append("pre-child"), d)[1], mode="before")
    Base.add_validator(lambda s: (calls.append("post-base"), s)[1], mode="after")
    Child.add_validator(lambda s: (calls.append("post-child"), s)[1], mode="after")

    TypeAdapter(Child).validate_python({"a": 1, "b": 2})
    # before (base then child) run before construction; after (base then child) after.
    assert calls == ["pre-base", "pre-child", "post-base", "post-child"]


def test_child_validator_does_not_leak_to_base():
    class Base(GatewayStruct):
        a: int = 0

    class Child(Base):
        b: int = 0

    def _reject(s):
        raise ValueError("child-only")

    Child.add_validator(_reject)
    with pytest.raises(ValidationError, match="child-only"):
        TypeAdapter(Child).validate_python({"a": 0})
    assert TypeAdapter(Base).validate_python({"a": 0}).a == 0  # base unaffected


def test_isolation_between_sibling_classes():
    class A(GatewayStruct):
        x: int = 0

    class B(GatewayStruct):
        x: int = 0

    def _reject(s):
        raise ValueError("only-A")

    A.add_validator(_reject)
    assert TypeAdapter(B).validate_python({"x": 5}).x == 5
    with pytest.raises(ValidationError, match="only-A"):
        TypeAdapter(A).validate_python({"x": 5})


def test_runs_even_when_after_hook_overridden_without_super():
    # A subclass may override _validate_gateway_struct_after without calling super(). The registry must
    # STILL run because it executes in the wrap validator (_validate_gateway_struct), not the after hook.
    class S(GatewayStruct):
        a: int = 0

        @classmethod
        def _validate_gateway_struct_after(cls, val):
            return val

    ran = []
    S.add_validator(lambda s: (ran.append(1), s)[1])
    TypeAdapter(S).validate_python({"a": 1})
    assert ran, "registry must run even when the after hook is overridden without super()"


def test_validator_runs_exactly_once():
    class S(GatewayStruct):
        a: int = 0

    count = []
    S.add_validator(lambda s: (count.append(1), s)[1])
    TypeAdapter(S).validate_python({"a": 1})
    assert len(count) == 1


def test_after_validators_run_before_the_after_hook():
    # An after-validator may fix data that the after-hook then checks -> it must run first.
    class S(GatewayStruct):
        a: int = 0

        @classmethod
        def _validate_gateway_struct_after(cls, val):
            if val.a < 10:
                raise ValueError("hook: a<10")
            return val

    S.add_validator(lambda s: _set_a(s, s.a + 100), mode="after")
    assert TypeAdapter(S).validate_python({"a": 1}).a == 101  # bumped before the hook checked it


def test_after_hook_and_registered_validator_both_enforced():
    class S(GatewayStruct):
        a: int = 0
        b: int = 0

        @classmethod
        def _validate_gateway_struct_after(cls, val):
            if val.a < 0:
                raise ValueError("hook: a<0")
            return val

    def _reject_b(s):
        if s.b < 0:
            raise ValueError("validator: b<0")
        return s

    S.add_validator(_reject_b)
    with pytest.raises(ValidationError, match="validator: b<0"):
        TypeAdapter(S).validate_python({"a": 0, "b": -1})
    with pytest.raises(ValidationError, match="hook: a<0"):
        TypeAdapter(S).validate_python({"a": -1, "b": 0})
    assert TypeAdapter(S).validate_python({"a": 1, "b": 1}).a == 1


def test_multiple_after_validators_run_in_order_first_raise_wins():
    class S(GatewayStruct):
        a: int = 0

    order = []

    def _first(s):
        order.append("first")
        if s.a == 1:
            raise ValueError("stop")
        return s

    def _second(s):
        order.append("second")
        return s

    S.add_validator(_first)
    S.add_validator(_second)
    TypeAdapter(S).validate_python({"a": 0})
    assert order == ["first", "second"]
    order.clear()
    with pytest.raises(ValidationError, match="stop"):
        TypeAdapter(S).validate_python({"a": 1})
    assert order == ["first"]  # short-circuits on first raise


def test_after_validators_transform_then_reject():
    class S(GatewayStruct):
        a: int = 0

    def _require_ge_10(s):
        if s.a < 10:
            raise ValueError("too-small")
        return s

    # first bumps into range, second accepts
    S.add_validator(lambda s: _set_a(s, s.a + 100), mode="after")
    S.add_validator(_require_ge_10)
    assert TypeAdapter(S).validate_python({"a": 1}).a == 101

    # a transform that breaks the struct is caught by the reject validator
    S.clear_validators()
    S.add_validator(lambda s: _set_a(s, -1), mode="after")
    S.add_validator(_require_ge_10)
    with pytest.raises(ValidationError, match="too-small"):
        TypeAdapter(S).validate_python({"a": 500})


def test_no_validators_is_noop():
    class S(GatewayStruct):
        a: int = 0

    assert TypeAdapter(S).validate_python({"a": 7}).a == 7


def test_bare_decorator_registers_after_validator():
    class S(GatewayStruct):
        a: int = 0

    @S.add_validator
    def _v(s):
        return _bump(s, 1)

    assert _v(S(a=1)).a == 2  # the decorator returns the function itself, still directly callable
    assert TypeAdapter(S).validate_python({"a": 1}).a == 2


def test_decorator_factory_with_mode():
    class S(GatewayStruct):
        a: int = 0

    @S.add_validator(mode="before")
    def _pre(d):
        return {**d, "a": d.get("a", 0) + 5}

    assert _pre({"a": 1}) == {"a": 6}  # the factory also returns the function itself
    assert TypeAdapter(S).validate_python({"a": 1}).a == 6


def test_bound_method_validator_registered_by_another_object():
    # "some other object registers a validator and passes in a bound method that needs to be called"
    class Enricher:
        def __init__(self, bump):
            self.bump = bump

        def enrich(self, s):
            return _bump(s, self.bump)

    class S(GatewayStruct):
        a: int = 0

    S.add_validator(Enricher(bump=100).enrich, mode="after")  # bound method captured at registration
    assert TypeAdapter(S).validate_python({"a": 1}).a == 101


def test_manual_call_on_csp_path():
    # Native/CSP construction does NOT auto-run validators; they can be invoked explicitly.
    class S(GatewayStruct):
        a: int = 0

    def _reject_neg(s):
        if s.a < 0:
            raise ValueError("neg")
        return s

    S.add_validator(_reject_neg)
    assert S.run_validators(S(a=1)).a == 1
    with pytest.raises(ValueError, match="neg"):
        S.run_validators(S(a=-1))


class _VChild(GatewayStruct):
    v: int = 0


class _VParent(GatewayStruct):
    child: _VChild
    name: str = ""


def test_nested_struct_validator_rejects_on_parent_validation():
    def _reject(c):
        if c.v < 0:
            raise ValueError("child-bad")
        return c

    _VChild.add_validator(_reject)
    try:
        with pytest.raises(ValidationError, match="child-bad"):
            TypeAdapter(_VParent).validate_python({"name": "p", "child": {"v": -1}})
    finally:
        _VChild.clear_validators()


def test_nested_struct_after_validator_transforms_on_parent_validation():
    _VChild.add_validator(lambda c: _set_v(c, c.v * 10), mode="after")
    try:
        out = TypeAdapter(_VParent).validate_python({"name": "p", "child": {"v": 5}})
        assert out.child.v == 50
    finally:
        _VChild.clear_validators()


def test_valueerror_becomes_validationerror_other_exceptions_propagate():
    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda s: (_ for _ in ()).throw(ValueError("as-value-error")))
    with pytest.raises(ValidationError, match="as-value-error"):
        TypeAdapter(S).validate_python({"a": 1})

    S.clear_validators()

    def _boom(s):
        raise RuntimeError("raw-runtime")

    S.add_validator(_boom)
    with pytest.raises(RuntimeError, match="raw-runtime"):
        TypeAdapter(S).validate_python({"a": 1})


def test_after_validator_returning_none_raises_clear_error():
    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda s: None, mode="after")
    with pytest.raises(ValidationError, match="returned None"):
        TypeAdapter(S).validate_python({"a": 1})
    # Called directly the guard surfaces as a plain ValueError, not a pydantic ValidationError.
    with pytest.raises(ValueError, match="returned None") as excinfo:
        S.run_validators(S(a=1))
    assert not isinstance(excinfo.value, ValidationError)


def test_before_validator_returning_none_raises_clear_error():
    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda d: None, mode="before")
    with pytest.raises(ValidationError, match="returned None"):
        TypeAdapter(S).validate_python({"a": 1})


def test_clear_validators_removes_all():
    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda s: _bump(s), mode="after")
    assert TypeAdapter(S).validate_python({"a": 1}).a == 11
    S.clear_validators()
    assert TypeAdapter(S).validate_python({"a": 1}).a == 1


def test_clear_validators_by_mode():
    calls = []

    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda d: (calls.append("pre"), d)[1], mode="before")
    S.add_validator(lambda s: (calls.append("post"), s)[1], mode="after")
    S.clear_validators(mode="before")
    calls.clear()
    TypeAdapter(S).validate_python({"a": 1})
    assert calls == ["post"]  # only the after validator remains


def test_clear_validators_by_mode_alias():
    calls = []

    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda d: (calls.append("pre"), d)[1], mode="before")
    S.add_validator(lambda s: (calls.append("post"), s)[1], mode="after")
    S.clear_validators(mode="post")  # alias for "after"
    calls.clear()
    TypeAdapter(S).validate_python({"a": 1})
    assert calls == ["pre"]  # only the before validator remains


def test_clear_validators_removes_own_but_not_inherited_or_sibling():
    # The refactor's central invariant: clearing one class must NOT remove inherited (parent) or
    # sibling registrations -- only the class's own.
    class Base(GatewayStruct):
        a: int = 0

    class Child(Base):
        b: int = 0

    class Sibling(GatewayStruct):
        a: int = 0

    def _base_reject(s):
        if s.a < 0:
            raise ValueError("base-reject")
        return s

    def _child_reject(s):
        if getattr(s, "b", 0) < 0:
            raise ValueError("child-reject")
        return s

    def _sibling_reject(s):
        if s.a < 0:
            raise ValueError("sibling-reject")
        return s

    Base.add_validator(_base_reject)
    Child.add_validator(_child_reject)
    Sibling.add_validator(_sibling_reject)

    # Child initially enforces its own rule (b<0).
    with pytest.raises(ValidationError, match="child-reject"):
        TypeAdapter(Child).validate_python({"a": 0, "b": -1})

    Child.clear_validators()

    # Child's OWN validator is gone: b<0 no longer rejected.
    assert TypeAdapter(Child).validate_python({"a": 0, "b": -1}).b == -1
    # The INHERITED base validator still runs on Child.
    with pytest.raises(ValidationError, match="base-reject"):
        TypeAdapter(Child).validate_python({"a": -1, "b": 0})
    # A SIBLING class is unaffected by clearing Child.
    with pytest.raises(ValidationError, match="sibling-reject"):
        TypeAdapter(Sibling).validate_python({"a": -1})


def test_before_validator_skipped_for_already_constructed_input():
    class S(GatewayStruct):
        a: int = 0

    seen = []
    # A dict-shaped "before" validator, as documented -- it must never be handed a constructed struct.
    S.add_validator(lambda d: (seen.append(type(d)), {**d, "a": d.get("a", 0) + 1})[1], mode="before")

    out = TypeAdapter(S).validate_python(S(a=3))
    assert seen == []
    assert out.a == 3  # not bumped: no raw input to reshape
    assert TypeAdapter(S).validate_python({"a": 3}).a == 4  # dict input still reshaped
    assert seen == [dict]


def test_after_validator_still_runs_for_already_constructed_input():
    class S(GatewayStruct):
        a: int = 0

    def _reject_neg(s):
        if s.a < 0:
            raise ValueError("neg")
        return s

    S.add_validator(_reject_neg)
    assert TypeAdapter(S).validate_python(S(a=1)).a == 1
    with pytest.raises(ValidationError, match="neg"):
        TypeAdapter(S).validate_python(S(a=-1))


def test_nested_instance_field_does_not_break_dict_shaped_before_validator():
    class Child(GatewayStruct):
        v: int = 0

    class Parent(GatewayStruct):
        child: Child

    Child.add_validator(lambda d: {**d, "v": d["v"] * 2}, mode="before")
    # A struct instance in a nested field must not be fed to a dict-shaped validator (would TypeError).
    assert TypeAdapter(Parent).validate_python({"child": Child(v=5)}).child.v == 5
    assert TypeAdapter(Parent).validate_python({"child": {"v": 5}}).child.v == 10


def test_subclass_validators_run_for_base_annotated_field():
    class Base(GatewayStruct):
        a: int = 0

    class Derived(Base):
        b: int = 0

    class Holder(GatewayStruct):
        item: Base

    calls = []
    Base.add_validator(lambda s: (calls.append("base"), s)[1])
    Derived.add_validator(lambda s: (calls.append("derived"), s)[1])

    # The field is annotated `Base`, so pydantic validates against Base's schema -- but the value is a
    # `Derived`, whose own validators must still run (base first, then subclass).
    out = TypeAdapter(Holder).validate_python({"item": Derived(a=1, b=2)})
    assert type(out.item) is Derived
    assert calls == ["base", "derived"]

    # A dict really does construct a `Base`, so only Base's validators apply.
    calls.clear()
    TypeAdapter(Holder).validate_python({"item": {"a": 1}})
    assert calls == ["base"]


def test_subclass_validator_rejects_through_base_annotated_field():
    class Base(GatewayStruct):
        a: int = 0

    class Derived(Base):
        b: int = 0

    class Holder(GatewayStruct):
        item: Base

    def _reject(s):
        raise ValueError("derived-reject")

    Derived.add_validator(_reject)
    with pytest.raises(ValidationError, match="derived-reject"):
        TypeAdapter(Holder).validate_python({"item": Derived(a=1, b=2)})
    TypeAdapter(Holder).validate_python({"item": Base(a=1)})  # base value unaffected


def test_registration_after_first_validation_takes_effect():
    # The MRO-resolved validator list is cached per class; registering must invalidate it.
    class S(GatewayStruct):
        a: int = 0

    assert TypeAdapter(S).validate_python({"a": 1}).a == 1  # populates the cache with no validators
    S.add_validator(lambda s: _bump(s))
    assert TypeAdapter(S).validate_python({"a": 1}).a == 11
    S.add_validator(lambda s: _bump(s))
    assert TypeAdapter(S).validate_python({"a": 1}).a == 21
    S.clear_validators()
    assert TypeAdapter(S).validate_python({"a": 1}).a == 1


def test_base_registration_invalidates_subclass_cache():
    class Base(GatewayStruct):
        a: int = 0

    class Child(Base):
        b: int = 0

    assert TypeAdapter(Child).validate_python({"a": 1}).a == 1  # caches Child's empty resolution
    Base.add_validator(lambda s: _bump(s))  # registered on the PARENT after Child was cached
    assert TypeAdapter(Child).validate_python({"a": 1}).a == 11
    Base.clear_validators()
    assert TypeAdapter(Child).validate_python({"a": 1}).a == 1


def test_after_hook_also_dispatches_on_concrete_type():
    # The hook must follow the same concrete-type dispatch as registered validators, or a subclass's
    # rules are still bypassed by routing it through a base-annotated field.
    class Base(GatewayStruct):
        a: int = 0

    class Derived(Base):
        @classmethod
        def _validate_gateway_struct_after(cls, val):
            raise ValueError("derived-hook")

    class Holder(GatewayStruct):
        item: Base

    with pytest.raises(ValidationError, match="derived-hook"):
        TypeAdapter(Holder).validate_python({"item": Derived(a=1)})
    # A dict really does construct a Base, whose hook is a no-op.
    assert TypeAdapter(Holder).validate_python({"item": {"a": 1}}).item.a == 1


def test_resolved_cache_is_immutable():
    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda s: s)
    resolved = S._collect_validators("_post_validators")
    assert isinstance(resolved, tuple)
    with pytest.raises(AttributeError):
        resolved.append(lambda s: s)  # cannot inject a validator behind clear_validators' back


def test_after_validator_must_return_the_validated_type():
    class Expected(GatewayStruct):
        value: int = 0

    class Unrelated(GatewayStruct):
        secret: str = "wrong"

    Expected.add_validator(lambda v: Unrelated())
    with pytest.raises(TypeError, match="must return a Expected"):
        TypeAdapter(Expected).validate_python({"value": 1})


def test_after_validator_may_return_a_subclass():
    class Expected(GatewayStruct):
        value: int = 0

    class SubExpected(Expected):
        extra: int = 0

    Expected.add_validator(lambda v: SubExpected(value=v.value, extra=1))
    out = TypeAdapter(Expected).validate_python({"value": 5})
    assert type(out) is SubExpected and out.extra == 1


def test_none_input_is_not_blamed_on_the_validator():
    # A correct identity before-validator must not turn a client's `null` into a "returned None" error.
    class Child(GatewayStruct):
        a: int = 0

    class Parent(GatewayStruct):
        item: Child

    Child.add_validator(lambda d: d, mode="before")
    try:
        with pytest.raises(ValidationError) as excinfo:
            TypeAdapter(Parent).validate_python({"item": None})
        assert "returned None" not in str(excinfo.value)
        assert "valid dictionary" in str(excinfo.value)
    finally:
        Child.clear_validators()


def test_before_validator_cannot_reinstate_a_scrubbed_id():
    class S(GatewayStruct):
        a: int = 0

    S.add_validator(lambda d: {**d, "id": "FORGED"}, mode="before")
    out = TypeAdapter(S).validate_python({"id": "CLIENT", "a": 1}, context={"force_new_id": True})
    assert out.id not in ("FORGED", "CLIENT")


def test_force_new_id_honored_for_instance_input():
    class S(GatewayStruct):
        a: int = 0

    inst = S(a=1)
    out = TypeAdapter(S).validate_python(inst, context={"force_new_id": True})
    assert out.id != inst.id
    assert out.a == 1
    assert out is not inst  # rebuilt rather than mutated, so the caller's object is untouched


def test_validation_context_reaches_nested_models():
    observed = []

    class Child(GatewayStruct):
        value: int

        def model_post_init(self, context):
            super().model_post_init(context)
            observed.append(context)

    class Parent(GatewayStruct):
        child: Child

    context = {"request": "nested-validation"}
    Parent.model_validate({"child": {"value": 2}}, context=context)
    assert observed == [{"request": "nested-validation"}]
    assert context == {"request": "nested-validation"}


def test_force_new_identity_for_nested_instance_input():
    class Child(GatewayStruct):
        value: int

    class Parent(GatewayStruct):
        child: Child

    child = Child(value=2)
    parent = Parent(child=child)
    original_id = child.id
    original_timestamp = child.timestamp
    rebuilt = Parent.model_validate(parent, context={"force_new_id": True, "force_new_timestamp": True})
    assert rebuilt.id != parent.id
    assert rebuilt.child.id != original_id
    assert rebuilt.child.timestamp != original_timestamp
    assert child.id == original_id
    assert child.timestamp == original_timestamp
    assert Child.lookup(original_id) is child
    assert Child.lookup(rebuilt.child.id) is rebuilt.child


def test_instance_input_passes_through_without_a_force_context():
    class S(GatewayStruct):
        a: int = 0

    inst = S(a=1)
    assert TypeAdapter(S).validate_python(inst) is inst


def test_invalid_mode_error_suppresses_the_chained_keyerror():
    class S(GatewayStruct):
        a: int = 0

    with pytest.raises(ValueError) as excinfo:
        S.add_validator(lambda s: s, mode="sideways")
    assert excinfo.value.__suppress_context__


def test_add_validator_rejects_invalid_mode():
    class S(GatewayStruct):
        a: int = 0

    with pytest.raises(ValueError, match="mode must be"):
        S.add_validator(lambda s: s, mode="sideways")


def test_add_validator_rejects_noncallable():
    class S(GatewayStruct):
        a: int = 0

    with pytest.raises(TypeError, match="must be callable"):
        S.add_validator("not-callable")
    with pytest.raises(TypeError, match="must be callable"):
        S.add_validator("not-callable", mode="before")


def test_clear_validators_rejects_invalid_mode():
    class S(GatewayStruct):
        a: int = 0

    with pytest.raises(ValueError, match="mode must be"):
        S.clear_validators(mode="sideways")


def test_run_validators_rejects_invalid_mode():
    class S(GatewayStruct):
        a: int = 0

    with pytest.raises(ValueError, match="mode must be"):
        S.run_validators(S(a=1), mode="sideways")
