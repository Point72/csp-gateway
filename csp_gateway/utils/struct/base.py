from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, ClassVar, Literal, Optional, Self, TypeVar

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_serializer, model_serializer, model_validator
from pydantic_core import core_schema

from ..id_generator import get_counter
from .psp import PerspectiveUtilityMixin, model_metadata

IdType = str

#: A validator receives a value and returns the (possibly transformed) value, or raises to reject it.
ValidatorFn = Callable[[Any], Any]

#: Accepted ``mode`` arguments; "pre"/"post" are aliases for "before"/"after".
ValidatorMode = Literal["before", "pre", "after", "post"]

_TYPE_ADAPTERS: dict = {}

__all__ = (
    "GatewayLookupMixin",
    "GatewayPydanticMixin",
    "GatewayStruct",
    "GatewayStructMixins",
    "IdType",
    "ValidatorFn",
    "ValidatorMode",
    "global_lookup",
    "is_gateway_struct_like",
    "type_adapter_for",
)

T = TypeVar("T")

# Global registry: maps ID -> instance for all GatewayLookupMixin instances
_global_registry: dict[str, Any] = {}

# Class-specific registry: maps (class, ID) -> instance
_class_registry: dict[tuple, Any] = {}

# Bumped on every validator registration/clear so per-class resolved caches invalidate without having
# to know which classes in which MRO were affected.
_validator_registry_version = 0

_CONSTRUCTION = "csp_gateway_construction"
_FIELD_VALUES = "csp_gateway_field_values"

# Core-schema metadata key marking a schema this class has already wrapped.
_WRAPPED_MARKER = "csp_gateway_validated"

# Serialization-context key asking the timestamp serializer to keep the stored offset.
_PRESERVE_TZ = "csp_gateway_preserve_tz"

# FastAPI collects component schemas under #/components/schemas.
_REF_TEMPLATE = "#/components/schemas/{model}"


def global_lookup(id: IdType, cls: type[T] | None = None) -> T | None:
    """Look up a GatewayStruct instance by ID.

    Args:
        id: The unique ID of the instance to look up.
        cls: Optional class to filter by. If provided, only returns
             instances of that specific class.

    Returns:
        The instance if found, None otherwise.
    """
    if cls is not None:
        return _class_registry.get((cls, id))
    return _global_registry.get(id)


class GatewayLookupMixin:
    # Shared global ID generator
    id_generator = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Use the single global generator for all classes
        if GatewayLookupMixin.id_generator is None:
            GatewayLookupMixin.id_generator = get_counter()
        cls.id_generator = GatewayLookupMixin.id_generator
        cls._include_in_lookup = True

    def __init__(self, **kwargs: Any) -> None:
        self.__pydantic_validator__.validate_python(kwargs, self_instance=self, context={_CONSTRUCTION: True})

    @model_validator(mode="before")
    @classmethod
    def _mint_identity(cls, data: Any, info: ValidationInfo) -> Any:
        """Fill in a fresh id/timestamp for any the caller left out."""
        if not isinstance(data, dict) or (isinstance(info.context, dict) and info.context.get(_FIELD_VALUES, False)):
            return data
        fields = cls.model_fields
        missing = {}
        # Absent, not falsy: an explicit ``None`` is the caller saying "no value", and overwriting it
        # with a freshly minted one would lose that.
        if "id" in fields and "id" not in data:
            missing["id"] = str(cls.id_generator.next())
        if "timestamp" in fields and "timestamp" not in data:
            # Naive UTC, the only shape a csp timestamp ever had; mixing aware and naive values
            # in one field makes ordinary comparisons raise.
            missing["timestamp"] = datetime.now(UTC).replace(tzinfo=None)
        # Copy rather than mutate: the caller owns the dict handed to model_validate.
        return {**data, **missing} if missing else data

    def model_post_init(self, context: Any, /) -> None:
        super().model_post_init(context)
        if not (isinstance(context, dict) and context.get(_FIELD_VALUES, False)) and getattr(type(self), "_include_in_lookup", True):
            id = getattr(self, "id", None)
            if id is not None:
                _global_registry[id] = self
                _class_registry[(type(self), id)] = self

    @classmethod
    def omit_from_lookup(cls, omit=True):
        cls._include_in_lookup = not omit

    @classmethod
    def included_in_lookup(cls):
        return cls._include_in_lookup

    @classmethod
    def generate_id(cls) -> str:
        return str(cls.id_generator.next())

    @classmethod
    def lookup(cls, id: IdType) -> Any | None:
        """Look up an instance by ID, scoped to this class.

        Args:
            id: The unique ID of the instance to look up.

        Returns:
            The instance if found in this class's registry, None otherwise.
        """
        return _class_registry.get((cls, id))


class GatewayPydanticMixin:
    # Validators registered through add_validator, invoked by the _validate_gateway_struct wrap
    # validator. Deliberately unannotated so csp does not treat them as Struct fields.
    _pre_validators = []
    _post_validators = []

    # Accepted ``mode`` values -> internal registry attribute (both "before"/"pre" and "after"/"post").
    _VALIDATOR_MODE_ATTRS = {
        "before": "_pre_validators",
        "pre": "_pre_validators",
        "after": "_post_validators",
        "post": "_post_validators",
    }

    # Registry attribute -> attribute holding this class's MRO-resolved (version, validators) cache.
    _VALIDATOR_CACHE_ATTRS = {
        "_pre_validators": "_pre_validators_resolved",
        "_post_validators": "_post_validators_resolved",
    }

    @classmethod
    def _validator_mode_attr(cls, mode: ValidatorMode) -> str:
        """Resolve a public ``mode`` ("before"/"pre"/"after"/"post") to its registry attribute name."""
        try:
            return cls._VALIDATOR_MODE_ATTRS[mode]
        except (KeyError, TypeError):
            raise ValueError(f"mode must be 'before'/'pre' or 'after'/'post'; got {mode!r}") from None

    @classmethod
    def add_validator(cls, fn: ValidatorFn | None = None, *, mode: ValidatorMode = "after") -> ValidatorFn | Callable[[ValidatorFn], ValidatorFn]:
        """Register a validator invoked during pydantic validation.

        A validator ``fn(value) -> value`` receives the value and returns the (possibly transformed)
        value; it rejects the input by raising ``ValueError`` (or ``AssertionError``), which pydantic
        converts into a ``ValidationError`` and the REST API reports as a 422. Any OTHER exception type
        propagates uncaught and reaches the client as a 500, so a validator that rejects untrusted input
        must raise ``ValueError`` -- guard lookups rather than letting a ``KeyError`` escape.

        An "after" validator must return an instance of the class being validated; returning another type
        raises ``TypeError``. Returning ``None`` is likewise an error unless the incoming value was itself
        ``None``.

        ``mode="before"`` (alias ``"pre"``) runs on the raw input (usually a dict) before construction --
        useful for accepting legacy/aliased input shapes. It is skipped when the input is already a
        constructed struct, so a "before" validator only ever sees unconstructed input. It must not set
        ``id`` or ``timestamp`` when the caller asked for fresh ones; those are re-scrubbed afterwards.
        ``mode="after"`` (alias ``"post"``, the default) runs on the constructed struct, dispatched on
        that struct's concrete type. ``fn`` may be any callable -- a lambda, or a bound method of some
        other object (e.g. an adapter holding a secmaster). Validators registered on base classes also
        run (aggregated across the MRO); registering on ``GatewayStruct`` or ``GatewayPydanticMixin``
        therefore instruments every struct in the process. Usable directly, as a bare decorator
        (``@Struct.add_validator``), or as a decorator factory (``@Struct.add_validator(mode="before")``).
        Returns ``fn``.
        """
        attr = cls._validator_mode_attr(mode)

        def _register(func: ValidatorFn) -> ValidatorFn:
            if not callable(func):
                raise TypeError(f"validator must be callable; got {func!r}")
            # Give this class its own list rather than mutating an inherited one.
            if attr not in cls.__dict__:
                setattr(cls, attr, [])
            getattr(cls, attr).append(func)
            global _validator_registry_version
            _validator_registry_version += 1
            return func

        if fn is None:
            return _register
        return _register(fn)

    @classmethod
    def _collect_validators(cls, attr: str) -> tuple[ValidatorFn, ...]:
        """Aggregate validators of one kind (``_pre_validators``/``_post_validators``) across the MRO.

        The result is cached on the class, keyed by the global registry version, so any registration or
        clear anywhere invalidates it. The version is sampled BEFORE the walk: a registration racing the
        walk then leaves the cache stamped older than the global and the next read recomputes.
        """
        cache_attr = cls._VALIDATOR_CACHE_ATTRS[attr]
        version = _validator_registry_version
        cached = cls.__dict__.get(cache_attr)
        if cached is not None and cached[0] == version:
            return cached[1]
        collected = []
        for klass in reversed(cls.__mro__):
            collected.extend(klass.__dict__.get(attr, ()))
        resolved = tuple(collected)
        setattr(cls, cache_attr, (version, resolved))
        return resolved

    @classmethod
    def run_validators(cls, val: Any, *, mode: ValidatorMode = "after") -> Any:
        """Run the registered validators of one kind on ``val``; return the (possibly transformed) value.

        Each validator must return the value, raising ``ValueError`` to reject it. Returning ``None`` is
        rejected as a forgotten ``return`` -- unless the incoming value was itself ``None``, in which case
        the value passes through and the type error surfaces normally. An "after" validator must return an
        instance of ``cls``. Useful for manually validating a natively/CSP-constructed struct, which does
        not auto-run validators.
        """
        attr = cls._validator_mode_attr(mode)
        enforce_type = attr == "_post_validators"
        label = "after" if enforce_type else "before"
        for fn in cls._collect_validators(attr):
            result = fn(val)
            name = getattr(fn, "__name__", fn)
            if result is None and val is not None:
                raise ValueError(
                    f"{cls.__name__}: {label!r} validator {name!r} returned None; validators must return the (possibly transformed) value"
                )
            if enforce_type and not isinstance(result, cls):
                raise TypeError(f"{cls.__name__}: 'after' validator {name!r} returned {type(result).__name__}; it must return a {cls.__name__}")
            val = result
        return val

    @classmethod
    def clear_validators(cls, *, mode: ValidatorMode | None = None) -> None:
        """Remove validators registered directly on this class, leaving inherited ones in place.

        ``mode=None`` clears both "before" and "after"; ``"before"``/``"pre"`` or ``"after"``/``"post"``
        clears just that kind. Useful for teardown/idempotency when validators are attached dynamically at
        gateway-build time.
        """
        if mode is None:
            cls._pre_validators = []
            cls._post_validators = []
        else:
            setattr(cls, cls._validator_mode_attr(mode), [])
        global _validator_registry_version
        _validator_registry_version += 1

    @classmethod
    def _validate_gateway_struct_after(cls, val):
        """Validate GatewayStruct after pydantic type validation.
        A validator attached to every GatewayStruct to allow for defining custom
        model-level after validators that run after pydantic type validation.
        If not defined on a child class, the parent's validator will be used.  If defined on a child class, the parent's validator will be ignored. Please call the parent's validator directly if you want to run both.

        Args:
            cls: The class this validator is attached to
            val: The value to validate
        Returns:
            The validated value, possibly modified
        """
        return val

    @classmethod
    def type_adapter(cls):
        # NOTE: Only needed until csp>0.9 is released with this fix
        # We mangle ourselves, explicitly, to make sure that child Structs
        # will get their own type adapters.
        attr_name = f"_{cls.__name__}__pydantic_type_adapter"
        internal_type_adapter = getattr(cls, attr_name, None)
        if internal_type_adapter:
            return internal_type_adapter

        # Late import to avoid autogen issues
        from pydantic import TypeAdapter

        type_adapter = TypeAdapter(cls)
        setattr(cls, attr_name, type_adapter)
        return type_adapter

    @classmethod
    def _scrub_identity(cls, val, info: ValidationInfo):
        """Drop a caller-supplied id/timestamp when the validation context asks for fresh ones."""
        if not isinstance(info.context, dict):
            return val
        new_id = bool(info.context.get("force_new_id", False))
        new_timestamp = bool(info.context.get("force_new_timestamp", False))
        if not (new_id or new_timestamp):
            return val
        if isinstance(val, dict):
            val = val.copy()
            if new_id:
                val.pop("id", None)
            if new_timestamp:
                val.pop("timestamp", None)
        elif isinstance(val, BaseModel):
            # Scrubbing in place would mutate the caller's object and strand it in the lookup registry
            # under its old id, so rebuild instead and let validation mint and register the new values.
            # Only explicitly-set fields are carried over, so unset fields stay unset in the copy.
            fields = {name: getattr(val, name) for name in val.model_fields_set}
            if new_id:
                fields.pop("id", None)
            if new_timestamp:
                fields.pop("timestamp", None)
            return type(val).__pydantic_validator__.validate_python(fields, context={**info.context, _CONSTRUCTION: True})
        return val

    @classmethod
    def _validate_gateway_struct(cls, val, handler, info: ValidationInfo):
        if isinstance(info.context, dict) and info.context.pop(_CONSTRUCTION, False):
            return handler(val)
        val = cls._scrub_identity(val, info)
        # An already-constructed model has no raw input to reshape, so "before" validators are skipped.
        if not isinstance(val, cls):
            val = cls.run_validators(val, mode="before")
            # Re-scrub: a before validator that rebuilds the input can otherwise reinstate the old id.
            val = cls._scrub_identity(val, info)
        model = handler(val)
        # Dispatch on the concrete type: a subclass instance in a base-annotated field is validated
        # against the base's schema, but must still run its own validators and hook.
        concrete = type(model)
        model = concrete.run_validators(model, mode="after")
        return concrete._validate_gateway_struct_after(model)

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        schema = handler(source_type)
        # Generating the schema for a field annotated with a struct hands back that struct's own
        # already-wrapped schema, so wrapping unconditionally would run every validator once per
        # nesting level. The marker makes the wrap idempotent.
        if schema.get("metadata", {}).get(_WRAPPED_MARKER):
            return schema
        model_schema = schema
        while model_schema["type"] in ("function-before", "function-after", "function-wrap"):
            model_schema = model_schema["schema"]
        if model_schema["type"] == "model":
            model_schema["custom_init"] = False
        return core_schema.with_info_wrap_validator_function(
            function=cls._validate_gateway_struct,
            schema=schema,
            # No explicit serialization: the wrapped model schema already carries its own, and
            # overriding it leaves FastAPI unable to derive a response schema (every endpoint would
            # document as a bare object).
            metadata={_WRAPPED_MARKER: True},
        )


GatewayStructMixins = (GatewayLookupMixin, GatewayPydanticMixin, PerspectiveUtilityMixin)


def _to_naive_utc(value: datetime) -> datetime:
    """Normalize to a naive UTC datetime, the only shape a csp timestamp ever serialized as.

    A naive input is assumed to already be UTC.
    """
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


class GatewayStruct(
    *GatewayStructMixins,
    BaseModel,
):
    """Convenience class composing the gateway mixins with a pydantic `BaseModel`.

    Provides id/timestamp fields, lookup/registry utilities, and pydantic
    integration, plus Perspective utilities.

    Deliberately a plain pydantic model rather than ccflow's `BaseModel`: a struct is data on the
    wire, so it wants neither the registry integration nor the ``type_`` discriminator that ccflow
    adds to every payload.
    """

    model_config = ConfigDict(
        # Retained from the csp.Struct era: ids arrive off the wire as bare numbers.
        coerce_numbers_to_str=True,
        extra="forbid",
        ser_json_timedelta="float",
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    #: Fields made optional by ``_relax_required_fields`` rather than by a declared default.
    __gateway_implicit_fields__: ClassVar[frozenset[str]] = frozenset()

    id: IdType | None = None
    timestamp: datetime | None = None

    @classmethod
    def from_field_values(cls, **fields: Any) -> Self:
        """Validate field values without generating identities or registering model instances.

        Explicit identities and declared defaults are preserved. The same identity and lookup
        policy applies to nested models built from field values.
        """
        return cls.__pydantic_validator__.validate_python(fields, context={_CONSTRUCTION: True, _FIELD_VALUES: True})

    @field_serializer("timestamp", when_used="json")
    def _serialize_timestamp(self, value: datetime | None, info) -> str | None:
        # csp emitted naive UTC, and clients parse that shape. ``to_json`` is the exception: it stands
        # in for csp's own serializer, which preserved whatever offset the caller stored.
        if value is None:
            return None
        if isinstance(info.context, dict) and info.context.get(_PRESERVE_TZ):
            return value.isoformat()
        return _to_naive_utc(value).isoformat()

    @model_serializer(mode="wrap")
    def _drop_implicitly_unset(self, handler: Callable[[Any], dict[str, Any]], info) -> dict[str, Any]:
        """Omit fields that were never set and have no declared default.

        A model serializer rather than an ``exclude=`` argument so the rule also applies to structs
        nested inside another struct, which is where csp's unset fields mattered most: a payload round
        trips back through validation, and a ``None`` standing in for "absent" fails the field's own
        constraints.
        """
        data = handler(self)
        if self is None:
            # A null value for a struct-typed field still routes through that struct's serializer.
            return data
        by_alias = info.by_alias if info.by_alias is not None else self.model_config.get("serialize_by_alias", False)
        for name in self._implicitly_unset():
            field = type(self).model_fields[name]
            key = (field.serialization_alias or name) if by_alias else name
            data.pop(key, None)
        return data

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        super().__pydantic_init_subclass__(**kwargs)
        cls._relax_required_fields()

    @classmethod
    def _relax_required_fields(cls) -> None:
        """Default every field to ``None`` so declaring one without a default leaves it optional.

        csp.Struct had no notion of a required field -- an unset field simply had no value -- and the
        REST API inherited that: a payload may carry any subset of a struct's fields. Pydantic instead
        treats a field without a default as required, which would reject those payloads. Defaults are
        not themselves validated, so a ``None`` default coexists with constraints like ``Field(gt=0)``,
        which still apply to any value actually supplied. Use ``model_fields_set`` to tell a field the
        caller set from one that defaulted.
        """
        relaxed = set()
        for name, field in cls.model_fields.items():
            if field.is_required():
                # Nullable, not merely defaulted: csp accepted an explicit ``None`` for a field it had
                # no value for, and callers pass one to mean "absent". Constraints stay attached to the
                # inner type so they still apply to a real value.
                try:
                    inner = Annotated[(field.annotation, *field.metadata)] if field.metadata else field.annotation
                    if not (isinstance(field.annotation, type) and issubclass(field.annotation, BaseModel)):
                        # A nested struct keeps rejecting an explicit None: csp had no value to stand
                        # in for a missing struct, and silently accepting one hides a real type error.
                        # Optional[] rather than `inner | None`: inner is a runtime value.
                        field.annotation = Optional[inner]  # noqa: UP045
                        field.metadata = []
                except TypeError:
                    # Not something typing can wrap (csp-normalized container shapes); a default alone
                    # still makes the field optional, it just will not accept an explicit None.
                    pass
                field.default = None
                relaxed.add(name)
        # A field relaxed on a base class is still implicit here.
        inherited = frozenset().union(*(getattr(base, "__gateway_implicit_fields__", frozenset()) for base in cls.__mro__[1:]))
        cls.__gateway_implicit_fields__ = frozenset(relaxed) | (inherited & cls.model_fields.keys())
        if relaxed:
            cls.model_rebuild(force=True, raise_errors=False)

    def _implicitly_unset(self) -> set[str]:
        """Fields that only exist because ``_relax_required_fields`` gave them a default.

        These are csp's "never set" fields, so they stay out of serialization. A field with a default
        the author actually declared is a different thing and is always reported. Identity fields
        also stay absent if neither supplied nor generated; an explicit None is still reported.
        """
        fields = type(self).model_fields
        implicit = type(self).__gateway_implicit_fields__ | {
            name for name in ("id", "timestamp") if name in fields and fields[name].default is None and fields[name].default_factory is None
        }
        return implicit - self.model_fields_set

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema_, handler):
        json_schema = handler(core_schema_)
        # `_drop_implicitly_unset` is a wrap serializer, which leaves pydantic unable to describe the
        # serialized shape -- it degrades to a bare object, and FastAPI then documents every endpoint
        # that returns a struct as `additionalProperties: true`. Serializing only ever omits fields,
        # so the validated shape describes it.
        if handler.mode == "serialization" and "properties" not in json_schema:
            json_schema.update(cls.model_json_schema(mode="validation", ref_template=_REF_TEMPLATE))
        return json_schema

    @classmethod
    def metadata(cls, typed: bool = False) -> dict[str, Any]:
        """The field types, in the shape csp's ``Struct.metadata`` returned."""
        return model_metadata(cls, typed=typed)

    def to_dict(self) -> dict[str, Any]:
        """The model as plain data, for callers written against csp's ``Struct.to_dict``."""
        return self.model_dump(mode="python")

    def to_json(self, default_fn: Callable[[Any], Any] | None = None) -> str:
        """The model as a JSON string, for callers written against csp's ``Struct.to_json``.

        ``default_fn`` maps values pydantic cannot serialize itself (numpy arrays, sets, locks), the
        role csp's ``default`` argument played.
        """
        return self.model_dump_json(fallback=default_fn, context={_PRESERVE_TZ: True})

    def copy(self, **kwargs: Any) -> "GatewayStruct":
        """A shallow copy, matching csp's ``Struct.copy`` rather than pydantic's deprecated one."""
        return self.model_copy(**kwargs)


def is_gateway_struct_like(cls) -> bool:
    """Strict check: requires all gateway mixins and a pydantic `BaseModel`.

    Returns True only if `cls` is a `BaseModel` subclass AND also
    subclasses `GatewayLookupMixin`, `GatewayPydanticMixin`, and
    `PerspectiveUtilityMixin`.
    """
    if not isinstance(cls, type):
        return False
    # Shortcut for explicit GatewayStruct
    if issubclass(cls, GatewayStruct):
        return True
    try:
        return (
            issubclass(cls, BaseModel)
            and issubclass(cls, GatewayLookupMixin)
            and issubclass(cls, GatewayPydanticMixin)
            and issubclass(cls, PerspectiveUtilityMixin)
        )
    except TypeError:
        return False


def type_adapter_for(obj):
    """Return a pydantic ``TypeAdapter`` able to serialize ``obj``.

    ``GatewayStruct`` carries its own cached ``type_adapter``, but a channel is
    free to carry a plain pydantic model, and those do not. Falling back to an
    adapter built from the model's own type lets such a channel be served over
    REST instead of failing inside the response path.

    The fallback is deliberately limited to pydantic models. Anything else
    still raises ``AttributeError``, because reaching this function with, say,
    a ``str`` means a caller mishandled a container, and serializing it would
    turn that mistake into quietly wrong output.
    """
    own = getattr(obj, "type_adapter", None)
    if callable(own):
        return own()

    from pydantic import BaseModel, TypeAdapter

    if not isinstance(obj, BaseModel):
        # AttributeError, not TypeError: this is the error callers already see
        # and the response path already documents, so the contract is kept.
        raise AttributeError(f"{type(obj).__name__!r} object has no attribute 'type_adapter'")  # noqa: TRY004

    cls = type(obj)
    cached = _TYPE_ADAPTERS.get(cls)
    if cached is None:
        cached = TypeAdapter(cls)
        _TYPE_ADAPTERS[cls] = cached
    return cached
