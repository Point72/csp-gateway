from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Dict

import csp
from csp import Struct
from pydantic import ValidationInfo
from pydantic_core import CoreConfig, core_schema

from ..id_generator import get_counter
from .psp import PerspectiveUtilityMixin

IdType = str

__all__ = (
    "GatewayStruct",
    "IdType",
    "GatewayLookupMixin",
    "GatewayPydanticMixin",
    "GatewayStructMixins",
    "is_gateway_struct_like",
)


class GatewayLookupMixin:
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.id_generator = get_counter(cls)
        cls._internal_mapping: Dict[str, Any] = {}
        cls.lookup = MappingProxyType(cls._internal_mapping).get
        cls._include_in_lookup = True

    def __init__(self, **kwargs: Any) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(self.__class__.id_generator.next())
        if "timestamp" not in kwargs:
            kwargs["timestamp"] = datetime.now(timezone.utc)
        if getattr(self.__class__, "_include_in_lookup", True):
            # Insert into lookup before super to keep behavior consistent
            # with previous GatewayStruct construction
            # (instance becomes available immediately after init)
            # Self will be fully initialized once super returns
            self.__class__._internal_mapping[kwargs["id"]] = self
        super().__init__(**kwargs)

    @classmethod
    def omit_from_lookup(cls, omit=True):
        cls._include_in_lookup = not omit

    @classmethod
    def included_in_lookup(cls):
        return cls._include_in_lookup

    @classmethod
    def generate_id(cls) -> str:
        return str(cls.id_generator.next())


class GatewayPydanticMixin:
    @classmethod
    def _validate_gateway_struct_after(cls, val):
        """Validate GatewayStruct after pydantic type validation.
        A validator attached to every GatewayStruct to allow for defining custom
        model-level after validators that run after pydantic type validation.
        If not defined on a child class, the parent's validator will be used.  If defined on a child class, the parent's validator will be ignored. Please call the parent's validator directly if you want to run both.

        This is meant to be mixed-in with csp.Struct's. We do not inherit from a csp.Struct
        since csp.Struct's do not support multiple inheritance with other csp.Struct's

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
    def _validate_gateway_struct(cls, val, handler, info: ValidationInfo):
        if isinstance(info.context, dict) and isinstance(val, dict):
            if info.context.get("force_new_id", False):
                # If we are forcing a new id, we need to remove the old one
                val.pop("id", None)
            if info.context.get("force_new_timestamp", False):
                # If we are forcing a new timestamp, we need to remove the old one
                val.pop("timestamp", None)
        csp_struct = handler(val)
        final = cls._validate_gateway_struct_after(csp_struct)
        return final

    @staticmethod
    def _get_pydantic_core_schema(cls, source_type, handler):
        # Get parent schema - note the cls parameter
        parent_schema = csp.Struct._get_pydantic_core_schema(cls, source_type, handler)
        core_config = CoreConfig(coerce_numbers_to_str=True)
        # soooo hacky...
        parent_schema["schema"]["config"] = core_config
        return core_schema.with_info_wrap_validator_function(
            function=cls._validate_gateway_struct, schema=parent_schema, serialization=parent_schema.get("serialization")
        )


GatewayStructMixins = (GatewayLookupMixin, GatewayPydanticMixin, PerspectiveUtilityMixin)


class GatewayStruct(
    *GatewayStructMixins,
    Struct,
):
    """Convenience class composing gateway mixins with csp.Struct.

    Provides id/timestamp fields, lookup/registry utilities, and pydantic
    integration, plus Perspective utilities.
    """

    id: IdType
    timestamp: datetime


def is_gateway_struct_like(cls) -> bool:
    """Strict check: requires all gateway mixins and `csp.Struct`.

    Returns True only if `cls` is a `csp.Struct` subclass AND also
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
            issubclass(cls, Struct)
            and issubclass(cls, GatewayLookupMixin)
            and issubclass(cls, GatewayPydanticMixin)
            and issubclass(cls, PerspectiveUtilityMixin)
        )
    except Exception:
        return False
