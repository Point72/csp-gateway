from datetime import datetime
from types import MappingProxyType
from typing import Any, Dict

import csp
from csp import Struct
from csp.impl.struct import StructMeta
from pydantic import ValidationInfo
from pydantic_core import CoreConfig, core_schema

from ..id_generator import get_counter
from .psp import PerspectiveUtilityMixin

IdType = str

__all__ = ("GatewayStruct", "IdType", "PydanticizedCspStruct")


class PydanticizedCspStruct(StructMeta):
    """A subclass of StructMeta from csp, this class adds additional properties onto csp.Struct classes to link them into the Gateway format.

    Specifically, allows lookups and automatic id generation.
    """

    def __init__(cls: Any, name: str, bases: Any, attr_dict: Any) -> None:
        super().__init__(name, bases, attr_dict)
        # Automatically construct pydantic model from csp.struct

        # Attach an id generator to every class
        cls.id_generator = get_counter(cls)

        # Allow for looking up by ID
        cls._internal_mapping: Dict[str, Any] = {}

        # But expose this lookup as a readonly mapping proxy
        cls.lookup = MappingProxyType(cls._internal_mapping).get
        cls._include_in_lookup = True

    def omit_from_lookup(cls, omit=True):
        cls._include_in_lookup = not omit

    def included_in_lookup(cls):
        return cls._include_in_lookup


class GatewayStruct(PerspectiveUtilityMixin, Struct, metaclass=PydanticizedCspStruct):
    """Sub-class of csp.Struct specifically designed for usage with csp-gateway.
    These classes inherit from csp.Struct, but each one also contains a pydantic model
    as an attribute that mirrors the underlying struct class.

    The pydantic model can be constructed by running `.to_pydantic()` on an instance of the
    given GatewayStruct. To access the underlying class, one can call `__pydantic_model__` on the specific GatewayStruct sub-class object.
    For example:
        class MyClass(GatewayStruct):
            x: int
        pydantic_model = MyClass.__pydantic_model__

    The pydantic model of the the GatewayStruct allows for data validation. Furthermore, the utilities
    in csp-gateway (such as Rest routes, Kafka, Perspective integrations) are specifically designed for GatewayStruct's.
    """

    id: IdType
    timestamp: datetime

    def __init__(self, **kwargs: Any) -> None:
        # auto generate id on every new construction
        if "id" not in kwargs:
            # TODO consider postfixing with a _ for conflicts
            kwargs["id"] = str(self.__class__.id_generator.next())
        if "timestamp" not in kwargs:
            kwargs["timestamp"] = datetime.utcnow()

        # And put into lookup
        # TODO make this nicer when we switch to pydantic as first class instead of csp struct
        if self.__class__.included_in_lookup():
            self.__class__._internal_mapping[kwargs["id"]] = self

        # and defer to normal csp.struct construction
        super().__init__(**kwargs)

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

    @classmethod
    def generate_id(cls) -> str:
        return str(cls.id_generator.next())
