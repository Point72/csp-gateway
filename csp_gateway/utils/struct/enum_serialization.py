"""Enum-name JSON serialization configured when gateway model fields are built."""

import types
from enum import Enum
from functools import partial
from operator import attrgetter
from typing import Annotated, Union, get_args, get_origin

import csp
import numpy as np
from csp.typing import Numpy1DArray, NumpyNDArray
from pydantic import GetPydanticSchema
from pydantic_core import core_schema


def _accept_name(value, *, names):
    return names.get(value, value) if isinstance(value, str) else value


def _enum_member(value, enum):
    try:
        return enum(value)
    except ValueError:
        if isinstance(value, str) and value in enum.__members__:
            return enum.__members__[value]
        raise


def _array_names(value, enum):
    if isinstance(value, list):
        return [_array_names(item, enum) for item in value]
    return _enum_member(value, enum).name


def _serialize_array(value, *, enum):
    return _array_names(value.tolist(), enum)


def _array_input(value, *, enum):
    if value is None or isinstance(value, np.ndarray):
        return value

    def convert(item):
        if isinstance(item, list):
            return [convert(child) for child in item]
        return _enum_member(item, enum)

    return np.array(convert(value), dtype=object)


def _schema(source, handler):
    schema = handler(source)
    origin = get_origin(source)
    if origin in (Numpy1DArray, NumpyNDArray):
        enum = get_args(source)[0]
        return core_schema.no_info_before_validator_function(
            partial(_array_input, enum=enum),
            schema,
            serialization=core_schema.plain_serializer_function_ser_schema(
                partial(_serialize_array, enum=enum), info_arg=False, when_used="json-unless-none", return_schema=core_schema.list_schema()
            ),
        )
    resolved = handler.resolve_ref_schema(schema)
    # A type's own serializer remains authoritative, including csp.Enum's name serializer.
    if "serialization" in resolved:
        return schema
    members = source.__members__
    values = {member.value for member in members.values() if isinstance(member.value, str)}
    names = {name: member for name, member in members.items() if name not in values}
    choices = [schema]
    if names:
        choices.append(core_schema.no_info_after_validator_function(partial(_accept_name, names=names), core_schema.literal_schema(list(names))))
    return core_schema.union_schema(
        choices,
        serialization=core_schema.plain_serializer_function_ser_schema(
            attrgetter("name"),
            info_arg=False,
            when_used="json-unless-none",
            return_schema=core_schema.literal_schema(list(dict.fromkeys(member.name for member in members.values()))),
        ),
    )


_ENUM_NAMES = GetPydanticSchema(_schema)


def enum_names_annotation(annotation):
    """Add defaults below explicit Annotated serializers, without changing other model classes."""
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin is Annotated:
        if _ENUM_NAMES in args[1:]:
            return annotation
        return Annotated[enum_names_annotation(args[0]), *args[1:]]
    if isinstance(annotation, type) and issubclass(annotation, (Enum, csp.Enum)):
        return Annotated[annotation, _ENUM_NAMES]
    if origin in (Numpy1DArray, NumpyNDArray):
        if args and isinstance(args[0], type) and issubclass(args[0], (Enum, csp.Enum)):
            return Annotated[annotation, _ENUM_NAMES]
        return annotation
    if origin in (Union, types.UnionType, list, dict, tuple, set, frozenset):
        converted = tuple(enum_names_annotation(arg) for arg in args)
        if converted == args:
            return annotation
        return Union[converted] if origin in (Union, types.UnionType) else origin[converted]  # noqa: UP007
    return annotation
