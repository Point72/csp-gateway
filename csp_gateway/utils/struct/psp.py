import _thread
import itertools
import types
from collections.abc import Callable
from datetime import date, datetime
from enum import Enum as PyEnum
from logging import getLogger
from typing import Annotated, Any, Optional, Union, get_args, get_origin

import orjson
from csp import Enum as CspEnum
from csp.impl.types.container_type_normalizer import ContainerTypeNormalizer
from numpy import ndarray
from pydantic import BaseModel
from typing_extensions import TypeAliasType

__all__ = (
    "CustomJsonifier",
    "ExcludedColumns",
    "PerspectiveUtilityMixin",
    "model_metadata",
    "psp_flatten",
    "psp_flatten_dict",
    "psp_flatten_list",
    "psp_schema",
)

log = getLogger(__name__)


def _strip_annotated(annotation: Any) -> Any:
    """Drop ``Annotated`` wrappers, including inside an ``Optional``.

    ``GatewayStruct._relax_required_fields`` re-homes a field's constraints into ``Annotated`` so they
    survive being made nullable. Callers of ``model_metadata`` want the plain type -- perspective,
    duckdb and pyarrow all feed it straight into ``issubclass``.
    """
    while get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]
    args = get_args(annotation)
    if get_origin(annotation) in (Union, types.UnionType) and type(None) in args:
        inner = [_strip_annotated(arg) for arg in args if arg is not type(None)]
        if len(inner) == 1:
            return Optional[inner[0]]  # noqa: UP045 -- inner[0] is a runtime value
    return annotation


def model_metadata(cls, typed: bool = False) -> dict[str, Any]:
    """The field types of a pydantic model, in the shape csp's ``Struct.metadata`` returned.

    ``typed=True`` gives the declared annotation; ``typed=False`` normalizes it the way callers
    expect -- an optional collapses to its inner type, and a list reports as ``[element_type]``.
    """
    out: dict[str, Any] = {}
    for name, field in cls.model_fields.items():
        annotation = _strip_annotated(field.annotation)
        if typed:
            out[name] = annotation
            continue
        origin = get_origin(annotation)
        if origin is not None and type(None) in get_args(annotation):
            inner = [arg for arg in get_args(annotation) if arg is not type(None)]
            annotation = inner[0] if len(inner) == 1 else annotation
            origin = get_origin(annotation)
        if origin in (list, set, tuple):
            args = get_args(annotation)
            out[name] = [args[0]] if args else origin
        elif origin is not None:
            out[name] = origin
        else:
            out[name] = annotation
    return out


CustomJsonifier = Callable[[Any], tuple[Any, bool]]


# We expose these functions separate from the class definition
# so that they can be called recursively.
# However, the top level call should always come from a
# a PerspectiveUtilityMixin subclass or instance of such.
def psp_flatten_dict(obj: dict[str, Any]) -> Any:
    """Flatten dicts of values into a top level dict"""

    # Base template to use for creating copies later
    base_dict = {}
    # List of deltas that will be applied to the base dict
    # to create final dicts
    list_items = []
    for obj_key, obj_val in obj.items():
        # Flatten every item
        res = psp_flatten(obj_val)
        if isinstance(res, list):
            if len(res) == 0:
                # Key needs to be deleted, use empty dict as delta
                list_items.append([{}])

            else:
                # Delta options for current key
                delta_list = []
                for res_val in res:
                    # NOTE: We should never receive a non-empty list as an item here

                    # Delta dict for the current item in list
                    delta_dict = {}
                    if isinstance(res_val, dict):
                        # Merge the sub-dict with parent key
                        for k, v in res_val.items():
                            delta_dict[f"{obj_key}.{k}"] = v
                        delta_list.append(delta_dict)
                    elif isinstance(res_val, list) and len(res) == 0:
                        # Key needs to be deleted, use empty dict as delta
                        delta_list.append({})
                    else:
                        # Create new delta dict with key, val
                        delta_list.append({obj_key: res_val})
                list_items.append(delta_list)
        else:
            # Non-list item found, use as is
            base_dict[obj_key] = res

    ret = []
    # Process all possible combinations of delta options for keys
    for combination in itertools.product(*list_items):
        # Make a copy from the base template
        new_dict = base_dict.copy()
        for elem in combination:
            # Merge the delta into copy
            new_dict.update(elem)
        ret.append(new_dict)

    return ret


def psp_flatten_list(obj: list[Any]) -> list[Any]:
    """Flatten list of complex types (sub-lists, dicts) to a top level list"""

    ret = []
    for val in obj:
        res = psp_flatten(val)
        if isinstance(res, list) and res:
            # Flatten sub-lists into a single list
            # NOTE: Special handling for empty list
            #  Empty list indicate key should be deleted
            #  so we preserve empty list during flattening
            ret.extend(res)
        else:
            ret.append(res)
    return ret


def psp_flatten(obj: Any) -> Any:
    """Flatten an object"""

    #  This should only return simple objects or lists of simple objects (not dicts)
    ret = obj
    if isinstance(obj, list):
        ret = psp_flatten_list(obj)
    elif isinstance(obj, dict):
        ret = psp_flatten_dict(obj)
    return ret


ExcludedColumns = TypeAliasType("ExcludedColumns", "set[str] | dict[str, bool | ExcludedColumns]")


def _is_excluded(field: str, excluded_columns: ExcludedColumns) -> bool | ExcludedColumns:
    if isinstance(excluded_columns, set):
        return field in excluded_columns

    return excluded_columns.get(field, False)


def _is_optional(t: type) -> bool:
    # Accept both typing.Optional[X]/typing.Union[X, None] and the PEP 604 ``X | None`` form.
    # The former have get_origin() is typing.Union; the latter is a types.UnionType.
    if get_origin(t) not in (Union, types.UnionType):
        return False
    args = list(get_args(t))
    return not (len(args) != 2 or type(None) not in args)


def _get_type_from_optional(t: type):
    args = list(get_args(t))
    args.remove(type(None))
    return args[0]


def psp_schema(cls, excluded_columns: ExcludedColumns | None = None) -> dict[str, type]:
    """Returns the perspective schema for a class.

    Args:
        excluded_columns: Columns to exclude from the schema.
    """

    # Pydantic doesn't support fields that start with underscore
    schema = {k: v for k, v in model_metadata(cls, typed=False).items() if not k.startswith("_")}
    schema_annotated = {k: v for k, v in model_metadata(cls, typed=True).items() if not k.startswith("_")}
    add = {}
    remove = []

    for field, value in schema.items():
        # Make sure its a type so `issubclass`
        # calls don't fail
        if _is_optional(schema_annotated[field]):
            value = _get_type_from_optional(schema_annotated[field])
            value = ContainerTypeNormalizer.normalized_type_to_actual_python_type(value)

        if not isinstance(value, type):
            # TODO other generics
            if isinstance(value, list):
                value = value[0]
                schema[field] = value
            else:
                remove.append(field)
                # TODO deal with dropped
                log.warning(f"Type is not actually a type: {field} {value}")
                continue

        is_excluded = excluded_columns and _is_excluded(field, excluded_columns)
        if is_excluded:
            remove.append(field)

        if issubclass(value, list) or issubclass(value, ndarray):
            try:
                # will be unrolled into root type
                try:
                    annotation = cls.__annotations__[field]
                except KeyError:
                    # Fallback: search bases for annotation
                    annotation = None
                    for base in cls.__mro__[1:]:
                        anns = getattr(base, "__annotations__", {})
                        if field in anns:
                            annotation = anns[field]
                            break
                    if annotation is None:
                        raise KeyError(field)

                # get arg type
                annotation = _strip_annotated(annotation)
                if _is_optional(annotation):
                    annotation = _get_type_from_optional(annotation)
                arg = get_args(annotation)[0]

                # use this as type
                value = arg
            except (KeyError, IndexError):
                # just use str
                value = str
            finally:
                schema[field] = value

        # If its a complicated type that we just serialize to json, leave as str
        if issubclass(value, dict):
            schema[field] = str
            continue

        # If its an enum, promote to str
        if issubclass(value, (PyEnum, CspEnum)):
            schema[field] = str
            continue

        # Otherwise if its not a handled type
        if (
            not issubclass(value, str)
            and not issubclass(value, int)
            and not issubclass(value, float)
            and not issubclass(value, bool)
            and not issubclass(value, datetime)
            and not issubclass(value, date)
        ):
            excluded_sub_fields = None
            if is_excluded:
                # no need to add field to remove, it has been added already
                if isinstance(is_excluded, bool):
                    if is_excluded:
                        continue

                else:
                    excluded_sub_fields = is_excluded

            else:
                # remove it from the schema
                remove.append(field)

            # if its a struct, flatten
            if issubclass(value, BaseModel):
                if hasattr(value, "psp_schema"):
                    struct_items = value.psp_schema(excluded_sub_fields).items()
                else:
                    struct_items = psp_schema(value, excluded_sub_fields).items()

                # add subschema
                for subkey, subvalue in struct_items:
                    add[f"{field}.{subkey}"] = subvalue
            else:
                # TODO deal with dropped
                log.warning(f"Type {value} on has no perspective conversion, ignoring in perspective tables: {cls.__name__}.{field}")

    # remove all that need to be removed
    for to_remove in remove:
        schema.pop(to_remove)

    for key, value in schema.items():
        if value is object and _is_optional(schema_annotated[key]):
            schema[key] = _get_type_from_optional(schema_annotated[key])

    schema.update(add)
    return schema


class PerspectiveUtilityMixin:
    def psp_flatten(self, custom_jsonifier: CustomJsonifier | None = None) -> list[dict[str, Any]]:
        def _callback(obj):
            """Callback helper that either calls custom_jsonifier or a default set of conversions"""
            if custom_jsonifier:
                obj = custom_jsonifier(obj)
            if isinstance(obj, ndarray):
                return obj.tolist()
            elif isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, (PyEnum, CspEnum)):
                return obj.name
            elif isinstance(obj, _thread.LockType):
                return "<Lock>"
            else:
                log.warning(f"No serializer for {obj}, converting to ''")
                return ""

        json_obj = orjson.loads(self.to_json(_callback))
        flat_obj = psp_flatten(json_obj)
        return flat_obj

    @classmethod
    def psp_schema(cls, excluded_columns: ExcludedColumns | None = None) -> dict[str, type]:
        """Return the perspective schema.

        Args:
            excluded_columns: Columns to exclude from the schema.
        """
        return psp_schema(cls, excluded_columns)
