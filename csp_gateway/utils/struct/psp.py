import _thread
import itertools
from datetime import date, datetime
from enum import Enum as PyEnum
from logging import getLogger
from typing import Any, Callable, Dict, List, Optional, Tuple, get_args

import orjson
from csp import Enum, Struct
from csp.impl.enum import EnumMeta
from numpy import ndarray

log = getLogger(__name__)

CustomJsonifier = Callable[[Any], Tuple[Any, bool]]


# We expose these functions separate from the class definition
# so that they can be called recursively.
# However, the top level call should always come from a
# a PerspectiveUtilityMixin subclass or instance of such.
def psp_flatten_dict(obj: Dict[str, Any]) -> Any:
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
                            delta_dict["{}.{}".format(obj_key, k)] = v
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


def psp_flatten_list(obj: List[Any]) -> List[Any]:
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


def psp_schema(cls) -> Dict[str, type]:
    """Returns the perspective schema for a class"""

    # Pydantic doesn't support fields that start with underscore
    schema = {k: v for k, v in cls.metadata().items() if not k.startswith("_")}

    add = {}
    remove = []

    for field, value in schema.items():
        # Make sure its a type so `issubclass`
        # calls don't fail
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

        if issubclass(value, list) or issubclass(value, ndarray):
            try:
                # will be unrolled into root type
                annotation = cls.__annotations__[field]

                # get arg type
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
        if issubclass(value, (Enum, EnumMeta, PyEnum)):
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
            # if its a struct, flatten
            if issubclass(value, Struct):
                if hasattr(value, "psp_schema"):
                    struct_items = value.psp_schema().items()
                else:
                    struct_items = psp_schema(value).items()

                # add subschema
                for subkey, subvalue in struct_items:
                    add["{}.{}".format(field, subkey)] = subvalue
            else:
                # TODO deal with dropped
                log.warning(f"Type {value} on has no perspective conversion, ignoring in perspective tables: {cls.__name__}.{field}")
            # remove it from the schema
            remove.append(field)

    # remove all that need to be removed
    for to_remove in remove:
        schema.pop(to_remove)

    schema.update(add)
    return schema


class PerspectiveUtilityMixin:
    def psp_flatten(self, custom_jsonifier: Optional[CustomJsonifier] = None) -> List[Dict[str, Any]]:
        def _callback(obj):
            """Callback helper that either calls custom_jsonifier or a default set of conversions"""
            if custom_jsonifier:
                obj = custom_jsonifier(obj)
            if isinstance(obj, ndarray):
                return obj.tolist()
            elif isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, (PyEnum, Enum)):
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
    def psp_schema(cls) -> Dict[str, type]:
        return psp_schema(cls)
