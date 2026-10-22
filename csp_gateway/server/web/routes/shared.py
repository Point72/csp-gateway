import asyncio
from typing import Any, get_args, get_origin

from fastapi.responses import Response
from pydantic import BaseModel

from csp_gateway.utils.struct.base import type_adapter_for

__all__ = (
    "get_fully_qualified_type_name",
    "get_next_tick",
    "prepare_response",
)


def get_fully_qualified_type_name(model: BaseModel | list[BaseModel] | None) -> str:
    """
    Get the fully qualified type name for a model.

    For example, for ExampleData defined in csp_gateway.server.demo.simple,
    this returns "csp_gateway.server.demo.simple.ExampleData".

    If the model is a List[SomeModel], this returns the fully qualified name of SomeModel.
    """
    if model is None:
        return ""

    # If it's a List type, extract the inner type
    if get_origin(model) is list:
        args = get_args(model)
        if args:
            model = args[0]

    # Get the module and class name
    if hasattr(model, "__module__") and hasattr(model, "__name__"):
        return f"{model.__module__}.{model.__name__}"
    elif hasattr(model, "__module__") and hasattr(model, "__qualname__"):
        return f"{model.__module__}.{model.__qualname__}"

    return ""


def prepare_response(
    res: Any,
    is_list_model: bool = False,
    is_dict_basket: bool = False,
    wrap_in_response: bool = True,
) -> list[dict[Any, Any]]:
    # If we've ticked
    if res:
        # Convert the dict basket to just the list of values
        if is_dict_basket:
            res = [record for records in res.values() for record in records] if is_list_model else res.values()

        # If its not a list model, it means we got back 1 thing, so wrap it
        elif not is_list_model and not isinstance(res, list):
            res = [res]

    else:
        #  Else return an empty json
        res = []

    json_res_bytes = _dump_records(list(res))
    # Prepare and return response
    if wrap_in_response:
        return Response(
            content=json_res_bytes,
            media_type="application/json",
        )
    # useful when you want the data, but outside a fastapi response object
    return json_res_bytes.decode()


def _dump_records(res: list) -> bytes:
    """Serialize records to a JSON array, byte-identical to dumping each with its own adapter.

    Records that are all exactly one `GatewayStruct` type go through its batched dump instead.
    """
    if not res:
        return b"[]"
    cls = type(res[0])
    # Called even on the fast path: it is what rejects non-model records.
    type_adapter_for(res[0])
    if all(type(r) is cls for r in res):
        dump_json_list = getattr(cls, "_dump_json_list", None)
        if dump_json_list is not None and (json_res_bytes := dump_json_list(res)) is not None:
            return json_res_bytes
    return b"[" + b",".join(type_adapter_for(r).dump_json(r) for r in res) + b"]"


async def get_next_tick(gateway, field, key=""):
    """Need to do some fanciness so that a `next` call doesnt block the webserver"""
    return await asyncio.get_event_loop().run_in_executor(None, gateway.channels.next, field, key)
