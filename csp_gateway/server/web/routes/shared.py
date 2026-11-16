import asyncio
from typing import Any, get_args, get_origin

from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, TypeAdapter

from csp_gateway.utils.struct.base import type_adapter_for

__all__ = (
    "get_fully_qualified_type_name",
    "get_next_tick",
    "prepare_response",
    "response_model_for",
)


def response_model_for(model):
    """Describe prepare_response's per-model alias policy without changing request models."""

    def copy_schema(value, by_alias=False):
        if isinstance(value, list):
            return [copy_schema(item, by_alias) for item in value]
        if not isinstance(value, dict):
            return value
        if value.get("type") == "model":
            by_alias = value.get("config", {}).get("serialize_by_alias", False)
        is_schema = isinstance(value.get("type"), str)
        result = {key: item if is_schema and key in ("default", "metadata", "config") else copy_schema(item, by_alias) for key, item in value.items()}
        # Keep these definitions separate from FastAPI responses serialized with by_alias=True.
        if is_schema and "ref" in value:
            result["ref"] = "gateway_response." + value["ref"]
        if value.get("type") == "definition-ref":
            result["schema_ref"] = "gateway_response." + value["schema_ref"]
        if value.get("type") == "model-fields" and not by_alias:
            for field in result["fields"].values():
                field.pop("serialization_alias", None)
            for field in result.get("computed_fields", []):
                field.pop("alias", None)
        return result

    schema = copy_schema(TypeAdapter(model).core_schema)

    class ResponseModel:
        @classmethod
        def __get_pydantic_core_schema__(cls, _source, _handler):
            return schema

    return ResponseModel


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


def _validate_batch_size(batch_size: int) -> None:
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")


def prepare_response(
    res: Any,
    is_list_model: bool = False,
    is_dict_basket: bool = False,
    wrap_in_response: bool = True,
    *,
    batch_size: int = 500,
    materialize: bool = True,
) -> Response | str:
    _validate_batch_size(batch_size)
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

    records = list(res)

    def encode():
        yield b"["
        for start in range(0, len(records), batch_size):
            encoded = _dump_records(records[start : start + batch_size])[1:-1]
            yield (b"," if start else b"") + encoded
        yield b"]"

    if not wrap_in_response:
        return b"".join(encode()).decode()
    if materialize:
        return Response(content=b"".join(encode()), media_type="application/json")
    return StreamingResponse(encode(), media_type="application/json")


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
