from typing import Any, get_args, get_origin

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from csp_gateway.server import ChannelSelection
from csp_gateway.utils.struct import global_lookup

from ..utils import get_default_responses
from .shared import _validate_batch_size, get_fully_qualified_type_name, prepare_response

__all__ = (
    "add_lookup_available_channels",
    "add_lookup_routes",
)


def add_lookup_routes(
    api_router: APIRouter,
    field: str,
    model: BaseModel | list[BaseModel],
    *,
    batch_size: int = 500,
    materialize: bool = True,
) -> None:
    _validate_batch_size(batch_size)
    if model and get_origin(model) is list:
        model = get_args(model)[0]

    # Get the fully qualified type name for the description
    fq_type_name = get_fully_qualified_type_name(model)

    def lookup(id: str, request: Request) -> list[model]:  # type: ignore[misc, valid-type]
        """
        This endpoint lets you lookup any GatewayStruct by its uniquely generated `id`.
        """
        # Throw 404 if not a supported channel
        if not hasattr(request.app.gateway.channels, field):
            raise HTTPException(status_code=404, detail=f"Channel not found: {field}")

        # lookup by id
        res = model.lookup(id)

        return prepare_response(res, is_list_model=False, batch_size=batch_size, materialize=materialize)

    api_router.get(
        f"/{field}/{{id:path}}",
        responses=get_default_responses(),
        response_model=list[model],
        name=f"Lookup {field}",
        openapi_extra={"type_": fq_type_name} if fq_type_name else None,
    )(lookup)

    api_router.get(
        "/{}/{{id:path}}".format(field.replace("_", "-")),
        responses=get_default_responses(),
        response_model=list[model],
        include_in_schema=False,
    )(lookup)


def add_lookup_available_channels(api_router: APIRouter, fields: set[str] | None = None, *, batch_size: int = 500, materialize: bool = True) -> None:
    _validate_batch_size(batch_size)

    @api_router.get(
        "/",
        responses=get_default_responses(),
        response_model=list[str],
    )
    async def get_lookup(request: Request) -> list[str]:
        """
        This endpoint will return a list of string values of all available channels under the `/lookup` route.
        """
        return sorted(ChannelSelection().select_from(request.app.gateway.channels) if fields is None else fields)

    @api_router.get(
        "/id/{id:path}",
        responses=get_default_responses(),
    )
    def get_lookup_by_id(id: str, request: Request) -> Any:
        """
        This endpoint lets you lookup any GatewayStruct by its globally unique `id`.
        Returns the GatewayStruct instance if found, otherwise returns 404.
        """
        result = global_lookup(id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"No GatewayStruct found with id: {id}")
        return prepare_response(result, is_list_model=False, batch_size=batch_size, materialize=materialize)
