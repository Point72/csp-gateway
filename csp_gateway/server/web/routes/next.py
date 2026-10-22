from typing import Any, get_origin

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from csp_gateway.server import ChannelSelection
from csp_gateway.utils import NoProviderException, coerce_basket_key

from ..utils import get_default_responses
from .shared import get_fully_qualified_type_name, get_next_tick, prepare_response

__all__ = (
    "add_next_available_channels",
    "add_next_routes",
)


def add_next_routes(
    api_router: APIRouter,
    field: str,
    model: BaseModel | list[BaseModel] = None,
    subroute_key: Any = None,
) -> None:
    if model and get_origin(model) is list:
        is_list_model = True
        list_model = model
    else:
        is_list_model = False
        list_model = list[model]

    # Get the fully qualified type name for the description
    fq_type_name = get_fully_qualified_type_name(model)

    if subroute_key:

        async def get_next(key: str, request: Request) -> list_model:  # type: ignore[valid-type]
            """
            Get next ticked value on a dictionary basket channel, where `key` is the key of the dictionary basket.
            If such a key does not exist or is not mounted, this endpoint will raise a `404` error.
            """
            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, field):
                raise HTTPException(status_code=404, detail=f"Channel not found: {field}")

            if subroute_key is str:
                actual_key = key
            else:
                actual_key = coerce_basket_key(subroute_key, key)  # type: ignore[misc]

            # Throw 404 if not a supported key for channel
            if actual_key not in request.app.gateway.channels.keys_for_channel(field):  # type: ignore[union-attr]
                raise HTTPException(
                    status_code=404,
                    detail=f"Channel not found: {field}/{actual_key}",
                )

            # Grab the request off the edge
            try:
                res = await get_next_tick(
                    request.app.gateway,
                    getattr(request.app.gateway.channels_model, field),
                    actual_key,
                )
            except NoProviderException:
                raise HTTPException(
                    status_code=404,
                    detail=f"Channel not found: {field}/{key}",
                )

            return await run_in_threadpool(prepare_response, res, is_list_model=is_list_model)

        api_router.get(
            f"/{field}/{{key:path}}",
            responses=get_default_responses(),
            response_model=list_model,
            name=f"Get Next {field} by key",
            openapi_extra={"type_": fq_type_name} if fq_type_name else None,
        )(get_next)

        api_router.get(
            "/{}/{{key:path}}".format(field.replace("_", "-")),
            responses=get_default_responses(),
            response_model=list_model,
            include_in_schema=False,
        )(get_next)

        async def get_next_basket(request: Request) -> list_model:  # type: ignore[misc, valid-type]
            """Get next ticked value on a dictionary basket channel. This endpoint will return the entire basket"""
            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, field):
                raise HTTPException(status_code=404, detail=f"Channel not found: {field}")

            # Grab the request off the edge
            try:
                res = await get_next_tick(
                    request.app.gateway,
                    getattr(request.app.gateway.channels_model, field),
                )
            except NoProviderException:
                raise HTTPException(
                    status_code=404,
                    detail=f"Channel not found: {field}",
                )
            return await run_in_threadpool(
                prepare_response,
                res,
                is_list_model=is_list_model,
                is_dict_basket=True,
            )

        api_router.get(
            f"/{field}",
            responses=get_default_responses(),
            response_model=list_model,  # type: ignore[valid-type]
            name=f"Get Next {field}",
            openapi_extra={"type_": fq_type_name} if fq_type_name else None,
        )(get_next_basket)

        api_router.get(
            "/{}".format(field.replace("_", "-")),
            responses=get_default_responses(),
            response_model=list_model,  # type: ignore[valid-type]
            include_in_schema=False,
        )(get_next_basket)

    elif model:

        async def get_next(request: Request) -> list_model:  # type: ignore[misc, valid-type]
            """
            Get next ticked value on a non-basket channel.
            This endpoint will always return a list of elements.

            When the underlying channel only handles individual elements, the returned list will only ever contain a single element.

            When the underlying channel handles lists of elements, the returned list will contain `N>=1` elements.
            """
            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, field):
                raise HTTPException(status_code=404, detail=f"Channel not found: {field}")

            # Grab the request off the edge
            try:
                res = await get_next_tick(
                    request.app.gateway,
                    getattr(request.app.gateway.channels_model, field),
                )
            except NoProviderException:
                raise HTTPException(
                    status_code=404,
                    detail=f"Channel not found: {field}",
                )

            return await run_in_threadpool(prepare_response, res, is_list_model=is_list_model)

        api_router.get(
            f"/{field}",
            responses=get_default_responses(),
            response_model=list_model,
            name=f"Get Next {field}",
            openapi_extra={"type_": fq_type_name} if fq_type_name else None,
        )(get_next)

        api_router.get(
            "/{}".format(field.replace("_", "-")),
            responses=get_default_responses(),
            response_model=list_model,
            include_in_schema=False,
        )(get_next)


def add_next_available_channels(api_router: APIRouter, fields: set[str] | None = None) -> None:
    @api_router.get(
        "/",
        responses=get_default_responses(),
        response_model=list[str],
    )
    async def get_next(request: Request) -> list[str]:
        """
        This endpoint will return a list of string values of all available channels under the `/next` route.
        """
        return sorted(ChannelSelection().select_from(request.app.gateway.channels) if fields is None else fields)
