import logging
from typing import Any, get_args, get_origin

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from csp_gateway.utils import NoProviderException

from ..utils import get_default_responses
from .shared import get_fully_qualified_type_name, prepare_response

log = logging.getLogger(__name__)


__all__ = (
    "add_send_available_channels",
    "add_send_routes",
)


def add_send_routes(
    api_router: APIRouter,
    field: str,
    model: BaseModel | list[BaseModel] = None,
    subroute_key: Any = None,
) -> None:
    if model and get_origin(model) is list:
        is_list_model = True
        base_model = get_args(model)[0]
        list_model = model
    else:
        is_list_model = False
        base_model = model
        list_model = list[model]

    # Get the fully qualified type name for the description
    fq_type_name = get_fully_qualified_type_name(model)

    if subroute_key:
        # Sync, so FastAPI runs it in its threadpool: pushing and echoing a large
        # payload would otherwise hold the event loop and stall every other request.
        def send(key: subroute_key, data: list_model | base_model, request: Request) -> list_model:  # type: ignore[valid-type]
            """
            Send data to a dictionary basket channel, where `key` is the key of the dictionary basket.
            If such a key does not exist or is not mounted, this endpoint will raise a `404` error.
            """

            log.debug(f"send: {data}")

            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, field):
                raise HTTPException(status_code=404, detail=f"Channel not found: {field}")

            if not isinstance(data, list):
                data = [data]

            if len(data):
                # send to the edge
                try:
                    if is_list_model:
                        # send as a list
                        request.app.gateway.channels.send(
                            getattr(request.app.gateway.channels_model, field),
                            data,
                            key,
                        )
                    else:
                        # unroll and send individually
                        for datum in data:
                            request.app.gateway.channels.send(
                                getattr(request.app.gateway.channels_model, field),
                                datum,
                                key,
                            )
                except NoProviderException:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Channel not found: {field}/{key}",
                    )

            # Emit the pydantic model back as it
            # will now have the `id` and `timestamp`
            return prepare_response(data, is_list_model=is_list_model)

        api_router.post(
            f"/{field}/{{key:path}}",
            responses=get_default_responses(),
            name=f"Send {field} by key",
            openapi_extra={"type_": fq_type_name} if fq_type_name else None,
        )(send)
        api_router.post(
            "/{}/{{key:path}}".format(field.replace("_", "-")),
            responses=get_default_responses(),
            name=f"Send {field} by key",
            include_in_schema=False,
        )(send)

        # Sync, so FastAPI runs it in its threadpool: pushing and echoing a large
        # payload would otherwise hold the event loop and stall every other request.
        def send(data: dict[subroute_key, base_model], request: Request) -> dict[subroute_key, base_model]:  # type: ignore[valid-type]
            log.debug(f"send: {data}")

            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, field):
                raise HTTPException(status_code=404, detail=f"Channel not found: {field}")

            # send to the edge
            try:
                # send as a list
                request.app.gateway.channels.send(
                    getattr(request.app.gateway.channels_model, field),
                    data,
                )
            except NoProviderException:
                raise HTTPException(
                    status_code=404,
                    detail=f"Channel not found: {field}",
                )

            # Emit the pydantic model back as it
            # will now have the `id` and `timestamp`
            return prepare_response(data, is_dict_basket=True)

        api_router.post(
            f"/{field}",
            responses=get_default_responses(),
            name=f"Send {field}",
            openapi_extra={"type_": fq_type_name} if fq_type_name else None,
        )(send)
        api_router.post(
            "/{}".format(field.replace("_", "-")),
            responses=get_default_responses(),
            name=f"Send {field}",
            include_in_schema=False,
        )(send)

    elif model:
        # Sync, so FastAPI runs it in its threadpool: pushing and echoing a large
        # payload would otherwise hold the event loop and stall every other request.
        def send(data: list_model | base_model, request: Request) -> list_model:  # type: ignore[misc, valid-type]
            """
            Send data to a non-basket channel. This endpoint can accept either a single element, or a list of elements.
            A list of elements will be returned with `id` and `timestamp` fields assigned.
            Users should not provide `id` or `timestamp` fields as these will be ignored.
            """

            log.debug(f"send: {data}")

            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, field):
                raise HTTPException(status_code=404, detail=f"Channel not found: {field}")

            if not isinstance(data, list):
                data = [data]

            if len(data):
                # send to the edge
                try:
                    if is_list_model:
                        # send as a list
                        request.app.gateway.channels.send(
                            getattr(request.app.gateway.channels_model, field),
                            data,
                        )
                    else:
                        # unroll and send individually
                        for datum in data:
                            request.app.gateway.channels.send(
                                getattr(request.app.gateway.channels_model, field),
                                datum,
                            )
                except NoProviderException:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Channel not found: {field}",
                    )

            # Emit the pydantic model back as it
            # will now have the `id` and `timestamp`
            return prepare_response(data, is_list_model=is_list_model)

        api_router.post(
            f"/{field}",
            responses=get_default_responses(),
            name=f"Send {field}",
            openapi_extra={"type_": fq_type_name} if fq_type_name else None,
        )(send)
        api_router.post(
            "/{}".format(field.replace("_", "-")),
            responses=get_default_responses(),
            name=f"Send {field}",
            include_in_schema=False,
        )(send)


def add_send_available_channels(api_router: APIRouter, fields: set[str] | None = None) -> None:
    @api_router.get(
        "/",
        responses=get_default_responses(),
        response_model=list[str],
    )
    async def get_send(request: Request) -> list[str]:
        """
        This endpoint will return a list of string values of all available channels under the `/send` route.
        """
        return sorted(
            field + ("" if indexer is None else f"/{indexer.name if hasattr(indexer, 'name') else indexer}")
            for field, indexer in request.app.gateway.channels._send_channels
            if fields is None or field in fields
        )
