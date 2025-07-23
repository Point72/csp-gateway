import logging
from typing import Any, Dict, List, Optional, Set, Union, get_args, get_origin

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from csp_gateway.utils import NoProviderException

from ..utils import get_default_responses
from .shared import prepare_response

log = logging.getLogger(__name__)


__all__ = (
    "add_send_routes",
    "add_send_available_channels",
)


def add_send_routes(
    api_router: APIRouter,
    field: str,
    model: Union[BaseModel, List[BaseModel]] = None,
    subroute_key: Any = None,
) -> None:
    if model and get_origin(model) is list:
        is_list_model = True
        base_model = get_args(model)[0]
        list_model = model
    else:
        is_list_model = False
        base_model = model
        list_model = List[model]

    if subroute_key:

        async def send(key: subroute_key, data: Union[list_model, base_model], request: Request) -> list_model:  # type: ignore[valid-type]
            """
            Send data to a dictionary basket channel, where `key` is the key of the dictionary basket.
            If such a key does not exist or is not mounted, this endpoint will raise a `404` error.
            """

            log.debug(f"send: {data}")

            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, field):
                raise HTTPException(status_code=404, detail="Channel not found: {}".format(field))

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
                        for data in data:
                            request.app.gateway.channels.send(
                                getattr(request.app.gateway.channels_model, field),
                                data,
                                key,
                            )
                except NoProviderException:
                    raise HTTPException(
                        status_code=404,
                        detail="Channel not found: {}/{}".format(field, key),
                    )

            # Emit the pydantic model back as it
            # will now have the `id` and `timestamp`
            return prepare_response(data, is_list_model=is_list_model)

        api_router.post(
            "/{}/{{key:path}}".format(field),
            responses=get_default_responses(),
            name="Send {} by key".format(field),
        )(send)
        api_router.post(
            "/{}/{{key:path}}".format(field.replace("_", "-")),
            responses=get_default_responses(),
            name="Send {} by key".format(field),
            include_in_schema=False,
        )(send)

        async def send(data: Dict[subroute_key, base_model], request: Request) -> Dict[subroute_key, base_model]:  # type: ignore[valid-type]
            log.debug(f"send: {data}")

            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, field):
                raise HTTPException(status_code=404, detail="Channel not found: {}".format(field))

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
                    detail="Channel not found: {}".format(field),
                )

            # Emit the pydantic model back as it
            # will now have the `id` and `timestamp`
            return prepare_response(data, is_dict_basket=True)

        api_router.post(
            "/{}".format(field),
            responses=get_default_responses(),
            name="Send {}".format(field),
        )(send)
        api_router.post(
            "/{}".format(field.replace("_", "-")),
            responses=get_default_responses(),
            name="Send {}".format(field),
            include_in_schema=False,
        )(send)

    elif model:

        async def send(data: Union[list_model, base_model], request: Request) -> list_model:  # type: ignore[misc, valid-type]
            """
            Send data to a non-basket channel. This endpoint can accept either a single element, or a list of elements.
            A list of elements will be returned with `id` and `timestamp` fields assigned.
            Users should not provide `id` or `timestamp` fields as these will be ignored.
            """

            log.debug(f"send: {data}")

            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, field):
                raise HTTPException(status_code=404, detail="Channel not found: {}".format(field))

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
                        for data in data:
                            request.app.gateway.channels.send(
                                getattr(request.app.gateway.channels_model, field),
                                data,
                            )
                except NoProviderException:
                    raise HTTPException(
                        status_code=404,
                        detail="Channel not found: {}".format(field),
                    )

            # Emit the pydantic model back as it
            # will now have the `id` and `timestamp`
            return prepare_response(data, is_list_model=is_list_model)

        api_router.post(
            "/{}".format(field),
            responses=get_default_responses(),
            name="Send {}".format(field),
        )(send)
        api_router.post(
            "/{}".format(field.replace("_", "-")),
            responses=get_default_responses(),
            name="Send {}".format(field),
            include_in_schema=False,
        )(send)


def add_send_available_channels(api_router: APIRouter, fields: Optional[Set[str]] = None) -> None:
    @api_router.get(
        "/",
        responses=get_default_responses(),
        response_model=List[str],
    )
    async def get_send(request: Request) -> List[str]:
        """
        This endpoint will return a list of string values of all available channels under the `/send` route.
        """
        return sorted(
            field + ("" if indexer is None else f"/{indexer.name if hasattr(indexer, 'name') else indexer}")
            for field, indexer in request.app.gateway.channels._send_channels.keys()
            if fields is None or field in fields
        )
