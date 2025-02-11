from typing import List, Union, get_args, get_origin

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..utils import get_default_responses
from .shared import prepare_response


def add_lookup_routes(
    api_router: APIRouter,
    field: str,
    model: Union[BaseModel, List[BaseModel]],
) -> None:
    if model and get_origin(model) is list:
        model = get_args(model)[0]

    async def lookup(id: str, request: Request) -> List[model]:  # type: ignore[misc, valid-type]
        """
        This endpoint lets you lookup any GatewayStruct by its uniquely generated `id`.
        """
        # Throw 404 if not a supported channel
        if not hasattr(request.app.gateway.channels, field):
            raise HTTPException(status_code=404, detail="Channel not found: {}".format(field))

        # lookup by id
        res = model.lookup(id)

        return prepare_response(res, is_list_model=False)

    api_router.get(
        "/{}/{{id:path}}".format(field),
        responses=get_default_responses(),
        response_model=List[model],
        name="Lookup {}".format(field),
    )(lookup)

    api_router.get(
        "/{}/{{id:path}}".format(field.replace("_", "-")),
        responses=get_default_responses(),
        response_model=List[model],
        include_in_schema=False,
    )(lookup)
