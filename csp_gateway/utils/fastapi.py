from typing import Any, Optional

from fastapi import Depends, HTTPException, Query
from pydantic import Json, ValidationError

from .web import Query as QueryParamType


def json_param(param_name: str, model: Any, **query_kwargs):
    """Parse JSON-encoded query parameters as pydantic models.
    The function returns a `Depends()` instance that takes the JSON-encoded value from
    the query parameter `param_name` and converts it to a Pydantic model, defined
    by the `model` attribute.
    """

    def get_parsed_object(value: Optional[Json] = Query(default=None, alias=param_name, **query_kwargs)):
        try:
            if value is None:
                return None

            return model.model_validate(value)

        except ValidationError as err:
            raise HTTPException(400, detail=err.errors())

    return Depends(get_parsed_object)


def query_json():
    # NOTE: if we switch querys back to be csp structs, do this:
    # return json_param("query", QueryParamType.__pydantic_model__, description="Query Parameters")
    return json_param("query", QueryParamType, description="Query Parameters")
