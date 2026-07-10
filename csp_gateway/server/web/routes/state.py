from inspect import cleandoc
from typing import Any, List, Optional, Set, Tuple, Union, get_origin

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from csp_gateway.server import ChannelSelection
from csp_gateway.utils import NoProviderException, Query, query_json

from ..utils import get_default_responses
from .shared import get_fully_qualified_type_name, prepare_response

__all__ = (
    "add_state_routes",
    "add_state_available_channels",
)


def add_state_routes(
    api_router: APIRouter,
    field: str = "",
    model: Union[BaseModel, List[BaseModel]] = None,
    subroute_key: Any = None,
    keyby: Tuple[str, ...] = (),
    indexer: Optional[Union[str, int]] = None,
) -> None:
    """Mount REST routes for a single state ``field``.

    The state mechanism is now name-based; there is no implicit ``s_`` prefix.
    Routes are exposed at ``/state/<field>`` (and a variant with ``_``
    replaced by ``-`` for URL friendliness).

    ``keyby`` / ``indexer`` are surfaced in the route description so the
    accumulation semantics are visible in the OpenAPI schema.
    """
    if model and get_origin(model) is list:
        list_model = model
    else:
        list_model = List[model]

    fq_type_name = get_fully_qualified_type_name(model)

    keyby_lines = []
    if keyby:
        keyby_lines.append("**Keyed by:** ``{}``".format(", ".join(repr(k) for k in keyby)))
    if indexer is not None:
        keyby_lines.append("**Indexer:** ``{!r}``".format(indexer))
    keyby_prefix = ("\n\n".join(keyby_lines) + "\n\n") if keyby_lines else ""

    if subroute_key:

        async def get_state(key: str, query: Optional[Query] = query_json(), request: Request = None) -> list_model:  # type: ignore[valid-type]
            """
            Get state value on a dictionary basket channel, where `key` is the key of the dictionary basket.
            If such a key does not exist or is not mounted, this endpoint will raise a `404` error.

            States may be queried by certain conditions. See `/state/<field>` for query examples.
            """
            try:
                res = request.app.gateway.channels.query(field, key, query=query)
            except NoProviderException:
                raise HTTPException(
                    status_code=404,
                    detail="State not found: {}/{}".format(field, key),
                )

            return prepare_response(res, is_list_model=True)

        api_router.get(
            "/{}/{{key:path}}".format(field),
            responses=get_default_responses(),
            response_model=list_model,  # type: ignore[valid-type]
            name="Get State {} by key".format(field),
            description=keyby_prefix + cleandoc(get_state.__doc__ or ""),
            openapi_extra={"type_": fq_type_name} if fq_type_name else None,
        )(get_state)

        if "_" in field:
            api_router.get(
                "/{}/{{key:path}}".format(field.replace("_", "-")),
                responses=get_default_responses(),
                response_model=list_model,  # type: ignore[valid-type]
                include_in_schema=False,
            )(get_state)

    if model:

        async def get_state(query: Optional[Query] = query_json(), request: Request = None) -> list_model:  # type: ignore[misc, valid-type]
            """Get state value on a non-dict basket channel. This endpoint will flatten the state structure and return a list of the elements.
            Query parameters may be provided to perform server-side filtering and other functionality on the state object.

            States may be queried by certain conditions. Currently only filtering is supported. Filters can be used to evaluate
            objects in state and compare them to either scalar values or other attributes on the object. Here are some simple examples
            using the demo application provided with `csp-gateway`:

            ```
            # Filter only records where `record.x` == 5
            api/v1/state/example_with_state?query={"filters":[{"attr":"x","by":{"value":5,"where":"=="}}]}

            # Filter only records where `record.x` < 10
            /api/v1/state/example_with_state?query={"filters":[{"attr":"x","by":{"value":10,"where":"<"}}]}

            # Filter only records where `record.timestamp` < "2023-03-30T14:45:26.394000"
            /api/v1/state/example_with_state?query={"filters":[{"attr":"timestamp","by":{"when":"2023-03-30T14:45:26.394000","where":"<"}}]}

            # Filter only records where `record.id` < `record.y`
            /api/v1/state/example_with_state?query={"filters":[{"attr":"id","by":{"attr":"y","where":"<"}}]}

            # Filter only records where `record.x` < 50 and `record.x` >= 30
            /api/v1/state/example_with_state?query={"filters":[{"attr":"x","by":{"value":50,"where":"<"}},{"attr":"x","by":{"value":30,"where":">="}}]}
            ```
            """
            try:
                res = request.app.gateway.channels.query(field, query=query)
            except NoProviderException:
                raise HTTPException(
                    status_code=404,
                    detail="State not found: {}".format(field),
                )

            return prepare_response(res, is_list_model=True)

        api_router.get(
            "/{}".format(field),
            responses=get_default_responses(),
            response_model=list_model,  # type: ignore[valid-type]
            name="Get State {}".format(field),
            description=keyby_prefix + cleandoc(get_state.__doc__ or ""),
            openapi_extra={"type_": fq_type_name} if fq_type_name else None,
        )(get_state)

        if "_" in field:
            api_router.get(
                "/{}".format(field.replace("_", "-")),
                responses=get_default_responses(),
                response_model=list_model,  # type: ignore[valid-type]
                include_in_schema=False,
            )(get_state)


def add_state_available_channels(
    api_router: APIRouter,
    fields: Optional[Set[str]] = None,
) -> None:
    @api_router.get(
        "/",
        responses=get_default_responses(),
        response_model=List[str],
    )
    async def get_state(request: Request) -> List[str]:
        """
        Return the list of all available state names under the `/state` route.

        Note: This endpoint does not support filtering.
        """
        return sorted(
            name for name in ChannelSelection().select_from(request.app.gateway.channels, state_channels=True) if fields is None or name in fields
        )
