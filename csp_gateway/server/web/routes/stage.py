"""REST routes for the staging API.

Exposes endpoints under ``/api/v1/stage/`` for managing staged structs
on channels that have staging enabled.

See STAGE.md for the full API specification.
"""

import json
import logging
from typing import Dict, List, Optional, Set, Union

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel

from csp_gateway.utils import NoProviderException

from ..utils import get_default_responses

log = logging.getLogger(__name__)

__all__ = (
    "add_stage_routes",
    "add_stage_available_channels",
)


def _serialize_staging_result(result: Dict[str, List]) -> Response:
    """Serialize a staging result dict (staging_id -> list of structs) to JSON Response."""
    serialized = {}
    for sid, items in result.items():
        serialized[sid] = [json.loads(item.type_adapter().dump_json(item)) for item in items]
    return Response(
        content=json.dumps(serialized),
        media_type="application/json",
    )


def add_stage_routes(
    api_router: APIRouter,
    field: str,
    model: Union[BaseModel, List[BaseModel]] = None,
) -> None:
    """Mount REST routes for staging on a single channel ``field``."""

    # POST /stage/<channel> — stage_add
    async def stage_add(
        request: Request,
        id: Optional[str] = Query(None, description="Comma-separated staging IDs to add to"),
        data: Optional[model] = Body(None),
    ):
        """Add a struct to staging area(s).

        - Empty body, no id: create a new empty staging
        - Body with struct, no id: add to latest staging or create new
        - Body with struct, id=<ids>: add to specified staging(s)
        """
        try:
            staging_ids = _parse_staging_ids(id)
            affected = request.app.gateway.channels.stage_add(field, struct=data, staging_ids=staging_ids)
            # Return the affected stagings with their contents
            result = request.app.gateway.channels.stage_lookup(field)
            filtered = {sid: result.get(sid, []) for sid in affected}
            return _serialize_staging_result(filtered)
        except NoProviderException:
            raise HTTPException(status_code=404, detail=f"Staging not enabled for channel: {field}")
        except (ValueError, KeyError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    api_router.post(
        f"/{field}",
        responses=get_default_responses(),
        name=f"Stage Add {field}",
        description=f"Add struct(s) to staging for channel `{field}`.",
    )(stage_add)

    if "_" in field:
        api_router.post(
            f"/{field.replace('_', '-')}",
            responses=get_default_responses(),
            include_in_schema=False,
        )(stage_add)

    # DELETE /stage/<channel> — stage_remove
    async def stage_remove(
        request: Request,
        id: Optional[str] = Query(None, description="Comma-separated staging IDs to remove from"),
        data: Optional[model] = Body(None),
    ):
        """Remove struct(s) from staging area(s).

        - Empty body, no id: clear latest staging
        - Empty body, id=: clear all stagings
        - Empty body, id=<id>: clear structs from specific staging
        - Body with struct, no id: remove struct from latest staging containing it
        - Body with struct, id=: remove struct from all stagings
        - Body with struct, id=<id>: remove struct from specific staging
        """
        try:
            staging_ids = _parse_staging_ids(id)
            affected = request.app.gateway.channels.stage_remove(field, struct=data, staging_ids=staging_ids)
            # Return affected staging IDs mapped to their remaining contents
            result = request.app.gateway.channels.stage_lookup(field)
            filtered = {sid: result.get(sid, []) for sid in affected}
            return _serialize_staging_result(filtered)
        except NoProviderException:
            raise HTTPException(status_code=404, detail=f"Staging not enabled for channel: {field}")
        except (ValueError, KeyError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    api_router.delete(
        f"/{field}",
        responses=get_default_responses(),
        name=f"Stage Remove {field}",
        description=f"Remove struct(s) from staging for channel `{field}`.",
    )(stage_remove)

    if "_" in field:
        api_router.delete(
            f"/{field.replace('_', '-')}",
            responses=get_default_responses(),
            include_in_schema=False,
        )(stage_remove)

    # PATCH /stage/<channel> — stage_release
    async def stage_release(
        request: Request,
        id: Optional[str] = Query(None, description="Comma-separated staging IDs to release"),
    ):
        """Release staged structs into the channel.

        - No id: release all stagings
        - id=<ids>: release specific staging(s)
        """
        try:
            staging_ids = _parse_staging_ids(id)
            released = request.app.gateway.channels.stage_release(field, staging_ids=staging_ids)
            return _serialize_staging_result(released)
        except NoProviderException:
            raise HTTPException(status_code=404, detail=f"Staging not enabled for channel: {field}")
        except (ValueError, KeyError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    api_router.patch(
        f"/{field}",
        responses=get_default_responses(),
        name=f"Stage Release {field}",
        description=f"Release staged structs into channel `{field}`.",
    )(stage_release)

    if "_" in field:
        api_router.patch(
            f"/{field.replace('_', '-')}",
            responses=get_default_responses(),
            include_in_schema=False,
        )(stage_release)

    # GET /stage/<channel> — stage_list
    async def stage_list(
        request: Request,
        id: Optional[str] = Query(None, description="Specific staging ID to check"),
    ) -> List[str]:
        """List staging IDs for a channel.

        - No id: list all staging IDs
        - id=<id>: check if specific staging exists
        """
        try:
            return request.app.gateway.channels.stage_list(field, staging_id=id)
        except NoProviderException:
            raise HTTPException(status_code=404, detail=f"Staging not enabled for channel: {field}")

    api_router.get(
        f"/{field}",
        responses=get_default_responses(),
        response_model=List[str],
        name=f"Stage List {field}",
        description=f"List staging IDs for channel `{field}`.",
    )(stage_list)

    if "_" in field:
        api_router.get(
            f"/{field.replace('_', '-')}",
            responses=get_default_responses(),
            response_model=List[str],
            include_in_schema=False,
        )(stage_list)

    # PUT /stage/<channel> — stage_lookup
    async def stage_lookup(
        request: Request,
        id: Optional[str] = Query(None, description="Specific staging ID to look up"),
    ):
        """Look up contents of staging area(s).

        - No id: list all staging contents
        - id=<id>: list contents of specific staging
        """
        try:
            result = request.app.gateway.channels.stage_lookup(field, staging_id=id)
            return _serialize_staging_result(result)
        except NoProviderException:
            raise HTTPException(status_code=404, detail=f"Staging not enabled for channel: {field}")

    api_router.put(
        f"/{field}",
        responses=get_default_responses(),
        name=f"Stage Lookup {field}",
        description=f"Look up staged contents for channel `{field}`.",
    )(stage_lookup)

    if "_" in field:
        api_router.put(
            f"/{field.replace('_', '-')}",
            responses=get_default_responses(),
            include_in_schema=False,
        )(stage_lookup)


def add_stage_available_channels(
    api_router: APIRouter,
    fields: Optional[Set[str]] = None,
) -> None:
    """Mount the top-level GET /stage/ route listing all staged channels."""

    @api_router.get(
        "/",
        responses=get_default_responses(),
        response_model=List[str],
    )
    async def get_staged_channels(request: Request) -> List[str]:
        """Return the list of all channels with staging enabled."""
        all_staged = request.app.gateway.channels.staged_channels()
        if fields is not None:
            return sorted(name for name in all_staged if name in fields)
        return sorted(all_staged)


def _parse_staging_ids(id_param: Optional[str]) -> Optional[List[str]]:
    """Parse the comma-separated id query parameter.

    Returns:
    - None if id_param is None (not provided)
    - [] if id_param is empty string
    - list of IDs otherwise
    """
    if id_param is None:
        return None
    if id_param == "":
        return []
    return [s.strip() for s in id_param.split(",") if s.strip()]
