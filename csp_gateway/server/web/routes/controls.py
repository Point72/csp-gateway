import asyncio
import logging
from typing import List, Optional, Set

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from csp_gateway.utils import Controls

from ..utils import get_default_responses
from .shared import prepare_response

log = logging.getLogger(__name__)


_WAIT_THRESHOLD = 0.1

__all__ = (
    "add_controls_routes",
    "add_controls_available_channels",
)


def add_controls_routes(api_router: APIRouter, field: str) -> None:
    if field == "heartbeat":
        # Add heartbeat channel
        @api_router.get(
            "/heartbeat",
            responses=get_default_responses(),
            response_model=Controls,
            name="Get Heartbeat",
        )
        async def heartbeat(request: Request) -> Controls:
            """
            This endpoint is a lightweight `ping`/`pong` endpoint that can be used to determine the status of the underlying webserver.
            """
            data = Controls(name="heartbeat")

            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, "controls"):
                raise HTTPException(status_code=404, detail="Channel not found: controls")

            # send data to csp
            request.app.gateway.channels.send("controls", data)

            # don't care about the result
            while data.status != "ok":
                await asyncio.sleep(_WAIT_THRESHOLD)

            return prepare_response(data, is_list_model=False)

    elif field == "stats":

        @api_router.get(
            "/stats",
            responses=get_default_responses(),
            response_model=Controls,
            name="Get CSP Stats",
        )
        async def stats(request: Request) -> Controls:
            """This endpoint will collect and return various engine and system stats, including:

            - CPU utilization (`cpu`)
            - Virtual memory utilization (`memory`)
            - Total memory available (`memory-total`)
            - Current system time (`now`)
            - CSP engine time (`csp-now`)
            - Hostname (`host`)
            - Username (`user`)
            """
            data = Controls(name="stats")

            # Throw 404 if not a supported channel
            if not hasattr(request.app.gateway.channels, "controls"):
                raise HTTPException(status_code=404, detail="Channel not found: controls")

            # send data to csp
            request.app.gateway.channels.send("controls", data)

            while not data.data:
                await asyncio.sleep(_WAIT_THRESHOLD)
            data.update_str()

            return prepare_response(data, is_list_model=False)

    elif field == "shutdown":

        @api_router.post(
            "/shutdown",
            responses=get_default_responses(),
            response_model=Controls,
            name="Shutdown Server",
        )
        async def shutdown(request: Request, background_tasks: BackgroundTasks) -> Controls:
            """
            **WARNING:** Use this endpoint with caution.

            This endpoint will cleanly shutdown the engine and webserver. It is used for the kill switch in UIs.
            """
            # FIXME ugly
            background_tasks.add_task(request.app.gateway.stop, user_initiated=True)

            data = Controls(name="shutdown", status="ok")
            return prepare_response(data, is_list_model=False)

    else:
        raise ValueError(f"Unsupported controls field: {field}. Supported fields are 'heartbeat', 'stats', and 'shutdown'.")


def add_controls_available_channels(api_router: APIRouter, fields: Optional[Set[str]] = None) -> None:
    @api_router.get(
        "/",
        responses=get_default_responses(),
        response_model=List[str],
    )
    async def get_controls(request: Request) -> List[str]:
        """
        This endpoint will return a list of string values of all available channels under the `/controls` route.
        """
        return sorted(fields if fields else ("heartbeat", "stats", "shutdown"))
