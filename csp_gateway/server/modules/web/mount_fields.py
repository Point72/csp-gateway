from typing import List, Optional, Type, Union

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from csp_gateway.server import ChannelSelection, GatewayChannels, GatewayModule
from csp_gateway.server.web import GatewayWebApp, get_default_responses


class MountFieldRestRoutes(GatewayModule):
    """Mount rest routes for specific non-csp fields of the GatewayChannels.

    This is not done generically across all static fields as they may not always be serializable.
    """

    requires: Optional[ChannelSelection] = []
    fields: List[str] = Field(description="Static fields on the Channels that should be exposed via REST. These must be JSON serializable.")
    route: str = "/field"

    def connect(self, channels: GatewayChannels) -> None:
        # NO-OP
        ...

    def rest(self, app: GatewayWebApp) -> None:
        # Get API Router
        api_router: APIRouter = app.get_router("api")

        for field in self.fields:
            model = app.gateway.channels_model.get_outer_type(field)
            add_field_routes(api_router, field, self.route, model)

        @api_router.get(
            "{}".format(self.route),
            responses=get_default_responses(),
            response_model=List[str],
            include_in_schema=False,
        )
        async def get_field(request: Request) -> List[str]:
            """
            This endpoint will return a list of string values of all available channels under the `/field` route.
            """
            return self.fields


def add_field_routes(
    api_router: APIRouter,
    field: str,
    route: str,
    model: Union[BaseModel, Type],
) -> None:
    async def get_field(request: Request) -> model:  # type: ignore[misc, valid-type]
        """
        Get static field value on a static channel.
        """
        # Throw 404 if not a supported channel
        if not hasattr(request.app.gateway.channels, field):
            raise HTTPException(status_code=404, detail="Channel field not found: {}".format(field))

        # Grab the request off the edge
        try:
            res = getattr(request.app.gateway.channels, field)
        except AttributeError:
            raise HTTPException(
                status_code=404,
                detail="Channel field not found: {}".format(field),
            )

        return res

    api_router.get(
        "{}/{}".format(route, field),
        responses=get_default_responses(),
        response_model=model,
        name="Get Channel field {}".format(field),
    )(get_field)

    api_router.get(
        "/{}".format(field.replace("_", "-")),
        responses=get_default_responses(),
        response_model=model,
        include_in_schema=False,
    )(get_field)
