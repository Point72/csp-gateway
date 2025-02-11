from json import dumps
from typing import Dict, List

from fastapi import Request
from fastapi.responses import HTMLResponse

from csp_gateway.server import GatewayChannels, GatewayModule

# separate to avoid circular
from csp_gateway.server.web import GatewayWebApp


class MountChannelsGraph(GatewayModule):
    route: str = "/channels_graph"

    def connect(self, channels: GatewayChannels) -> None:
        # NO-OP
        ...

    def rest(self, app: GatewayWebApp) -> None:
        api_router = app.get_router("api")
        app_router = app.get_router("app")

        # TODO subselect
        @api_router.get(
            self.route,
            response_model=Dict[str, Dict[str, List[str]]],
            tags=["Utility"],
        )
        def channels_graph_data(request: Request) -> Dict[str, Dict[str, List[str]]]:
            """
            This endpoint returns the structure of the GatewayChannels graph as a JSON object.
            It is used by the `Browse Channels Graph` endpoint to generate a nice, interactive view of the graph.

            Data is of the form:

            ```
            {
                "<channel name>": {
                    "getters": [`GatewayModule`s that pull from that channel],
                    "setters": [`GatewayModule`s that push to that channel]
                },
                ...
            }
            ```
            """
            return request.app.gateway.channels.graph()

        @app_router.get("/channels_graph", response_class=HTMLResponse, tags=["Utility"])
        def browse_channels_graph(request: Request):
            """
            This endpoint is a small webpage that shows the dependency relationship of the GatewayChannels graph powering this API.
            """
            channels_graph = request.app.gateway.channels.graph()
            return app.templates.TemplateResponse(
                "channels_graph.html.j2",
                {"request": request, "channels_graph": dumps(channels_graph)},
            )
