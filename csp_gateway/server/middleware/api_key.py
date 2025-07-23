from datetime import timedelta
from logging import getLogger
from secrets import token_urlsafe
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import Field, PrivateAttr, field_validator
from starlette.status import HTTP_403_FORBIDDEN

from csp_gateway.server import GatewayChannels, GatewayModule

from ..shared import ChannelSelection

# separate to avoid circular
from ..web import GatewayWebApp
from .hacks.api_key_middleware_websocket_fix.api_key import (
    APIKeyCookie,
    APIKeyHeader,
    APIKeyQuery,
)

_log = getLogger(__name__)

__all__ = (
    "MountAuthMiddleware",
    "MountAPIKeyMiddleware",
)

# TODO: More eventually


class MountAuthMiddleware(GatewayModule):
    enforce: list = Field(default=(), description="Routes to enforce, default empty means 'all'")
    channels: ChannelSelection = Field(
        default_factory=ChannelSelection,
        description="Channels or subroutes to enforce. If route is not present in `enforce`, implies 'allow all'",
    )

    enforce_controls: bool = Field(default=False, description="Whether to allow access to controls routes. Defaults to True")
    enforce_ui: bool = Field(default=True, description="Whether to allow web access to the API Key authentication routes. Defaults to True")

    unauthorized_status_message: str = "unauthorized"

    _enforced_channels: List[str] = PrivateAttr(default_factory=list)

    def connect(self, channels: GatewayChannels) -> None:
        # NO-OP
        ...


class MountAPIKeyMiddleware(MountAuthMiddleware):
    api_key: str = Field(default=token_urlsafe(32), description="API Key to use")
    api_key_name: str = Field(default="token", description="API Key to use")
    api_key_timeout: timedelta = Field(description="Cookie timeout for API Key authentication", default=timedelta(hours=12))

    _instance_count = 0

    @field_validator("api_key_name", mode="before")
    @classmethod
    def _validate_api_key_name(cls, value: str) -> str:
        if not value:
            raise ValueError("API Key name must be a non-empty string")
        value = f"{value.strip().lower()}-{cls._instance_count}"
        cls._instance_count += 1
        return value

    def rest(self, app: GatewayWebApp) -> None:
        if app.settings.AUTHENTICATE:
            # Use configuration to determine allowed routes
            # for this API key
            self._calculate_auth(app)

            # Setup the routes for authentication
            self._setup_routes(app)

    def _calculate_auth(self, app: GatewayWebApp) -> None:
        self._enforced_channels = self.channels.select_from(app.gateway.channels_model)

        # Fully form the url
        self._api_str = app.settings.API_STR

    def _setup_routes(self, app: GatewayWebApp) -> None:
        # reinitialize header
        api_key_query = APIKeyQuery(name=self.api_key_name, auto_error=False)
        api_key_header = APIKeyHeader(name=self.api_key_name, auto_error=False)
        api_key_cookie = APIKeyCookie(name=self.api_key_name, auto_error=False)

        # routers
        auth_router: APIRouter = app.get_router("auth")
        public_router: APIRouter = app.get_router("public")

        # now mount middleware
        async def get_api_key(
            request: Request = None,
            api_key_query: str = Security(api_key_query),
            api_key_header: str = Security(api_key_header),
            api_key_cookie: str = Security(api_key_cookie),
        ):
            if request is None:
                # If request is None, we are not in a request context, return None
                _log.warning("API Key check: request is None, returning None")
                return None

            if hasattr(request.state, "auth"):
                # Already authenticated, return the API key
                _log.info(f"API Key check: already authenticated, returning {self.api_key_name}")
                return request.state.auth

            resolved_path = request.url.path.rstrip("/").replace(self._api_str, "").lstrip("/").rsplit("/", 1)

            if len(resolved_path) == 1:
                root = resolved_path[0]
                channel = ""

            elif len(resolved_path) > 1:
                root = resolved_path[0]
                channel = resolved_path[1]

            if self.enforce and root not in self.enforce:
                # Route not in enforce, allow
                _log.info(f"API Key check: {root}/{channel} not in enforced list {self.enforce}, allowing")
                return ""

            if root == "controls" and not self.enforce_controls:
                # Controls route not enforced, allow
                _log.info(f"API Key check: root {root} not enforced, allowing")
                return ""

            # TODO
            if root in ("", "auth", "perspective") and not self.enforce_ui:
                # UI route not enforced, allow
                _log.info(f"API Key check: root {root} not enforced, allowing")
                return ""

            if root not in ("controls", "auth", "perspective") and channel and channel not in self._enforced_channels:
                # Channel not in enforce, allow
                _log.info(f"API Key check: channel {root}/{channel} not in enforced channels {self._enforced_channels}, allowing")
                return ""

            # Else, enforce
            if api_key_query == self.api_key or api_key_header == self.api_key or api_key_cookie == self.api_key:
                # Return the API key secret to allow access
                _log.info(f"API Key check: {self.api_key_name} matched for {root}/{channel}, allowing access")

                # NOTE: only set this if we are the one validating, not if we are ignoring
                request.state.auth = self.api_key
                return self.api_key

            _log.warning(f"API Key check: {self.api_key_name} did not match, denying access")
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=self.unauthorized_status_message,
            )

        # add auth to all other routes
        app.add_middleware(Depends(get_api_key))

        if self.enforce_ui:

            @auth_router.get("/login")
            async def route_login_and_add_cookie(api_key: str = Depends(get_api_key)):
                if not api_key:
                    raise HTTPException(
                        status_code=HTTP_403_FORBIDDEN,
                        detail=self.unauthorized_status_message,
                    )
                response = RedirectResponse(url="/")
                response.set_cookie(
                    self.api_key_name,
                    value=api_key,
                    domain=app.settings.AUTHENTICATION_DOMAIN,
                    httponly=True,
                    max_age=self.api_key_timeout.total_seconds(),
                    expires=self.api_key_timeout.total_seconds(),
                )
                return response

            @auth_router.get("/logout")
            async def route_logout_and_remove_cookie():
                response = RedirectResponse(url="/login")
                response.delete_cookie(self.api_key_name, domain=app.settings.AUTHENTICATION_DOMAIN)
                return response

            # I'm hand rolling these for now...
            @public_router.get("/login", response_class=HTMLResponse, include_in_schema=False)
            async def get_login_page(token: str = "", request: Request = None):
                if token and token != "":
                    return RedirectResponse(url=f"{self._api_str}/auth/login?token={token}")
                return app.templates.TemplateResponse(
                    "login.html.j2",
                    {"request": request, "api_key_name": self.api_key_name},
                )

            @public_router.get("/logout", response_class=HTMLResponse, include_in_schema=False)
            async def get_logout_page(request: Request = None):
                return app.templates.TemplateResponse("logout.html.j2", {"request": request})

        @app.app.exception_handler(403)
        async def custom_403_handler(request: Request = None, *args):
            if "/api" in request.url.path:
                # programmatic api access, return json
                return JSONResponse(
                    {
                        "detail": self.unauthorized_status_message,
                        "status_code": 403,
                    },
                    status_code=403,
                )
            return app.templates.TemplateResponse(
                "login.html.j2",
                {
                    "request": request,
                    "api_key_name": self.api_key_name,
                    "status_code": 403,
                    "detail": self.unauthorized_status_message,
                },
            )
