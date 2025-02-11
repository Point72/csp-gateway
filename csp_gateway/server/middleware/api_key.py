from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import Field, PrivateAttr
from starlette.status import HTTP_403_FORBIDDEN

from csp_gateway.server import GatewayChannels, GatewayModule

# separate to avoid circular
from ..web import GatewayWebApp
from .hacks.api_key_middleware_websocket_fix.api_key import (
    APIKeyCookie,
    APIKeyHeader,
    APIKeyQuery,
)


class MountAPIKeyMiddleware(GatewayModule):
    api_key_timeout: timedelta = Field(description="Cookie timeout for API Key authentication", default=timedelta(hours=12))

    # NOTE: don't make this publically configureable
    # as it is needed in gateway.py
    _api_key_name: str = PrivateAttr("token")
    _api_key_secret: str = PrivateAttr("")

    unauthorized_status_message: str = "unauthorized"

    def connect(self, channels: GatewayChannels) -> None:
        # NO-OP
        ...

    def rest(self, app: GatewayWebApp) -> None:
        if app.settings.AUTHENTICATE:
            # first, pull out the api key secret from the settings
            self._api_key_secret = app.settings.API_KEY

            # reinitialize header
            api_key_query = APIKeyQuery(name=self._api_key_name, auto_error=False)
            api_key_header = APIKeyHeader(name=self._api_key_name, auto_error=False)
            api_key_cookie = APIKeyCookie(name=self._api_key_name, auto_error=False)

            # routers
            auth_router: APIRouter = app.get_router("auth")
            public_router: APIRouter = app.get_router("public")

            # now mount middleware
            async def get_api_key(
                api_key_query: str = Security(api_key_query),
                api_key_header: str = Security(api_key_header),
                api_key_cookie: str = Security(api_key_cookie),
            ):
                if api_key_query == self._api_key_secret or api_key_header == self._api_key_secret or api_key_cookie == self._api_key_secret:
                    return self._api_key_secret
                else:
                    raise HTTPException(
                        status_code=HTTP_403_FORBIDDEN,
                        detail=self.unauthorized_status_message,
                    )

            @auth_router.get("/login")
            async def route_login_and_add_cookie(api_key: str = Depends(get_api_key)):
                response = RedirectResponse(url="/")
                response.set_cookie(
                    self._api_key_name,
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
                response.delete_cookie(self._api_key_name, domain=app.settings.AUTHENTICATION_DOMAIN)
                return response

            # I'm hand rolling these for now...
            @public_router.get("/login", response_class=HTMLResponse, include_in_schema=False)
            async def get_login_page(token: str = "", request: Request = None):
                if token:
                    if token != "":
                        return RedirectResponse(url=f"{app.settings.API_V1_STR}/auth/login?token={token}")
                return app.templates.TemplateResponse(
                    "login.html.j2",
                    {"request": request, "api_key_name": self._api_key_name},
                )

            @public_router.get("/logout", response_class=HTMLResponse, include_in_schema=False)
            async def get_logout_page(request: Request = None):
                return app.templates.TemplateResponse("logout.html.j2", {"request": request})

            # add auth to all other routes
            app.add_middleware(Depends(get_api_key))

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
                        "api_key_name": self._api_key_name,
                        "status_code": 403,
                        "detail": self.unauthorized_status_message,
                    },
                )
