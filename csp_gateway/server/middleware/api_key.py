from datetime import timedelta
from secrets import token_urlsafe
from socket import gethostname
from typing import List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import Field
from starlette.status import HTTP_403_FORBIDDEN

# separate to avoid circular
from ..settings import GatewaySettings
from ..web import GatewayWebApp
from .base import AuthenticationMiddleware
from .hacks.api_key_middleware_websocket_fix.api_key import (
    APIKeyCookie,
    APIKeyHeader,
    APIKeyQuery,
)


class MountAPIKeyMiddleware(AuthenticationMiddleware):
    api_key: Optional[Union[str, List[str]]] = Field(
        token_urlsafe(32),
        description="The API key(s) for access. Can be a single string or a list of valid keys. The default is auto-generated, but user-provided value(s) can be used.",
    )
    domain: str = gethostname()

    api_key_name: str = "token"
    api_key_timeout: timedelta = Field(description="Cookie timeout for API Key authentication", default=timedelta(hours=12))

    unauthorized_status_message: str = "unauthorized"

    def info(self, settings: GatewaySettings) -> str:
        url = f"http://{gethostname()}:{settings.PORT}"
        if settings.UI:
            return f"\tUI: {url}?token={self.api_key}"
        return f"\tAPI: {url}/openapi.json?token={self.api_key}"

    def validate(self):
        """Return a FastAPI dependency function for API key validation."""
        api_key_query_security = Security(APIKeyQuery(name=self.api_key_name, auto_error=False))
        api_key_header_security = Security(APIKeyHeader(name=self.api_key_name, auto_error=False))
        api_key_cookie_security = Security(APIKeyCookie(name=self.api_key_name, auto_error=False))

        async def validate_credentials(
            api_key_query: str = api_key_query_security,
            api_key_header: str = api_key_header_security,
            api_key_cookie: str = api_key_cookie_security,
        ) -> str:
            """Validate API key from query, header, or cookie."""
            valid_keys = self.api_key if isinstance(self.api_key, list) else [self.api_key]
            for provided_key in (api_key_query, api_key_header, api_key_cookie):
                if provided_key in valid_keys:
                    return provided_key
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=self.unauthorized_status_message,
            )

        return validate_credentials

    def rest(self, app: GatewayWebApp) -> None:
        # routers
        auth_router: APIRouter = app.get_router("auth")
        check = self.get_check_dependency()

        @auth_router.get("/login")
        async def route_login_and_add_cookie(api_key: str = Depends(check)):
            response = RedirectResponse(url="/")
            response.set_cookie(
                self.api_key_name,
                value=api_key,
                domain=self.domain,
                httponly=True,
                max_age=self.api_key_timeout.total_seconds(),
                expires=self.api_key_timeout.total_seconds(),
            )
            return response

        @auth_router.get("/logout")
        async def route_logout_and_remove_cookie():
            response = RedirectResponse(url="/login")
            response.delete_cookie(self.api_key_name, domain=self.domain)
            return response

        self._setup_public_routes(app)

    def _setup_public_routes(self, app: GatewayWebApp) -> None:
        """Setup public routes, middleware, and exception handler. Shared by subclasses.""" ""
        public_router: APIRouter = app.get_router("public")

        @public_router.get("/login", response_class=HTMLResponse, include_in_schema=False)
        async def get_login_page(token: str = "", request: Request = None):
            if token:
                if token != "":
                    return RedirectResponse(url=f"{app.settings.API_STR}/auth/login?token={token}")
            return app.templates.TemplateResponse(
                "login.html.j2",
                {"request": request, "api_key_name": self.api_key_name},
            )

        @public_router.get("/logout", response_class=HTMLResponse, include_in_schema=False)
        async def get_logout_page(request: Request = None):
            return app.templates.TemplateResponse("logout.html.j2", {"request": request})

        # add auth to all other routes
        app.add_middleware(Depends(self.get_check_dependency()))

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
