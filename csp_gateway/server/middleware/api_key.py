from datetime import timedelta
from secrets import token_urlsafe
from socket import gethostname
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import Field
from starlette.status import HTTP_403_FORBIDDEN

# Imported from the leaf module, not the `csp_gateway.server` package: that package re-exports
# `.modules` before `.web`, so it is only partially initialized while this module is imported.
from ..settings import GatewaySettings
from ..web import GatewayWebApp
from .base import AuthenticationMiddleware
from .hacks.api_key_middleware_websocket_fix import (
    APIKeyCookie,
    APIKeyHeader,
    APIKeyQuery,
)


class MountAPIKeyMiddleware(AuthenticationMiddleware):
    api_key: str | list[str] | None = Field(
        token_urlsafe(32),
        description="The API key(s) for access. Can be a single string or a list of valid keys. The default is auto-generated, but user-provided value(s) can be used.",
    )
    domain: str | None = Field(
        default=None,
        description="Domain for the authentication cookie. Defaults to unset, which scopes the cookie to the host that served it.",
    )

    api_key_name: str = "token"
    api_key_timeout: timedelta = Field(description="Cookie timeout for API Key authentication", default=timedelta(hours=12))

    unauthorized_status_message: str = "unauthorized"

    def info(self, settings: GatewaySettings) -> str:
        url = f"http://{gethostname()}:{settings.PORT}"
        if settings.UI:
            # The login route trades the key for a session cookie before handing over to the UI.
            # Landing on "/" with a key authenticates that one request, leaving the page unable to
            # authenticate the tree and data it goes on to fetch for itself.
            return f"\tUI: {url}/login?token={self.api_key}"
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
        async def route_login_and_add_cookie(request: Request, api_key: str = Depends(check)):
            response = RedirectResponse(url=app.root_path_url(request, "/"))
            response.set_cookie(
                self.api_key_name,
                value=api_key,
                domain=self.domain,
                httponly=True,
                max_age=int(self.api_key_timeout.total_seconds()),
            )
            return response

        @auth_router.get("/logout")
        async def route_logout_and_remove_cookie(request: Request):
            response = RedirectResponse(url=app.root_path_url(request, "/login"))
            response.delete_cookie(self.api_key_name, domain=self.domain)
            return response

        self._setup_public_routes(app)

    def _setup_public_routes(self, app: GatewayWebApp) -> None:
        """Setup public routes, middleware, and exception handler. Shared by subclasses."""
        public_router: APIRouter = app.get_router("public")
        login_page, logout_page = self._auth_pages(app)

        def _login_html(request: Request) -> HTMLResponse:
            if login_page is not None:
                return HTMLResponse(login_page)
            return app.templates.TemplateResponse(request, "login.html.j2", context={"api_key_name": self.api_key_name})

        @public_router.get("/login", response_class=HTMLResponse, include_in_schema=False)
        async def get_login_page(token: str = "", request: Request = None):
            if token and token != "":
                return RedirectResponse(url=app.root_path_url(request, app.api_path(f"/auth/login?token={token}")))
            return _login_html(request)

        @public_router.get("/logout", response_class=HTMLResponse, include_in_schema=False)
        async def get_logout_page(request: Request = None):
            if logout_page is not None:
                return HTMLResponse(logout_page)
            return app.templates.TemplateResponse(request, "logout.html.j2")

        # add auth to all other routes
        app.add_middleware(Depends(self.get_check_dependency()))

        @app.app.exception_handler(403)
        async def custom_403_handler(request: Request = None, *args):
            if app.is_api_request(request):
                # programmatic api access, return json
                return JSONResponse(
                    {
                        "detail": self.unauthorized_status_message,
                        "status_code": 403,
                    },
                    status_code=403,
                )
            if login_page is not None:
                # Sent to the login page rather than rendered in place, so the reason rides the query
                # string the page reads it from.
                return RedirectResponse(url=app.root_path_url(request, f"/login?error={quote(self.unauthorized_status_message)}"))
            return app.templates.TemplateResponse(
                request,
                "login.html.j2",
                context={
                    "api_key_name": self.api_key_name,
                    "status_code": 403,
                    "detail": self.unauthorized_status_message,
                },
            )

    def _auth_pages(self, app: GatewayWebApp) -> tuple[str | None, str | None]:
        """The spaday login and logout markup, or a pair of Nones when the legacy templates are in play."""
        if app.ui is None:
            return None, None
        login = app.ui.mount_auth_page(
            title="Login",
            action=app.api_path("/auth/login"),
            fields=[{"name": self.api_key_name, "type": "password", "placeholder": "API Key..."}],
        )
        logout = app.ui.mount_auth_page(
            title="Logout",
            action=app.api_path("/auth/logout"),
            submit="Logout",
        )
        return login, logout
