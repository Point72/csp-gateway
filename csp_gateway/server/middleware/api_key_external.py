from typing import Optional
from uuid import uuid4

from ccflow import PyObjectPath
from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import RedirectResponse
from pydantic import Field, field_validator
from starlette.status import HTTP_403_FORBIDDEN

from ..settings import GatewaySettings
from ..web import GatewayWebApp
from .api_key import MountAPIKeyMiddleware
from .hacks.api_key_middleware_websocket_fix.api_key import (
    APIKeyCookie,
    APIKeyHeader,
    APIKeyQuery,
)

__all__ = ("MountExternalAPIKeyMiddleware",)


class MountExternalAPIKeyMiddleware(MountAPIKeyMiddleware):
    external_validator: Optional[PyObjectPath] = Field(
        default=None, description="Path to external API key validation function (ccflow.PyObjectPath as string)."
    )

    _identity_store: dict = {}

    @field_validator("external_validator")
    def validate_external_validator(cls, v):
        if v is not None:
            if not isinstance(v, PyObjectPath):
                raise ValueError("external_validator must be a PyObjectPath")
            if not callable(v.object):
                raise ValueError("external_validator must point to a callable object")
        return v

    def _invoke_external(self, api_key: str, settings: GatewaySettings, module=None):
        if self.external_validator is None:
            return None
        return self.external_validator.object(api_key, settings, module)

    def validate(self):
        """Return a FastAPI dependency function for external API key validation."""
        api_key_query_security = Security(APIKeyQuery(name=self.api_key_name, auto_error=False))
        api_key_header_security = Security(APIKeyHeader(name=self.api_key_name, auto_error=False))
        api_key_cookie_security = Security(APIKeyCookie(name=self.api_key_name, auto_error=False))

        async def validate_credentials(
            api_key_query: str = api_key_query_security,
            api_key_header: str = api_key_header_security,
            api_key_cookie: str = api_key_cookie_security,
        ) -> str:
            """Validate API key using external validator and return a session UUID."""
            try:
                for provided_key in (api_key_query, api_key_header, api_key_cookie):
                    identity = self._invoke_external(provided_key, self._app_settings, self._app_module)
                    if identity and isinstance(identity, dict):
                        user_uuid = str(uuid4())
                        while user_uuid in self._identity_store:
                            user_uuid = str(uuid4())
                        self._identity_store[user_uuid] = identity
                        return user_uuid
            except Exception as e:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail=self.unauthorized_status_message,
                ) from e
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=self.unauthorized_status_message,
            )

        return validate_credentials

    def rest(self, app: GatewayWebApp) -> None:
        # Store app references for use in check()
        self._app_settings = app.settings
        self._app_module = app

        auth_router: APIRouter = app.get_router("auth")
        check = self.get_check_dependency()

        @auth_router.get("/login")
        async def route_login_and_add_cookie(api_key: str = Depends(check)):
            response = RedirectResponse(url="/")
            if api_key in self._identity_store:
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
        async def route_logout_and_remove_cookie(request: Request = None):
            response = RedirectResponse(url="/login")
            user_uuid = request.cookies.get(self.api_key_name) if request else None
            if user_uuid and user_uuid in self._identity_store:
                self._identity_store.pop(user_uuid, None)
            response.delete_cookie(self.api_key_name, domain=self.domain)
            return response

        # Call parent to set up public routes, middleware, and exception handler
        self._setup_public_routes(app)
