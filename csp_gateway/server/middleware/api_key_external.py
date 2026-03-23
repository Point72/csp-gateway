from typing import Any, Dict, Optional
from uuid import uuid4

from ccflow import PyObjectPath
from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import RedirectResponse
from pydantic import Field, PrivateAttr, field_validator
from starlette.status import HTTP_403_FORBIDDEN

from ..settings import GatewaySettings
from ..web import GatewayWebApp
from .api_key import MountAPIKeyMiddleware
from .base import IdentityAwareMiddlewareMixin
from .hacks.api_key_middleware_websocket_fix.api_key import (
    APIKeyCookie,
    APIKeyHeader,
    APIKeyQuery,
)

__all__ = ("MountExternalAPIKeyMiddleware",)


class MountExternalAPIKeyMiddleware(MountAPIKeyMiddleware, IdentityAwareMiddlewareMixin):
    """API Key middleware with external validation and identity tracking.

    This middleware validates API keys using an external function and maintains
    an identity store mapping session UUIDs to user identities.

    Attributes:
        external_validator: Path to external validation function.
        identity_store: Maps session UUIDs to identity dicts (via IdentityAwareMiddlewareMixin).
    """

    external_validator: Optional[PyObjectPath] = Field(
        default=None, description="Path to external API key validation function (ccflow.PyObjectPath as string)."
    )

    # Identity store - maps session UUID to identity dict
    _identity_store: Dict[str, Dict[str, Any]] = PrivateAttr(default_factory=dict)
    _app_settings: Optional[GatewaySettings] = PrivateAttr(default=None)
    _app_module: Any = PrivateAttr(default=None)

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

    async def get_identity_from_credentials(
        self,
        *,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Extract and validate API key credentials.

        Checks session cookie first, then query param, then header for API key.
        Validates via external validator if found.

        Args:
            cookies: Dict of request cookies
            headers: Dict of request headers
            query_params: Dict of query parameters

        Returns:
            Identity dict if valid API key found, None otherwise.
        """
        cookies = cookies or {}
        headers = headers or {}
        query_params = query_params or {}

        # Check session cookie first (via base implementation)
        session_uuid = cookies.get(self.api_key_name)
        if session_uuid:
            identity = await self.get_identity(session_uuid)
            if identity:
                return identity

        # Try query param
        api_key = query_params.get(self.api_key_name)
        if api_key:
            try:
                identity = self._invoke_external(api_key, self._app_settings, self._app_module)
                if identity and isinstance(identity, dict):
                    return identity
            except Exception:
                pass

        # Try header
        api_key = headers.get(self.api_key_name)
        if api_key:
            try:
                identity = self._invoke_external(api_key, self._app_settings, self._app_module)
                if identity and isinstance(identity, dict):
                    return identity
            except Exception:
                pass

        return None

    @property
    def cookie_name(self) -> str:
        """Return the cookie/query param name for auth tokens."""
        return self.api_key_name

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
