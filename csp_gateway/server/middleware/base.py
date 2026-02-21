from fnmatch import fnmatch
from typing import Any, Callable, Dict, List, Optional, Union

from ccflow import PyObjectPath
from fastapi import Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from csp_gateway.server import GatewayChannels, GatewayModule

__all__ = ("AuthenticationMiddleware", "IdentityAwareMiddlewareMixin")


class AuthenticationMiddleware(GatewayModule):
    scope: Optional[Union[str, List[str]]] = "*"
    check: Optional[Union[PyObjectPath, Callable]] = None

    def get_check_callable(self) -> Optional[Callable]:
        """Return the check callable from PyObjectPath or direct callable."""
        if self.check is None:
            return None
        return self.check if callable(self.check) else self.check.object

    def _matches_scope(self, path: str) -> bool:
        """Check if path matches any of the scope glob patterns."""
        if self.scope is None:
            return True
        patterns = self.scope if isinstance(self.scope, list) else [self.scope]
        return any(fnmatch(path, pattern) for pattern in patterns)

    def validate(self) -> Callable:
        """Return a FastAPI dependency function for credential validation.

        Subclasses must implement this method. The returned function should:
        - Accept credentials (extracted via Security dependencies)
        - Return a validated identity/token on success
        - Raise HTTPException on failure

        Note: Scope checking via _matches_scope() is available but not automatically
        applied in validate() due to WebSocket route compatibility constraints.
        """
        raise NotImplementedError("Subclasses must implement validate()")

    def _skip_if_out_of_scope(self, request: Request) -> bool:
        """Check if request is out of scope. Returns True if should skip auth."""
        return not self._matches_scope(request.url.path)

    def get_check_dependency(self) -> Callable:
        """Return the validate() dependency. Scope checking is handled in validate()."""
        return self.validate()

    async def check_scope(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Check that request path is valid in the scope/s. Returns True if in scope."""
        if self._matches_scope(request.url.path):
            return await call_next(request)
        # Path not in scope, skip authentication middleware
        return await call_next(request)

    def connect(self, channels: GatewayChannels) -> None:
        # NO-OP
        ...


class IdentityAwareMiddlewareMixin:
    """Mixin for authentication middlewares that maintain an identity store.

    This mixin provides a standardized interface for middlewares that need to
    track user identities. It provides async methods for credential validation
    and identity lookup, supporting both local stores and external services.

    This is a mixin class - use it alongside AuthenticationMiddleware:
        class MyAuthMiddleware(AuthenticationMiddleware, IdentityAwareMiddlewareMixin):
            ...

    Subclasses should:
    1. Implement `get_identity()` for session-based identity lookup
    2. Override `get_identity_from_credentials()` for direct credential validation
    3. Define `cookie_name` as a Pydantic Field for the auth filter to find the token

    Attributes:
        cookie_name: Name of the cookie/query param used for auth tokens (defined by subclass).
    """

    # Note: cookie_name should be defined as a Pydantic Field in subclasses
    # e.g., cookie_name: str = Field(default="token", description="Cookie name")

    async def get_identity(self, session_uuid: str) -> Optional[Dict[str, Any]]:
        """Get identity from store by session UUID.

        This async method looks up a session UUID and returns the associated
        identity dict. Implementations can use local dicts, databases, Redis, etc.

        The base implementation checks for a local _identity_store dict.
        Subclasses can override for external storage.

        Args:
            session_uuid: The session UUID to look up

        Returns:
            The identity dict if found, None otherwise.
        """
        # Default: check local _identity_store dict
        if hasattr(self, "_identity_store"):
            return self._identity_store.get(session_uuid)
        return None

    async def get_identity_from_credentials(
        self,
        *,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Extract and validate credentials, returning identity if valid.

        This async method extracts credentials from the provided request data
        and validates them. Each middleware knows its own auth scheme:
        - API Key: token from query/header/cookie
        - OAuth: Bearer token from Authorization header or session cookie
        - SimpleAuth: Basic Auth header or session cookie

        The base implementation checks session cookie via get_identity().
        Subclasses should override to add their specific validation logic.

        Args:
            cookies: Dict of request cookies
            headers: Dict of request headers
            query_params: Dict of query parameters

        Returns:
            Identity dict if valid credentials found, None otherwise.
        """
        cookies = cookies or {}
        # Check session cookie against identity store
        cookie_name = getattr(self, "cookie_name", "token")
        session_uuid = cookies.get(cookie_name)
        if session_uuid:
            identity = await self.get_identity(session_uuid)
            if identity:
                return identity
        return None
