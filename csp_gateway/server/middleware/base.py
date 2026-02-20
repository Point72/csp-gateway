from fnmatch import fnmatch
from typing import Callable, List, Optional, Union

from ccflow import PyObjectPath
from fastapi import Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from csp_gateway.server import GatewayChannels, GatewayModule

__all__ = ("AuthenticationMiddleware",)


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
