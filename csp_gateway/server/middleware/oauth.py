"""OAuth2/OIDC Authentication Middleware."""

import urllib.parse
from datetime import timedelta
from socket import gethostname
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import Field, PrivateAttr
from starlette.status import HTTP_401_UNAUTHORIZED

from ..settings import GatewaySettings
from ..web import GatewayWebApp
from .base import AuthenticationMiddleware, IdentityAwareMiddlewareMixin

__all__ = ("MountOAuth2Middleware",)


class MountOAuth2Middleware(AuthenticationMiddleware, IdentityAwareMiddlewareMixin):
    """OAuth2/OIDC authentication middleware.

    Supports OAuth2 authorization code flow with OIDC discovery.
    Tokens are validated either via introspection endpoint or JWT verification.
    Implements IdentityAwareMiddlewareMixin for integration with AuthFilterMiddleware.

    Attributes:
        issuer: The OAuth2/OIDC issuer URL (e.g., https://auth.example.com)
        client_id: OAuth2 client identifier
        client_secret: OAuth2 client secret (required for confidential clients)
        scopes: List of OAuth2 scopes to request
        token_url: Token endpoint URL (auto-discovered from issuer if not set)
        authorize_url: Authorization endpoint URL (auto-discovered if not set)
        userinfo_url: Userinfo endpoint URL (auto-discovered if not set)
        introspection_url: Token introspection endpoint (optional)
        audience: Expected audience claim for JWT validation
        verify_ssl: Whether to verify SSL certificates
        identity_store: Maps session UUIDs to identity dicts (via IdentityAwareMiddlewareMixin).
    """

    issuer: str = Field(..., description="OAuth2/OIDC issuer URL")
    client_id: str = Field(..., description="OAuth2 client identifier")
    client_secret: Optional[str] = Field(default=None, description="OAuth2 client secret")

    scopes: List[str] = Field(
        default_factory=lambda: ["openid", "profile", "email"],
        description="OAuth2 scopes to request",
    )

    # Endpoint URLs (auto-discovered from issuer/.well-known/openid-configuration if not set)
    token_url: Optional[str] = Field(default=None, description="Token endpoint URL")
    authorize_url: Optional[str] = Field(default=None, description="Authorization endpoint URL")
    userinfo_url: Optional[str] = Field(default=None, description="Userinfo endpoint URL")
    introspection_url: Optional[str] = Field(default=None, description="Token introspection endpoint URL")

    audience: Optional[str] = Field(default=None, description="Expected audience claim for JWT validation")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")

    domain: str = Field(default_factory=gethostname)
    cookie_name: str = Field(default="oauth_session", description="Cookie name for session")
    session_timeout: timedelta = Field(default=timedelta(hours=12), description="Session timeout")

    unauthorized_status_message: str = "unauthorized"

    # Private attributes for runtime state
    _identity_store: Dict[str, Dict[str, Any]] = PrivateAttr(default_factory=dict)
    _oidc_config: Optional[Dict[str, Any]] = PrivateAttr(default=None)
    _app_settings: Optional[GatewaySettings] = PrivateAttr(default=None)

    def info(self, settings: GatewaySettings) -> str:
        url = f"http://{gethostname()}:{settings.PORT}"
        return f"\tOAuth2: {url}/login (issuer: {self.issuer})"

    def _get_oidc_config(self) -> Dict[str, Any]:
        """Fetch OIDC discovery document from issuer."""
        if self._oidc_config is not None:
            return self._oidc_config

        discovery_url = f"{self.issuer.rstrip('/')}/.well-known/openid-configuration"
        try:
            response = httpx.get(discovery_url, verify=self.verify_ssl)
            response.raise_for_status()
            self._oidc_config = response.json()
            return self._oidc_config
        except Exception as e:
            raise ValueError(f"Failed to fetch OIDC discovery document from {discovery_url}: {e}") from e

    def _get_token_url(self) -> str:
        """Get token endpoint URL."""
        if self.token_url:
            return self.token_url
        return self._get_oidc_config().get("token_endpoint", f"{self.issuer}/oauth/token")

    def _get_authorize_url(self) -> str:
        """Get authorization endpoint URL."""
        if self.authorize_url:
            return self.authorize_url
        return self._get_oidc_config().get("authorization_endpoint", f"{self.issuer}/authorize")

    def _get_userinfo_url(self) -> str:
        """Get userinfo endpoint URL."""
        if self.userinfo_url:
            return self.userinfo_url
        return self._get_oidc_config().get("userinfo_endpoint", f"{self.issuer}/userinfo")

    async def _exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchange authorization code for tokens."""
        token_url = self._get_token_url()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret

        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            return response.json()

    async def _get_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Fetch user info from userinfo endpoint."""
        userinfo_url = self._get_userinfo_url()
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            return response.json()

    async def _introspect_token(self, token: str) -> Dict[str, Any]:
        """Introspect token to validate it."""
        if not self.introspection_url:
            # Try to get from OIDC config
            introspection_url = self._get_oidc_config().get("introspection_endpoint")
            if not introspection_url:
                raise ValueError("No introspection endpoint configured")
        else:
            introspection_url = self.introspection_url

        data = {"token": token}
        auth = None
        if self.client_secret:
            auth = (self.client_id, self.client_secret)
        else:
            data["client_id"] = self.client_id

        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            response = await client.post(introspection_url, data=data, auth=auth)
            response.raise_for_status()
            return response.json()

    async def get_identity_from_credentials(
        self,
        *,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Extract and validate OAuth2 credentials.

        Checks session cookie first, then Bearer token in Authorization header.
        Bearer tokens are validated via introspection or userinfo endpoints.

        Args:
            cookies: Dict of request cookies
            headers: Dict of request headers
            query_params: Dict of query parameters

        Returns:
            Identity dict if valid credentials found, None otherwise.
        """
        cookies = cookies or {}
        headers = headers or {}

        # Check session cookie first
        session_uuid = cookies.get(self.cookie_name)
        if session_uuid:
            identity = await self.get_identity(session_uuid)
            if identity:
                # Return userinfo if available, otherwise the full identity
                return identity.get("userinfo", identity)

        # Try Bearer token from Authorization header
        auth_header = headers.get("authorization") or headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
            try:
                # Validate token via introspection or userinfo
                if self.introspection_url:
                    token_info = await self._introspect_token(token)
                    if token_info.get("active", False):
                        return token_info
                else:
                    # Fallback to userinfo endpoint
                    userinfo = await self._get_userinfo(token)
                    if userinfo:
                        return userinfo
            except Exception:
                pass

        return None

    def validate(self):
        """Return a FastAPI dependency function for OAuth2 token validation."""
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl=self._get_token_url(), auto_error=False)

        async def validate_credentials(
            request: Request,
            token: Optional[str] = Security(oauth2_scheme),
        ) -> str:
            """Validate OAuth2 token and return session UUID."""
            # Check for session cookie first
            session_uuid = request.cookies.get(self.cookie_name)
            if session_uuid and session_uuid in self._identity_store:
                return session_uuid

            # Check for bearer token
            if token:
                try:
                    # Validate token via introspection or userinfo
                    if self.introspection_url:
                        token_info = await self._introspect_token(token)
                        if not token_info.get("active", False):
                            raise HTTPException(
                                status_code=HTTP_401_UNAUTHORIZED,
                                detail="Token is not active",
                            )
                        identity = token_info
                    else:
                        # Fallback to userinfo endpoint
                        identity = await self._get_userinfo(token)

                    # Create session
                    session_uuid = str(uuid4())
                    while session_uuid in self._identity_store:
                        session_uuid = str(uuid4())
                    self._identity_store[session_uuid] = identity
                    return session_uuid
                except Exception as e:
                    raise HTTPException(
                        status_code=HTTP_401_UNAUTHORIZED,
                        detail=str(e),
                    ) from e

            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail=self.unauthorized_status_message,
            )

        return validate_credentials

    def rest(self, app: GatewayWebApp) -> None:
        self._app_settings = app.settings

        auth_router: APIRouter = app.get_router("auth")
        public_router: APIRouter = app.get_router("public")
        check = self.get_check_dependency()

        @public_router.get("/login", response_class=HTMLResponse, include_in_schema=False)
        async def login_redirect(request: Request):
            """Redirect to OAuth2 authorization endpoint."""
            redirect_uri = str(request.url_for("oauth_callback"))
            authorize_url = self._get_authorize_url()

            params = {
                "client_id": self.client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": " ".join(self.scopes),
                "state": str(uuid4()),  # Should be stored and validated
            }
            auth_url = f"{authorize_url}?{urllib.parse.urlencode(params)}"
            return RedirectResponse(url=auth_url)

        @auth_router.get("/callback", name="oauth_callback")
        async def oauth_callback(request: Request, code: str = None, error: str = None):
            """Handle OAuth2 callback with authorization code."""
            if error:
                return JSONResponse({"error": error}, status_code=400)

            if not code:
                return JSONResponse({"error": "No authorization code provided"}, status_code=400)

            try:
                redirect_uri = str(request.url_for("oauth_callback"))
                tokens = await self._exchange_code_for_token(code, redirect_uri)

                access_token = tokens.get("access_token")
                if not access_token:
                    return JSONResponse({"error": "No access token in response"}, status_code=400)

                # Get user info
                userinfo = await self._get_userinfo(access_token)

                # Create session
                session_uuid = str(uuid4())
                while session_uuid in self._identity_store:
                    session_uuid = str(uuid4())

                self._identity_store[session_uuid] = {
                    "userinfo": userinfo,
                    "access_token": access_token,
                    "refresh_token": tokens.get("refresh_token"),
                    "id_token": tokens.get("id_token"),
                }

                response = RedirectResponse(url="/")
                response.set_cookie(
                    self.cookie_name,
                    value=session_uuid,
                    domain=self.domain,
                    httponly=True,
                    max_age=int(self.session_timeout.total_seconds()),
                    expires=int(self.session_timeout.total_seconds()),
                )
                return response

            except Exception as e:
                return JSONResponse({"error": str(e)}, status_code=500)

        @auth_router.get("/logout")
        async def logout(request: Request):
            """Logout and clear session."""
            session_uuid = request.cookies.get(self.cookie_name)
            if session_uuid and session_uuid in self._identity_store:
                self._identity_store.pop(session_uuid, None)

            response = RedirectResponse(url="/login")
            response.delete_cookie(self.cookie_name, domain=self.domain)
            return response

        @auth_router.get("/userinfo")
        async def get_userinfo(session_uuid: str = Depends(check)):
            """Get current user info."""
            if session_uuid not in self._identity_store:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Session not found")
            identity = self._identity_store[session_uuid]
            return identity.get("userinfo", {})

        # Add auth middleware to all routes
        app.add_middleware(Depends(check))

        @app.app.exception_handler(401)
        @app.app.exception_handler(403)
        async def auth_error_handler(request: Request, exc):
            if "/api" in request.url.path:
                return JSONResponse(
                    {"detail": self.unauthorized_status_message, "status_code": exc.status_code},
                    status_code=exc.status_code,
                )
            return RedirectResponse(url="/login")
