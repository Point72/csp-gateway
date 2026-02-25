"""Simple Authentication Middleware."""

import logging
import platform
from datetime import timedelta
from socket import gethostname
from typing import Any, Callable, Dict, Optional
from uuid import uuid4

from ccflow import PyObjectPath
from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import Field, PrivateAttr, field_validator, model_validator
from starlette.status import HTTP_401_UNAUTHORIZED

from ..settings import GatewaySettings
from ..web import GatewayWebApp
from .base import AuthenticationMiddleware, IdentityAwareMiddlewareMixin
from .hacks.api_key_middleware_websocket_fix.api_key import APIKeyCookie

__all__ = ("MountSimpleAuthMiddleware",)

log = logging.getLogger(__name__)


def _validate_host_unix(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Validate credentials on Unix/Linux/macOS using PAM.

    Tries pamela first, falls back to python-pam.

    Args:
        username: The system username
        password: The user's password

    Returns:
        Identity dict with user info if valid, None otherwise.
    """
    # Try pamela first
    try:
        import pamela

        try:
            pamela.authenticate(username, password)
            return _get_unix_user_info(username)
        except pamela.PAMError:
            return None
    except ImportError:
        pass

    # Fall back to python-pam
    try:
        import pam

        p = pam.pam()
        if p.authenticate(username, password):
            return _get_unix_user_info(username)
        return None
    except ImportError:
        pass

    log.warning("No PAM library available. Install pamela or python-pam: pip install pamela  # or: pip install python-pam")
    return None


def _get_unix_user_info(username: str) -> Dict[str, Any]:
    """Get Unix user info from pwd database."""
    try:
        import pwd

        pw = pwd.getpwnam(username)
        return {
            "user": username,
            "uid": pw.pw_uid,
            "gid": pw.pw_gid,
            "home": pw.pw_dir,
            "shell": pw.pw_shell,
            "gecos": pw.pw_gecos,
        }
    except (ImportError, KeyError):
        return {"user": username}


def _validate_host_windows(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Validate credentials on Windows using pywin32.

    Args:
        username: The Windows username
        password: The user's password

    Returns:
        Identity dict with user info if valid, None otherwise.
    """
    try:
        import win32security

        try:
            # Try to log on the user - this validates credentials
            # LOGON32_LOGON_NETWORK = 3, LOGON32_PROVIDER_DEFAULT = 0
            handle = win32security.LogonUser(
                username,
                None,  # Domain - None means local machine
                password,
                win32security.LOGON32_LOGON_NETWORK,
                win32security.LOGON32_PROVIDER_DEFAULT,
            )
            handle.Close()

            # Get additional user info if available
            try:
                import win32net

                user_info = win32net.NetUserGetInfo(None, username, 2)
                return {
                    "user": username,
                    "full_name": user_info.get("full_name", ""),
                    "home": user_info.get("home_dir", ""),
                    "comment": user_info.get("comment", ""),
                }
            except Exception:
                return {"user": username}

        except win32security.error:
            return None

    except ImportError:
        log.warning("pywin32 package not installed. Install with: pip install pywin32")
        return None
    except Exception as e:
        log.debug(f"Windows authentication failed for {username}: {e}")
        return None


class MountSimpleAuthMiddleware(AuthenticationMiddleware, IdentityAwareMiddlewareMixin):
    """Simple authentication middleware using external validation function or host auth.

    Supports HTTP Basic Auth and form-based login. Credentials can be validated via:
    - An external validator function (via `external_validator`)
    - Host/system authentication (via `use_host_auth`)

    Implements IdentityAwareMiddlewareMixin for integration with AuthFilterMiddleware.

    Attributes:
        external_validator: Path to external validation function (ccflow.PyObjectPath).
            The function signature should be:
            def validator(username: str, password: str, settings: GatewaySettings, module) -> Optional[dict]
            Returns a dict with user identity on success, None on failure.
        use_host_auth: Whether to use host/system authentication.
            On Unix/Linux/macOS: Uses PAM (requires python-pam or pamela package).
            On Windows: Uses Windows authentication (requires pywin32 package).
            When enabled, users can authenticate with their system username/password.
        domain: Cookie domain for session cookies.
        cookie_name: Cookie name for session storage.
        session_timeout: Session timeout duration.
        enable_basic_auth: Whether to enable HTTP Basic Auth.
        enable_form_login: Whether to enable form-based login.
        identity_store: Maps session UUIDs to identity dicts (via IdentityAwareMiddlewareMixin).

    Note:
        If both `external_validator` and `use_host_auth` are set, the external
        validator is tried first. If it returns None, host auth is attempted.
    """

    external_validator: Optional[PyObjectPath] = Field(
        default=None,
        description="Path to external validation function (ccflow.PyObjectPath as string).",
    )

    use_host_auth: bool = Field(
        default=False,
        description="Use host/system authentication (PAM on Unix, Windows auth on Windows).",
    )

    domain: str = Field(default_factory=gethostname)
    cookie_name: str = Field(default="session", description="Cookie name for session")
    session_timeout: timedelta = Field(default=timedelta(hours=12), description="Session timeout")

    enable_basic_auth: bool = Field(default=True, description="Enable HTTP Basic Auth")
    enable_form_login: bool = Field(default=True, description="Enable form-based login")

    unauthorized_status_message: str = "unauthorized"

    # Private attributes
    _identity_store: Dict[str, Dict[str, Any]] = PrivateAttr(default_factory=dict)
    _app_settings: Optional[GatewaySettings] = PrivateAttr(default=None)
    _app_module: Any = PrivateAttr(default=None)

    @field_validator("external_validator")
    @classmethod
    def validate_external_validator(cls, v):
        if v is not None:
            if not isinstance(v, PyObjectPath):
                raise ValueError("external_validator must be a PyObjectPath")
            if not callable(v.object):
                raise ValueError("external_validator must point to a callable object")
        return v

    @model_validator(mode="after")
    def validate_auth_method(self):
        """Ensure at least one authentication method is configured."""
        if self.external_validator is None and not self.use_host_auth:
            raise ValueError("Either external_validator or use_host_auth must be set")
        return self

    def info(self, settings: GatewaySettings) -> str:
        url = f"http://{gethostname()}:{settings.PORT}"
        methods = []
        if self.enable_basic_auth:
            methods.append("Basic Auth")
        if self.enable_form_login:
            methods.append("Form Login")
        auth_type = "Host" if self.use_host_auth else "External"
        return f"\tSimple Auth ({auth_type}): {url}/login ({', '.join(methods)})"

    def _validate_host(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Validate credentials against host/system authentication.

        Uses platform-appropriate authentication:
        - Unix/Linux/macOS: PAM (via python-pam or pamela)
        - Windows: Windows authentication (via pywin32)

        Args:
            username: The system username
            password: The user's password

        Returns:
            Identity dict with user info if valid, None otherwise.
        """
        system = platform.system()
        if system == "Windows":
            return _validate_host_windows(username, password)
        else:  # Linux, Darwin (macOS), etc.
            return _validate_host_unix(username, password)

    def _validate_credentials(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Validate credentials using configured method(s).

        Tries external validator first (if configured), then host auth (if enabled).

        Args:
            username: The username to validate
            password: The password to validate

        Returns:
            Identity dict if valid, None otherwise.
        """
        # Try external validator first
        if self.external_validator is not None:
            identity = self._invoke_external(username, password, self._app_settings, self._app_module)
            if identity:
                return identity

        # Try host authentication
        if self.use_host_auth:
            identity = self._validate_host(username, password)
            if identity:
                return identity

        return None

    def _invoke_external(self, username: str, password: str, settings: GatewaySettings, module) -> Optional[Dict[str, Any]]:
        """Invoke external validator function."""
        if self.external_validator is None:
            return None
        try:
            return self.external_validator.object(username, password, settings, module)
        except Exception:
            return None

    def _create_session(self, identity: Dict[str, Any]) -> str:
        """Create a new session and return the session UUID."""
        session_uuid = str(uuid4())
        while session_uuid in self._identity_store:
            session_uuid = str(uuid4())
        self._identity_store[session_uuid] = identity
        return session_uuid

    async def get_identity_from_credentials(
        self,
        *,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Extract and validate SimpleAuth credentials.

        Checks session cookie first, then HTTP Basic Auth header.

        Args:
            cookies: Dict of request cookies
            headers: Dict of request headers
            query_params: Dict of query parameters

        Returns:
            Identity dict if valid credentials found, None otherwise.
        """
        import base64

        cookies = cookies or {}
        headers = headers or {}

        # Check session cookie first
        session_uuid = cookies.get(self.cookie_name)
        if session_uuid:
            identity = await self.get_identity(session_uuid)
            if identity:
                return identity

        # Try HTTP Basic Auth header
        if self.enable_basic_auth:
            auth_header = headers.get("authorization") or headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("basic "):
                try:
                    encoded = auth_header[6:]  # Remove "Basic " prefix
                    decoded = base64.b64decode(encoded).decode("utf-8")
                    username, password = decoded.split(":", 1)
                    identity = self._validate_credentials(username, password)
                    if identity and isinstance(identity, dict):
                        return identity
                except Exception:
                    pass

        return None

    def validate(self) -> Callable:
        """Return a FastAPI dependency function for credential validation."""
        basic_security = HTTPBasic(auto_error=False)
        cookie_security = Security(APIKeyCookie(name=self.cookie_name, auto_error=False))

        async def validate_credentials(
            request: Request,
            basic_credentials: Optional[HTTPBasicCredentials] = Security(basic_security),
            session_cookie: Optional[str] = cookie_security,
        ) -> str:
            """Validate credentials and return session UUID."""
            # Check for existing session cookie first
            if session_cookie and session_cookie in self._identity_store:
                return session_cookie

            # Try HTTP Basic Auth
            if self.enable_basic_auth and basic_credentials:
                identity = self._validate_credentials(
                    basic_credentials.username,
                    basic_credentials.password,
                )
                if identity and isinstance(identity, dict):
                    return self._create_session(identity)

            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail=self.unauthorized_status_message,
                headers={"WWW-Authenticate": "Basic"} if self.enable_basic_auth else None,
            )

        return validate_credentials

    def rest(self, app: GatewayWebApp) -> None:
        self._app_settings = app.settings
        self._app_module = app

        auth_router: APIRouter = app.get_router("auth")
        public_router: APIRouter = app.get_router("public")
        check = self.get_check_dependency()

        if self.enable_form_login:

            @public_router.get("/login", response_class=HTMLResponse, include_in_schema=False)
            async def get_login_page(request: Request, error: str = ""):
                """Render login form."""
                return app.templates.TemplateResponse(
                    "login.html.j2",
                    {
                        "request": request,
                        "api_key_name": "credentials",
                        "error": error,
                    },
                )

            @public_router.post("/login", include_in_schema=False)
            async def post_login(request: Request):
                """Handle form-based login."""
                form = await request.form()
                username = form.get("username", "")
                password = form.get("password", "")

                if not username or not password:
                    return RedirectResponse(url="/login?error=missing_credentials", status_code=303)

                identity = self._validate_credentials(str(username), str(password))

                if identity and isinstance(identity, dict):
                    session_uuid = self._create_session(identity)
                    response = RedirectResponse(url="/", status_code=303)
                    response.set_cookie(
                        self.cookie_name,
                        value=session_uuid,
                        domain=self.domain,
                        httponly=True,
                        max_age=int(self.session_timeout.total_seconds()),
                        expires=int(self.session_timeout.total_seconds()),
                    )
                    return response

                return RedirectResponse(url="/login?error=invalid_credentials", status_code=303)

        @auth_router.get("/login")
        async def api_login(session_uuid: str = Depends(check)):
            """API login endpoint - validates Basic Auth and returns session cookie."""
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

        @auth_router.get("/logout")
        async def logout(request: Request):
            """Logout and clear session."""
            session_uuid = request.cookies.get(self.cookie_name)
            if session_uuid and session_uuid in self._identity_store:
                self._identity_store.pop(session_uuid, None)

            response = RedirectResponse(url="/login")
            response.delete_cookie(self.cookie_name, domain=self.domain)
            return response

        @auth_router.get("/whoami")
        async def whoami(session_uuid: str = Depends(check)):
            """Get current user identity."""
            if session_uuid not in self._identity_store:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Session not found")
            return self._identity_store[session_uuid]

        @public_router.get("/logout", response_class=HTMLResponse, include_in_schema=False)
        async def get_logout_page(request: Request):
            return app.templates.TemplateResponse("logout.html.j2", {"request": request})

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
            if self.enable_form_login:
                return RedirectResponse(url="/login")
            # Return 401 with Basic Auth challenge
            return JSONResponse(
                {"detail": self.unauthorized_status_message},
                status_code=HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Basic"} if self.enable_basic_auth else None,
            )
