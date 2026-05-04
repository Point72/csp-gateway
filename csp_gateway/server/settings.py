from typing import List, Optional

from pydantic import AnyHttpUrl, Field

from csp_gateway import __version__

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseModel as BaseSettings


__all__ = (
    "Settings",
    "GatewaySettings",
)


class Settings(BaseSettings):
    """Generic settings for the CSP Gateway."""

    model_config = dict(case_sensitive=True)

    API_STR: str = "/api/v1"
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    TITLE: str = "Gateway"
    DESCRIPTION: str = "# Welcome to CSP Gateway API\nContains REST/Websocket interfaces to underlying CSP Gateway engine"
    VERSION: str = __version__
    AUTHOR: str = ""
    EMAIL: str = "example@domain.com"

    BIND: str = "0.0.0.0"
    PORT: int = 8000

    UI: bool = Field(False, description="Enables ui in the web application")

    # --- DEPRECATED auth settings ---
    # Historically (csp-gateway <2.5), auth was configured via these two fields
    # on Settings. In 2.5+, auth moved onto `MountAPIKeyMiddleware` as module
    # fields. Keeping these here (default-None sentinels) lets existing YAML
    # configs that set `gateway.settings.AUTHENTICATE` / `gateway.settings.API_KEY`
    # continue to validate. The `Gateway` class reads them at `start()` and
    # applies them to the middleware with a DeprecationWarning. Remove these
    # fields (and the `_apply_legacy_auth_settings()` shim in gateway.py) in a
    # future major release.
    AUTHENTICATE: Optional[bool] = Field(
        default=None,
        description="DEPRECATED. Use `MountAPIKeyMiddleware` (set it to None or omit from modules) to disable auth.",
    )
    API_KEY: Optional[str] = Field(
        default=None,
        description="DEPRECATED. Set `api_key` on `MountAPIKeyMiddleware` directly.",
    )


# Alias
GatewaySettings = Settings
