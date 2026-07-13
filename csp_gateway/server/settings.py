from typing import List, Literal, Optional

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

    ROOT_PATH: str = Field(
        default="",
        description="URL path prefix the app is served under when behind a reverse proxy that "
        "strips the prefix (e.g. '/watchtower'). Passed to the ASGI server as root_path and used "
        "to prefix all server-rendered asset/API URLs so the UI works under a sub-path. Leave "
        "empty when served at a domain root.",
    )

    UI: bool = Field(False, description="Enables ui in the web application")

    UI_PROVIDER: Literal["default", "spaday"] = Field(
        "default",
        description="Frontend provider for the UI. 'default' serves the built-in "
        "Perspective/React UI; 'spaday' serves a spaday-based UI that mimics it "
        "(requires the 'spaday' optional dependency).",
    )

    # UI customization fields that let downstream applications white-label the
    # default UI from server-side config alone, without a custom Javascript bundle.
    HEADER_LOGO: Optional[str] = Field(
        default=None,
        description="Header logo image, given as an http(s) URL, a data URI, an absolute "
        "URL path, or a local file path (local files are served automatically).",
    )
    FOOTER_LOGO: Optional[str] = Field(
        default=None,
        description="Footer logo image, given as an http(s) URL, a data URI, an absolute "
        "URL path, or a local file path (local files are served automatically).",
    )
    CUSTOM_JS: List[str] = Field(
        default_factory=list,
        description="Custom Javascript files to inject into the UI, given as URLs or local "
        "file paths (local files are served automatically). Loaded after the main bundle.",
    )
    CUSTOM_CSS: List[str] = Field(
        default_factory=list,
        description="Custom CSS files to inject into the UI, given as URLs or local file "
        "paths (local files are served automatically). Loaded after the main stylesheet.",
    )
    CUSTOM_STATIC_DIR: Optional[str] = Field(
        default=None,
        description="Local directory served at <root_path>/custom. The entire directory is exposed "
        "as public static content (useful for assets like logos, e.g. /custom/logo.svg); its top-level "
        "*.js and *.css files are additionally auto-injected into the UI in sorted filename order. Do "
        "not point this at a directory containing private files.",
    )

    # DEPRECATED auth settings
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
