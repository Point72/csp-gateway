import warnings
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator, model_validator

from csp_gateway import __version__

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseModel as BaseSettings


__all__ = (
    "GatewaySettings",
    "Settings",
)


class Settings(BaseSettings):
    """Generic settings for the CSP Gateway."""

    model_config = {"case_sensitive": True}

    API_PREFIX: str = Field("api", description="Top level path segment under which all versioned API routes are mounted.")
    API_VERSION_DEFAULT: str = Field("v1", description="API version used by routes that do not ask for a specific one.")

    @field_validator("API_PREFIX", "API_VERSION_DEFAULT", mode="after")
    @classmethod
    def _strip_slashes(cls, value: str) -> str:
        # Normalized once, so these are also safe to use as router registry keys.
        return value.strip("/")

    @model_validator(mode="before")
    @classmethod
    def _split_legacy_api_str(cls, values):
        if isinstance(values, dict) and (api_str := values.pop("API_STR", None)) is not None:
            warnings.warn(
                "API_STR is deprecated, use API_PREFIX and API_VERSION_DEFAULT instead",
                DeprecationWarning,
                stacklevel=2,
            )
            prefix, _, version = str(api_str).strip("/").rpartition("/")
            values.setdefault("API_PREFIX", prefix or "api")
            values.setdefault("API_VERSION_DEFAULT", version)
        return values

    def api(self, version: str | None = None) -> str:
        """The URL path prefix for an API version, e.g. ``/api/v1``."""
        return f"/{self.API_PREFIX}/{(version or self.API_VERSION_DEFAULT).strip('/')}"

    @property
    def API_STR(self) -> str:
        """The URL path prefix for the default API version."""
        return self.api()

    BACKEND_CORS_ORIGINS: list[AnyHttpUrl] = []

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

    # Kept at one value rather than dropped: a setting the gateway no longer knows is an error, so
    # removing it would fail every config that names the provider it is already being given.
    UI_PROVIDER: Literal["spaday"] = Field(
        "spaday",
        description="Frontend provider for the UI. The legacy Perspective/React provider, 'default', was removed in favour of the spaday one.",
    )

    # UI customization fields that let downstream applications white-label the
    # UI from server-side config alone, without a custom Javascript bundle.
    HEADER_LOGO: str | None = Field(
        default=None,
        description="Header logo image, given as an http(s) URL, a data URI, an absolute "
        "URL path, or a local file path (local files are served automatically).",
    )
    FOOTER_LOGO: str | None = Field(
        default=None,
        description="Footer logo image, given as an http(s) URL, a data URI, an absolute "
        "URL path, or a local file path (local files are served automatically).",
    )
    CUSTOM_JS: list[str] = Field(
        default_factory=list,
        description="Custom Javascript files to inject into the UI, given as URLs or local "
        "file paths (local files are served automatically). Loaded after the main bundle.",
    )
    CUSTOM_CSS: list[str] = Field(
        default_factory=list,
        description="Custom CSS files to inject into the UI, given as URLs or local file "
        "paths (local files are served automatically). Loaded after the main stylesheet.",
    )
    CUSTOM_STATIC_DIR: str | None = Field(
        default=None,
        description="Local directory served at <root_path>/custom. The entire directory is exposed "
        "as public static content (useful for assets like logos, e.g. /custom/logo.svg); its top-level "
        "*.js and *.css files are additionally auto-injected into the UI in sorted filename order. Do "
        "not point this at a directory containing private files.",
    )
    UI_PACKAGES: list[str] = Field(
        default_factory=list,
        description="Extra spaday component packages to load into the UI, on top of the ones the "
        "gateway ships. Each entry is either the name a package registers under its spaday entry "
        "point (e.g. 'webawesome'), or a dotted path to a ComponentPackage or to a zero-argument "
        "callable returning one (e.g. 'my_library.ui:PACKAGE'). Loading a package makes its elements "
        "available to components a module contributes, and serves its assets alongside the built-in "
        "ones. Only applies to the spaday UI provider.",
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
    AUTHENTICATE: bool | None = Field(
        default=None,
        description="DEPRECATED. Use `MountAPIKeyMiddleware` (set it to None or omit from modules) to disable auth.",
    )
    API_KEY: str | None = Field(
        default=None,
        description="DEPRECATED. Set `api_key` on `MountAPIKeyMiddleware` directly.",
    )


# Alias
GatewaySettings = Settings
