from secrets import token_urlsafe
from socket import gethostname
from typing import List

from pydantic import AnyHttpUrl, Field

from csp_gateway import __version__

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseModel as BaseSettings


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
    AUTHENTICATE: bool = Field(False, description="Whether to authenticate users for access to the web application")
    API_KEY: str = Field(
        token_urlsafe(32),
        description="The API key for access if `AUTHENTICATE=True`. The default is auto-generated, but a user-provided value can be used.",
    )
    AUTHENTICATION_DOMAIN: str = gethostname()
