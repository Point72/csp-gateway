# https://github.com/tiangolo/fastapi/pull/10147
from typing import get_type_hints

from fastapi import security
from starlette.requests import HTTPConnection

__all__ = ("APIKeyCookie", "APIKeyHeader", "APIKeyQuery")

if all(
    get_type_hints(dependency.__call__).get("request") is HTTPConnection
    for dependency in (security.APIKeyCookie, security.APIKeyHeader, security.APIKeyQuery)
):
    from fastapi.security import APIKeyCookie, APIKeyHeader, APIKeyQuery
else:
    from .api_key import APIKeyCookie, APIKeyHeader, APIKeyQuery
