from base64 import b64decode
from typing import Optional

from fastapi.exceptions import HTTPException
from fastapi.openapi.models import (
    HTTPBase as HTTPBaseModel,
    HTTPBearer as HTTPBearerModel,
)
from fastapi.security.base import SecurityBase
from pydantic import BaseModel
from starlette.requests import HTTPConnection
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
from utils import get_authorization_scheme_param, handle_exc_for_ws


class HTTPBasicCredentials(BaseModel):
    username: str
    password: str


class HTTPAuthorizationCredentials(BaseModel):
    scheme: str
    credentials: str


class HTTPBase(SecurityBase):
    def __init__(
        self,
        *,
        scheme: str,
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        self.model = HTTPBaseModel(scheme=scheme, description=description)
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    @handle_exc_for_ws
    async def __call__(self, request: HTTPConnection) -> Optional[HTTPAuthorizationCredentials]:
        authorization = request.headers.get("Authorization")
        scheme, credentials = get_authorization_scheme_param(authorization)
        if not (authorization and scheme and credentials):
            if self.auto_error:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
            else:
                return None
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)


class HTTPBasic(HTTPBase):
    def __init__(
        self,
        *,
        scheme_name: Optional[str] = None,
        realm: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        self.model = HTTPBaseModel(scheme="basic", description=description)
        self.scheme_name = scheme_name or self.__class__.__name__
        self.realm = realm
        self.auto_error = auto_error

    @handle_exc_for_ws
    async def __call__(  # type: ignore
        self, request: HTTPConnection
    ) -> Optional[HTTPBasicCredentials]:
        authorization = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if self.realm:
            unauthorized_headers = {"WWW-Authenticate": f'Basic realm="{self.realm}"'}
        else:
            unauthorized_headers = {"WWW-Authenticate": "Basic"}
        if not authorization or scheme.lower() != "basic":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers=unauthorized_headers,
                )
            else:
                return None
        invalid_user_credentials_exc = HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers=unauthorized_headers,
        )
        try:
            data = b64decode(param).decode("ascii")
        except ValueError:
            raise invalid_user_credentials_exc
        username, separator, password = data.partition(":")
        if not separator:
            raise invalid_user_credentials_exc
        return HTTPBasicCredentials(username=username, password=password)


class HTTPBearer(HTTPBase):
    def __init__(
        self,
        *,
        bearerFormat: Optional[str] = None,
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        self.model = HTTPBearerModel(bearerFormat=bearerFormat, description=description)
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    @handle_exc_for_ws
    async def __call__(self, request: HTTPConnection) -> Optional[HTTPAuthorizationCredentials]:
        authorization = request.headers.get("Authorization")
        scheme, credentials = get_authorization_scheme_param(authorization)
        if not (authorization and scheme and credentials):
            if self.auto_error:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
            else:
                return None
        if scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Invalid authentication credentials",
                )
            else:
                return None
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)


class HTTPDigest(HTTPBase):
    def __init__(
        self,
        *,
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        self.model = HTTPBaseModel(scheme="digest", description=description)
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    @handle_exc_for_ws
    async def __call__(self, request: HTTPConnection) -> Optional[HTTPAuthorizationCredentials]:
        authorization = request.headers.get("Authorization")
        scheme, credentials = get_authorization_scheme_param(authorization)
        if not (authorization and scheme and credentials):
            if self.auto_error:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
            else:
                return None
        if scheme.lower() != "digest":
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Invalid authentication credentials",
            )
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)
