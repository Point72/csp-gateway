__version__ = "3.0.0"

from ._optional_dependencies import (
    CLIENT_OPTIONAL_IMPORTS as _CLIENT_OPTIONAL_IMPORTS,
    SERVER_OPTIONAL_IMPORTS as _SERVER_OPTIONAL_IMPORTS,
    is_missing_optional_dependency as _is_missing_optional_dependency,
)

try:
    from .client import *
except ImportError as error:
    # If client is not available, we can still use the server.
    if not _is_missing_optional_dependency(error, _CLIENT_OPTIONAL_IMPORTS):
        raise

try:
    from .server import *
except ImportError as error:
    # If server is not available, we can still use the client.
    if not _is_missing_optional_dependency(error, _SERVER_OPTIONAL_IMPORTS):
        raise

from .utils import *
