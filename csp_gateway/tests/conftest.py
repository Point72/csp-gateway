import socket

import pytest

# Environment variables read by GatewayClientConfig (and, for some, the server Settings)
_CONFIG_ENVIRONMENT = ("PROTOCOL", "HOST", "PORT", "API_PREFIX", "API_VERSION", "API_KEY", "BEARER_TOKEN", "RETURN_TYPE")


@pytest.fixture(autouse=True)
def _isolate_config_environment(monkeypatch):
    for name in _CONFIG_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="class")
def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        return s.getsockname()[1]
