"""Routes that wait on the csp engine must leave the event loop free for other requests."""

import threading
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from csp_gateway import GatewayStruct
from csp_gateway.server.web.routes.last import add_last_routes
from csp_gateway.server.web.routes.send import add_send_routes


class _Row(GatewayStruct):
    x: int = 0


class _Channels:
    """Stands in for the engine: every call parks until the test releases it."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.records = _Row(x=1)
        self.sent = []

    def _park(self) -> None:
        self.entered.set()
        assert self.release.wait(timeout=10), "engine call was never released"

    def last(self, field: Any, key: Any = None) -> _Row:
        self._park()
        return self.records

    def send(self, field: Any, value: Any) -> None:
        self._park()
        self.sent.append(value)


class _Model:
    records = "records"


def _app(add_routes, prefix: str) -> tuple[FastAPI, _Channels]:
    channels = _Channels()
    app = FastAPI()
    app.gateway = type("_Gateway", (), {"channels": channels, "channels_model": _Model})()
    router = APIRouter()
    add_routes(router, field="records", model=_Row)
    app.include_router(router, prefix=prefix)

    @app.get("/ping")
    async def ping():
        return "pong"

    return app, channels


@pytest.mark.parametrize(
    "add_routes, prefix, call",
    [
        pytest.param(add_last_routes, "/last", lambda client: client.get("/last/records"), id="last"),
        pytest.param(add_send_routes, "/send", lambda client: client.post("/send/records", json={"x": 5}), id="send"),
    ],
)
def test_engine_bound_route_does_not_block_event_loop(add_routes, prefix, call):
    app, channels = _app(add_routes, prefix)
    with TestClient(app) as client:
        responses = []
        slow = threading.Thread(target=lambda: responses.append(call(client)))
        slow.start()
        try:
            assert channels.entered.wait(timeout=5), "request never reached the engine"
            # The request is parked inside the engine call; an async route on the same loop must still answer.
            assert client.get("/ping").json() == "pong"
            assert slow.is_alive()
        finally:
            channels.release.set()
            slow.join(timeout=10)
    assert not slow.is_alive()
    assert responses[0].status_code == 200
    assert [r["x"] for r in responses[0].json()] == [1 if prefix == "/last" else 5]
