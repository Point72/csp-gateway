"""Routes that wait on the csp engine must leave the event loop free for other requests."""

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from importlib import import_module
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from starlette.concurrency import run_in_threadpool

from csp_gateway import GatewayStruct
from csp_gateway.server.web.routes import lookup as lookup_routes
from csp_gateway.server.web.routes.last import add_last_routes
from csp_gateway.server.web.routes.next import add_next_routes
from csp_gateway.server.web.routes.send import add_send_routes
from csp_gateway.server.web.routes.stage import add_stage_routes
from csp_gateway.server.web.routes.state import add_state_routes


class _Row(GatewayStruct):
    x: int = 0


@pytest.mark.parametrize(
    "add_routes",
    [add_last_routes, add_next_routes, add_send_routes, add_state_routes, lookup_routes.add_lookup_routes],
)
@pytest.mark.parametrize("batch_size", [0, -1, 1.5, True])
def test_record_routes_reject_invalid_batch_size_at_mount(add_routes, batch_size):
    with pytest.raises(ValueError, match="batch_size"):
        add_routes(APIRouter(), field="records", model=_Row, batch_size=batch_size)


class _Channels:
    def __init__(self, list_model: bool, basket: bool) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.record_values = [_Row(x=1)] if list_model else _Row(x=1)
        self.basket = basket
        self.sent = []

    def _park(self) -> None:
        self.entered.set()
        assert self.release.wait(timeout=10), "engine call was never released"

    def keys_for_channel(self, field: str) -> list[str]:
        return ["one"]

    def last(self, field: Any, key: Any = None):
        self._park()
        return {"one": self.record_values} if self.basket and key is None else self.record_values

    async def last_async(self, field: Any, key: Any = None):
        return await asyncio.to_thread(self.last, field, key)

    def query(self, field: str, key: Any = None, query: Any = None):
        self._park()
        return self.record_values if isinstance(self.record_values, list) else [self.record_values]

    def next(self, field: str, key: Any = None):
        return self.last(field, key or None)

    def send(self, field: Any, value: Any, key: Any = None) -> None:
        self._park()
        self.sent.append(value)

    def stage_add(self, field: str, struct=None, staging_ids=None):
        self._park()
        return ["one"]

    stage_remove = stage_add

    def stage_list(self, field: str, staging_id=None):
        self._park()
        return ["one"]

    def stage_lookup(self, field: str, staging_id=None):
        self._park()
        return {"one": [self.record_values]}

    def stage_release(self, field: str, staging_ids=None):
        return self.stage_lookup(field)


def _app(add_routes, prefix: str, list_model: bool, basket: bool, materialize: bool = True) -> tuple[FastAPI, _Channels]:
    channels = _Channels(list_model, basket)
    app = FastAPI()
    app.gateway = SimpleNamespace(channels=channels, channels_model=SimpleNamespace(record_values="record_values"))
    router = APIRouter()
    add_routes(
        router,
        field="record_values",
        model=list[_Row] if list_model else _Row,
        subroute_key=str if basket else None,
        batch_size=2,
        materialize=materialize,
    )
    app.include_router(router, prefix=prefix)

    @app.get("/ping")
    async def ping():
        return "pong"

    return app, channels


def _request_while_parked(app, channels, method, path, **kwargs):
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=2) as executor:
        slow = executor.submit(client.request, method, path, **kwargs)
        try:
            if not channels.entered.wait(timeout=2):
                response = slow.result(timeout=1)
                pytest.fail(f"request never reached the operation: {response.status_code} {response.text}")
            ping = executor.submit(client.get, "/ping")
            assert ping.result(timeout=2).json() == "pong"
            assert not slow.done()
        finally:
            channels.release.set()
        return slow.result(timeout=5)


@pytest.mark.parametrize(
    "add_routes, prefix, method",
    [
        pytest.param(add_last_routes, "/last", "GET", id="last"),
        pytest.param(add_next_routes, "/next", "GET", id="next"),
        pytest.param(add_send_routes, "/send", "POST", id="send"),
        pytest.param(add_state_routes, "/state", "GET", id="state"),
    ],
)
@pytest.mark.parametrize("list_model", [False, True], ids=["scalar", "list"])
@pytest.mark.parametrize("selection", ["channel", "key", "basket"])
@pytest.mark.parametrize("alias", [False, True], ids=["canonical", "hyphenated"])
@pytest.mark.parametrize("materialize", [True, False], ids=["materialized", "streamed"])
def test_engine_bound_route_does_not_block_event_loop(add_routes, prefix, method, list_model, selection, alias, materialize):
    app, channels = _app(add_routes, prefix, list_model, selection != "channel", materialize)
    path = prefix + ("/record-values" if alias else "/record_values") + ("/one" if selection == "key" else "")
    data = [{"x": 5}] if list_model else {"x": 5}
    if selection == "basket":
        data = {"one": data}
    kwargs = {"json": data} if method == "POST" else {}
    response = _request_while_parked(app, channels, method, path, **kwargs)
    assert response.status_code == 200
    assert [record["x"] for record in response.json()] == [5 if method == "POST" else 1]
    if materialize:
        assert response.headers["content-length"] == str(len(response.content))
    else:
        assert "content-length" not in response.headers


def test_last_submits_engine_request_when_worker_pool_is_busy():
    app, channels = _app(add_last_routes, "/last", False, False)
    worker_entered = threading.Event()
    worker_release = threading.Event()

    def hold_worker():
        worker_entered.set()
        assert worker_release.wait(timeout=10)

    async def reserve_worker():
        limiter = anyio.to_thread.current_default_thread_limiter()
        original_tokens = limiter.total_tokens
        limiter.total_tokens = 1
        task = asyncio.create_task(run_in_threadpool(hold_worker))
        return task, limiter, original_tokens

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as executor:
        task, limiter, original_tokens = client.portal.call(reserve_worker)
        pending = None
        try:
            assert worker_entered.wait(timeout=2)
            pending = executor.submit(client.get, "/last/record_values")
            assert channels.entered.wait(timeout=2), "engine request is waiting for a FastAPI worker"
            assert not pending.done()
        finally:
            channels.release.set()
            worker_release.set()

            async def restore_workers():
                await task
                limiter.total_tokens = original_tokens

            client.portal.call(restore_workers)
        response = pending.result(timeout=5)
    assert response.status_code == 200
    assert [record["x"] for record in response.json()] == [1]


@pytest.mark.parametrize(
    "add_routes, prefix, method",
    [
        pytest.param(add_last_routes, "/last", "GET", id="last"),
        pytest.param(add_next_routes, "/next", "GET", id="next"),
        pytest.param(add_send_routes, "/send", "POST", id="send"),
        pytest.param(add_state_routes, "/state", "GET", id="state"),
    ],
)
@pytest.mark.parametrize("list_model", [False, True], ids=["scalar", "list"])
@pytest.mark.parametrize("selection", ["channel", "key", "basket"])
def test_response_serialization_does_not_block_event_loop(add_routes, prefix, method, list_model, selection, monkeypatch):
    app, channels = _app(add_routes, prefix, list_model, selection != "channel")
    module = import_module(add_routes.__module__)
    prepare_response = module.prepare_response
    park = channels._park
    monkeypatch.setattr(channels, "_park", lambda: None)

    def serialize(*args, **kwargs):
        park()
        return prepare_response(*args, **kwargs)

    monkeypatch.setattr(module, "prepare_response", serialize)
    path = f"{prefix}/record_values" + ("/one" if selection == "key" else "")
    data = [{"x": 5}] if list_model else {"x": 5}
    if selection == "basket":
        data = {"one": data}
    response = _request_while_parked(app, channels, method, path, **({"json": data} if method == "POST" else {}))
    assert response.status_code == 200
    assert [record["x"] for record in response.json()] == [5 if method == "POST" else 1]


@pytest.mark.parametrize(
    "add_routes, prefix, method",
    [
        pytest.param(add_last_routes, "/last", "GET", id="last"),
        pytest.param(add_next_routes, "/next", "GET", id="next"),
        pytest.param(add_send_routes, "/send", "POST", id="send"),
        pytest.param(add_state_routes, "/state", "GET", id="state"),
    ],
)
def test_streamed_record_encoding_does_not_block_event_loop(add_routes, prefix, method, monkeypatch):
    app, channels = _app(add_routes, prefix, False, False, materialize=False)
    module = import_module("csp_gateway.server.web.routes.shared")
    dump_records = module._dump_records
    park = channels._park
    monkeypatch.setattr(channels, "_park", lambda: None)

    def encode(records):
        park()
        return dump_records(records)

    monkeypatch.setattr(module, "_dump_records", encode)
    response = _request_while_parked(app, channels, method, f"{prefix}/record_values", **({"json": {"x": 5}} if method == "POST" else {}))
    assert response.status_code == 200
    assert [record["x"] for record in response.json()] == [5 if method == "POST" else 1]
    assert "content-length" not in response.headers


@pytest.mark.parametrize("method", ["POST", "DELETE", "PATCH", "GET", "PUT"])
@pytest.mark.parametrize("alias", [False, True], ids=["canonical", "hyphenated"])
def test_staging_route_does_not_block_event_loop(method, alias):
    app, channels = _app(add_last_routes, "/last", False, False)
    router = APIRouter()
    add_stage_routes(router, field="record_values", model=_Row)
    app.include_router(router, prefix="/stage")
    response = _request_while_parked(app, channels, method, "/stage/" + ("record-values" if alias else "record_values"))
    assert response.status_code == 200
    if method == "GET":
        assert response.json() == ["one"]
    else:
        assert [record["x"] for record in response.json()["one"]] == [1]


@pytest.mark.parametrize("selection", ["record_values", "record-values", "id"])
def test_lookup_route_does_not_block_event_loop(selection, monkeypatch):
    app, channels = _app(add_last_routes, "/last", False, False)

    def lookup(record_id):
        channels._park()
        return channels.record_values

    monkeypatch.setattr(_Row, "lookup", staticmethod(lookup))
    monkeypatch.setattr(lookup_routes, "global_lookup", lookup)
    router = APIRouter()
    lookup_routes.add_lookup_routes(router, field="record_values", model=_Row)
    lookup_routes.add_lookup_available_channels(router, fields={"record_values"})
    app.include_router(router, prefix="/lookup")
    response = _request_while_parked(app, channels, "GET", f"/lookup/{selection}/123")
    assert response.status_code == 200
    assert [record["x"] for record in response.json()] == [1]
