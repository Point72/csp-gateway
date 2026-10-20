import asyncio
import json
import multiprocessing
import threading
import time
from datetime import datetime, timedelta

import csp
import httpx2
import pytest
from csp import ts
from pydantic import Field

from csp_gateway import (
    AsyncClient,
    ClientConfig,
    Filter,
    FilterCondition,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewaySettings,
    GatewayStruct,
    MountRestRoutes,
    Query,
    ReturnType,
)
from csp_gateway.utils.exceptions import ServerRouteNotMountedException
from csp_gateway.utils.struct.base import type_adapter_for


class _Row(GatewayStruct):
    x: int = 0


def test_state_route_does_not_block_event_loop():
    """A slow state query must leave the event loop free to serve other requests."""
    from fastapi import APIRouter, FastAPI
    from fastapi.testclient import TestClient

    from csp_gateway.server.web.routes.state import add_state_routes

    entered = threading.Event()
    release = threading.Event()

    class _Channels:
        def query(self, field, indexer=None, query=None):
            entered.set()
            release.wait(timeout=10)
            return [_Row(x=1)]

    app = FastAPI()
    app.gateway = type("_Gateway", (), {"channels": _Channels()})()
    router = APIRouter()
    add_state_routes(router, field="records", model=_Row)
    app.include_router(router, prefix="/state")

    @app.get("/ping")
    async def ping():
        return "pong"

    with TestClient(app) as client:
        state_response = []
        slow = threading.Thread(target=lambda: state_response.append(client.get("/state/records")))
        slow.start()
        try:
            assert entered.wait(timeout=5)
            # The state query is parked mid-handler; an async route on the same loop must still answer.
            assert client.get("/ping").json() == "pong"
            assert slow.is_alive()
        finally:
            release.set()
            slow.join(timeout=10)
    assert [r["x"] for r in state_response[0].json()] == [1]


class _Fill(GatewayStruct):
    symbol: str = ""
    quantity: float = 0.0
    venue: str
    note: str = Field(default="", serialization_alias="comment")


class _FillChannels(GatewayChannels):
    fills: ts[_Fill] = None
    ready: ts[_Fill] = None


_N_FILLS = 3000


def _fills():
    # Mixed unset fields and naive timestamps, so the batched dump splits into several runs.
    return [
        _Fill(id=str(i), timestamp=datetime(2026, 1, 1) + timedelta(microseconds=i), symbol=f"S{i % 7}", quantity=float(i))
        if i % 3
        else _Fill(id=str(i), timestamp=datetime(2026, 1, 1) + timedelta(microseconds=i), symbol=f"S{i % 7}", quantity=float(i), venue="XNYS")
        for i in range(_N_FILLS)
    ]


class _FillModule(GatewayModule):
    def connect(self, channels: _FillChannels) -> None:
        # Relative delays: a realtime engine never reaches ticks scheduled at a fixed past time.
        channels.set_channel(_FillChannels.fills, csp.unroll(csp.const(_fills(), delay=timedelta(milliseconds=100))))
        channels.set_state(_FillChannels.fills, "id")
        # Ticks once every fill has gone into state, so the test knows when to query.
        channels.set_channel(_FillChannels.ready, csp.const(_Fill(id="ready"), delay=timedelta(seconds=1)))


def _serve_fills(port):
    """Run the gateway for real: it exits the process when done, so it gets a process of its own."""
    Gateway(
        modules=[_FillModule(), MountRestRoutes(force_mount_all=True)],
        channels=_FillChannels(),
        settings=GatewaySettings(BIND="127.0.0.1", PORT=port),
    ).start(rest=True, realtime=True)


@pytest.fixture(scope="class")
def fill_port(free_port):
    server = multiprocessing.get_context("spawn").Process(target=_serve_fills, args=(free_port,), daemon=True)
    server.start()
    try:
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                if httpx2.get(f"http://127.0.0.1:{free_port}/api/v1/last/ready", timeout=1).json():
                    break
            except (httpx2.HTTPError, ValueError):
                pass
            assert server.is_alive(), "gateway process exited before serving"
            time.sleep(0.2)
        else:
            pytest.fail("gateway never served the ready channel")
        yield free_port
    finally:
        server.terminate()
        server.join(timeout=10)


def _per_record(records):
    return json.loads(b"[" + b",".join(type_adapter_for(r).dump_json(r) for r in records) + b"]")


def _expected(query=None):
    records = sorted(_fills(), key=lambda r: int(r.id))
    if query is not None:
        records = [r for r in records if r.quantity > 1500]
    return _per_record(records)


def _by_id(rows):
    return sorted(rows, key=lambda r: int(r["id"]))


class TestAsyncClientState:
    """The async client against a live gateway serving a struct state over HTTP."""

    @pytest.mark.asyncio
    async def test_state_matches_per_record(self, fill_port):
        """AsyncClient sees `/state` exactly as main's per-record serializer wrote it, for every return type."""
        port = fill_port
        query = Query(filters=[Filter(attr="quantity", by=FilterCondition(value=1500.0, where=">"))])

        client = AsyncClient(ClientConfig(host="127.0.0.1", port=port, return_type=ReturnType.JSON))
        assert _by_id(await client.state("fills")) == _expected()
        assert _by_id(await client.state("fills", query=query)) == _expected(query)
        with pytest.raises(ServerRouteNotMountedException):
            await client.state("does_not_exist")

        wrapper = await AsyncClient(ClientConfig(host="127.0.0.1", port=port, return_type=ReturnType.Wrapper)).state("fills")
        assert _by_id(wrapper.json_data) == _expected()
        structs = await AsyncClient(ClientConfig(host="127.0.0.1", port=port, return_type=ReturnType.Struct)).state("fills")
        assert len(structs) == _N_FILLS
        pandas = await AsyncClient(ClientConfig(host="127.0.0.1", port=port, return_type=ReturnType.Pandas)).state("fills")
        assert len(pandas) == _N_FILLS and "comment" not in pandas.columns
        polars = await AsyncClient(ClientConfig(host="127.0.0.1", port=port, return_type=ReturnType.Polars)).state("fills")
        assert polars.height == _N_FILLS

    @pytest.mark.asyncio
    async def test_concurrent_state_queries(self, fill_port):
        """Concurrent `/state` calls from one AsyncClient all complete with identical bodies, alongside small calls."""
        client = AsyncClient(ClientConfig(host="127.0.0.1", port=fill_port, return_type=ReturnType.JSON))
        results = await asyncio.wait_for(asyncio.gather(*(client.state("fills") for _ in range(4)), client.last("ready")), timeout=60)
        expected = _expected()
        for rows in results[:4]:
            assert _by_id(rows) == expected
        assert results[4][0]["id"] == "ready"
