import asyncio
import hashlib
import math
import multiprocessing
import os
import random
import socket
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from importlib import import_module
from pathlib import Path
from statistics import median, quantiles
from types import SimpleNamespace
from urllib.parse import urlsplit

import csp
import httpx2
import orjson
import psutil
import pytest
import uvicorn
from csp import ts
from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.testclient import TestClient
from pydantic import PrivateAttr, field_serializer
from pydantic_core import PydanticSerializationError

from csp_gateway import Gateway, GatewayChannels, GatewayModule, GatewayStruct
from csp_gateway.server.web.routes.last import add_last_routes
from csp_gateway.server.web.routes.send import add_send_routes
from csp_gateway.server.web.routes.shared import _dump_records, prepare_response
from csp_gateway.server.web.routes.state import add_state_routes

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


class _Record(GatewayStruct):
    x: int = 1
    price: float = 1.5
    label: str = "record"
    active: bool = True


class _Channels(GatewayChannels):
    records: ts[_Record] = None


class _Module(GatewayModule):
    engine_delay: float = 0.0

    def connect(self, channels):
        channels.set_channel("records", csp.const(_Record(id="seed", timestamp=_NOW)))
        channels.add_send_channel("records")
        self._busy(csp.timer(timedelta(milliseconds=250)), self.engine_delay)

    @csp.node
    def _busy(self, tick: ts[bool], delay: float):
        if csp.ticked(tick) and delay:
            time.sleep(delay)


@contextmanager
def _client(engine_delay=0.0):
    gateway = Gateway(channels=_Channels(), modules=[_Module(engine_delay=engine_delay)])
    gateway.start(block=False, realtime=True, rest=False, _in_test=True)
    try:
        app = FastAPI()
        app.gateway = gateway
        last_router = APIRouter()
        send_router = APIRouter()
        add_last_routes(last_router, field="records", model=_Record)
        add_send_routes(send_router, field="records", model=_Record)
        app.include_router(last_router, prefix="/last")
        app.include_router(send_router, prefix="/send")

        @app.get("/ping")
        async def ping():
            return "pong"

        with TestClient(app) as client:
            assert client.get("/last/records").status_code == 200
            yield client
    finally:
        gateway.stop()


@pytest.mark.parametrize("engine_delay", [0.0, 0.2], ids=["idle", "busy-200ms"])
@pytest.mark.benchmark(group="small-request-under-last-load")
def test_small_request_with_concurrent_last(benchmark, engine_delay):
    stop = threading.Event()
    counts = [0] * 4

    with _client(engine_delay) as client, ThreadPoolExecutor(max_workers=4) as executor:

        def poll(worker):
            while not stop.is_set():
                response = client.get("/last/records")
                assert response.status_code == 200
                assert response.json()[0]["x"] == 1
                counts[worker] += 1

        workers = [executor.submit(poll, worker) for worker in range(4)]
        started = time.perf_counter()

        def pace():
            stop.wait(0.01)

        try:
            response = benchmark.pedantic(
                client.get,
                args=("/ping",),
                setup=pace,
                rounds=100,
                iterations=1,
            )
            assert response.json() == "pong"
        finally:
            stop.set()
            for worker in workers:
                worker.result(timeout=10)
        elapsed = time.perf_counter() - started
    benchmark.extra_info.update(last_requests=sum(counts), elapsed_s=elapsed, last_requests_per_s=sum(counts) / elapsed)


@pytest.mark.parametrize("count", [100_000, 200_000])
@pytest.mark.benchmark(group="large-send-with-last-poller")
def test_send_with_concurrent_last(benchmark, count):
    records = [
        {"id": f"row-{index}", "timestamp": "2026-01-01T00:00:00", "x": index, "price": 1.5, "label": "record", "active": True}
        for index in range(count)
    ]
    payload = orjson.dumps(records)
    latencies = []
    completed = []
    worst_latencies = []

    with _client() as client, ThreadPoolExecutor(max_workers=1) as executor:

        def post():
            started = time.perf_counter()
            response = client.post("/send/records", content=payload, headers={"content-type": "application/json"})
            return response, time.perf_counter() - started

        def send_and_poll():
            round_latencies = []
            pending = executor.submit(post)
            while not pending.done():
                started = time.perf_counter()
                response = client.get("/last/records")
                round_latencies.append(time.perf_counter() - started)
                assert response.status_code == 200
            response, elapsed = pending.result(timeout=30)
            completed.append((response, elapsed))
            latencies.extend(round_latencies)
            worst_latencies.append(max(round_latencies))
            return response

        response = benchmark.pedantic(send_and_poll, rounds=3, iterations=1)
    for result, _ in completed:
        assert result.status_code == 200
        assert result.content == payload
    assert latencies
    benchmark.extra_info.update(
        records=count,
        send_p50_s=median(elapsed for _, elapsed in completed),
        send_rounds_s=[elapsed for _, elapsed in completed],
        poller_p50_s=median(latencies),
        poller_max_s=max(latencies),
        poller_round_max_s=worst_latencies,
        sha256=hashlib.sha256(response.content).hexdigest(),
    )


class _LoadChannels(GatewayChannels):
    records: ts[list[_Record]] = None


class _LoadModule(GatewayModule):
    update_hz: int
    cpu_work_ms: float
    rows: int
    measure_engine_lag: bool = False
    _metrics: list[float] = PrivateAttr(default_factory=lambda: [0, 0.0])
    _lag_samples: list[float] = PrivateAttr(default_factory=list)
    _lag_lock: object = PrivateAttr(default_factory=threading.Lock)
    _next_tick_due: float | None = PrivateAttr(default=None)

    def lag_metrics(self, drain=True):
        with self._lag_lock:
            samples = self._lag_samples if drain else []
            if drain:
                self._lag_samples = []
            current = max(0.0, time.perf_counter() - self._next_tick_due) * 1000 if self._next_tick_due is not None else 0.0
        result = {"samples": len(samples), "in_progress_ms": current}
        if len(samples) >= 2:
            result.update(_latency_summary(samples))
        result["max_ms"] = max(result.get("max_ms", 0.0), current)
        return result

    def connect(self, channels):
        records = [_Record(id=f"row-{index}", timestamp=_NOW, x=index) for index in range(self.rows)]
        edge = csp.const(records)
        if self.update_hz:
            ready = self._work(csp.timer(timedelta(seconds=1 / self.update_hz)), self.cpu_work_ms / 1000)
            edge = csp.sample(ready, edge)
        channels.set_channel("records", edge)

    @csp.node
    def _work(self, tick: ts[bool], cpu_seconds: float) -> ts[bool]:
        with csp.state():
            s_clock_offset = 0.0
        with csp.start():
            s_clock_offset = datetime.now(UTC).timestamp() - time.perf_counter()
            if self.measure_engine_lag:
                with self._lag_lock:
                    self._next_tick_due = csp.now().replace(tzinfo=UTC).timestamp() - s_clock_offset + 1 / self.update_hz
        if csp.ticked(tick):
            if self.measure_engine_lag:
                expected = csp.now().replace(tzinfo=UTC).timestamp() - s_clock_offset
                lag = max(0.0, time.perf_counter() - expected)
                with self._lag_lock:
                    self._lag_samples.append(lag)
                    self._next_tick_due = expected + 1 / self.update_hz
            started = time.thread_time()
            while time.thread_time() - started < cpu_seconds:
                pass
            self._metrics[0] += 1
            self._metrics[1] += time.thread_time() - started
            return True


class _MixedChannels(_LoadChannels):
    bulk: ts[list[_Record]] = None


def test_engine_lag_accounts_for_stall_in_progress(monkeypatch):
    module = _LoadModule(update_hz=100, cpu_work_ms=1, rows=1, measure_engine_lag=True)
    module._lag_samples = [0.001, 0.002]
    module._next_tick_due = 100.0
    monkeypatch.setattr(time, "perf_counter", lambda: 100.25)
    result = module.lag_metrics()
    assert result["samples"] == 2
    assert result["in_progress_ms"] == 250
    assert result["max_ms"] == 250
    assert result["p95_ms"] < 3
    assert module._lag_samples == []
    current = module.lag_metrics(drain=False)
    assert current["samples"] == 0
    assert current["in_progress_ms"] == 250


def _batched_state_response(records, batch_rows):
    def encode():
        yield b"["
        for start in range(0, len(records), batch_rows):
            payload = _dump_records(records[start : start + batch_rows])[1:-1]
            yield (b"," if start else b"") + payload
        yield b"]"

    return StreamingResponse(encode(), media_type="application/json")


@pytest.mark.asyncio
@pytest.mark.parametrize("rows", [0, 1, 7])
@pytest.mark.parametrize("batch_rows", [1, 2, 500])
async def test_batched_state_response_matches_wire_bytes(rows, batch_rows):
    records = [_Record(id=f"row-{index}", timestamp=_NOW, x=index) for index in range(rows)]
    response = _batched_state_response(records, batch_rows)
    chunks = [chunk async for chunk in response.body_iterator]
    assert b"".join(chunks) == prepare_response(records, is_list_model=True).body
    for chunk in chunks[1:-1]:
        decoded = orjson.loads(b"[" + chunk.lstrip(b",") + b"]")
        assert 1 <= len(decoded) <= batch_rows
    assert response.media_type == "application/json"


@pytest.mark.asyncio
async def test_batched_state_response_changes_serialization_error_timing():
    class FragileRecord(_Record):
        @field_serializer("label")
        def serialize_label(self, value):
            if value == "invalid":
                raise ValueError("Cannot encode label")
            return value

    records = [FragileRecord(label="valid"), FragileRecord(label="invalid")]
    with pytest.raises(PydanticSerializationError):
        prepare_response(records, is_list_model=True)
    messages = []

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    response = _batched_state_response(records, 1)
    with pytest.raises(PydanticSerializationError):
        await response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send)
    assert messages[0]["status"] == 200
    body = b"".join(message.get("body", b"") for message in messages)
    assert body.startswith(b"[{")
    assert not body.endswith(b"]")


class _MixedModule(_LoadModule):
    bulk_rows: int
    mutate_bulk: bool = False
    _ready: threading.Event = PrivateAttr(default_factory=threading.Event)
    _state_type: str = PrivateAttr(default="unknown")
    _bulk_generation: int = PrivateAttr(default=0)

    def connect(self, channels):
        super().connect(channels)
        records = [_Record(id=f"bulk-{index}", timestamp=_NOW, x=index) for index in range(self.bulk_rows)]
        edge = csp.const(records)
        if self.mutate_bulk:
            edge = self._update_bulk(edge, csp.timer(timedelta(milliseconds=100)))
        channels.set_channel("bulk", edge)
        channels.set_state("bulk", "id")
        self._state_ready(channels.get_state("bulk"))

    @csp.node
    def _state_ready(self, state: ts[object]):
        if csp.ticked(state):
            self._state_type = state.state_type().name
            self._ready.set()

    @csp.node
    def _update_bulk(self, initial: ts[list[_Record]], tick: ts[bool]) -> ts[list[_Record]]:
        with csp.state():
            s_generation = 0
            s_position = 0
        if csp.ticked(initial):
            return initial
        if csp.ticked(tick):
            s_generation += 1
            records = [
                _Record(id=f"bulk-{index}", timestamp=_NOW, x=index, price=1.5 + s_generation)
                for index in ((s_position + offset) % self.bulk_rows for offset in range(min(1000, self.bulk_rows)))
            ]
            s_position = (s_position + 1000) % self.bulk_rows
            self._bulk_generation = s_generation
            return records


class _BulkAdmission:
    def __init__(self, app, limit, queue_limit=None, queue_timeout=None):
        self.app = app
        self.semaphore = asyncio.Semaphore(limit) if limit else None
        self.queue_limit = queue_limit
        self.queue_timeout = queue_timeout
        self.active = 0
        self.waiting = 0
        self.arrived = 0
        self.peak_active = 0
        self.peak_waiting = 0
        self.completed = 0
        self.rejected = 0
        self.expired = 0
        self.disconnected = 0
        self.cancelled = 0
        self.payload_rejected = 0
        self.buffered_messages_peak = 0
        self.buffered_body_peak = 0
        self.wait_seconds = 0.0
        self.running = set()

    async def reject(self, scope, receive, send, detail):
        await JSONResponse({"detail": detail}, status_code=503, headers={"Retry-After": "1"})(scope, receive, send)

    async def acquire(self, scope, receive, send, buffered):
        if self.semaphore is None:
            return True
        if not self.semaphore.locked():
            await self.semaphore.acquire()
            return True
        if self.queue_limit is not None and self.waiting >= self.queue_limit:
            self.rejected += 1
            await self.reject(scope, receive, send, "Bulk request queue is full")
            return False
        self.waiting += 1
        self.peak_waiting = max(self.peak_waiting, self.waiting)
        deadline = None if self.queue_timeout is None else time.monotonic() + self.queue_timeout

        async def disconnect():
            buffered_bytes = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return "disconnected"
                buffered_bytes += len(message.get("body", b""))
                if buffered_bytes > 64 * 1024:
                    return "payload_rejected"
                if buffered:
                    buffered[0]["body"].extend(message.get("body", b""))
                    buffered[0]["more_body"] = message.get("more_body", False)
                else:
                    buffered.append({**message, "body": bytearray(message.get("body", b""))})
                self.buffered_messages_peak = max(self.buffered_messages_peak, len(buffered))
                self.buffered_body_peak = max(self.buffered_body_peak, buffered_bytes)

        slot = asyncio.create_task(self.semaphore.acquire())
        monitor = asyncio.create_task(disconnect())
        acquired = False
        classified = False
        try:
            done, _ = await asyncio.wait({slot, monitor}, timeout=self.queue_timeout, return_when=asyncio.FIRST_COMPLETED)
            if monitor in done:
                classified = True
                if monitor.result() == "payload_rejected":
                    self.payload_rejected += 1
                    await JSONResponse({"detail": "Queued request body is too large"}, status_code=413)(scope, receive, send)
                else:
                    self.disconnected += 1
                return False
            if slot not in done or (deadline is not None and time.monotonic() >= deadline):
                classified = True
                self.expired += 1
                await self.reject(scope, receive, send, "Bulk request queue wait expired")
                return False
            acquired = slot.result()
            return acquired
        except asyncio.CancelledError:
            if not classified:
                self.cancelled += 1
            raise
        finally:
            self.waiting -= 1
            if slot.done() and not slot.cancelled() and slot.exception() is None:
                if slot.result() and not acquired:
                    self.semaphore.release()
            else:
                slot.cancel()
            monitor.cancel()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/state/bulk":
            return await self.app(scope, receive, send)
        started = time.perf_counter()
        self.arrived += 1
        buffered = []
        if not await self.acquire(scope, receive, send, buffered):
            return
        self.wait_seconds += time.perf_counter() - started
        self.active += 1
        self.peak_active = max(self.peak_active, self.active)

        async def replay():
            if buffered:
                message = buffered.pop(0)
                return {**message, "body": bytes(message["body"])}
            return await receive()

        async def transmit(message):
            body = message.get("body", b"")
            chunk_size = 64 * 1024
            if message["type"] != "http.response.body" or len(body) <= chunk_size:
                return await send(message)
            for offset in range(0, len(body), chunk_size):
                end = offset + chunk_size
                await send({**message, "body": body[offset:end], "more_body": end < len(body) or message.get("more_body", False)})

        async def work():
            try:
                return await self.app(scope, replay, transmit)
            finally:
                self.active -= 1
                self.completed += 1
                if self.semaphore is not None:
                    self.semaphore.release()

        def finished(task):
            self.running.discard(task)
            if not task.cancelled():
                task.exception()

        task = asyncio.create_task(work())
        self.running.add(task)
        task.add_done_callback(finished)
        return await asyncio.shield(task)

    def metrics(self):
        return {
            "active": self.active,
            "waiting": self.waiting,
            "arrived": self.arrived,
            "peak_active": self.peak_active,
            "peak_waiting": self.peak_waiting,
            "completed": self.completed,
            "rejected": self.rejected,
            "expired": self.expired,
            "disconnected": self.disconnected,
            "cancelled": self.cancelled,
            "payload_rejected": self.payload_rejected,
            "buffered_messages_peak": self.buffered_messages_peak,
            "buffered_body_peak": self.buffered_body_peak,
            "running_tasks": len(self.running),
            "wait_seconds": self.wait_seconds,
        }


@pytest.mark.asyncio
async def test_queued_body_fragmentation_stays_coalesced():
    entered = asyncio.Event()
    resume = asyncio.Event()
    body_received = asyncio.Event()
    incoming = asyncio.Queue()
    delivered = []

    async def app(scope, receive, send):
        if scope["request_id"] == "active":
            entered.set()
            await resume.wait()
        else:
            message = await receive()
            delivered.append(message["body"])
            assert message["more_body"] is False

    async def receive():
        message = await incoming.get()
        if not message["more_body"]:
            body_received.set()
        return message

    async def send(message):
        pass

    admission = _BulkAdmission(app, 1, queue_limit=1, queue_timeout=1)
    scope = {"type": "http", "path": "/state/bulk"}
    active = asyncio.create_task(admission({**scope, "request_id": "active"}, receive, send))
    await asyncio.wait_for(entered.wait(), timeout=1)
    queued = asyncio.create_task(admission({**scope, "request_id": "queued"}, receive, send))
    try:
        for index in range(1024):
            incoming.put_nowait({"type": "http.request", "body": b"x" * 64, "more_body": index != 1023})
        await asyncio.wait_for(body_received.wait(), timeout=1)
        assert admission.metrics()["buffered_messages_peak"] == 1
        assert admission.metrics()["buffered_body_peak"] == 64 * 1024
        resume.set()
        await asyncio.wait_for(asyncio.gather(active, queued), timeout=1)
        assert delivered == [b"x" * (64 * 1024)]
    finally:
        resume.set()
        await asyncio.gather(active, queued, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("queued_exit", ["timeout", "disconnect", "cancel"])
async def test_bulk_queue_lifecycle(queued_exit):
    entered = asyncio.Event()
    resume = asyncio.Event()
    called = []

    async def app(scope, receive, send):
        called.append(scope["request_id"])
        entered.set()
        await resume.wait()

    admission = _BulkAdmission(app, 1, queue_limit=1, queue_timeout=0.05)
    messages = []
    incoming = asyncio.Queue()

    async def receive():
        return await incoming.get()

    async def send(message):
        messages.append(message)

    scope = {"type": "http", "path": "/state/bulk"}
    active = asyncio.create_task(admission({**scope, "request_id": "active"}, receive, send))
    await asyncio.wait_for(entered.wait(), timeout=1)
    queued = asyncio.create_task(admission({**scope, "request_id": "queued"}, receive, send))
    try:
        async with asyncio.timeout(1):
            while admission.waiting != 1:
                await asyncio.sleep(0)
        await admission({**scope, "request_id": "overflow"}, receive, send)
        assert [message["status"] for message in messages if message["type"] == "http.response.start"] == [503]
        assert called == ["active"]
        messages.clear()
        if queued_exit == "disconnect":
            await incoming.put({"type": "http.request", "body": b"", "more_body": False})
            await incoming.put({"type": "http.disconnect"})
        elif queued_exit == "cancel":
            queued.cancel()
        if queued_exit == "cancel":
            with pytest.raises(asyncio.CancelledError):
                await queued
        else:
            await asyncio.wait_for(queued, timeout=1)
        assert called == ["active"]
        assert admission.waiting == 0
        assert admission.active == 1
        statuses = [message["status"] for message in messages if message["type"] == "http.response.start"]
        assert statuses == ([503] if queued_exit == "timeout" else [])
        counters = admission.metrics()
        assert counters["rejected"] == 1
        assert counters["expired"] == (1 if queued_exit == "timeout" else 0)
        assert counters["disconnected"] == (1 if queued_exit == "disconnect" else 0)
        assert counters["cancelled"] == (1 if queued_exit == "cancel" else 0)
    finally:
        resume.set()
        await asyncio.gather(active, queued, return_exceptions=True)
    assert admission.active == 0
    messages.clear()
    await admission({**scope, "request_id": "later"}, receive, send)
    assert called == ["active", "later"]
    assert admission.completed == 2


@pytest.mark.asyncio
async def test_bulk_expiry_response_cancellation_counts_once():
    entered = asyncio.Event()
    resume = asyncio.Event()

    async def app(scope, receive, send):
        entered.set()
        await resume.wait()

    async def receive():
        await asyncio.Future()

    async def send(message):
        raise asyncio.CancelledError

    admission = _BulkAdmission(app, 1, queue_limit=1, queue_timeout=0.01)
    scope = {"type": "http", "path": "/state/bulk"}
    active = asyncio.create_task(admission(scope, receive, send))
    await asyncio.wait_for(entered.wait(), timeout=1)
    try:
        with pytest.raises(asyncio.CancelledError):
            await admission(scope, receive, send)
        assert admission.expired == 1
        assert admission.cancelled == 0
        assert admission.waiting == 0
    finally:
        resume.set()
        await active
    assert admission.completed + admission.expired == admission.arrived


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_on_release", [False, True], ids=["replay", "cancel-race"])
async def test_bulk_slot_handoff_and_receive_replay(cancel_on_release):
    entered = asyncio.Event()
    resume = asyncio.Event()
    body_read = asyncio.Event()
    incoming = asyncio.Queue()
    called = []
    received = []
    body = {"type": "http.request", "body": b"", "more_body": False}

    async def app(scope, receive, send):
        called.append(scope["request_id"])
        if scope["request_id"] == "active":
            entered.set()
            await resume.wait()
        elif scope["request_id"] == "queued":
            received.append(await receive())

    async def receive():
        message = await incoming.get()
        body_read.set()
        return message

    async def send(message):
        pass

    admission = _BulkAdmission(app, 1, queue_limit=1, queue_timeout=1)
    scope = {"type": "http", "path": "/state/bulk"}
    active = asyncio.create_task(admission({**scope, "request_id": "active"}, receive, send))
    await asyncio.wait_for(entered.wait(), timeout=1)
    queued = asyncio.create_task(admission({**scope, "request_id": "queued"}, receive, send))
    try:
        await incoming.put(body)
        await asyncio.wait_for(body_read.wait(), timeout=1)
        resume.set()
        if cancel_on_release:
            asyncio.get_running_loop().call_soon(queued.cancel)
            with pytest.raises(asyncio.CancelledError):
                await queued
        else:
            await asyncio.wait_for(queued, timeout=1)
        await asyncio.wait_for(active, timeout=1)
        assert called == (["active"] if cancel_on_release else ["active", "queued"])
        assert received == ([] if cancel_on_release else [body])
        assert admission.active == admission.waiting == 0
        await asyncio.wait_for(admission({**scope, "request_id": "later"}, receive, send), timeout=1)
        assert called[-1] == "later"
        assert admission.peak_active == 1
    finally:
        resume.set()
        await asyncio.gather(active, queued, return_exceptions=True)


@pytest.mark.asyncio
async def test_bulk_wait_deadline_is_checked_after_event_loop_stall():
    entered = asyncio.Event()
    resume = asyncio.Event()
    called = []
    messages = []

    async def app(scope, receive, send):
        called.append(scope["request_id"])
        entered.set()
        await resume.wait()

    async def receive():
        await asyncio.Future()

    async def send(message):
        messages.append(message)

    admission = _BulkAdmission(app, 1, queue_limit=1, queue_timeout=0.01)
    scope = {"type": "http", "path": "/state/bulk"}
    active = asyncio.create_task(admission({**scope, "request_id": "active"}, receive, send))
    await entered.wait()
    queued = asyncio.create_task(admission({**scope, "request_id": "queued"}, receive, send))
    try:
        async with asyncio.timeout(1):
            while admission.waiting != 1:
                await asyncio.sleep(0)
        until = time.perf_counter() + 0.03
        while time.perf_counter() < until:
            pass
        resume.set()
        await asyncio.wait_for(asyncio.gather(active, queued), timeout=1)
        assert called == ["active"]
        assert admission.expired == 1
        assert [message["status"] for message in messages if message["type"] == "http.response.start"] == [503]
    finally:
        resume.set()
        await asyncio.gather(active, queued, return_exceptions=True)


@pytest.mark.asyncio
async def test_bulk_active_cancellation_holds_capacity_until_work_finishes():
    entered = asyncio.Event()
    resume = asyncio.Event()
    finished = asyncio.Event()
    called = []

    async def app(scope, receive, send):
        called.append(scope["request_id"])
        entered.set()
        await resume.wait()
        finished.set()

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    messages = []

    async def send(message):
        messages.append(message)

    admission = _BulkAdmission(app, 1, queue_limit=0, queue_timeout=0.05)
    scope = {"type": "http", "path": "/state/bulk"}
    pending = asyncio.create_task(admission({**scope, "request_id": "active"}, receive, send))
    await asyncio.wait_for(entered.wait(), timeout=1)
    try:
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert admission.active == 1
        await admission({**scope, "request_id": "overflow"}, receive, send)
        assert called == ["active"]
        assert [message["status"] for message in messages if message["type"] == "http.response.start"] == [503]
    finally:
        resume.set()
        await asyncio.wait_for(finished.wait(), timeout=1)
    async with asyncio.timeout(1):
        while admission.active:
            await asyncio.sleep(0)
    assert admission.completed == 1


class _RequestStages:
    def __init__(self):
        self.current = ContextVar("request_stages", default=None)
        self.samples = []
        self.sampler = random.Random(0)

    def install(self, gateway):
        context = self.current
        trigger = gateway.channels._last_requests["records", None]

        def submit(future=None):
            trace = context.get()
            if trace is None:
                return trigger.push_tick(future)

            class TimedFuture(Future):
                def set_result(self, value):
                    trace["engine_completed"] = time.perf_counter()
                    super().set_result(value)

            trace["engine_submitted"] = time.perf_counter()
            return trigger.push_tick(TimedFuture())

        gateway.channels._last_requests["records", None] = SimpleNamespace(push_tick=submit)
        last = _LoadChannels.last

        def timed_last(channels, *args, **kwargs):
            result = last(channels, *args, **kwargs)
            if (trace := context.get()) is not None:
                trace["engine_resumed"] = time.perf_counter()
            return result

        _LoadChannels.last = timed_last
        if (last_async := getattr(_LoadChannels, "last_async", None)) is not None:

            async def timed_last_async(channels, *args, **kwargs):
                result = await last_async(channels, *args, **kwargs)
                if (trace := context.get()) is not None:
                    trace["engine_resumed"] = time.perf_counter()
                return result

            _LoadChannels.last_async = timed_last_async

        routes = import_module(add_last_routes.__module__)
        routing = import_module("fastapi.routing")
        prepare_response = routes.prepare_response
        run_in_threadpool = routing.run_in_threadpool

        def serialize(*args, **kwargs):
            trace = context.get()
            if trace is None:
                return prepare_response(*args, **kwargs)
            trace["serialization_started"] = time.perf_counter()
            started = time.thread_time()
            result = prepare_response(*args, **kwargs)
            trace["serialization_cpu"] = time.thread_time() - started
            trace["serialization_finished"] = time.perf_counter()
            return result

        async def dispatch(function, *args, **kwargs):
            trace = context.get()
            if trace is None:
                return await run_in_threadpool(function, *args, **kwargs)
            trace["worker_queued"] = time.perf_counter()

            def work():
                trace["worker_started"] = time.perf_counter()
                result = function(*args, **kwargs)
                trace["worker_finished"] = time.perf_counter()
                return result

            result = await run_in_threadpool(work)
            trace["worker_resumed"] = time.perf_counter()
            return result

        routes.prepare_response = serialize
        routes.run_in_threadpool = dispatch
        routing.run_in_threadpool = dispatch

    def middleware(self, app):
        async def traced(scope, receive, send):
            if scope["type"] != "http" or scope["path"] != "/last/records":
                return await app(scope, receive, send)
            if self.sampler.getrandbits(4):
                return await app(scope, receive, send)
            trace = {"request_started": time.perf_counter()}
            token = self.current.set(trace)
            try:
                await app(scope, receive, send)
            finally:
                trace["request_finished"] = time.perf_counter()
                self.current.reset(token)
                self.samples.append(trace)

        return traced

    def drain(self):
        samples, self.samples = self.samples, []
        spans = {
            "engine_service": ("engine_submitted", "engine_completed"),
            "engine_resume": ("engine_completed", "engine_resumed"),
            "worker_dispatch": ("worker_queued", "worker_started"),
            "serialization_wall": ("serialization_started", "serialization_finished"),
            "worker_resume": ("worker_finished", "worker_resumed"),
            "request_wall": ("request_started", "request_finished"),
        }
        summaries = {}
        for name, (start, end) in spans.items():
            values = [sample[end] - sample[start] for sample in samples if start in sample and end in sample]
            if len(values) >= 2:
                summaries[name] = _latency_summary(values)
        cpu = [sample["serialization_cpu"] for sample in samples if "serialization_cpu" in sample]
        if len(cpu) >= 2:
            summaries["serialization_cpu"] = _latency_summary(cpu)
        return {"sample_count": len(samples), "timings": summaries}


def _serve_load(
    connection,
    stop,
    update_hz,
    cpu_work_ms,
    rows,
    profile_stages,
    bulk_rows,
    bulk_limit,
    mutate_bulk,
    measure_engine_lag,
    queue_limit,
    queue_timeout,
    state_batch_rows,
    state_materialize,
):
    if bulk_rows:
        module = _MixedModule(
            update_hz=update_hz,
            cpu_work_ms=cpu_work_ms,
            rows=rows,
            bulk_rows=bulk_rows,
            mutate_bulk=mutate_bulk,
            measure_engine_lag=measure_engine_lag,
        )
        channels = _MixedChannels()
    else:
        module = _LoadModule(update_hz=update_hz, cpu_work_ms=cpu_work_ms, rows=rows, measure_engine_lag=measure_engine_lag)
        channels = _LoadChannels()
    gateway = Gateway(channels=channels, modules=[module])
    gateway.start(block=False, realtime=True, rest=False, _in_test=True)
    try:
        app = FastAPI()
        app.gateway = gateway
        router = APIRouter()
        add_last_routes(router, field="records", model=list[_Record])
        app.include_router(router, prefix="/last")
        if bulk_rows:
            state_router = APIRouter()
            add_state_routes(state_router, field="bulk", model=list[_Record], batch_size=state_batch_rows, materialize=state_materialize)
            app.include_router(state_router, prefix="/state")

        @app.get("/ping")
        async def ping():
            return "pong"

        @app.get("/metrics")
        async def metrics(drain_lag: bool = True):
            result = {"ticks": module._metrics[0], "engine_cpu_s": module._metrics[1], "server_cpu_s": time.process_time(), "pid": os.getpid()}
            if stages is not None:
                result["stages"] = stages.drain()
            if bulk_rows:
                result["bulk"] = admission.metrics()
                result["state_type"] = module._state_type
                result["bulk_generation"] = module._bulk_generation
            if measure_engine_lag:
                result["engine_lag"] = module.lag_metrics(drain=drain_lag)
            return result

        stages = _RequestStages() if profile_stages else None

        class Server(uvicorn.Server):
            async def startup(self, sockets=None):
                await super().startup(sockets=sockets)
                if bulk_rows:
                    assert await asyncio.to_thread(module._ready.wait, 30), "bulk state did not populate"
                if stages is not None:
                    deadline = time.perf_counter() + 10
                    while ("records", None) not in gateway.channels._last_requests:
                        assert time.perf_counter() < deadline, "engine request adapter did not start"
                        await asyncio.sleep(0.001)
                    stages.install(gateway)
                port = self.servers[0].sockets[0].getsockname()[1]
                connection.send({"url": f"http://127.0.0.1:{port}", "source": str(Path(add_last_routes.__code__.co_filename).resolve())})

        application = stages.middleware(app) if stages is not None else app
        admission = _BulkAdmission(application, bulk_limit, queue_limit=queue_limit, queue_timeout=queue_timeout)
        if bulk_rows:
            application = admission
        server = Server(uvicorn.Config(application, host="127.0.0.1", port=0, log_level="error", access_log=False, loop="asyncio"))

        def request_stop():
            stop.wait()
            server.should_exit = True

        threading.Thread(target=request_stop, daemon=True).start()
        server.run()
    finally:
        gateway.stop()


@contextmanager
def _load_client(
    update_hz,
    cpu_work_ms,
    rows,
    profile_stages=False,
    bulk_rows=0,
    bulk_limit=0,
    mutate_bulk=False,
    measure_engine_lag=False,
    queue_limit=None,
    queue_timeout=None,
    state_batch_rows=500,
    state_materialize=True,
):
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    stop = context.Event()
    process = context.Process(
        target=_serve_load,
        args=(
            sender,
            stop,
            update_hz,
            cpu_work_ms,
            rows,
            profile_stages,
            bulk_rows,
            bulk_limit,
            mutate_bulk,
            measure_engine_lag,
            queue_limit,
            queue_timeout,
            state_batch_rows,
            state_materialize,
        ),
    )
    process.start()
    sender.close()
    try:
        assert receiver.poll(30), "benchmark server did not start"
        ready = receiver.recv()
        assert ready["source"] == str(Path(add_last_routes.__code__.co_filename).resolve())
        with httpx2.Client(base_url=ready["url"], timeout=10, trust_env=False) as client:
            yield client
    finally:
        receiver.close()
        stop.set()
        process.join(timeout=15)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
            pytest.fail("benchmark server did not stop")
        assert process.exitcode == 0


def _latency_summary(samples):
    assert len(samples) >= 2
    return {"p50_ms": median(samples) * 1000, "p95_ms": quantiles(samples, n=100, method="inclusive")[94] * 1000, "max_ms": max(samples) * 1000}


@contextmanager
def _bulk_socket(client, body=b""):
    address = urlsplit(str(client.base_url))
    with socket.socket() as connection:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        connection.settimeout(5)
        connection.connect((address.hostname, address.port))
        headers = f"GET /state/bulk HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        connection.sendall(headers + body)
        yield connection


def _read_http_head(connection):
    data = b""
    while b"\r\n\r\n" not in data:
        part = connection.recv(4096)
        assert part, "connection closed before response headers"
        data += part
    return data.split(b"\r\n\r\n", 1)[0]


def _wait_bulk(client, predicate):
    deadline = time.perf_counter() + 5
    pace = threading.Event()
    while True:
        result = client.get("/metrics", params={"drain_lag": "false"}).json()
        if predicate(result["bulk"]):
            return result
        assert time.perf_counter() < deadline, f"bulk state did not settle: {result['bulk']}"
        pace.wait(0.01)


def test_slow_bulk_socket_holds_capacity_until_disconnect():
    with _load_client(100, 1.0, 1, bulk_rows=50_000, bulk_limit=1, queue_limit=2, queue_timeout=1) as client:
        before = client.get("/metrics").json()["bulk"]
        with _bulk_socket(client) as slow:
            assert _read_http_head(slow).startswith(b"HTTP/1.1 200")
            for _ in range(5):
                current = client.get("/metrics").json()["bulk"]
                assert current["active"] == 1, "bulk credit was released while response bytes remained buffered"
                assert current["completed"] == before["completed"]
        after = _wait_bulk(client, lambda result: result["active"] == result["waiting"] == 0)["bulk"]
        assert after["completed"] == before["completed"] + 1
        assert client.get("/last/records").status_code == 200


def test_queued_socket_disconnect_and_body_bound():
    with _load_client(100, 1.0, 1, bulk_rows=50_000, bulk_limit=1, queue_limit=2, queue_timeout=3) as client:
        before = client.get("/metrics").json()["bulk"]
        with _bulk_socket(client) as slow:
            assert _read_http_head(slow).startswith(b"HTTP/1.1 200")
            with _bulk_socket(client):
                _wait_bulk(client, lambda result: result["waiting"] == 1)
            after = _wait_bulk(client, lambda result: result["waiting"] == 0)["bulk"]
            assert after["disconnected"] == before["disconnected"] + 1
            assert after["active"] == 1
            assert after["completed"] == before["completed"]
            with _bulk_socket(client, body=b"x" * (128 * 1024)) as oversized:
                assert _read_http_head(oversized).startswith(b"HTTP/1.1 413")
            after = _wait_bulk(client, lambda result: result["waiting"] == 0)["bulk"]
            assert after["payload_rejected"] == before["payload_rejected"] + 1
            assert after["active"] == 1
        after = _wait_bulk(client, lambda result: result["active"] == result["waiting"] == result["running_tasks"] == 0)["bulk"]
        assert after["completed"] == before["completed"] + 1
        assert after["arrived"] == before["arrived"] + 3


@pytest.mark.benchmark(group="bulk-socket-resource-stability")
def test_bulk_socket_resource_stability(benchmark):
    rounds = []
    with _load_client(100, 1.0, 1, bulk_rows=50_000, bulk_limit=1, queue_limit=2, queue_timeout=3) as client:
        initial = client.get("/state/bulk")
        assert initial.status_code == 200
        response_bytes = len(initial.content)
        process = psutil.Process(client.get("/metrics").json()["pid"])

        def sample():
            return {
                "rss_bytes": process.memory_info().rss,
                "fds": process.num_fds() if hasattr(process, "num_fds") else None,
                "threads": process.num_threads(),
            }

        def abort_cycle():
            before = client.get("/metrics").json()["bulk"]
            with _bulk_socket(client) as slow:
                assert _read_http_head(slow).startswith(b"HTTP/1.1 200")
                with _bulk_socket(client), _bulk_socket(client):
                    _wait_bulk(client, lambda result: result["waiting"] == 2)
                after = _wait_bulk(client, lambda result: result["waiting"] == 0)["bulk"]
                assert after["disconnected"] == before["disconnected"] + 2
                assert after["active"] == 1
            after = _wait_bulk(client, lambda result: result["active"] == result["waiting"] == result["running_tasks"] == 0)["bulk"]
            assert after["completed"] == before["completed"] + 1
            return sample()

        for _ in range(3):
            abort_cycle()
        baseline = sample()
        peak = [baseline["rss_bytes"]]
        stop = threading.Event()

        def monitor():
            while not stop.wait(0.02):
                peak[0] = max(peak[0], process.memory_info().rss)

        watcher = threading.Thread(target=monitor)
        watcher.start()

        def repeat_aborts():
            samples = [abort_cycle() for _ in range(8)]
            rounds.append(samples)
            return samples

        try:
            benchmark.pedantic(repeat_aborts, rounds=3, iterations=1)
        finally:
            stop.set()
            watcher.join(timeout=2)
        final = sample()
        if baseline["fds"] is not None:
            assert final["fds"] <= baseline["fds"] + 2
        assert final["threads"] <= baseline["threads"] + 1
        settled = [batch[-1]["rss_bytes"] for batch in rounds]
        if len(settled) >= 2:
            assert settled[-1] - settled[0] <= max(32 * 1024 * 1024, response_bytes * 4)
        assert client.get("/last/records").status_code == 200
    benchmark.extra_info.update(
        cycles=8 * len(rounds),
        queued_disconnects=16 * len(rounds),
        response_bytes=response_bytes,
        baseline=baseline,
        final=final,
        peak_rss_bytes=peak[0],
        settled_rss_bytes=settled,
        rounds=rounds,
    )


def test_changing_bulk_state_fixture():
    with _load_client(100, 1.0, 1, bulk_rows=1000, mutate_bulk=True, measure_engine_lag=True) as client:
        before = client.get("/metrics").json()
        deadline = time.perf_counter() + 5
        while True:
            response = client.get("/state/bulk")
            assert response.status_code == 200
            records = orjson.loads(response.content)
            assert len(records) == 1000
            assert {record["id"] for record in records} == {f"bulk-{index}" for index in range(1000)}
            newest = max(record["price"] - 1.5 for record in records)
            if newest > before["bulk_generation"]:
                break
            assert time.perf_counter() < deadline, "state updates were not visible"
        after = client.get("/metrics").json()
        assert after["bulk_generation"] >= newest
        assert after["engine_lag"]["samples"] >= 2
        assert after["engine_lag"]["max_ms"] >= after["engine_lag"]["p95_ms"] >= 0


def test_engine_lag_fixture():
    with _load_client(100, 1.0, 1, measure_engine_lag=True) as client:
        for _ in range(100):
            assert client.get("/last/records").status_code == 200
        lag = client.get("/metrics").json()["engine_lag"]
        assert lag["samples"] >= 2
        assert lag["max_ms"] >= lag["p95_ms"] >= 0


@pytest.mark.parametrize(
    "update_hz, cpu_work_ms",
    [pytest.param(0, 0.0, id="idle"), pytest.param(100, 1.0, id="light"), pytest.param(100, 5.0, id="moderate")],
)
@pytest.mark.parametrize("rows", [1, 1000], ids=["one-row", "1000-rows"])
@pytest.mark.benchmark(group="steady-updates-over-http")
def test_last_with_steady_updates(benchmark, update_hz, cpu_work_ms, rows):
    duration = 1.0 if benchmark.disabled else 10.0
    profile_stages = os.environ.get("CSP_GATEWAY_BENCHMARK_STAGES") == "1"
    rounds = []
    expected = orjson.dumps(
        [
            {"id": f"row-{index}", "timestamp": "2026-01-01T00:00:00", "x": index, "price": 1.5, "label": "record", "active": True}
            for index in range(rows)
        ]
    )

    with _load_client(update_hz, cpu_work_ms, rows, profile_stages=profile_stages) as client, ThreadPoolExecutor(max_workers=4) as executor:

        def run_window(seconds, record=True):
            before = client.get("/metrics").json()
            started = time.perf_counter()
            deadline = started + seconds

            def poll():
                samples = []
                while time.perf_counter() < deadline:
                    sent = time.perf_counter()
                    response = client.get("/last/records")
                    samples.append(time.perf_counter() - sent)
                    assert response.status_code == 200
                    assert response.content == expected
                return samples

            workers = [executor.submit(poll) for _ in range(4)]
            ping_latencies = []
            pace = threading.Event()
            while time.perf_counter() < deadline:
                sent = time.perf_counter()
                response = client.get("/ping")
                ping_latencies.append(time.perf_counter() - sent)
                assert response.status_code == 200
                assert response.json() == "pong"
                pace.wait(0.01)
            last_latencies = [sample for worker in workers for sample in worker.result(timeout=15)]
            elapsed = time.perf_counter() - started
            after = client.get("/metrics").json()
            if not record:
                return
            ticks = after["ticks"] - before["ticks"]
            assert ticks > 0 if update_hz else ticks == 0
            result = {
                "elapsed_s": elapsed,
                "last_requests": len(last_latencies),
                "last_rps": len(last_latencies) / elapsed,
                "last": _latency_summary(last_latencies),
                "ping": _latency_summary(ping_latencies),
                "observed_update_hz": ticks / elapsed,
                "engine_work_cpu_percent": 100 * (after["engine_cpu_s"] - before["engine_cpu_s"]) / elapsed,
                "server_cpu_percent": 100 * (after["server_cpu_s"] - before["server_cpu_s"]) / elapsed,
            }
            if profile_stages:
                result["stages"] = after["stages"]
                assert after["stages"]["sample_count"] >= 2
                assert len(after["stages"]["timings"]) == 7
            rounds.append(result)
            return result

        run_window(0.25 if benchmark.disabled else 2.0, record=False)
        benchmark.pedantic(run_window, args=(duration,), rounds=3, iterations=1)

    benchmark.extra_info.update(
        rows=rows,
        target_update_hz=update_hz,
        cpu_work_ms=cpu_work_ms,
        duration_s=duration,
        profile_stages=profile_stages,
        rounds=rounds,
        last_rps=median(result["last_rps"] for result in rounds),
        ping_p50_ms=median(result["ping"]["p50_ms"] for result in rounds),
        ping_p95_ms=median(result["ping"]["p95_ms"] for result in rounds),
        sha256=hashlib.sha256(expected).hexdigest(),
    )


@pytest.mark.parametrize("changing_bursts", [False, True], ids=["static", "changing-bursts"])
@pytest.mark.parametrize("cpu_work_ms", [1.0, 5.0], ids=["light", "moderate"])
@pytest.mark.parametrize(
    "bulk_limit, queue_limit, queue_timeout",
    [
        pytest.param(0, None, None, id="shared"),
        pytest.param(1, None, None, id="bulk-1"),
        pytest.param(2, None, None, id="bulk-2"),
        pytest.param(1, 4, 0.5, id="queue-4-wait-500ms"),
        pytest.param(1, 4, 1.5, id="queue-4-wait-1500ms"),
    ],
)
@pytest.mark.benchmark(group="mixed-state-and-last-over-http")
def test_mixed_state_and_last(benchmark, cpu_work_ms, bulk_limit, queue_limit, queue_timeout, changing_bursts):
    bulk_rows = 50_000
    state_batch_rows = int(os.environ.get("CSP_GATEWAY_BENCHMARK_STATE_BATCH_ROWS", "500"))
    state_materialize = {"true": True, "false": False}[os.environ.get("CSP_GATEWAY_BENCHMARK_MATERIALIZE", "true").lower()]
    assert state_batch_rows > 0
    duration = (5.0 if changing_bursts else 3.0) if benchmark.disabled else 10.0
    rounds = []
    expected_last = b'[{"id":"row-0","timestamp":"2026-01-01T00:00:00","x":0,"price":1.5,"label":"record","active":true}]'

    def validate_bulk(content):
        records = orjson.loads(content)
        assert len(records) == bulk_rows
        newest = 0.0
        for index, record in enumerate(sorted(records, key=lambda record: record["x"])):
            revision = record["price"] - 1.5
            assert revision >= 0 and revision.is_integer()
            assert changing_bursts or revision == 0
            newest = max(newest, revision)
            assert record == {
                "id": f"bulk-{index}",
                "timestamp": "2026-01-01T00:00:00",
                "x": index,
                "price": 1.5 + revision,
                "label": "record",
                "active": True,
            }
        return newest

    with _load_client(
        100,
        cpu_work_ms,
        1,
        bulk_rows=bulk_rows,
        bulk_limit=bulk_limit,
        mutate_bulk=changing_bursts,
        measure_engine_lag=changing_bursts,
        queue_limit=queue_limit,
        queue_timeout=queue_timeout,
        state_batch_rows=state_batch_rows,
        state_materialize=state_materialize,
    ) as client:
        initial = client.get("/state/bulk")
        assert initial.status_code == 200
        validate_bulk(initial.content)
        bulk_hash = hashlib.sha256(initial.content).digest()
        response_bytes = len(initial.content)

        burst_workers = 8 * math.ceil(duration / 2.0) if changing_bursts else 8
        with ThreadPoolExecutor(max_workers=8) as executor, ThreadPoolExecutor(max_workers=burst_workers) as burst_executor:

            def run_window(seconds, record=True):
                before = client.get("/metrics").json()
                started = time.perf_counter()
                deadline = started + seconds
                pace = threading.Event()

                def request_once(path, offered_at=None):
                    sent = time.perf_counter() if offered_at is None else offered_at
                    try:
                        response = client.get(path)
                    except httpx2.TimeoutException as error:
                        return time.perf_counter() - sent, -1, type(error).__name__
                    latency = time.perf_counter() - sent
                    if path == "/state/bulk" and response.status_code == 503:
                        assert queue_limit is not None or queue_timeout is not None
                        assert response.headers["retry-after"] == "1"
                        reason = {
                            "Bulk request queue is full": "queue_full",
                            "Bulk request queue wait expired": "queue_expired",
                        }[response.json()["detail"]]
                        return latency, -1, reason
                    assert response.status_code == 200
                    revision = 0
                    if path == "/state/bulk":
                        if changing_bursts:
                            revision = validate_bulk(response.content)
                        else:
                            assert hashlib.sha256(response.content).digest() == bulk_hash
                    elif path == "/last/records":
                        assert response.content == expected_last
                    else:
                        assert response.json() == "pong"
                    return latency, revision, None

                def poll(path):
                    samples = []
                    while time.perf_counter() < deadline:
                        samples.append(request_once(path))
                    return samples

                def bursts():
                    pending = []
                    offered = started
                    while offered < deadline:
                        pace.wait(max(0, offered - time.perf_counter()))
                        pending.extend(burst_executor.submit(request_once, "/state/bulk", offered) for _ in range(8))
                        offered += 2.0
                    return [future.result(timeout=60) for future in pending]

                small = [executor.submit(poll, "/last/records") for _ in range(4)]
                if changing_bursts:
                    bulk = [executor.submit(bursts)]
                else:
                    bulk = [executor.submit(poll, "/state/bulk") for _ in range(4)]
                ping_results = []
                while time.perf_counter() < deadline:
                    ping_results.append(request_once("/ping"))
                    pace.wait(0.01)
                last_results = [sample for worker in small for sample in worker.result(timeout=30)]
                state_results = [sample for worker in bulk for sample in worker.result(timeout=60)]
                after = client.get("/metrics", params={"drain_lag": "false"}).json()
                drain_deadline = time.perf_counter() + 30
                while after["bulk"]["active"] or after["bulk"]["waiting"]:
                    assert time.perf_counter() < drain_deadline, "bulk admission queue did not drain"
                    pace.wait(0.02)
                    after = client.get("/metrics", params={"drain_lag": "false"}).json()
                after = client.get("/metrics").json()
                elapsed = time.perf_counter() - started
                last_latencies = [sample[0] for sample in last_results if sample[2] is None]
                state_latencies = [sample[0] for sample in state_results if sample[2] is None]
                ping_latencies = [sample[0] for sample in ping_results if sample[2] is None]
                if not record:
                    return
                assert after["ticks"] > before["ticks"]
                if bulk_limit:
                    assert after["bulk"]["peak_active"] <= bulk_limit
                if queue_limit is not None:
                    assert after["bulk"]["peak_waiting"] <= queue_limit
                completed = after["bulk"]["completed"] - before["bulk"]["completed"]
                arrived = after["bulk"]["arrived"] - before["bulk"]["arrived"]
                terminal = sum(
                    after["bulk"][name] - before["bulk"][name] for name in ("rejected", "expired", "disconnected", "cancelled", "payload_rejected")
                )
                assert completed + terminal == arrived == len(state_results)
                full = [sample[0] for sample in state_results if sample[2] == "queue_full"]
                expired = [sample[0] for sample in state_results if sample[2] == "queue_expired"]
                result = {
                    "elapsed_s": elapsed,
                    "drain_s": max(0, elapsed - seconds),
                    "last_rps": len(last_latencies) / elapsed,
                    "state_rps": len(state_latencies) / elapsed,
                    "last": _latency_summary(last_latencies) if len(last_latencies) >= 2 else None,
                    "state": _latency_summary(state_latencies) if len(state_latencies) >= 2 else None,
                    "ping": _latency_summary(ping_latencies) if len(ping_latencies) >= 2 else None,
                    "last_timeouts": len(last_results) - len(last_latencies),
                    "state_timeouts": sum(sample[2] is not None and sample[2].endswith("Timeout") for sample in state_results),
                    "state_succeeded": len(state_latencies),
                    "state_queue_full": len(full),
                    "state_queue_expired": len(expired),
                    "queue_full_latency": _latency_summary(full) if len(full) >= 2 else None,
                    "queue_expired_latency": _latency_summary(expired) if len(expired) >= 2 else None,
                    "ping_timeouts": len(ping_results) - len(ping_latencies),
                    "observed_update_hz": (after["ticks"] - before["ticks"]) / elapsed,
                    "server_cpu_percent": 100 * (after["server_cpu_s"] - before["server_cpu_s"]) / elapsed,
                    "peak_bulk_active": after["bulk"]["peak_active"],
                    "peak_bulk_waiting": after["bulk"]["peak_waiting"],
                    "bulk_admission_mean_ms": 1000 * (after["bulk"]["wait_seconds"] - before["bulk"]["wait_seconds"]) / completed
                    if completed
                    else None,
                    "state_type": after["state_type"],
                }
                if changing_bursts:
                    newest = max((sample[1] for sample in state_results if sample[2] is None), default=None)
                    if newest is not None:
                        assert before["bulk_generation"] < newest <= after["bulk_generation"]
                    assert after["engine_lag"]["samples"] >= 2
                    assert len(state_results) == 8 * math.ceil(seconds / 2.0)
                    result["bulk_generation"] = after["bulk_generation"]
                    result["newest_served_generation"] = newest
                    result["engine_lag"] = after["engine_lag"]
                    result["state_offered"] = len(state_results)
                rounds.append(result)
                return result

            run_window(0.5 if benchmark.disabled else 2.0, record=False)
            benchmark.pedantic(run_window, args=(duration,), rounds=3, iterations=1)

    def median_tail(route):
        values = [result[route]["p95_ms"] for result in rounds if result[route] is not None]
        return median(values) if values else None

    benchmark.extra_info.update(
        bulk_rows=bulk_rows,
        response_bytes=response_bytes,
        bulk_limit=bulk_limit,
        queue_limit=queue_limit,
        queue_timeout_s=queue_timeout,
        state_batch_rows=state_batch_rows,
        materialize=state_materialize,
        changing_bursts=changing_bursts,
        cpu_work_ms=cpu_work_ms,
        duration_s=duration,
        state_type=rounds[0]["state_type"],
        rounds=rounds,
        last_rps=median(result["last_rps"] for result in rounds),
        state_rps=median(result["state_rps"] for result in rounds),
        last_p95_ms=median_tail("last"),
        ping_p95_ms=median_tail("ping"),
        last_timeouts=sum(result["last_timeouts"] for result in rounds),
        state_timeouts=sum(result["state_timeouts"] for result in rounds),
        state_succeeded=sum(result["state_succeeded"] for result in rounds),
        state_queue_full=sum(result["state_queue_full"] for result in rounds),
        state_queue_expired=sum(result["state_queue_expired"] for result in rounds),
        ping_timeouts=sum(result["ping_timeouts"] for result in rounds),
        sha256=None if changing_bursts else bulk_hash.hex(),
    )
