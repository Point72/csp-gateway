import hashlib
import multiprocessing
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import median, quantiles

import csp
import httpx2
import orjson
import pytest
import uvicorn
from csp import ts
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from pydantic import PrivateAttr

from csp_gateway import Gateway, GatewayChannels, GatewayModule, GatewayStruct
from csp_gateway.server.web.routes.last import add_last_routes
from csp_gateway.server.web.routes.send import add_send_routes

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
    _metrics: list[float] = PrivateAttr(default_factory=lambda: [0, 0.0])

    def connect(self, channels):
        records = [_Record(id=f"row-{index}", timestamp=_NOW, x=index) for index in range(self.rows)]
        edge = csp.const(records)
        if self.update_hz:
            ready = self._work(csp.timer(timedelta(seconds=1 / self.update_hz)), self.cpu_work_ms / 1000)
            edge = csp.sample(ready, edge)
        channels.set_channel("records", edge)

    @csp.node
    def _work(self, tick: ts[bool], cpu_seconds: float) -> ts[bool]:
        if csp.ticked(tick):
            started = time.thread_time()
            while time.thread_time() - started < cpu_seconds:
                pass
            self._metrics[0] += 1
            self._metrics[1] += time.thread_time() - started
            return True


def _serve_load(connection, stop, update_hz, cpu_work_ms, rows):
    module = _LoadModule(update_hz=update_hz, cpu_work_ms=cpu_work_ms, rows=rows)
    gateway = Gateway(channels=_LoadChannels(), modules=[module])
    gateway.start(block=False, realtime=True, rest=False, _in_test=True)
    try:
        app = FastAPI()
        app.gateway = gateway
        router = APIRouter()
        add_last_routes(router, field="records", model=list[_Record])
        app.include_router(router, prefix="/last")

        @app.get("/ping")
        async def ping():
            return "pong"

        @app.get("/metrics")
        async def metrics():
            return {"ticks": module._metrics[0], "engine_cpu_s": module._metrics[1], "server_cpu_s": time.process_time()}

        class Server(uvicorn.Server):
            async def startup(self, sockets=None):
                await super().startup(sockets=sockets)
                port = self.servers[0].sockets[0].getsockname()[1]
                connection.send({"url": f"http://127.0.0.1:{port}", "source": str(Path(add_last_routes.__code__.co_filename).resolve())})

        server = Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", access_log=False, loop="asyncio"))

        def request_stop():
            stop.wait()
            server.should_exit = True

        threading.Thread(target=request_stop, daemon=True).start()
        server.run()
    finally:
        gateway.stop()


@contextmanager
def _load_client(update_hz, cpu_work_ms, rows):
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    stop = context.Event()
    process = context.Process(target=_serve_load, args=(sender, stop, update_hz, cpu_work_ms, rows))
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


@pytest.mark.parametrize(
    "update_hz, cpu_work_ms",
    [pytest.param(0, 0.0, id="idle"), pytest.param(100, 1.0, id="light"), pytest.param(100, 5.0, id="moderate")],
)
@pytest.mark.parametrize("rows", [1, 1000], ids=["one-row", "1000-rows"])
@pytest.mark.benchmark(group="steady-updates-over-http")
def test_last_with_steady_updates(benchmark, update_hz, cpu_work_ms, rows):
    duration = 1.0 if benchmark.disabled else 10.0
    rounds = []
    expected = orjson.dumps(
        [
            {"id": f"row-{index}", "timestamp": "2026-01-01T00:00:00", "x": index, "price": 1.5, "label": "record", "active": True}
            for index in range(rows)
        ]
    )

    with _load_client(update_hz, cpu_work_ms, rows) as client, ThreadPoolExecutor(max_workers=4) as executor:

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
            if record:
                rounds.append(result)
            return result

        run_window(0.25 if benchmark.disabled else 2.0, record=False)
        benchmark.pedantic(run_window, args=(duration,), rounds=3, iterations=1)

    benchmark.extra_info.update(
        rows=rows,
        target_update_hz=update_hz,
        cpu_work_ms=cpu_work_ms,
        duration_s=duration,
        rounds=rounds,
        last_rps=median(result["last_rps"] for result in rounds),
        ping_p50_ms=median(result["ping"]["p50_ms"] for result in rounds),
        ping_p95_ms=median(result["ping"]["p95_ms"] for result in rounds),
        sha256=hashlib.sha256(expected).hexdigest(),
    )
