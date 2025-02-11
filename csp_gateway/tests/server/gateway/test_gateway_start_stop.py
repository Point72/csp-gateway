import multiprocessing
import os
import signal
import socket
import sys
import time
from datetime import timedelta
from unittest.mock import patch

import csp.impl.error_handling
import pytest
import requests
from fastapi.testclient import TestClient

from csp_gateway import Gateway, GatewaySettings, MountRestRoutes
from csp_gateway.server.demo import ExampleGatewayChannels, ExampleModule
from csp_gateway.testing import CspDieModule, LongStartModule
from csp_gateway.tests.server.gateway.test_gateway import MyBuildFailureModule

csp.impl.error_handling.set_print_full_exception_stack(True)


def test_long_startup_die_cleanly(free_port):
    with patch("os._exit") as exit_mock, patch("os.kill") as kill_mock:
        # instantiate gateway
        gateway = Gateway(
            settings=GatewaySettings(API_KEY="12345", AUTHENTICATE=False, PORT=free_port),
            modules=[
                # NeverDieModule(),
                # CspDieModule(),
                LongStartModule(),
                ExampleModule(),
                MountRestRoutes(force_mount_all=True),
            ],
            channels=ExampleGatewayChannels(),
        )
        try:
            gateway.start(realtime=True, rest=True, build_timeout=1)
        except RuntimeError:
            assert exit_mock.call_count == 1
            assert kill_mock.call_count == 1
            return
        raise Exception("test failed")


def test_start_with_endtime(free_port):
    @csp.graph
    def user_graph(channels: ExampleGatewayChannels) -> csp.ts[int]:
        return csp.const(1)

    # instantiate gateway
    gateway = Gateway(
        settings=GatewaySettings(API_KEY="12345", AUTHENTICATE=False, PORT=free_port),
        modules=[
            ExampleModule(),
            MountRestRoutes(force_mount_all=True),
        ],
        channels=ExampleGatewayChannels(),
    )
    res = gateway.start(user_graph=user_graph, realtime=True, rest=True, endtime=timedelta(seconds=5))
    assert "user_graph" in res


def test_start_with_endtime_usergraph_no_return(free_port):
    @csp.graph
    def user_graph(channels: ExampleGatewayChannels):
        csp.print("here", csp.const(1))

    # instantiate gateway
    gateway = Gateway(
        settings=GatewaySettings(API_KEY="12345", AUTHENTICATE=False, PORT=free_port),
        modules=[
            ExampleModule(),
            MountRestRoutes(force_mount_all=True),
        ],
        channels=ExampleGatewayChannels(),
    )
    res = gateway.start(user_graph=user_graph, realtime=True, rest=True, endtime=timedelta(seconds=5))
    assert "user_graph" in res


def test_start_and_then_die_with_error(free_port):
    # instantiate gateway
    gateway = Gateway(
        settings=GatewaySettings(API_KEY="12345", AUTHENTICATE=False, PORT=free_port),
        modules=[
            ExampleModule(),
            CspDieModule(),
            MountRestRoutes(force_mount_all=True),
        ],
        channels=ExampleGatewayChannels(),
    )
    try:
        gateway.start(realtime=True, rest=True)
    except RuntimeError:
        return
    raise Exception("test failed")


@pytest.mark.skipif(sys.platform == "darwin", reason="Flaky on MacOS GHA runners")
def test_start_and_then_graph_start_error(caplog, free_port):
    gateway = Gateway(
        settings=GatewaySettings(API_KEY="12345", AUTHENTICATE=False, PORT=free_port),
        modules=[
            ExampleModule(),
            MyBuildFailureModule(),
            MountRestRoutes(force_mount_all=True),
        ],
        channels=ExampleGatewayChannels(),
    )
    try:
        gateway.start(realtime=True, rest=True, block=False, build_timeout=timedelta(seconds=60))
    except RuntimeError:
        assert "Graph start failure" in caplog.text
        return
    raise Exception("test failed")


def test_stop_with_shutdown(free_port):
    # instantiate gateway
    gateway = Gateway(
        settings=GatewaySettings(API_KEY="12345", AUTHENTICATE=False, PORT=free_port),
        modules=[
            ExampleModule(),
            MountRestRoutes(force_mount_all=True),
        ],
        channels=ExampleGatewayChannels(),
    )
    gateway.start(realtime=True, rest=True, _in_test=True)
    rest_client = TestClient(gateway.web_app.get_fastapi())
    response = rest_client.post("/api/v1/controls/shutdown")
    assert response.status_code == 200

    return_data = response.json()
    assert return_data[0]["status"] == "ok"


def run_gateway(port_str):
    from csp_gateway import Gateway, GatewaySettings, MountRestRoutes
    from csp_gateway.server.demo import ExampleGatewayChannels, ExampleModule

    # instantiate gateway
    gateway = Gateway(
        settings=GatewaySettings(AUTHENTICATE=False, PORT=int(port_str)),
        modules=[
            ExampleModule(),
            MountRestRoutes(force_mount_all=True),
        ],
        channels=ExampleGatewayChannels(),
    )
    # Start gateway without test mode
    gateway.start(realtime=True, rest=True)


@pytest.mark.parametrize("signal_val", [signal.SIGINT, signal.SIGTERM, signal.SIGUSR1])
def test_signal_with_shutdown(signal_val, free_port):
    REQUEST_RETRY_TIMEOUT = 2
    AFTER_KILL_WAIT_TIME = 10
    NUM_TRIES = 10
    port_str = str(free_port)
    # URL to check if the server is up
    url = f"http://localhost:{port_str}/api/v1/state"

    # Start the gateway in another process
    p = multiprocessing.Process(target=run_gateway, args=(port_str,))
    p.start()
    # Wait for it to startup
    for idx in range(NUM_TRIES + 1):
        if idx == NUM_TRIES:
            # Unable to fully start the server
            assert False
        try:
            time.sleep(REQUEST_RETRY_TIMEOUT)
            resp = requests.get(url, timeout=1)
            resp.raise_for_status()
            break
        except (requests.HTTPError, requests.Timeout, requests.ConnectionError):
            pass
    print("Server is up")
    # Send signal to invoke shutdown
    print(f"Sending SIGNAL: {signal_val}")
    os.kill(p.pid, signal_val)
    # Wait for gateway to react to signal
    p.join(AFTER_KILL_WAIT_TIME)
    # Check if gateway shutdown with proper exit status
    assert not p.is_alive()
    assert p.exitcode == 0


def test_shutdown_with_big_red_button(free_port):
    REQUEST_RETRY_TIMEOUT = 2
    AFTER_SHUTDOWN_WAIT_TIME = 10
    NUM_TRIES = 10
    port_str = str(free_port)
    # URL to check if the server is up
    state_url = f"http://{socket.gethostname()}:{port_str}/api/v1/state"
    shutdown_url = f"http://{socket.gethostname()}:{port_str}/api/v1/controls/shutdown"

    # Start the gateway in another process
    p = multiprocessing.Process(target=run_gateway, args=(port_str,))
    p.start()
    # Wait for it to startup
    for idx in range(NUM_TRIES + 1):
        if idx == NUM_TRIES:
            # Unable to fully start the server
            assert False
        try:
            time.sleep(REQUEST_RETRY_TIMEOUT)
            resp = requests.get(state_url, timeout=1)
            resp.raise_for_status()
            break
        except (requests.HTTPError, requests.Timeout, requests.ConnectionError):
            print("Server not up yet")
            continue
    print("Server is up")
    # Send signal to invoke shutdown
    print("Sending Shutdown Request")
    resp = requests.post(shutdown_url, timeout=1)
    # Wait for gateway to react to signal
    p.join(AFTER_SHUTDOWN_WAIT_TIME)
    # Check if gateway shutdown with proper exit status
    assert not p.is_alive()
    assert p.exitcode == 0
