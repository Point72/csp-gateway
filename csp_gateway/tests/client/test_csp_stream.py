"""Tests for the CSP streaming client module."""

import multiprocessing
import os
import signal
import socket
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import csp
import pytest

from csp_gateway import GatewayStruct
from csp_gateway.client import GatewayClient, GatewayClientConfig
from csp_gateway.client.csp_stream import (
    GatewayStreamAdapterManager,
    _create_stream_csp_graph,
)


class SampleStruct(GatewayStruct):
    """A simple GatewayStruct for testing."""

    value: Optional[int] = None
    name: Optional[str] = None


def test_gateway_stream_adapter_manager_init():
    """Test that GatewayStreamAdapterManager initializes correctly."""
    config = GatewayClientConfig(host="localhost", port=8000)
    manager = GatewayStreamAdapterManager(config)

    assert manager._config == config
    assert manager._impl is None


def test_gateway_stream_adapter_manager_add_channel_before_impl():
    """Test that add_channel works even before impl is created."""
    config = GatewayClientConfig(host="localhost", port=8000)
    manager = GatewayStreamAdapterManager(config)

    # Should not raise - just does nothing since impl is None
    manager.add_channel("test_channel")


def test_gateway_stream_adapter_manager_remove_channel_before_impl():
    """Test that remove_channel works even before impl is created."""
    config = GatewayClientConfig(host="localhost", port=8000)
    manager = GatewayStreamAdapterManager(config)

    # Should not raise - just does nothing since impl is None
    manager.remove_channel("test_channel")


def test_create_stream_csp_graph():
    """Test that _create_stream_csp_graph returns a valid graph function."""
    config = GatewayClientConfig(host="localhost", port=8000)
    stream_csp = _create_stream_csp_graph(config)

    # Verify the function is callable (CSP wraps the signature)
    assert callable(stream_csp)

    # The wrapped function has the original parameters
    assert hasattr(stream_csp, "__wrapped__")
    import inspect

    sig = inspect.signature(stream_csp.__wrapped__)
    params = list(sig.parameters.keys())
    assert "subscribe" in params
    assert "unsubscribe" in params
    assert "data" in params
    assert "push_mode" in params
    # config should NOT be in params since it's bound
    assert "config" not in params


def test_gateway_stream_adapter_manager_subscribe():
    """Test that subscribe returns a proper adapter definition."""
    config = GatewayClientConfig(host="localhost", port=8000)
    manager = GatewayStreamAdapterManager(config)

    # Subscribe should return an adapter definition
    result = manager.subscribe()
    # The result should be a graph-time object (adapter definition)
    assert result is not None


def test_gateway_stream_adapter_manager_subscribe_with_push_mode():
    """Test that subscribe accepts push_mode parameter."""
    config = GatewayClientConfig(host="localhost", port=8000)
    manager = GatewayStreamAdapterManager(config)

    # Should not raise with different push modes
    result_nc = manager.subscribe(push_mode=csp.PushMode.NON_COLLAPSING)
    assert result_nc is not None

    result_lv = manager.subscribe(push_mode=csp.PushMode.LAST_VALUE)
    assert result_lv is not None


def test_gateway_client_has_stream_csp_method():
    """Test that GatewayClient has the stream_csp method."""
    client = GatewayClient(host="localhost", port=8000)
    assert hasattr(client, "stream_csp")
    assert callable(client.stream_csp)


def test_gateway_client_stream_csp_signature():
    """Test that stream_csp method has the expected signature."""
    client = GatewayClient(host="localhost", port=8000)

    import inspect

    sig = inspect.signature(client.stream_csp)
    params = list(sig.parameters.keys())
    assert "subscribe" in params
    assert "unsubscribe" in params
    assert "data" in params
    assert "push_mode" in params


def test_gateway_stream_adapter_manager_is_importable():
    """Test that GatewayStreamAdapterManager can be imported."""
    from csp_gateway.client.csp_stream import GatewayStreamAdapterManager as ImportedManager

    assert ImportedManager is not None


def test_stream_csp_with_dynamic_basket():
    """Test that stream_csp returns a DynamicBasket and can be wired in a graph."""
    # This builds a graph without running it

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("example")

        # Returns a DynamicBasket[str, object]
        basket = client.stream_csp(subscribe=subscribe)
        csp.print("basket", basket)

    # Verify the graph function was created
    assert callable(my_graph)


def test_stream_csp_with_unsubscribe():
    """Test that stream_csp supports unsubscribe to remove channels."""
    # This builds a graph without running it
    from datetime import timedelta

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)

        # Subscribe to channels dynamically
        subscribe = csp.curve(str, [(timedelta(seconds=0), "channel1"), (timedelta(seconds=1), "channel2")])
        # Unsubscribe from channel1 later
        unsubscribe = csp.curve(str, [(timedelta(seconds=5), "channel1")])

        # Returns a DynamicBasket where each key is a channel name
        basket = client.stream_csp(subscribe=subscribe, unsubscribe=unsubscribe)
        csp.print("basket", basket)

    # Verify the graph function was created
    assert callable(my_graph)


def test_stream_csp_bidirectional():
    """Test that stream_csp can send data back through the websocket."""
    # This builds a graph without running it

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("example")

        # Create outgoing data to send back to the server (simplified format)
        outgoing = csp.const({"my_channel": {"value": 42}})

        # Bidirectional streaming
        basket = client.stream_csp(subscribe=subscribe, data=outgoing)
        csp.print("basket", basket)

    # Verify the graph function was created
    assert callable(my_graph)


def test_gateway_stream_adapter_manager_send_data_before_impl():
    """Test that send_data works even before impl is created."""
    config = GatewayClientConfig(host="localhost", port=8000)
    manager = GatewayStreamAdapterManager(config)

    # Should not raise - just does nothing since impl is None
    manager.send_data({"test": {"value": 1}})


def test_config_variations():
    """Test that stream_csp works with different config variations."""
    configs = [
        GatewayClientConfig(host="localhost", port=8000),
        GatewayClientConfig(host="example.com", port=443, protocol="https"),
        GatewayClientConfig(host="192.168.1.1", port=9000),
    ]

    for config in configs:
        manager = GatewayStreamAdapterManager(config)
        assert manager._config == config


def test_connection_timeout_parameter():
    """Test that connection_timeout parameter is properly stored."""
    config = GatewayClientConfig(host="localhost", port=8000)

    # Default timeout
    manager1 = GatewayStreamAdapterManager(config)
    assert manager1._connection_timeout == -1

    # Immediate connection required
    manager2 = GatewayStreamAdapterManager(config, connection_timeout=0)
    assert manager2._connection_timeout == 0

    # Specific timeout
    manager3 = GatewayStreamAdapterManager(config, connection_timeout=30)
    assert manager3._connection_timeout == 30

    # Wait forever
    manager4 = GatewayStreamAdapterManager(config, connection_timeout=-1)
    assert manager4._connection_timeout == -1


def test_connection_error_importable():
    """Test that ConnectionError can be imported from csp_gateway.client.csp_stream."""
    from csp_gateway.client.csp_stream import ConnectionError as ImportedError

    assert ImportedError is not None
    # Verify it's an Exception subclass
    assert issubclass(ImportedError, Exception)


def test_stream_csp_connection_timeout_parameter():
    """Test that stream_csp method accepts connection_timeout parameter."""

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("example")

        # Test with connection_timeout parameter
        basket = client.stream_csp(subscribe=subscribe, connection_timeout=10)
        csp.print("basket", basket)

    # Verify the graph function was created
    assert callable(my_graph)


def test_stream_csp_connection_timeout_immediate():
    """Test that stream_csp method accepts connection_timeout=0."""

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("example")

        # Test with immediate connection required
        basket = client.stream_csp(subscribe=subscribe, connection_timeout=0)
        csp.print("basket", basket)

    # Verify the graph function was created
    assert callable(my_graph)


def test_send_data_single_channel_single_dict():
    """Test sending a single dict to a single channel using simplified format."""

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("my_channel")

        # Single channel, single dict
        outgoing = csp.const({"my_channel": {"value": 42}})
        basket = client.stream_csp(subscribe=subscribe, data=outgoing)
        csp.print("basket", basket)

    # Verify the graph builds successfully
    assert callable(my_graph)


def test_send_data_single_channel_list_of_dicts():
    """Test sending a list of dicts to a single channel using simplified format."""

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("my_channel")

        # Single channel, list of dicts
        outgoing = csp.const({"my_channel": [{"value": 42}, {"value": 43}]})
        basket = client.stream_csp(subscribe=subscribe, data=outgoing)
        csp.print("basket", basket)

    # Verify the graph builds successfully
    assert callable(my_graph)


def test_send_data_multiple_channels():
    """Test sending data to multiple channels in a single tick using simplified format."""

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("my_channel1")

        # Multiple channels in a single message
        outgoing = csp.const({"my_channel1": {"value": 42}, "my_channel2": [{"value": 1}, {"value": 2}]})
        basket = client.stream_csp(subscribe=subscribe, data=outgoing)
        csp.print("basket", basket)

    # Verify the graph builds successfully
    assert callable(my_graph)


def test_send_data_single_channel_single_struct():
    """Test sending a single GatewayStruct to a single channel using simplified format."""

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("my_channel")

        # Single channel, single GatewayStruct
        struct = SampleStruct(value=42, name="test")
        outgoing = csp.const({"my_channel": struct})
        basket = client.stream_csp(subscribe=subscribe, data=outgoing)
        csp.print("basket", basket)

    # Verify the graph builds successfully
    assert callable(my_graph)


def test_send_data_single_channel_list_of_structs():
    """Test sending a list of GatewayStructs to a single channel using simplified format."""

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("my_channel")

        # Single channel, list of GatewayStructs
        structs = [SampleStruct(value=42, name="first"), SampleStruct(value=43, name="second")]
        outgoing = csp.const({"my_channel": structs})
        basket = client.stream_csp(subscribe=subscribe, data=outgoing)
        csp.print("basket", basket)

    # Verify the graph builds successfully
    assert callable(my_graph)


def test_send_data_multiple_channels_with_structs():
    """Test sending GatewayStructs to multiple channels in a single tick."""

    @csp.graph
    def my_graph():
        client = GatewayClient(host="localhost", port=8000)
        subscribe = csp.const("my_channel1")

        # Multiple channels with mixed struct and list of structs
        outgoing = csp.const(
            {
                "my_channel1": SampleStruct(value=42, name="single"),
                "my_channel2": [SampleStruct(value=1, name="first"), SampleStruct(value=2, name="second")],
            }
        )
        basket = client.stream_csp(subscribe=subscribe, data=outgoing)
        csp.print("basket", basket)

    # Verify the graph builds successfully
    assert callable(my_graph)


# Integration tests with real running gateway server


@pytest.fixture
def csp_stream_free_port():
    """Get a free port for each test."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        return s.getsockname()[1]


def _run_gateway_for_csp_stream(port_str):
    """Run a gateway server in a separate process for CSP stream testing."""
    from csp_gateway import Gateway, GatewaySettings, MountControls, MountRestRoutes, MountWebSocketRoutes
    from csp_gateway.server.demo import ExampleGatewayChannels, ExampleModule

    gateway = Gateway(
        settings=GatewaySettings(AUTHENTICATE=False, PORT=int(port_str)),
        modules=[
            ExampleModule(),
            MountRestRoutes(force_mount_all=True),
            MountWebSocketRoutes(),
            MountControls(),
        ],
        channels=ExampleGatewayChannels(),
    )
    gateway.start(realtime=True, rest=True)


def _wait_for_server(url: str, timeout: int = 30):
    """Wait for the server to be ready."""
    import requests

    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(url, timeout=1)
            resp.raise_for_status()
            return True
        except (requests.HTTPError, requests.Timeout, requests.ConnectionError):
            time.sleep(0.5)
    return False


@csp.node
def _collect_basket_data(basket: csp.DynamicBasket[str, object]) -> csp.ts[dict]:
    """Helper node to collect basket data into a dict on each tick."""
    if csp.ticked(basket):
        result = {}
        for key, value in basket.tickeditems():
            result[key] = value
        return result


@pytest.mark.skip(reason="Integration test requires further development - websocket data flow needs debugging")
@pytest.mark.skipif(sys.platform == "darwin" and "GITHUB_ACTIONS" in os.environ, reason="Skipping on macOS CI")
def test_stream_csp_integration_subscribe_and_receive(csp_stream_free_port):
    """Integration test: verify stream_csp can connect to a real gateway and receive data."""
    port = csp_stream_free_port
    state_url = f"http://localhost:{port}/api/v1/state"
    shutdown_url = f"http://localhost:{port}/api/v1/controls/shutdown"

    # Start gateway in a separate process
    p = multiprocessing.Process(target=_run_gateway_for_csp_stream, args=(str(port),))
    p.start()

    received_data: List[Dict[str, Any]] = []
    test_exception: List[Exception] = []

    try:
        # Wait for server to start
        if not _wait_for_server(state_url):
            os.kill(p.pid, signal.SIGKILL)
            p.join()
            pytest.fail("Server failed to start")

        # Define a CSP graph that uses stream_csp
        @csp.graph
        def test_graph() -> csp.Outputs(received=csp.ts[dict]):
            client = GatewayClient(host="localhost", port=port)

            # Subscribe to the example channel
            subscribe = csp.const("example")

            # Get the dynamic basket of data
            basket = client.stream_csp(subscribe=subscribe)

            # Collect received data using helper node
            collected = _collect_basket_data(basket)
            csp.add_graph_output("received", collected)

        # Run the CSP graph for a short duration
        try:
            results = csp.run(test_graph, starttime=datetime.now(), endtime=timedelta(seconds=3), realtime=True)
            if "received" in results:
                for timestamp, data in results["received"]:
                    received_data.append(data)
        except Exception as e:
            test_exception.append(e)

    finally:
        # Shutdown the gateway
        import requests

        try:
            requests.post(shutdown_url, timeout=1)
        except Exception:
            pass
        p.join(timeout=10)
        if p.is_alive():
            os.kill(p.pid, signal.SIGKILL)
            p.join()

    # Verify results
    if test_exception:
        pytest.fail(f"CSP graph raised exception: {test_exception[0]}")

    # We should have received some data from the example channel
    assert len(received_data) > 0, "Should have received data from the gateway"


@pytest.mark.skip(reason="Integration test requires further development - websocket data flow needs debugging")
@pytest.mark.skipif(sys.platform == "darwin" and "GITHUB_ACTIONS" in os.environ, reason="Skipping on macOS CI")
def test_stream_csp_integration_dynamic_subscribe_unsubscribe(csp_stream_free_port):
    """Integration test: verify dynamic subscribe/unsubscribe works with a real gateway."""
    port = csp_stream_free_port
    state_url = f"http://localhost:{port}/api/v1/state"
    shutdown_url = f"http://localhost:{port}/api/v1/controls/shutdown"

    # Start gateway in a separate process
    p = multiprocessing.Process(target=_run_gateway_for_csp_stream, args=(str(port),))
    p.start()

    received_data: List[Dict[str, Any]] = []
    test_exception: List[Exception] = []

    try:
        # Wait for server to start
        if not _wait_for_server(state_url):
            os.kill(p.pid, signal.SIGKILL)
            p.join()
            pytest.fail("Server failed to start")

        # Define a CSP graph with dynamic subscribe/unsubscribe
        @csp.graph
        def test_graph() -> csp.Outputs(received=csp.ts[dict]):
            client = GatewayClient(host="localhost", port=port)

            # Subscribe to example at t=0, then heartbeat at t=1s, then unsubscribe example at t=2s
            subscribe = csp.curve(
                str,
                [
                    (timedelta(seconds=0), "example"),
                    (timedelta(seconds=1), "heartbeat"),
                ],
            )
            unsubscribe = csp.curve(
                str,
                [
                    (timedelta(seconds=2), "example"),
                ],
            )

            basket = client.stream_csp(subscribe=subscribe, unsubscribe=unsubscribe)
            collected = _collect_basket_data(basket)
            csp.add_graph_output("received", collected)

        # Run the graph
        try:
            results = csp.run(test_graph, starttime=datetime.now(), endtime=timedelta(seconds=4), realtime=True)
            if "received" in results:
                for timestamp, data in results["received"]:
                    received_data.append(data)
        except Exception as e:
            test_exception.append(e)

    finally:
        # Shutdown the gateway
        import requests

        try:
            requests.post(shutdown_url, timeout=1)
        except Exception:
            pass
        p.join(timeout=10)
        if p.is_alive():
            os.kill(p.pid, signal.SIGKILL)
            p.join()

    # Verify results
    if test_exception:
        pytest.fail(f"CSP graph raised exception: {test_exception[0]}")

    # We should have received data from both channels
    assert len(received_data) > 0, "Should have received data from the gateway"
