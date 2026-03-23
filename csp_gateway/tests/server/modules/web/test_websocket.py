"""Tests for MountWebSocketRoutes module.

This module tests the WebSocket streaming functionality of csp-gateway,
including subscribe/unsubscribe, sending data, dict baskets, and heartbeat.

These tests use the demo ExampleModule and ExampleGatewayChannels from
csp_gateway.server.demo, which provide a working reference implementation.
"""

import socket
import time

import pytest
from fastapi.testclient import TestClient

from csp_gateway import (
    Gateway,
    GatewaySettings,
    MountControls,
    MountRestRoutes,
    MountWebSocketRoutes,
)
from csp_gateway.server.demo import ExampleGatewayChannels, ExampleModule


@pytest.fixture
def ws_free_port():
    """Get a free port for each test."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        return s.getsockname()[1]


def _wait_for_data(client: TestClient):
    """Wait for CSP data to start flowing."""
    tries = 0
    while tries < 50:
        time.sleep(0.1)
        response = client.get("/api/v1/last/example")
        if response.status_code == 200:
            data = response.json()
            if data:
                return data
        tries += 1
    raise AssertionError("No data returned from server")


@pytest.fixture
def gateway_client(ws_free_port):
    """Create a gateway with websocket support and return the test client."""
    gateway = Gateway(
        modules=[
            ExampleModule(),
            MountControls(),
            MountRestRoutes(force_mount_all=True),
            MountWebSocketRoutes(),
        ],
        channels=ExampleGatewayChannels(),
        settings=GatewaySettings(PORT=ws_free_port),
    )
    gateway.start(rest=True, _in_test=True)
    client = TestClient(gateway.web_app.get_fastapi())
    yield client
    gateway.stop()


class TestMountWebSocketRoutes:
    """Tests for MountWebSocketRoutes module."""

    def test_stream_endpoint_lists_channels(self, gateway_client: TestClient):
        """Test that the /stream endpoint lists available channels."""
        _wait_for_data(gateway_client)

        response = gateway_client.get("/api/v1/stream")
        assert response.status_code == 200

        channels = response.json()
        # Check that expected channels are present
        assert "example" in channels
        assert "heartbeat" in channels
        # Check basket channels are present with keys
        assert any("basket" in c for c in channels)

    def test_websocket_subscribe_and_receive(self, gateway_client: TestClient):
        """Test basic subscribe and receive functionality."""
        _wait_for_data(gateway_client)

        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            # Subscribe to example channel
            websocket.send_json({"action": "subscribe", "channel": "example"})

            # Receive data
            data = websocket.receive_json()
            assert "channel" in data
            assert data["channel"] == "example"
            assert "data" in data

            msg = data["data"][0]
            assert "id" in msg
            assert "timestamp" in msg
            assert "x" in msg
            assert "y" in msg

    def test_websocket_send_data(self, gateway_client: TestClient):
        """Test sending data via websocket."""
        _wait_for_data(gateway_client)

        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            # Subscribe to receive echoed data
            websocket.send_json({"action": "subscribe", "channel": "example"})

            # Drain initial data
            websocket.receive_json()

            # Send data with specific values
            websocket.send_json(
                {
                    "action": "send",
                    "channel": "example",
                    "data": {"x": 99999, "y": "test_send"},
                }
            )

            # Receive the sent data back
            data = websocket.receive_json()
            assert data["channel"] == "example"
            msg = data["data"][0]
            assert msg["x"] == 99999
            assert msg["y"] == "test_send"

    def test_websocket_send_data_as_list(self, gateway_client: TestClient):
        """Test sending data as a list via websocket."""
        _wait_for_data(gateway_client)

        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            websocket.send_json({"action": "subscribe", "channel": "example"})
            websocket.receive_json()  # Drain initial

            # Send data as list
            websocket.send_json(
                {
                    "action": "send",
                    "channel": "example",
                    "data": [{"x": 88888, "y": "list_send"}],
                }
            )

            data = websocket.receive_json()
            assert data["channel"] == "example"
            msg = data["data"][0]
            assert msg["x"] == 88888
            assert msg["y"] == "list_send"

    def test_websocket_heartbeat(self, gateway_client: TestClient):
        """Test heartbeat channel sends PING messages."""
        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            websocket.send_json({"action": "subscribe", "channel": "heartbeat"})

            # Wait for heartbeat
            data = websocket.receive_json()
            assert data["channel"] == "heartbeat"
            assert data["data"] == "PING"

    def test_websocket_enum_basket_subscribe_with_key(self, gateway_client: TestClient):
        """Test subscribing to a specific key in an enum dict basket."""
        _wait_for_data(gateway_client)

        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            # Subscribe to specific basket key using enum name
            websocket.send_json(
                {
                    "action": "subscribe",
                    "channel": "basket",
                    "key": "A",
                }
            )

            data = websocket.receive_json()
            assert data["channel"] == "basket"
            assert data["key"] == "A"
            assert "data" in data

    def test_websocket_str_basket_subscribe_with_key(self, gateway_client: TestClient):
        """Test subscribing to a specific key in a string dict basket."""
        _wait_for_data(gateway_client)

        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            websocket.send_json(
                {
                    "action": "subscribe",
                    "channel": "str_basket",
                    "key": "a",
                }
            )

            data = websocket.receive_json()
            assert data["channel"] == "str_basket"
            assert data["key"] == "a"

    def test_websocket_basket_send_with_key(self, gateway_client: TestClient):
        """Test sending data to a specific basket key."""
        _wait_for_data(gateway_client)

        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            # Subscribe to receive data
            websocket.send_json(
                {
                    "action": "subscribe",
                    "channel": "basket",
                    "key": "B",
                }
            )
            websocket.receive_json()  # Drain initial

            # Send to specific key
            websocket.send_json(
                {
                    "action": "send",
                    "channel": "basket",
                    "key": "B",
                    "data": {"x": 77777, "y": "basket_send"},
                }
            )

            data = websocket.receive_json()
            assert data["channel"] == "basket"
            assert data["key"] == "B"
            msg = data["data"][0]
            assert msg["x"] == 77777
            assert msg["y"] == "basket_send"

    def test_websocket_invalid_action_ignored(self, gateway_client: TestClient):
        """Test that invalid actions are ignored and connection remains usable."""
        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            # Send invalid action
            websocket.send_json({"action": "invalid_action", "channel": "example"})

            # Subscribe to heartbeat to verify connection still works
            websocket.send_json({"action": "subscribe", "channel": "heartbeat"})
            data = websocket.receive_json()
            assert data["channel"] == "heartbeat"

    def test_websocket_missing_channel_ignored(self, gateway_client: TestClient):
        """Test that messages without channel are ignored."""
        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            # Send without channel
            websocket.send_json({"action": "subscribe"})

            # Subscribe to heartbeat to verify connection still works
            websocket.send_json({"action": "subscribe", "channel": "heartbeat"})
            data = websocket.receive_json()
            assert data["channel"] == "heartbeat"

    def test_websocket_unsupported_channel_ignored(self, gateway_client: TestClient):
        """Test that subscribing to unsupported channels is ignored."""
        with gateway_client.websocket_connect("/api/v1/stream") as websocket:
            # Subscribe to non-existent channel
            websocket.send_json({"action": "subscribe", "channel": "nonexistent"})

            # Subscribe to heartbeat to verify connection still works
            websocket.send_json({"action": "subscribe", "channel": "heartbeat"})
            data = websocket.receive_json()
            assert data["channel"] == "heartbeat"


class TestMountWebSocketRoutesSelection:
    """Tests for MountWebSocketRoutes channel selection."""

    @pytest.fixture
    def selection_client(self, ws_free_port):
        """Create a gateway with channel selection."""
        gateway = Gateway(
            modules=[
                ExampleModule(),
                MountControls(),
                MountRestRoutes(force_mount_all=True),
                MountWebSocketRoutes(selection={"include": ["example"]}),
            ],
            channels=ExampleGatewayChannels(),
            settings=GatewaySettings(PORT=ws_free_port),
        )
        gateway.start(rest=True, _in_test=True)
        client = TestClient(gateway.web_app.get_fastapi())
        yield client
        gateway.stop()

    def test_selection_limits_channels(self, selection_client: TestClient):
        """Test that channel selection limits available websocket channels."""
        response = selection_client.get("/api/v1/stream")
        assert response.status_code == 200

        channels = response.json()
        # Should only include 'example' and 'heartbeat' (heartbeat is always included)
        assert "example" in channels
        assert "heartbeat" in channels
        # Should NOT include other channels
        assert "example_list" not in channels
        assert not any("basket" in c for c in channels if c != "heartbeat")
