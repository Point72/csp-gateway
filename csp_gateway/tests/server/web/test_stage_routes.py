from queue import Queue

import csp
import pytest
from csp import ts
from fastapi.testclient import TestClient
from pydantic import BaseModel, PrivateAttr

from csp_gateway import (
    Channels,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewaySettings,
    GatewayStruct,
    MountRestRoutes,
)


class StageOrder(GatewayStruct):
    symbol: str = ""
    quantity: int = 0
    price: float = 0.0


class StageChannels(GatewayChannels):
    orders: ts[StageOrder] = None


class StageGateway(Gateway):
    channels_model: type[Channels] = StageChannels  # type: ignore[assignment]


class StageModule(GatewayModule):
    def connect(self, channels: StageChannels) -> None:
        channels.set_channel(StageChannels.orders, csp.null_ts(StageOrder))
        channels.set_stage(StageChannels.orders)

    def shutdown(self) -> None:
        pass


class PlainOrder(BaseModel):
    id: object | None = None
    symbol: str = ""


class UnkeyedOrder(BaseModel):
    symbol: str = ""


class PlainStageChannels(GatewayChannels):
    orders: ts[PlainOrder] = None
    unkeyed: ts[UnkeyedOrder] = None
    gateway_orders: ts[StageOrder] = None


@csp.node
def _collect_orders(orders: ts[PlainOrder], received: Queue) -> None:
    if csp.ticked(orders):
        received.put(orders)


class PlainStageModule(GatewayModule):
    _received: Queue = PrivateAttr(default_factory=Queue)

    def connect(self, channels: PlainStageChannels) -> None:
        channels.set_channel(PlainStageChannels.orders, csp.null_ts(PlainOrder))
        channels.set_stage(PlainStageChannels.orders)
        channels.add_send_channel(PlainStageChannels.orders)
        _collect_orders(channels.get_channel(PlainStageChannels.orders), self._received)
        channels.set_channel(PlainStageChannels.unkeyed, csp.null_ts(UnkeyedOrder))
        channels.set_stage(PlainStageChannels.unkeyed)
        channels.add_send_channel(PlainStageChannels.unkeyed)
        channels.set_channel(PlainStageChannels.gateway_orders, csp.null_ts(StageOrder))
        channels.set_stage(PlainStageChannels.gateway_orders)

    def shutdown(self) -> None:
        pass


@pytest.fixture
def received_orders():
    return Queue()


@pytest.fixture
def plain_stage_client(free_port, received_orders):
    module = PlainStageModule()
    module._received = received_orders
    gateway = StageGateway(
        channels_model=PlainStageChannels,
        modules=[module, MountRestRoutes(force_mount_all=True)],
        channels=PlainStageChannels(),
        settings=GatewaySettings(PORT=free_port),
    )
    gateway.start(rest=True, _in_test=True)
    try:
        yield TestClient(gateway.web_app.get_fastapi())
    finally:
        gateway.stop()


@pytest.mark.parametrize(
    "channel,payload",
    [
        ("unkeyed", {"symbol": "AAPL"}),
        ("orders", {"id": None, "symbol": "AAPL"}),
        ("orders", {"id": [], "symbol": "AAPL"}),
        ("gateway_orders", {"id": None, "symbol": "AAPL"}),
    ],
)
def test_invalid_identity_returns_400_without_storing_items(plain_stage_client, channel, payload):
    client = plain_stage_client
    route = f"/api/v1/stage/{channel}"
    for attempt in range(2):
        response = client.post(route, json=payload)
        assert response.status_code == 400
        assert client.get(route).json() == []
        assert client.put(route).json() == {}

    staging_id = next(iter(client.post(route).json()))
    response = client.post(f"{route}?id={staging_id}", json=payload)
    assert response.status_code == 400
    response = client.request("DELETE", f"{route}?id={staging_id}", json=payload)
    assert response.status_code == 400
    assert client.put(route).json() == {staging_id: []}


def test_plain_model_stage_routes_full_lifecycle(plain_stage_client, received_orders):
    client = plain_stage_client
    first = {"id": "order-1", "symbol": "AAPL"}
    second = {"id": "order-2", "symbol": "MSFT"}
    response = client.post("/api/v1/send/orders", json=first)
    assert response.status_code == 200
    assert response.json() == [first]
    assert received_orders.get(timeout=5).model_dump() == first

    response = client.post("/api/v1/stage/orders", json=first)
    assert response.status_code == 200
    staging_id = next(iter(response.json()))
    assert response.json() == {staging_id: [first]}

    response = client.post("/api/v1/stage/orders", json=second)
    assert response.status_code == 200
    assert client.put("/api/v1/stage/orders").json() == {staging_id: [first, second]}

    response = client.request("DELETE", "/api/v1/stage/orders", json=first)
    assert response.status_code == 200
    assert response.json() == {staging_id: [second]}

    response = client.patch("/api/v1/stage/orders")
    assert response.status_code == 200
    assert response.json() == {staging_id: [second]}
    assert received_orders.get(timeout=5).model_dump() == second
    assert client.get("/api/v1/stage/orders").json() == []


def test_plain_model_without_identity_can_still_be_sent(plain_stage_client):
    payload = {"symbol": "AAPL"}
    response = plain_stage_client.post("/api/v1/send/unkeyed", json=payload)
    assert response.status_code == 200
    assert response.json() == [payload]


def test_stage_routes_basic_flow(free_port):
    gateway = StageGateway(
        modules=[
            StageModule(),
            MountRestRoutes(force_mount_all=True),
        ],
        channels=StageChannels(),
        settings=GatewaySettings(PORT=free_port),
    )

    gateway.start(rest=True, _in_test=True)
    client = TestClient(gateway.web_app.get_fastapi())
    try:
        # List staged channels
        response = client.get("/api/v1/stage/")
        assert response.status_code == 200
        assert "orders" in response.json()

        # stage_add: create new staging with an item
        payload = {"symbol": "AAPL", "quantity": 10, "price": 190.5}
        response = client.post("/api/v1/stage/orders", json=payload)
        assert response.status_code == 200
        add_result = response.json()
        assert len(add_result) == 1
        staging_id = next(iter(add_result.keys()))
        assert add_result[staging_id][0]["symbol"] == "AAPL"

        # stage_list: ensure staging is present
        response = client.get("/api/v1/stage/orders")
        assert response.status_code == 200
        assert staging_id in response.json()

        # stage_lookup specific staging
        response = client.put(f"/api/v1/stage/orders?id={staging_id}")
        assert response.status_code == 200
        lookup_result = response.json()
        assert staging_id in lookup_result
        assert lookup_result[staging_id][0]["quantity"] == 10

        # stage_release specific staging
        response = client.patch(f"/api/v1/stage/orders?id={staging_id}")
        assert response.status_code == 200
        release_result = response.json()
        assert staging_id in release_result
        assert release_result[staging_id][0]["symbol"] == "AAPL"

        # stage_list after release should no longer include released ID
        response = client.get("/api/v1/stage/orders")
        assert response.status_code == 200
        assert staging_id not in response.json()
    finally:
        gateway.stop()


def test_stage_routes_full_lifecycle(free_port):
    """Test the full stage lifecycle: new, add, remove, lookup, list, release."""
    gateway = StageGateway(
        modules=[
            StageModule(),
            MountRestRoutes(force_mount_all=True),
        ],
        channels=StageChannels(),
        settings=GatewaySettings(PORT=free_port),
    )

    gateway.start(rest=True, _in_test=True)
    client = TestClient(gateway.web_app.get_fastapi())
    try:
        # stage_new: POST with no body creates empty staging
        response = client.post("/api/v1/stage/orders")
        assert response.status_code == 200
        result = response.json()
        assert len(result) == 1
        staging_id = next(iter(result.keys()))
        assert result[staging_id] == []

        # stage_add: POST with body adds to latest staging
        payload = {"symbol": "AAPL", "quantity": 10, "price": 190.5}
        response = client.post(f"/api/v1/stage/orders?id={staging_id}", json=payload)
        assert response.status_code == 200
        result = response.json()
        assert result[staging_id][0]["symbol"] == "AAPL"

        # stage_add: add second item
        payload2 = {"symbol": "MSFT", "quantity": 5, "price": 400.0}
        response = client.post(f"/api/v1/stage/orders?id={staging_id}", json=payload2)
        assert response.status_code == 200
        result = response.json()
        assert len(result[staging_id]) == 2

        # stage_list
        response = client.get("/api/v1/stage/orders")
        assert response.status_code == 200
        assert staging_id in response.json()

        # stage_lookup
        response = client.put(f"/api/v1/stage/orders?id={staging_id}")
        assert response.status_code == 200
        lookup = response.json()
        assert len(lookup[staging_id]) == 2

        # stage_remove: DELETE with body removes specific struct
        item_to_remove = lookup[staging_id][0]
        response = client.request("DELETE", f"/api/v1/stage/orders?id={staging_id}", json=item_to_remove)
        assert response.status_code == 200
        result = response.json()
        assert len(result[staging_id]) == 1
        assert result[staging_id][0]["symbol"] == "MSFT"

        # stage_release
        response = client.patch(f"/api/v1/stage/orders?id={staging_id}")
        assert response.status_code == 200
        release_result = response.json()
        assert staging_id in release_result
        assert release_result[staging_id][0]["symbol"] == "MSFT"

        # After release, staging gone
        response = client.get("/api/v1/stage/orders")
        assert response.status_code == 200
        assert staging_id not in response.json()
    finally:
        gateway.stop()
