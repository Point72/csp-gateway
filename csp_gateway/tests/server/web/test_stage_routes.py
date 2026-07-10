from typing import Type

import csp
from csp import ts
from fastapi.testclient import TestClient

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
    channels_model: Type[Channels] = StageChannels  # type: ignore[assignment]


class StageModule(GatewayModule):
    def connect(self, channels: StageChannels) -> None:
        channels.set_channel(StageChannels.orders, csp.null_ts(StageOrder))
        channels.set_stage(StageChannels.orders)

    def shutdown(self) -> None:
        pass


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
        staging_id = list(add_result.keys())[0]
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
        staging_id = list(result.keys())[0]
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
