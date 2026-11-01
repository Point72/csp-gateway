"""Tests for the spaday staging panel (`MountStagingPanel`).

The panel is a reactive template: its structure ships in `/tree.json`, while the staged records ride the
UI's transports wire. So the tree tests assert the *template*, and the data tests assert the *snapshot*.
"""

import json

import csp
import pytest
from csp import ts
from fastapi.testclient import TestClient

from csp_gateway import (
    ChannelSelection,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewaySettings,
    GatewayStruct,
    MountRestRoutes,
    MountSendForm,
    MountStagingPanel,
)

pytest.importorskip("spaday")
pytest.importorskip("transports")


class Order(GatewayStruct):
    symbol: str = ""
    quantity: int = 0


class StagedChannels(GatewayChannels):
    orders: ts[Order] = None
    other: ts[Order] = None


class StagingModule(GatewayModule):
    def connect(self, channels: StagedChannels) -> None:
        channels.set_channel("orders", csp.null_ts(Order))
        channels.set_channel("other", csp.null_ts(Order))
        channels.set_stage("orders")
        channels.set_stage("other")
        channels.add_send_channel("orders")


def _stage(client: TestClient, **fields) -> str:
    """Stage one record and return its staging id."""
    response = client.post("/api/v1/stage/orders", json=fields)
    assert response.status_code == 200, response.text
    return next(iter(response.json()))


def _clear(client: TestClient) -> None:
    client.request("DELETE", "/api/v1/stage/orders?id=")
    client.request("DELETE", "/api/v1/stage/other?id=")


def _panel_of(gateway) -> MountStagingPanel:
    return next(m for m in gateway.modules if isinstance(m, MountStagingPanel))


def _areas(gateway) -> list:
    return _panel_of(gateway)._snapshot().areas


class TestStagingSnapshot:
    """What the panel publishes over the wire."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        return Gateway(
            modules=[StagingModule(), MountRestRoutes(force_mount_all=True), MountStagingPanel()],
            channels=StagedChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
        )

    @pytest.fixture(scope="class")
    def client(self, gateway):
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    @pytest.fixture(autouse=True)
    def _clean(self, client):
        _clear(client)
        yield
        _clear(client)

    def test_nothing_staged_is_empty(self, gateway, client: TestClient):
        snapshot = _panel_of(gateway)._snapshot()
        assert snapshot.empty is True
        assert snapshot.areas == []

    def test_a_staging_becomes_an_area(self, gateway, client: TestClient):
        staging_id = _stage(client, symbol="AAPL", quantity=10)
        client.post(f"/api/v1/stage/orders?id={staging_id}", json={"symbol": "MSFT", "quantity": 20})

        snapshot = _panel_of(gateway)._snapshot()
        assert snapshot.empty is False
        (area,) = snapshot.areas
        assert area.channel == "orders"
        assert area.summary == "2 staged"
        assert area.url == f"/api/v1/stage/orders?id={staging_id}"
        assert [cell.value for record in area.records for cell in record.cells] == ["AAPL", "10", "MSFT", "20"]

    def test_each_struct_field_becomes_a_column(self, gateway, client: TestClient):
        _stage(client, symbol="AAPL", quantity=10)
        (area,) = _areas(gateway)
        assert [column.id for column in area.columns] == ["symbol", "quantity"]

    def test_excluded_columns_are_omitted(self, gateway, client: TestClient):
        panel = _panel_of(gateway)
        _stage(client, symbol="AAPL", quantity=10)
        (area,) = _areas(gateway)
        assert set(panel.excluded_columns).isdisjoint(column.id for column in area.columns)

    def test_records_carry_their_own_id(self, gateway, client: TestClient):
        staging_id = _stage(client, symbol="AAPL", quantity=10)
        record_id = client.put(f"/api/v1/stage/orders?id={staging_id}").json()[staging_id][0]["id"]
        (area,) = _areas(gateway)
        assert [record.id for record in area.records] == [record_id]

    def test_removing_a_record_drops_it(self, gateway, client: TestClient):
        staging_id = _stage(client, symbol="AAPL", quantity=10)
        client.post(f"/api/v1/stage/orders?id={staging_id}", json={"symbol": "MSFT", "quantity": 20})
        record_id = client.put(f"/api/v1/stage/orders?id={staging_id}").json()[staging_id][0]["id"]

        client.request("DELETE", f"/api/v1/stage/orders?id={staging_id}", json={"id": record_id})

        (area,) = _areas(gateway)
        values = [cell.value for record in area.records for cell in record.cells]
        assert "AAPL" not in values
        assert "MSFT" in values  # the sibling record is untouched

    def test_released_staging_disappears(self, gateway, client: TestClient):
        staging_id = _stage(client, symbol="AAPL", quantity=10)
        client.patch(f"/api/v1/stage/orders?id={staging_id}")
        assert _panel_of(gateway)._snapshot().empty is True

    def test_multiple_stagings_are_separate_areas(self, gateway, client: TestClient):
        first = _stage(client, symbol="AAPL", quantity=10)
        second = next(iter(client.post("/api/v1/stage/orders").json()))
        assert {area.id for area in _areas(gateway)} == {f"orders:{first}", f"orders:{second}"}

    def test_max_records_bounds_the_payload(self, gateway, client: TestClient):
        panel = _panel_of(gateway)
        staging_id = _stage(client, symbol="A0", quantity=0)
        for i in range(1, 5):
            client.post(f"/api/v1/stage/orders?id={staging_id}", json={"symbol": f"A{i}", "quantity": i})

        original = panel.max_records
        panel.max_records = 2
        try:
            (area,) = _areas(gateway)
            assert area.summary == "5 staged"
            assert len(area.records) == 2
            assert area.overflow == "+3 more"
        finally:
            panel.max_records = original


class TestStagingTemplate:
    """What ships in the tree: a repeater template, not the records themselves."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        return Gateway(
            modules=[StagingModule(), MountRestRoutes(force_mount_all=True), MountStagingPanel()],
            channels=StagedChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
        )

    @pytest.fixture(scope="class")
    def client(self, gateway):
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_the_tree_repeats_over_the_wire_namespace(self, client: TestClient):
        tree = client.get("/tree.json").text
        assert '"tag": "spa-each"' in tree
        assert '"staging.areas"' in tree
        # Scopes let a row's delete reach its own staging's url and its own record id.
        assert '"scopeName": {"Str": "area"}' in tree
        assert '"scopeName": {"Str": "record"}' in tree

    def test_the_tree_carries_no_staged_records(self, client: TestClient):
        _stage(client, symbol="AAPL", quantity=10)
        try:
            # The template is static; records arrive over the wire, so the tree must not embed them.
            assert '"textContent": {"Str": "AAPL"}' not in client.get("/tree.json").text
        finally:
            _clear(client)

    def test_row_delete_and_release_are_scoped(self, client: TestClient):
        blob = client.get("/tree.json").text
        assert '"method": "DELETE"' in blob
        assert '"method": "PATCH"' in blob
        # A row's delete resolves its own staging's url and its own record id from the enclosing scopes.
        assert '"url": {"expr": "scope", "name": "area", "path": "url"}' in blob
        assert '"id": {"expr": "scope", "name": "record", "path": "id"}' in blob
        # Release targets the area currently being repeated.
        assert '"method": "PATCH", "url": {"expr": "item", "path": "url"}' in blob


class TestStagingLiveUpdates:
    """The point of the wire: staging changes reach a connected client without a page load."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        return Gateway(
            modules=[StagingModule(), MountRestRoutes(force_mount_all=True), MountStagingPanel()],
            channels=StagedChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
        )

    @pytest.fixture(scope="class")
    def client(self, gateway):
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_a_connected_client_is_told_about_a_new_staging(self, client: TestClient):
        _clear(client)
        try:
            with client.websocket_connect("/ws") as ws:
                snapshot = json.loads(ws.receive_text())
                assert snapshot["t"] == "snapshot"

                _stage(client, symbol="AAPL", quantity=10)

                # The update carries the new record without the page being rebuilt.
                for _ in range(20):
                    frame = json.loads(ws.receive_text())
                    if "AAPL" in json.dumps(frame):
                        break
                else:
                    raise AssertionError("no frame carried the staged record")
        finally:
            _clear(client)


class TestStagingPanelSelection:
    """The panel only reports channels selected by `mount_staging`."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        return Gateway(
            modules=[
                StagingModule(),
                MountRestRoutes(force_mount_all=True),
                MountStagingPanel(mount_staging=ChannelSelection(include=["other"])),
            ],
            channels=StagedChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
        )

    @pytest.fixture(scope="class")
    def client(self, gateway):
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_unselected_channel_is_not_reported(self, gateway, client: TestClient):
        _stage(client, symbol="AAPL", quantity=10)
        try:
            assert _panel_of(gateway)._snapshot().empty is True
        finally:
            _clear(client)


class TestStagingPanelSharesTheBottomDrawer:
    """With the send form alongside it, the bottom drawer presents both panels as tabs."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        return Gateway(
            modules=[StagingModule(), MountRestRoutes(force_mount_all=True), MountSendForm(), MountStagingPanel()],
            channels=StagedChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
        )

    @pytest.fixture(scope="class")
    def client(self, gateway):
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_both_panels_become_tabs(self, client: TestClient):
        tree = client.get("/tree.json").text
        assert '"tag": "wa-tab-group"' in tree
        assert '"textContent": {"Str": "Send data to channel"}' in tree
        assert '"textContent": {"Str": "Staged data"}' in tree


class TestStagingPanelWithoutUI:
    """With the UI switched off the module contributes none of it, and the gateway still starts."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        return Gateway(
            modules=[StagingModule(), MountRestRoutes(force_mount_all=True), MountStagingPanel()],
            channels=StagedChannels(),
            settings=GatewaySettings(PORT=free_port, UI=False),
        )

    def test_gateway_starts_without_a_ui(self, gateway):
        gateway.start(rest=True, _in_test=True)
        try:
            assert gateway.web_app.ui is None
        finally:
            gateway.stop()
