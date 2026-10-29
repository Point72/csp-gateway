"""Tests for the spaday UI's transports wire: namespacing and per-identity tenancy."""

import json
from typing import Any

import csp
import pytest
from csp import ts
from fastapi.testclient import TestClient
from pydantic import BaseModel
from starlette.websockets import WebSocketDisconnect

from csp_gateway import (
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewaySettings,
    GatewayStruct,
    MountRestRoutes,
)
from csp_gateway.server.middleware.api_key_external import MountExternalAPIKeyMiddleware
from csp_gateway.testing.mock_validators import mock_api_key_validator_by_user

pytest.importorskip("spaday")
pytest.importorskip("transports")


class Example(GatewayStruct):
    value: float = 0.0


class ExampleChannels(GatewayChannels):
    example: ts[Example] = None


class ExampleModule(GatewayModule):
    def connect(self, channels: ExampleChannels) -> None:
        channels.set_channel("example", csp.null_ts(Example))


class Rows(BaseModel):
    rows: list = []


class PublishingModule(GatewayModule):
    """Declares a live model and publishes a per-identity view of it."""

    # GatewayModule is a pydantic model, so the handle needs a declared field to live on.
    handle: Any = None

    def connect(self, channels: ExampleChannels) -> None: ...

    def ui(self, app) -> None:
        self.handle = app.model("staging", Rows)

    def publish_per_identity(self) -> None:
        # Each tenant only ever sees rows carrying its own user.
        self.handle.publish(lambda identity: {"rows": [{"user": (identity or {}).get("user", "anon")}]})


class Totals(BaseModel):
    total: int = 0


class SecondPublishingModule(GatewayModule):
    """A second module with its own namespace, published alongside `PublishingModule`."""

    handle: Any = None

    def connect(self, channels: ExampleChannels) -> None: ...

    def ui(self, app) -> None:
        self.handle = app.model("totals", Totals)


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("", 0))
        return sock.getsockname()[1]


class TestWireDeclaration:
    def test_no_model_declared_serves_no_websocket(self):
        gateway = Gateway(
            modules=[ExampleModule(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            client = TestClient(gateway.web_app.get_fastapi())
            with pytest.raises(WebSocketDisconnect) as excinfo, client.websocket_connect("/ws"):
                pass
            # 1000 is Starlette closing an unrouted websocket. Asserting the code keeps this from
            # passing on a 1008 rejection, which would mean the route exists but refuses every client.
            assert excinfo.value.code == 1000
        finally:
            gateway.stop()

    def test_declaring_a_model_serves_a_websocket(self):
        gateway = Gateway(
            modules=[ExampleModule(), PublishingModule(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            client = TestClient(gateway.web_app.get_fastapi())
            with client.websocket_connect("/ws") as ws:
                snapshot = json.loads(ws.receive_text())
            assert snapshot["t"] == "snapshot"
            assert snapshot["type"] == "staging_UIModel"
        finally:
            gateway.stop()

    def test_the_wire_carries_state_published_before_the_client_connected(self):
        publisher = PublishingModule()
        gateway = Gateway(
            modules=[ExampleModule(), publisher, MountRestRoutes(force_mount_all=True)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            publisher.publish_per_identity()
            client = TestClient(gateway.web_app.get_fastapi())
            with client.websocket_connect("/ws") as ws:
                snapshot = json.loads(ws.receive_text())
            assert snapshot["value"] == {"Map": {"rows": {"List": [{"Map": {"user": {"Str": "anon"}}}]}}}
        finally:
            gateway.stop()

    def test_namespaces_cannot_collide(self):
        gateway = Gateway(
            modules=[ExampleModule(), PublishingModule(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            with pytest.raises(ValueError, match="already declared"):
                gateway.web_app.ui.model("staging", Rows)
        finally:
            gateway.stop()

    def test_page_wires_the_declared_namespace(self):
        gateway = Gateway(
            modules=[ExampleModule(), PublishingModule(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            page = TestClient(gateway.web_app.get_fastapi()).get("/").text
            assert '"staging_UIModel"' in page
            assert 'namespace: "staging"' in page
        finally:
            gateway.stop()


class TestSeveralModels:
    """Every namespace rides one websocket, each selected by its own wire."""

    @pytest.fixture(scope="class")
    def gateway(self):
        gateway = Gateway(
            modules=[ExampleModule(), PublishingModule(), SecondPublishingModule(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield gateway
        finally:
            gateway.stop()

    def test_wires_share_one_connection(self, gateway):
        page = TestClient(gateway.web_app.get_fastapi()).get("/").text
        assert page.count(".connect(") == 1
        assert "const client1 = client0;" in page

    def test_each_namespace_is_its_own_model(self, gateway):
        totals = next(m for m in gateway.modules if isinstance(m, SecondPublishingModule))
        totals.handle.publish({"total": 7})
        snapshots = _snapshots(TestClient(gateway.web_app.get_fastapi()), "s1", count=2)
        assert set(snapshots) == {"staging_UIModel", "totals_UIModel"}
        assert "7" in json.dumps(snapshots["totals_UIModel"])

    def test_namespaces_must_be_identifiers(self, gateway):
        for bad in ("a.b", "a/b", "a b", "1a", ""):
            with pytest.raises(ValueError, match="identifier"):
                gateway.web_app.ui.model(bad, Rows)

    def test_models_cannot_be_declared_after_mount(self, gateway):
        with pytest.raises(RuntimeError, match="mounted"):
            gateway.web_app.ui.model("late", Rows)


def _snapshots(client, session, *, count, headers=None):
    """The first ``count`` model snapshots a page session receives, keyed by model type name."""
    out = {}
    with client.websocket_connect(f"/ws?session={session}", headers=headers or {}) as ws:
        while len(out) < count:
            frame = json.loads(ws.receive_text())
            if frame.get("t") == "snapshot":
                out[frame["type"]] = frame["value"]
    return out


class Ticket(BaseModel):
    side: str = "BUY"


class Drafts(BaseModel):
    label: str = ""


class EditableModule(GatewayModule):
    """A session-scoped ticket and a user-scoped drafts list, both editable from the browser."""

    ticket: Any = None
    drafts: Any = None

    def connect(self, channels: ExampleChannels) -> None: ...

    def ui(self, app) -> None:
        self.ticket = app.model("ticket", Ticket)
        self.drafts = app.model("drafts", Drafts, scope="user")


def _edit(ws, model_id, field, value):
    """Send the edit a two-way-bound control would: set ``field`` to a string ``value``."""
    patch = {"rev": 0, "ops": [{"Set": {"path": [{"Key": field}], "value": {"Str": value}}}]}
    ws.send_text(json.dumps({"t": "patch", "id": model_id, "patch": patch}))


def _ids(ws, count):
    """Model id by type name, from a connection's opening snapshots."""
    ids = {}
    while len(ids) < count:
        frame = json.loads(ws.receive_text())
        if frame.get("t") == "snapshot":
            ids[frame["type"]] = frame["id"]
    return ids


def _drain_until(ws, needle, *, limit=20):
    for _ in range(limit):
        frame = ws.receive_text()
        if needle in frame:
            return True
    return False


class TestIsolation:
    """One visitor's interaction with the UI never reaches another visitor."""

    @pytest.fixture(scope="class")
    def gateway(self):
        gateway = Gateway(
            modules=[
                ExampleModule(),
                EditableModule(),
                MountRestRoutes(force_mount_all=True),
                MountExternalAPIKeyMiddleware(external_validator=mock_api_key_validator_by_user),
            ],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield gateway
        finally:
            gateway.stop()

    def _hosted(self, gateway, tenant):
        return gateway.web_app.ui._tenant_models[tenant]

    def test_page_wires_ask_for_a_session(self, gateway):
        page = TestClient(gateway.web_app.get_fastapi()).get("/?token=alice_key").text
        assert "session=" in page

    def test_sessions_of_different_users_are_separate(self, gateway):
        ui = gateway.web_app.ui
        ui._host_tenant(("alice", "a1"), {"user": "alice"})
        ui._host_tenant(("bob", "b1"), {"user": "bob"})
        self._hosted(gateway, ("alice", "a1"))["ticket"][0].side = "SELL"
        assert self._hosted(gateway, ("bob", "b1"))["ticket"][0].side == "BUY"

    def test_two_tabs_of_one_user_keep_their_own_ticket(self, gateway):
        ui = gateway.web_app.ui
        ui._host_tenant(("alice", "a2"), {"user": "alice"})
        ui._host_tenant(("alice", "a3"), {"user": "alice"})
        assert self._hosted(gateway, ("alice", "a2"))["ticket"] is not self._hosted(gateway, ("alice", "a3"))["ticket"]

    def test_user_scope_is_shared_by_one_users_tabs_only(self, gateway):
        ui = gateway.web_app.ui
        for tenant, user in ((("alice", "a4"), "alice"), (("alice", "a5"), "alice"), (("bob", "b2"), "bob")):
            ui._host_tenant(tenant, {"user": user})
        alice_a, alice_b, bob = (self._hosted(gateway, t)["drafts"][1] for t in (("alice", "a4"), ("alice", "a5"), ("bob", "b2")))
        assert alice_a == alice_b
        assert alice_a != bob

    def test_edits_reach_only_the_editors_own_tabs(self, gateway):
        client = TestClient(gateway.web_app.get_fastapi())
        with (
            client.websocket_connect("/ws?session=t1&token=alice_key") as alice_tab1,
            client.websocket_connect("/ws?session=t2&token=alice_key") as alice_tab2,
            client.websocket_connect("/ws?session=t3&token=bob_key") as bob_tab,
        ):
            ids1 = _ids(alice_tab1, 2)
            _ids(alice_tab2, 2), _ids(bob_tab, 2)
            _edit(alice_tab1, ids1["drafts_UIModel"], "label", "wave-1")
            _edit(alice_tab1, ids1["ticket_UIModel"], "side", "SELL")

            assert _drain_until(alice_tab1, "SELL")
            # Alice's other tab shares her drafts but not her half-typed ticket; Bob gets neither.
            assert _drain_until(alice_tab2, "wave-1")
            ui = gateway.web_app.ui
            alice, bob = ui._user_key({"user": "alice", "role": "admin"}), ui._user_key({"user": "bob", "role": "viewer"})
            assert self._hosted(gateway, (alice, "t2"))["ticket"][0].side == "BUY"
            assert self._hosted(gateway, (bob, "t3"))["ticket"][0].side == "BUY"
            assert ui._hub.snapshot_shared(ui._user_models[(bob, "drafts")])["value"] == {"Map": {"label": {"Str": ""}}}

    def test_unauthenticated_visitors_share_nothing(self):
        gateway = Gateway(
            modules=[ExampleModule(), EditableModule(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            client = TestClient(gateway.web_app.get_fastapi())
            with client.websocket_connect("/ws?session=v1") as one, client.websocket_connect("/ws?session=v2") as two:
                ids1, _ = _ids(one, 2), _ids(two, 2)
                _edit(one, ids1["ticket_UIModel"], "side", "SELL")
                _edit(one, ids1["drafts_UIModel"], "label", "wave-1")
                assert _drain_until(one, "wave-1")
                ui = gateway.web_app.ui
                # Without an identity even user-scoped state stays with the page.
                assert ui._user_models == {}
                assert ui._tenant_models[(None, "v2")]["ticket"][0].side == "BUY"
                assert ui._tenant_models[(None, "v2")]["drafts"][0].label == ""
        finally:
            gateway.stop()

    def test_a_live_session_id_cannot_be_joined(self):
        gateway = Gateway(
            modules=[ExampleModule(), EditableModule(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            client = TestClient(gateway.web_app.get_fastapi())
            with client.websocket_connect("/ws?session=same") as owner, client.websocket_connect("/ws?session=same") as intruder:
                ids = _ids(owner, 2)
                _ids(intruder, 2)
                _edit(owner, ids["ticket_UIModel"], "side", "SELL")
                assert _drain_until(owner, "SELL")
                tenants = gateway.web_app.ui._tenant_models
                assert len(tenants) == 2
                assert sorted(hosted["ticket"][0].side for hosted in tenants.values()) == ["BUY", "SELL"]
        finally:
            gateway.stop()

    def test_a_connection_without_a_session_still_gets_its_own(self):
        gateway = Gateway(
            modules=[ExampleModule(), EditableModule(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            client = TestClient(gateway.web_app.get_fastapi())
            with client.websocket_connect("/ws") as one, client.websocket_connect("/ws") as two:
                _ids(one, 2), _ids(two, 2)
                tenants = list(gateway.web_app.ui._tenant_models)
            assert len(tenants) == 2
        finally:
            gateway.stop()


class TestPerIdentityPublishing:
    """`publish` derives each tenant's view from its identity, so filtered data stays filtered."""

    @pytest.fixture(scope="class")
    def gateway(self):
        gateway = Gateway(
            modules=[
                ExampleModule(),
                PublishingModule(),
                MountRestRoutes(force_mount_all=True),
                MountExternalAPIKeyMiddleware(external_validator=mock_api_key_validator_by_user),
            ],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=_free_port(), UI_PROVIDER="spaday"),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield gateway
        finally:
            gateway.stop()

    def test_distinct_identities_see_their_own_rows(self, gateway):
        ui = gateway.web_app.ui
        ui._host_tenant(("alice", "p1"), {"user": "alice"})
        ui._host_tenant(("bob", "p2"), {"user": "bob"})
        module = next(m for m in gateway.modules if isinstance(m, PublishingModule))
        module.publish_per_identity()
        assert ui._tenant_models[("alice", "p1")]["staging"][0].rows == [{"user": "alice"}]
        assert ui._tenant_models[("bob", "p2")]["staging"][0].rows == [{"user": "bob"}]

    def test_a_new_session_is_seeded_with_current_state(self, gateway):
        ui = gateway.web_app.ui
        module = next(m for m in gateway.modules if isinstance(m, PublishingModule))
        module.publish_per_identity()
        ui._host_tenant(("carol", "p3"), {"user": "carol"})
        assert ui._tenant_models[("carol", "p3")]["staging"][0].rows == [{"user": "carol"}]

    def test_publishing_before_the_loop_is_up_is_not_lost(self, gateway):
        ui = gateway.web_app.ui
        module = next(m for m in gateway.modules if isinstance(m, PublishingModule))
        ui._loop = None  # as during startup, before any connection
        module.handle.publish({"rows": [{"user": "seeded"}]})
        ui._host_tenant(("dave", "p4"), {"user": "dave"})
        assert ui._tenant_models[("dave", "p4")]["staging"][0].rows == [{"user": "seeded"}]
