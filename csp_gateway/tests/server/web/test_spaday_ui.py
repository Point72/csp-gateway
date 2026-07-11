"""Tests for the optional spaday UI provider (`Settings.UI_PROVIDER == "spaday"`)."""

from datetime import timedelta
from typing import Dict

import csp
import pytest
from csp import Enum, ts
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
)
from csp_gateway.server.middleware.api_key_external import MountExternalAPIKeyMiddleware
from csp_gateway.testing.mock_validators import mock_api_key_validator_by_user

pytest.importorskip("spaday")


class Example(GatewayStruct):
    value: float


class ExampleChannels(GatewayChannels):
    example: ts[Example] = None


class ExampleModule(GatewayModule):
    @csp.node
    def _produce(self, trigger: ts[bool]) -> ts[Example]:
        if csp.ticked(trigger):
            return Example(value=1.0)

    def connect(self, channels: ExampleChannels) -> None:
        channels.set_channel("example", self._produce(csp.timer(interval=timedelta(seconds=0.1), value=True)))


class TestSpadayAuth:
    """The spaday page and tree must sit behind the same auth as the default UI (review finding #1)."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        return Gateway(
            modules=[
                ExampleModule(),
                MountRestRoutes(force_mount_all=True),
                MountExternalAPIKeyMiddleware(external_validator=mock_api_key_validator_by_user),
            ],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
        )

    @pytest.fixture(scope="class")
    def client(self, gateway):
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_unauthenticated_does_not_serve_spaday(self, client: TestClient):
        # The auth middleware intercepts the page and tree (they carry the same dependencies as the
        # default UI), so an unauthenticated request never receives the spaday app or its tree.
        assert "spa-app" not in client.get("/").text
        assert not client.get("/tree.json").headers["content-type"].startswith("application/json")

    def test_authenticated_serves_spaday(self, client: TestClient):
        # With a valid key the page renders (200) and the tree is JSON — the provider-gated smoke test.
        page = client.get("/?token=alice_key")
        assert page.status_code == 200
        assert "spa-app" in page.text
        tree = client.get("/tree.json?token=alice_key")
        assert tree.status_code == 200
        assert tree.headers["content-type"].startswith("application/json")


class TwoSendChannels(GatewayChannels):
    alpha: ts[Example] = None
    beta: ts[Example] = None


class TwoSendModule(GatewayModule):
    @csp.node
    def _tick(self, trigger: ts[bool]) -> ts[Example]:
        if csp.ticked(trigger):
            return Example(value=1.0)

    def connect(self, channels: TwoSendChannels) -> None:
        trig = csp.timer(interval=timedelta(seconds=0.1), value=True)
        channels.set_channel("alpha", self._tick(trig))
        channels.set_channel("beta", self._tick(trig))
        channels.add_send_channel("alpha")
        channels.add_send_channel("beta")


class TestSpadaySendFormSelection:
    """The send panel only offers channels whose send route is mounted (review finding #4)."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        # `beta` has a send adapter but its send route is not mounted, so no form should be shown for it.
        return Gateway(
            modules=[
                TwoSendModule(),
                MountRestRoutes(mount_send=ChannelSelection(include=["alpha"])),
                MountSendForm(mount_send=ChannelSelection(include=["alpha"])),
            ],
            channels=TwoSendChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
        )

    @pytest.fixture(scope="class")
    def client(self, gateway):
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_only_mounted_send_channel_has_a_form(self, client: TestClient):
        tree = client.get("/tree.json").text
        assert "alpha" in tree
        assert "beta" not in tree


class SendableModule(GatewayModule):
    @csp.node
    def _tick(self, trigger: ts[bool]) -> ts[Example]:
        if csp.ticked(trigger):
            return Example(value=1.0)

    def connect(self, channels: ExampleChannels) -> None:
        channels.set_channel("example", self._tick(csp.timer(interval=timedelta(seconds=0.1), value=True)))
        channels.add_send_channel("example")


class TestSpadayRootPath:
    """Provider-generated URLs are prefixed with ROOT_PATH for reverse-proxy sub-path serving (finding #3)."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        return Gateway(
            modules=[SendableModule(), MountRestRoutes(force_mount_all=True), MountSendForm()],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday", ROOT_PATH="/watchtower"),
        )

    @pytest.fixture(scope="class")
    def client(self, gateway):
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_page_assets_prefixed(self, client: TestClient):
        # The page's own runtime/asset URLs (/js, wasm) carry the ROOT_PATH prefix.
        assert "/watchtower/js" in client.get("/").text

    def test_module_urls_prefixed(self, client: TestClient):
        # A module-generated action URL (the send POST) is prefixed in the component tree.
        assert "/watchtower/api/v1/send/example" in client.get("/tree.json").text


class Order(GatewayStruct):
    symbol: str
    secret: str


class BasketKey(Enum):
    A = Enum.auto()
    B = Enum.auto()


class DetailChannels(GatewayChannels):
    orders: ts[Order] = None
    basket: Dict[BasketKey, ts[Order]] = None


class DetailModule(GatewayModule):
    @csp.node
    def _order(self, trigger: ts[bool]) -> ts[Order]:
        if csp.ticked(trigger):
            return Order(symbol="AAPL", secret="hidden")

    def connect(self, channels: DetailChannels) -> None:
        trig = csp.timer(interval=timedelta(seconds=0.1), value=True)
        channels.set_channel("orders", self._order(trig))
        channels.add_send_channel("orders")
        channels.set_channel("basket", self._order(trig), BasketKey.A)
        channels.set_channel("basket", self._order(trig), BasketKey.B)
        channels.add_send_channel("basket", BasketKey.A)
        channels.add_send_channel("basket", BasketKey.B)


class TestSpadaySendFormDetails:
    """Send-form field overrides and dict-basket keyed URLs (finding #4 test gaps)."""

    @pytest.fixture(scope="class")
    def gateway(self, free_port):
        return Gateway(
            modules=[
                DetailModule(),
                MountRestRoutes(force_mount_all=True),
                MountSendForm(form_overrides={"symbol": {"label": "Ticker"}, "secret": {"exclude": True}}),
            ],
            channels=DetailChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
        )

    @pytest.fixture(scope="class")
    def client(self, gateway):
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_field_overrides(self, client: TestClient):
        tree = client.get("/tree.json").text
        assert "Ticker" in tree  # `symbol` relabelled via form_overrides
        assert "secret" not in tree  # `secret` excluded via form_overrides (id/timestamp are always filtered)

    def test_keyed_basket_url(self, client: TestClient):
        # A dict-basket send targets /send/{channel}/{key}: the base URL + the per-channel key field bind.
        tree = client.get("/tree.json").text
        assert "/api/v1/send/basket" in tree
        assert "send_key_basket" in tree
