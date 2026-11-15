import csp
import pytest
from csp import ts
from fastapi import Request
from fastapi.testclient import TestClient
from pydantic import ValidationError

from csp_gateway import (
    Channels,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewaySettings,
    GatewayStruct,
    MountAPIKeyMiddleware,
    MountRestRoutes,
    MountSendForm,
)
from csp_gateway.server.web.routes import shared as response_module


def _request(path: str, root_path: str = "") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "root_path": root_path,
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )


class VersionedData(GatewayStruct):
    value: int = 0


class VersionedChannels(GatewayChannels):
    example: ts[VersionedData] = None
    other: ts[VersionedData] = None


class VersionedGateway(Gateway):
    channels_model: type[Channels] = VersionedChannels  # type: ignore[assignment]


class VersionedModule(GatewayModule):
    def connect(self, channels: VersionedChannels) -> None:
        for name in (VersionedChannels.example, VersionedChannels.other):
            channels.set_channel(name, csp.null_ts(VersionedData))
            channels.add_send_channel(name)

    def shutdown(self) -> None:
        pass


@pytest.fixture
def build(free_port):
    """Start a gateway with the given modules and settings, stopping it on teardown."""
    started = []

    def _build(*modules, **settings):
        gateway = VersionedGateway(
            modules=[VersionedModule(), *modules],
            channels=VersionedChannels(),
            settings=GatewaySettings(PORT=free_port, **settings),
        )
        gateway.start(rest=True, _in_test=True)
        started.append(gateway)
        return gateway

    yield _build

    for gateway in started:
        gateway.stop()


class TestSettingsApiPaths:
    def test_default_version(self):
        settings = GatewaySettings()
        assert settings.api() == "/api/v1"
        assert settings.API_STR == "/api/v1"

    def test_explicit_version(self):
        assert GatewaySettings().api("v2") == "/api/v2"

    def test_slashes_are_normalized(self):
        settings = GatewaySettings(API_PREFIX="/api/", API_VERSION_DEFAULT="/v3/")
        assert settings.api() == "/api/v3"

    def test_default_version_is_configurable(self):
        settings = GatewaySettings(API_VERSION_DEFAULT="v2")
        assert settings.API_STR == "/api/v2"
        assert settings.api("v1") == "/api/v1"

    def test_fields_are_normalized_not_just_the_built_path(self):
        settings = GatewaySettings(API_PREFIX="/api/", API_VERSION_DEFAULT="/v3/")
        assert (settings.API_PREFIX, settings.API_VERSION_DEFAULT) == ("api", "v3")

    def test_legacy_api_str_is_split(self):
        with pytest.warns(DeprecationWarning, match="API_STR is deprecated"):
            settings = GatewaySettings(API_STR="/api/v2")

        assert (settings.API_PREFIX, settings.API_VERSION_DEFAULT) == ("api", "v2")
        assert settings.API_STR == "/api/v2"


class TestRouterRegistry:
    def test_versions_get_separate_api_routers(self, build):
        app = build().web_app
        assert app.get_router("last") is not app.get_router("last", "v2")

    def test_app_and_public_routers_are_shared_across_versions(self, build):
        app = build().web_app
        assert app.get_router("app", "v2") is app.get_router("app")
        assert app.get_router("public", "v2") is app.get_router("public")

    def test_asking_for_a_version_registers_it(self, build):
        app = build().web_app
        assert app.api_versions == ["v1"]
        app.get_router("last", "v2")
        assert app.api_versions == ["v1", "v2"]

    def test_unknown_kind_reports_the_valid_ones(self, build):
        app = build().web_app
        with pytest.raises(KeyError, match="Unknown router kind"):
            app.get_router("nonsense")

    def test_api_path(self, build):
        app = build().web_app
        assert app.api_path("/last/example") == "/api/v1/last/example"
        assert app.api_path("/last/example", "v2") == "/api/v2/last/example"

    def test_a_version_is_one_bucket_however_it_is_spelled(self, build):
        app = build().web_app
        assert app.get_router("last", "/v2/") is app.get_router("last", "v2")
        assert app.api_versions == ["v1", "v2"]


class TestModuleApiVersion:
    @pytest.mark.parametrize("materialize", [True, False])
    def test_record_response_options_follow_mount_configuration(self, build, materialize, monkeypatch):
        class EnableState(GatewayModule):
            def connect(self, channels):
                channels.set_state("example", "id")

        gateway = build(EnableState(), MountRestRoutes(force_mount_all=True, batch_size=2, materialize=materialize))
        sizes = []
        original = response_module._dump_records

        def encode(records):
            sizes.append(len(records))
            return original(records)

        monkeypatch.setattr(response_module, "_dump_records", encode)
        client = TestClient(gateway.web_app.get_fastapi())
        sent = client.post("/api/v1/send/example", json=[{"value": index} for index in range(5)])
        assert sent.status_code == 200
        assert [record["value"] for record in sent.json()] == [0, 1, 2, 3, 4]
        assert sum(sizes) == 5
        assert max(sizes) <= 2
        identity = sent.json()[-1]["id"]
        responses = [
            sent,
            client.get("/api/v1/last/example"),
            client.get("/api/v1/state/example"),
            client.get(f"/api/v1/lookup/example/{identity}"),
            client.get(f"/api/v1/lookup/id/{identity}"),
        ]
        assert [record["value"] for record in responses[1].json()] == [4]
        assert sorted(record["value"] for record in responses[2].json()) == [0, 1, 2, 3, 4]
        for response in responses:
            assert response.status_code == 200
            if materialize:
                assert response.headers["content-length"] == str(len(response.content))
            else:
                assert "content-length" not in response.headers

    @pytest.mark.parametrize("batch_size", [0, -1])
    def test_mount_rejects_nonpositive_batch_size(self, batch_size):
        with pytest.raises(ValidationError, match="batch_size"):
            MountRestRoutes(batch_size=batch_size)

    def test_module_routes_move_to_its_version(self, build):
        gateway = build(MountRestRoutes(force_mount_all=True, api_version="v2"))
        client = TestClient(gateway.web_app.get_fastapi())

        assert client.get("/api/v2/last/example").status_code == 200
        assert client.get("/api/v1/last/example").status_code == 404

    def test_versions_can_be_served_side_by_side(self, build):
        gateway = build(
            MountRestRoutes(mount_last=["example"]),
            MountRestRoutes(mount_last=["example"], api_version="v2"),
        )
        client = TestClient(gateway.web_app.get_fastapi())

        assert client.get("/api/v1/last/example").status_code == 200
        assert client.get("/api/v2/last/example").status_code == 200

    def test_default_version_follows_settings(self, build):
        gateway = build(MountRestRoutes(force_mount_all=True), API_VERSION_DEFAULT="v2")
        client = TestClient(gateway.web_app.get_fastapi())

        assert client.get("/api/v2/last/example").status_code == 200
        assert client.get("/api/v1/last/example").status_code == 404

    def test_subclass_can_pin_its_version(self, build):
        class PinnedRestRoutes(MountRestRoutes):
            api_version: str = "v2"

        gateway = build(PinnedRestRoutes(force_mount_all=True))
        client = TestClient(gateway.web_app.get_fastapi())

        assert client.get("/api/v2/last/example").status_code == 200
        assert client.get("/api/v1/last/example").status_code == 404

    def test_non_default_versions_get_their_own_openapi_tag(self, build):
        gateway = build(
            MountRestRoutes(mount_last=["example"]),
            MountRestRoutes(mount_last=["example"], api_version="v2"),
        )
        schema = TestClient(gateway.web_app.get_fastapi()).get("/openapi.json").json()

        assert schema["paths"]["/api/v1/last/example"]["get"]["tags"] == ["Last"]
        assert schema["paths"]["/api/v2/last/example"]["get"]["tags"] == ["Last (v2)"]


class TestApiIndex:
    def test_lists_the_default_version(self, build):
        gateway = build(MountRestRoutes(force_mount_all=True))
        body = TestClient(gateway.web_app.get_fastapi()).get("/api").json()

        assert body == {"default": "v1", "versions": [{"version": "v1", "path": "/api/v1"}]}

    def test_lists_every_mounted_version(self, build):
        gateway = build(
            MountRestRoutes(mount_last=["example"]),
            MountRestRoutes(mount_last=["example"], api_version="v2"),
        )
        body = TestClient(gateway.web_app.get_fastapi()).get("/api").json()

        assert body["default"] == "v1"
        assert body["versions"] == [
            {"version": "v1", "path": "/api/v1"},
            {"version": "v2", "path": "/api/v2"},
        ]

    def test_follows_the_configured_prefix_and_default(self, build):
        gateway = build(MountRestRoutes(force_mount_all=True), API_PREFIX="rest", API_VERSION_DEFAULT="v2")
        body = TestClient(gateway.web_app.get_fastapi()).get("/rest").json()

        assert body == {"default": "v2", "versions": [{"version": "v2", "path": "/rest/v2"}]}

    def test_paths_carry_the_proxy_root_path(self, build):
        gateway = build(MountRestRoutes(force_mount_all=True), ROOT_PATH="/watchtower")
        client = TestClient(gateway.web_app.get_fastapi(), root_path="/watchtower")
        body = client.get("/api").json()

        assert body["versions"] == [{"version": "v1", "path": "/watchtower/api/v1"}]


class TestAuthStaysOnTheDefaultVersion:
    def test_login_is_not_moved_by_a_middleware_api_version(self, build):
        gateway = build(
            MountRestRoutes(force_mount_all=True, api_version="v2"),
            MountAPIKeyMiddleware(api_key="test", api_version="v2"),
        )
        client = TestClient(gateway.web_app.get_fastapi())

        assert client.get("/api/v1/auth/login", params={"token": "test"}, follow_redirects=False).status_code == 307
        assert client.get("/api/v2/auth/login", params={"token": "test"}, follow_redirects=False).status_code == 404


class TestApiVersionFor:
    def test_falls_back_to_the_default_when_nothing_is_mounted(self, build):
        app = build().web_app
        assert app.api_version_for("send") == "v1"

    def test_finds_the_version_the_routes_landed_on(self, build):
        app = build(MountRestRoutes(force_mount_all=True, api_version="v2")).web_app
        assert app.api_version_for("send") == "v2"

    def test_prefers_the_default_when_it_carries_routes(self, build):
        app = build(
            MountRestRoutes(mount_send=["example"]),
            MountRestRoutes(mount_send=["example"], api_version="v2"),
        ).web_app
        assert app.api_version_for("send") == "v1"

    def test_an_explicit_version_wins(self, build):
        app = build(MountRestRoutes(force_mount_all=True)).web_app
        assert app.api_version_for("send", "v3") == "v3"

    def test_resolves_per_route_when_channels_are_split(self, build):
        app = build(
            MountRestRoutes(mount_send=["example"]),
            MountRestRoutes(mount_send=["other"], api_version="v2"),
        ).web_app

        assert app.api_version_for("send", path="/example") == "v1"
        assert app.api_version_for("send", path="/other") == "v2"


class TestApiRequestDetection:
    def test_matches_whole_path_segments(self, build):
        app = build().web_app

        assert app.is_api_request(_request("/api"))
        assert app.is_api_request(_request("/api/v1/last/example"))
        assert not app.is_api_request(_request("/apiary"))
        assert not app.is_api_request(_request("/login"))

    def test_follows_the_configured_prefix(self, build):
        app = build(API_PREFIX="rest").web_app

        assert app.is_api_request(_request("/rest/v1/last/example"))
        assert not app.is_api_request(_request("/api/v1/last/example"))

    def test_strips_the_proxy_root_path(self, build):
        app = build(ROOT_PATH="/watchtower").web_app

        assert app.is_api_request(_request("/watchtower/api/v1/last/example", root_path="/watchtower"))
        assert not app.is_api_request(_request("/watchtower/login", root_path="/watchtower"))

    def test_unauthenticated_api_call_answers_json_under_a_custom_prefix(self, build):
        gateway = build(
            MountRestRoutes(force_mount_all=True),
            MountAPIKeyMiddleware(api_key="test"),
            API_PREFIX="rest",
        )
        response = TestClient(gateway.web_app.get_fastapi()).get("/rest/v1/last/example", follow_redirects=False)

        assert response.status_code == 403
        assert response.json()["status_code"] == 403


class TestUiFollowsRelocatedRoutes:
    """A UI-only module links to the version the module that owns the routes actually used."""

    @pytest.fixture
    def tree(self, free_port):
        pytest.importorskip("spaday")
        started = []

        def _tree(*modules):
            gateway = VersionedGateway(
                modules=[VersionedModule(), *modules],
                channels=VersionedChannels(),
                settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
            )
            gateway.start(rest=True, ui=True, _in_test=True)
            started.append(gateway)
            return TestClient(gateway.web_app.get_fastapi()).get("/tree.json").text

        yield _tree

        for gateway in started:
            gateway.stop()

    def test_send_form_posts_to_the_mounted_version(self, tree):
        body = tree(
            MountRestRoutes(force_mount_all=True, api_version="v2"),
            MountSendForm(),
        )

        assert "/api/v2/send/example" in body
        assert "/api/v1/send/example" not in body

    def test_an_explicit_version_on_the_ui_module_still_wins(self, tree):
        body = tree(
            MountRestRoutes(force_mount_all=True),
            MountSendForm(api_version="v2"),
        )

        assert "/api/v2/send/example" in body
