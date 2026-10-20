import pytest
from fastapi.testclient import TestClient

from csp_gateway import (
    Gateway,
    GatewaySettings,
    MountControls,
    MountRestRoutes,
)
from csp_gateway.server.demo import ExampleGatewayChannels, ExampleModule
from csp_gateway.server.web.app import GatewayWebApp


def _make_client(tmp_path, **settings_kwargs) -> TestClient:
    # These assertions are against the legacy provider's markup, so pin it unless a test asks
    # for another one.
    settings_kwargs.setdefault("UI_PROVIDER", "default")
    settings = GatewaySettings(PORT=0, UI=True, **settings_kwargs)
    gateway = Gateway(
        modules=[ExampleModule(), MountControls(), MountRestRoutes(force_mount_all=True)],
        channels=ExampleGatewayChannels(),
        settings=settings,
    )
    gateway.start(rest=True, _in_test=True)
    return TestClient(gateway.web_app.get_fastapi()), gateway


class TestUiCustomization:
    def test_default_index_has_title(self, tmp_path):
        client, gateway = _make_client(tmp_path, TITLE="MyApp")
        try:
            html = client.get("/").text
            assert "<title>MyApp</title>" in html
            assert "__CSP_GATEWAY_UI_CONFIG__" in html
        finally:
            gateway.stop()

    def test_ui_config_endpoint(self, tmp_path):
        client, gateway = _make_client(
            tmp_path,
            TITLE="MyApp",
            HEADER_LOGO="https://example.com/logo.png",
            FOOTER_LOGO="data:image/svg+xml,<svg/>",
            CUSTOM_JS=["https://cdn.example.com/extra.js"],
            CUSTOM_CSS=["https://cdn.example.com/extra.css"],
        )
        try:
            config = client.get("/ui-config").json()
            assert config["title"] == "MyApp"
            assert config["headerLogo"] == "https://example.com/logo.png"
            assert config["footerLogo"] == "data:image/svg+xml,<svg/>"
            assert config["customJs"] == ["https://cdn.example.com/extra.js"]
            assert config["customCss"] == ["https://cdn.example.com/extra.css"]

            html = client.get("/").text
            assert 'href="https://cdn.example.com/extra.css"' in html
            assert 'src="https://cdn.example.com/extra.js"' in html
        finally:
            gateway.stop()

    def test_local_logo_is_served(self, tmp_path):
        logo = tmp_path / "logo.svg"
        logo.write_text("<svg></svg>")
        client, gateway = _make_client(tmp_path, HEADER_LOGO=str(logo))
        try:
            config = client.get("/ui-config").json()
            assert config["headerLogo"].startswith("/custom-assets/")
            assert client.get(config["headerLogo"]).status_code == 200
        finally:
            gateway.stop()

    def test_custom_static_dir_is_discovered(self, tmp_path):
        (tmp_path / "a.js").write_text("// js")
        (tmp_path / "b.css").write_text("/* css */")
        client, gateway = _make_client(tmp_path, CUSTOM_STATIC_DIR=str(tmp_path))
        try:
            config = client.get("/ui-config").json()
            assert "/custom/a.js" in config["customJs"]
            assert "/custom/b.css" in config["customCss"]
            assert client.get("/custom/a.js").status_code == 200
            assert client.get("/custom/b.css").status_code == 200
        finally:
            gateway.stop()

    def test_url_path_logo_passthrough(self, tmp_path):
        # A logo given as an already-served URL path (e.g. from CUSTOM_STATIC_DIR)
        # is passed through unchanged rather than treated as a local file.
        (tmp_path / "logo.svg").write_text("<svg></svg>")
        client, gateway = _make_client(
            tmp_path,
            HEADER_LOGO="/custom/logo.svg",
            CUSTOM_STATIC_DIR=str(tmp_path),
        )
        try:
            config = client.get("/ui-config").json()
            assert config["headerLogo"] == "/custom/logo.svg"
            assert client.get("/custom/logo.svg").status_code == 200
        finally:
            gateway.stop()

    def test_root_path_prefixes_urls(self, tmp_path):
        # When served behind a reverse proxy under a sub-path, all server-rendered
        # asset URLs are prefixed with ROOT_PATH so the browser requests them via
        # the proxied path. Already-absolute URLs (http/data) are left untouched.
        (tmp_path / "logo.svg").write_text("<svg></svg>")
        (tmp_path / "extra.css").write_text("/* css */")
        client, gateway = _make_client(
            tmp_path,
            ROOT_PATH="/watchtower",
            HEADER_LOGO=str(tmp_path / "logo.svg"),
            FOOTER_LOGO="https://example.com/logo.png",
            CUSTOM_STATIC_DIR=str(tmp_path),
        )
        try:
            config = client.get("/ui-config").json()
            assert config["basePath"] == "/watchtower"
            assert config["headerLogo"].startswith("/watchtower/custom-assets/")
            assert config["footerLogo"] == "https://example.com/logo.png"
            assert "/watchtower/custom/extra.css" in config["customCss"]

            html = client.get("/").text
            assert '<base href="/watchtower/" />' in html
            assert 'src="/watchtower/static/main.js"' in html
            assert 'href="/watchtower/static/index.css"' in html
        finally:
            gateway.stop()

    def test_default_root_path_is_unprefixed(self, tmp_path):
        # With no ROOT_PATH, URLs stay root-relative and basePath is empty.
        client, gateway = _make_client(tmp_path, TITLE="MyApp")
        try:
            config = client.get("/ui-config").json()
            assert config["basePath"] == ""
            html = client.get("/").text
            assert '<base href="/" />' in html
            assert 'src="/static/main.js"' in html
        finally:
            gateway.stop()


class TestRootPathNormalization:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("", ""),
            (None, ""),
            ("/", ""),
            ("/watchtower", "/watchtower"),
            ("/watchtower/", "/watchtower"),
            ("watchtower", "/watchtower"),
            ("  /watchtower/  ", "/watchtower"),
        ],
    )
    def test_normalize_root_path(self, raw, expected):
        assert GatewayWebApp._normalize_root_path(raw) == expected

    def test_normalized_root_path_prefixes_urls(self, tmp_path):
        # A non-leading-slash, trailing-slash value is normalized before use.
        (tmp_path / "logo.svg").write_text("<svg></svg>")
        settings = GatewaySettings(PORT=0, UI=True, UI_PROVIDER="default", ROOT_PATH="watchtower/", HEADER_LOGO=str(tmp_path / "logo.svg"))
        gateway = Gateway(
            modules=[ExampleModule(), MountControls(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleGatewayChannels(),
            settings=settings,
        )
        gateway.start(rest=True, _in_test=True)
        client = TestClient(gateway.web_app.get_fastapi())
        try:
            config = client.get("/ui-config").json()
            assert config["basePath"] == "/watchtower"
            assert config["headerLogo"].startswith("/watchtower/custom-assets/")
            assert '<base href="/watchtower/" />' in client.get("/").text
        finally:
            gateway.stop()


class TestSpadayUiCustomization:
    """The spaday provider must honour the same white-labeling settings as the default UI."""

    def test_custom_css_and_js_are_emitted(self, tmp_path):
        pytest.importorskip("spaday")
        client, gateway = _make_client(
            tmp_path,
            UI_PROVIDER="spaday",
            CUSTOM_CSS=["https://cdn.example.com/extra.css"],
            CUSTOM_JS=["https://cdn.example.com/extra.js"],
        )
        try:
            html = client.get("/").text
            assert 'href="https://cdn.example.com/extra.css"' in html
            assert '"/spaday-custom-scripts.js"' in html
            loader = client.get("/spaday-custom-scripts.js")
            assert loader.status_code == 200
            assert '"https://cdn.example.com/extra.js"' in loader.text
        finally:
            gateway.stop()

    def test_custom_static_dir_is_emitted(self, tmp_path):
        pytest.importorskip("spaday")
        (tmp_path / "a.js").write_text("// js")
        (tmp_path / "b.css").write_text("/* css */")
        client, gateway = _make_client(tmp_path, UI_PROVIDER="spaday", CUSTOM_STATIC_DIR=str(tmp_path))
        try:
            html = client.get("/").text
            assert 'href="/custom/b.css"' in html
            assert '"/custom/a.js"' in client.get("/spaday-custom-scripts.js").text
            assert client.get("/custom/a.js").status_code == 200
        finally:
            gateway.stop()

    def test_custom_assets_are_root_path_prefixed(self, tmp_path):
        pytest.importorskip("spaday")
        (tmp_path / "a.js").write_text("// js")
        (tmp_path / "b.css").write_text("/* css */")
        client, gateway = _make_client(tmp_path, UI_PROVIDER="spaday", ROOT_PATH="watchtower/", CUSTOM_STATIC_DIR=str(tmp_path))
        try:
            html = client.get("/").text
            assert 'href="/watchtower/custom/b.css"' in html
            assert '"/watchtower/spaday-custom-scripts.js"' in html
            assert '"/watchtower/custom/a.js"' in client.get("/spaday-custom-scripts.js").text
        finally:
            gateway.stop()
