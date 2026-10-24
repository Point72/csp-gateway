import pytest
from fastapi.testclient import TestClient
from omegaconf import OmegaConf

from csp_gateway import Gateway, GatewaySettings, MountAPIKeyMiddleware, MountConfig, load_gateway
from csp_gateway.server.web import GatewayWebApp

pytest.importorskip("spaday")


def config_client(gateway):
    web = GatewayWebApp(gateway, None, gateway.settings, ui=True)
    for module in gateway.modules:
        module.rest(web)
        module.ui(web.ui)
    web._finalize()
    return TestClient(web.app)


def _nodes(node):
    yield node
    for children in node.get("slots", {}).values():
        for child in children:
            yield from _nodes(child)


class TestConfigViewer:
    def test_displays_loaded_config_in_closeable_tab(self):
        gateway = load_gateway(overrides=["+gateway=demo", "+port=1234", "+gateway.settings.ROOT_PATH=/gateway"])
        # Only mount the config viewer; the demo's other UI modules require a running CSP engine.
        gateway.modules = [module for module in gateway.modules if isinstance(module, MountConfig)]
        client = config_client(gateway)
        tree = client.get("/tree.json").json()
        nodes = list(_nodes(tree))
        frame = next(node for node in nodes if node.get("props", {}).get("name") == {"Str": "config"})
        assert frame["tag"] == "regular-layout-frame"
        assert "data-no-close" not in frame["props"]
        viewer = next(node for node in nodes if node.get("props", {}).get("id") == {"Str": "gateway-config"})
        assert viewer["tag"] == "div"
        assert any(node["tag"] == "wa-tree" for node in _nodes(viewer))
        assert any(node.get("props", {}).get("textContent") == {"Str": "1234"} for node in _nodes(viewer))
        assert any(node.get("props", {}).get("data-tab") == {"Str": "config"} for node in nodes)

    def test_config_tree_preserves_nested_values_and_types(self):
        gateway = Gateway(modules=[MountConfig()], settings=GatewaySettings(UI_PROVIDER="spaday"))
        gateway._hydra_config = """mapping:
  nested.key:
    - enabled: true
      count: 42
      fraction: 1.5
      missing: null
      text: 'true'
      markup: '<script>alert(1)</script>'
empty_object: {}
empty_array: []
"""
        nodes = list(_nodes(config_client(gateway).get("/tree.json").json()))
        items = [node for node in nodes if node["tag"] == "wa-tree-item"]
        labels = [node["props"]["textContent"]["Str"] for node in nodes if "textContent" in node.get("props", {})]
        assert items[0]["props"]["expanded"] == {"Bool": True}
        assert all(item["props"]["expanded"] == {"Bool": False} for item in items[1:])
        assert {"mapping: ", "nested.key: ", "[0]: ", "true", "42", "1.5", "null", '"true"', "{}", "[]"} <= set(labels)
        assert '"<script>alert(1)</script>"' in labels
        assert not any(node["tag"] in ("script", "input", "textarea", "spaday-tree") for node in nodes)

    def test_python_gateway_without_hydra_shows_unavailable(self):
        gateway = Gateway(modules=[MountConfig()], settings=GatewaySettings(UI_PROVIDER="spaday"))
        tree = config_client(gateway).get("/tree.json").text
        assert "Hydra configuration is unavailable" in tree

    def test_credentials_are_redacted_from_authenticated_tree(self):
        gateway = Gateway(
            modules=[MountConfig(), MountAPIKeyMiddleware(api_key="test-key")],
            settings=GatewaySettings(UI_PROVIDER="spaday"),
        )
        config = {
            "modules": {"auth": {"api_key": "server-api-key"}},
            "users": [{"password": "server-password"}],
            "clientSecret": "server-client-secret",
            "BEARER_TOKEN": "server-bearer-token",
            "credentials": {"access": "server-credentials"},
            "title": "Visible title",
        }
        gateway._hydra_config = OmegaConf.to_yaml(OmegaConf.create(config))
        response = config_client(gateway).get("/tree.json?token=test-key")
        assert response.status_code == 200
        labels = [node["props"]["textContent"]["Str"] for node in _nodes(response.json()) if "textContent" in node.get("props", {})]
        assert labels.count('"[redacted]"') == 5
        assert '"Visible title"' in labels
        assert "server-" not in response.text
        assert "server-password" in gateway._hydra_config

    def test_config_uses_existing_auth(self):
        gateway = Gateway(
            modules=[MountConfig(), MountAPIKeyMiddleware(api_key="test-key")],
            settings=GatewaySettings(UI_PROVIDER="spaday"),
        )
        gateway._hydra_config = "instance: private-config-value\n"
        client = config_client(gateway)
        assert "private-config-value" not in client.get("/tree.json").text
        assert "private-config-value" not in client.get("/").text
        response = client.get("/tree.json?token=test-key")
        assert response.status_code == 200
        assert "private-config-value" in response.text
