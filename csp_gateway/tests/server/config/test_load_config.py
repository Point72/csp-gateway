import pytest
from ccflow import ModelRegistry
from omegaconf import OmegaConf

from csp_gateway import Gateway, load_config, load_gateway


class TestLoadConfig:
    def test_load_config(self):
        gw = load_config(overrides=["+gateway=demo", "+port=1234"], overwrite=True)["/gateway"]
        assert isinstance(gw, Gateway)
        assert gw.settings.PORT == 1234

    def test_resolved_config_belongs_to_loaded_instance(self, monkeypatch):
        monkeypatch.setenv("GATEWAY_CONFIG_TITLE", "First instance")
        first = load_gateway(overrides=["+gateway=demo", "+port=1234", "+gateway.settings.TITLE=${oc.env:GATEWAY_CONFIG_TITLE}"])
        monkeypatch.setenv("GATEWAY_CONFIG_TITLE", "Second instance")
        second = load_gateway(overrides=["+gateway=demo", "+port=5678", "+gateway.settings.TITLE=${oc.env:GATEWAY_CONFIG_TITLE}"])
        first_config = OmegaConf.create(first._hydra_config)
        second_config = OmegaConf.create(second._hydra_config)
        assert first_config.gateway.settings.PORT == first.settings.PORT == 1234
        assert first_config.gateway.settings.TITLE == first.settings.TITLE == "First instance"
        assert second_config.gateway.settings.PORT == second.settings.PORT == 5678
        assert second_config.gateway.settings.TITLE == second.settings.TITLE == "Second instance"
        assert "${" not in first._hydra_config
        assert "/modules/mount_config" in first_config.gateway.modules

    def test_cli_captures_config_before_start(self, monkeypatch):
        from csp_gateway.server.cli import _main

        cfg = OmegaConf.create(
            {
                "port": 1234,
                "gateway": {"_target_": "csp_gateway.Gateway", "settings": {"PORT": "${port}"}},
                "start": {"rest": True},
            }
        )
        snapshots = []

        def start(gateway, **kwargs):
            snapshots.append(gateway._hydra_config)
            assert kwargs == {"rest": True}

        monkeypatch.setattr(Gateway, "start", start)
        _main.__wrapped__(cfg)
        cfg.port = 5678
        assert OmegaConf.create(snapshots[0]).gateway.settings.PORT == 1234

    @pytest.mark.parametrize("loader", ["python", "cli"])
    def test_config_is_resolved_once(self, loader):
        calls = []

        def next_port():
            calls.append(8000 + len(calls))
            return calls[-1]

        OmegaConf.register_new_resolver("gateway_test_port", next_port)
        try:
            if loader == "python":
                gateway = load_gateway(overrides=["+gateway=demo", "+port=${gateway_test_port:}"])
            else:
                from csp_gateway.server.cli import _main

                cfg = OmegaConf.create(
                    {
                        "gateway": {"_target_": "csp_gateway.Gateway", "settings": {"PORT": "${gateway_test_port:}"}},
                        "start": False,
                    }
                )
                _main.__wrapped__(cfg)
                gateway = ModelRegistry.root()["gateway"]
            assert calls == [8000]
            assert OmegaConf.create(gateway._hydra_config).gateway.settings.PORT == gateway.settings.PORT == 8000
        finally:
            OmegaConf.clear_resolver("gateway_test_port")

    def test_loading_modules_only_preserves_existing_gateway_snapshot(self):
        gateway = load_gateway(overrides=["+gateway=demo", "+port=1234"])
        snapshot = gateway._hydra_config
        registry = load_config()
        assert registry["gateway"] is gateway
        assert gateway._hydra_config == snapshot
