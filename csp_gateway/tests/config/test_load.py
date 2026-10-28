import os

import csp_gateway.server.config
from csp_gateway import Gateway
from csp_gateway._config_framework import hydra


def test_config_file_load():
    """This case tests a config where the gateway is specified in the user config file"""
    user_config_dir = os.path.dirname(__file__)
    r = csp_gateway.server.config.load_config(
        overwrite=True,
        config_dir=user_config_dir,
        overrides=["+user_config=sample_config"],
    )
    try:
        assert isinstance(r["gateway"], Gateway)
    finally:
        r.clear()


def test_config_file_load_gateway():
    user_config_dir = os.path.dirname(__file__)
    g = csp_gateway.server.config.load_gateway(
        overwrite=True,
        config_dir=user_config_dir,
        overrides=["+user_config=sample_config"],
    )
    assert isinstance(g, Gateway)


def test_start_load():
    config_dir = os.path.join(os.path.dirname(__file__), "../../server/config")
    with hydra.initialize_config_dir(version_base=None, config_dir=config_dir):
        cfg = hydra.compose(config_name="base.yaml")
    assert dict(cfg["start"]) == {
        "realtime": True,
        "block": False,
        "show": False,
        "rest": True,
        "ui": True,
    }


def test_legacy_demo_config_loads():
    """The shipped legacy-UI demo config composes into a Gateway (guards omnibus_legacy)."""
    demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../server/demo"))
    g = csp_gateway.server.config.load_gateway(overwrite=True, config_dir=demo_dir, overrides=["+config=omnibus_legacy"])
    assert isinstance(g, Gateway)


def test_demo_config_loads_with_the_process_monitor():
    """The shipped spaday demo config composes, and carries the Process tab beside the controls."""
    from csp_gateway import MountControls, MountProcessMonitor

    demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../server/demo"))
    g = csp_gateway.server.config.load_gateway(overwrite=True, config_dir=demo_dir, overrides=["+config=omnibus"])
    assert isinstance(g, Gateway)
    mounted = {type(module) for module in g.modules}
    # The monitor renders what the controls module reports, so it is only useful alongside it.
    assert MountProcessMonitor in mounted
    assert MountControls in mounted
