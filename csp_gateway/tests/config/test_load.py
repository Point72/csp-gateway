import os

import hydra

import csp_gateway.server.config
from csp_gateway import Gateway


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
