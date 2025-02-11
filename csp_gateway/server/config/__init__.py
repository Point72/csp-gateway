import hydra
import logging
import os
import os.path
from ccflow import ModelRegistry, RootModelRegistry
from pprint import pprint
from typing import List, Optional

import csp_gateway
from csp_gateway import Gateway

log = logging.getLogger(__name__)

__all__ = (
    "load_config",
    "load_gateway",
    "load",
    "run",
)


def load_config(
    overrides: Optional[List[str]] = None,
    overwrite: bool = False,
    config_dir: Optional[str] = None,
    version_base: Optional[str] = None,
) -> RootModelRegistry:
    """Load the ETL registry.

    :param overrides: List of hydra-style override strings.
        For example, to override the base_path and cds_sql, you could pass:

        overrides=["base_path='/isilon/data01/users/pt10597'", "cds_sql='RESEARCHSQL'"]
    :param overwrite: Whether to over-write existing entries in the registry
    :param config_dir: Equivalent behavior of the command line argument --config-dir, used to point to
        a directory containing user-defined configs.
    :param version_base: See https://hydra.cc/docs/upgrades/version_base/
    :return: The instance of the root model registry, with the configs loaded.
    """

    overrides = overrides or []
    with hydra.initialize_config_dir(version_base=version_base, config_dir=os.path.dirname(__file__)):
        if config_dir is not None:
            # Add config_dir to searchpath overrides (which is what hydra does under the hood)
            # This is a little complicated as we first need to load existing searchpaths
            cfg = hydra.compose(config_name="conf.yaml", return_hydra_config=True, overrides=overrides)
            searchpaths = cfg["hydra"]["searchpath"]
            searchpaths.append(config_dir)
            overrides = overrides.copy() + [f"hydra.searchpath=[{','.join(searchpaths)}]"]

        cfg = hydra.compose(config_name="conf.yaml", overrides=overrides)
    registry = ModelRegistry.root()
    registry.load_config(cfg, overwrite=overwrite)
    return registry


def load_gateway(
    overrides: Optional[List[str]] = None,
    overwrite: bool = False,
    config_dir: Optional[str] = None,
    version_base: Optional[str] = None,
) -> Gateway:
    return load_config(overrides=overrides, overwrite=overwrite, config_dir=config_dir, version_base=version_base)["gateway"]


def load(cfg):
    log.info("Loading csp-gateway config...")
    registry = ModelRegistry.root()
    registry.load_config(cfg=cfg, overwrite=True)
    return registry["gateway"]


def run(cfg):
    gateway = load(cfg)
    log.info(f"Starting csp_gateway version {csp_gateway.__version__}")
    kwargs = cfg["start"]
    if kwargs:  # i.e. start=False override on command line
        log.info(f"Starting gateway with arguments: {kwargs}")
        gateway.start(**kwargs)
    else:
        pprint(gateway.model_dump(by_alias=True))
