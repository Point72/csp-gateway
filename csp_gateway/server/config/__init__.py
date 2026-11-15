import logging
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ccflow import ModelRegistry, RootModelRegistry
from ccflow.utils.hydra import load_config as load_config_base
from omegaconf import OmegaConf

if TYPE_CHECKING:
    from csp_gateway import Gateway

log = logging.getLogger(__name__)

__all__ = (
    "load_config",
    "load_gateway",
)


def load_config(
    config_dir: str = "",
    config_name: str = "",
    overrides: list[str] | None = None,
    *,
    overwrite: bool = True,
    basepath: str = "",
) -> RootModelRegistry:
    log.info("Loading csp-gateway config...")
    result = load_config_base(
        root_config_dir=str(Path(__file__).resolve().parent),
        root_config_name="base",
        config_dir=config_dir,
        config_name=config_name,
        overrides=overrides,
        basepath=basepath,
    )
    OmegaConf.resolve(result.cfg)
    config_yaml = OmegaConf.to_yaml(result.cfg)
    registry = ModelRegistry.root()
    registry.load_config(result.cfg, overwrite=overwrite)
    if "gateway" in result.cfg:
        registry["gateway"]._hydra_config = config_yaml
    return registry


@wraps(load_config)
def load_gateway(*args, **kwargs) -> "Gateway":
    log.info("Loading csp-gateway config...")
    return load_config(*args, **kwargs)["gateway"]
