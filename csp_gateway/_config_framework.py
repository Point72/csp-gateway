"""Select the gateway's configuration backend using ccflow's selection rules.

Hydra is preferred when available, otherwise Lerna is used. Set
``CCFLOW_CONFIG_BACKEND=lerna`` to require Lerna. Selection occurs on first API access.
"""

import importlib
import os
from functools import cache
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import hydra
    from hydra.core.hydra_config import HydraConfig

    CONFIG_FRAMEWORK: str

__all__ = (
    "CONFIG_FRAMEWORK",
    "HydraConfig",
    "hydra",
)

_ENV_VAR = "CCFLOW_CONFIG_BACKEND"


@cache
def _get_framework() -> ModuleType:
    requested = os.environ.get(_ENV_VAR, "").strip().lower()
    frameworks = ("lerna",) if requested == "lerna" else ("hydra", "lerna")
    for name in frameworks:
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError as error:
            if error.name != name:
                raise
    if requested == "lerna":
        raise ImportError(f"{_ENV_VAR}=lerna requires the 'lerna' package")
    raise ImportError("Configuration requires 'hydra-core' or 'lerna'; install one to use csp-gateway")


def __getattr__(name: str):
    if name == "CONFIG_FRAMEWORK":
        return _get_framework().__name__
    if name == "hydra":
        return _get_framework()
    if name == "HydraConfig":
        module = importlib.import_module(f"{_get_framework().__name__}.core.hydra_config")
        return module.HydraConfig
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
