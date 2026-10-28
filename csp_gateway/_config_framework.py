"""The configuration framework the gateway is built on.

`lerna` is a drop-in for the parts of hydra used here, and is preferred because hydra 1.3 does not
run on Python 3.14. Everything that would import hydra imports from here instead, so the choice is
made once.

Set ``CSP_GATEWAY_CONFIG_FRAMEWORK`` to ``hydra`` or ``lerna`` to pin one; left unset, `lerna` is
used when it is installed. Note that this only covers the gateway's own use: `ccflow`, which
composes the config, imports hydra directly.
"""

import os

__all__ = (
    "CONFIG_FRAMEWORK",
    "HydraConfig",
    "hydra",
)

_ENV_VAR = "CSP_GATEWAY_CONFIG_FRAMEWORK"
_requested = os.environ.get(_ENV_VAR, "").strip().lower()

if _requested not in ("", "hydra", "lerna"):
    raise ValueError(f"{_ENV_VAR} must be 'hydra', 'lerna', or unset, got {_requested!r}")

if _requested == "hydra":
    import hydra
    from hydra.core.hydra_config import HydraConfig
else:
    try:
        import lerna as hydra
        from lerna.core.hydra_config import HydraConfig
    except ImportError:
        if _requested == "lerna":
            raise
        import hydra
        from hydra.core.hydra_config import HydraConfig

#: The name of the framework in use, for anything that needs to report it.
CONFIG_FRAMEWORK = hydra.__name__
