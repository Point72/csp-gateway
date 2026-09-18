import logging
from pprint import pprint

from ccflow import ModelRegistry

from csp_gateway import __version__
from csp_gateway._config_framework import hydra

log = logging.getLogger(__name__)


@hydra.main(config_path="config", config_name="base", version_base=None)
def main(cfg):
    log.info("Loading csp-gateway config...")
    registry = ModelRegistry.root()
    registry.load_config(cfg=cfg, overwrite=True)
    gateway = registry["gateway"]

    log.info(f"Starting csp_gateway version {__version__}")
    kwargs = cfg["start"]
    if kwargs:  # i.e. start=False override on command line
        log.info(f"Starting gateway with arguments: {kwargs}")
        gateway.start(**kwargs)
    else:
        pprint(gateway.model_dump(by_alias=True))


if __name__ == "__main__":
    main()
