import argparse
import logging
from pprint import pprint

from ccflow import ModelRegistry

from csp_gateway import __version__
from csp_gateway._config_framework import hydra

log = logging.getLogger(__name__)


@hydra.main(config_path="config", config_name="base", version_base=None)
def _main(cfg):
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


def main():
    # Python 3.14's argparse validates help strings as arguments are added, and hydra registers
    # `--shell-completion` with a lazily rendered non-string help, so every released hydra
    # (<= 1.3.7) crashes before parsing. Skip the check for the call, as hydra's own unreleased
    # workaround does; the attribute only exists on 3.14+.
    check_help = getattr(argparse.ArgumentParser, "_check_help", None)
    if check_help is None:
        return _main()
    argparse.ArgumentParser._check_help = lambda self, action: None
    try:
        return _main()
    finally:
        argparse.ArgumentParser._check_help = check_help


if __name__ == "__main__":
    main()
