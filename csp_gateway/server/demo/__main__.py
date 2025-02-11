from logging import INFO, basicConfig
from pathlib import Path

from csp_gateway import (
    Gateway,
    GatewaySettings,
    MountPerspectiveTables,
    MountRestRoutes,
)
from csp_gateway.server.config import load_gateway

from .simple import ExampleGatewayChannels, ExampleModule

# csp-gateway is configured as a hydra application,
# but it can also be instantiated directly as we do so here:

# instantiate gateway
gateway = Gateway(
    settings=GatewaySettings(),
    modules=[
        ExampleModule(),
        MountPerspectiveTables(),
        MountRestRoutes(force_mount_all=True),
    ],
    channels=ExampleGatewayChannels(),
)

if __name__ == "__main__":
    # To run, we could run our object directly:
    # gateway.start(rest=True, ui=True)

    # But instead, lets run the same code via hydra
    # We can use our own custom config, in config/demo.yaml
    # which inherits from csp-gateway's example config.
    #
    # With hydra, we can easily construct hierarchichal,
    # extensible configurations for all our modules!
    gateway = load_gateway(
        overrides=["+config=demo"],
        config_dir=Path(__file__).parent,
    )

    # Set our log level to info. If using hydra,
    # we have even more configuration options at our disposal
    basicConfig(level=INFO)

    # Start the gateway
    gateway.start(rest=True, ui=True)

    # You can also run this directly via cli
    # > pip install csp-gateway
    # > csp-gateway-start --config-dir=csp_gateway/server/demo +config=demo

    # For more a more complicated example, see `./omnibus.py`
