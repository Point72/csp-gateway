import csp.impl.error_handling
from datetime import timedelta
from pathlib import Path

from csp_gateway import (
    Gateway,
    GatewaySettings,
    MountAPIKeyMiddleware,
    MountChannelsGraph,
    MountControls,
    MountOutputsFolder,
    MountPerspectiveTables,
    MountRestRoutes,
    MountWebSocketRoutes,
)
from csp_gateway.server.config import load_gateway

from . import ExampleGatewayChannels, ExampleModule

csp.impl.error_handling.set_print_full_exception_stack(True)


# csp-gateway is configured as a hydra application, but it can also
# be instantiated directly as we do so here:

# Setting authentication
settings = GatewaySettings(API_KEY="12345", AUTHENTICATE=False)

# instantiate gateway
gateway = Gateway(
    settings=settings,
    modules=[
        ExampleModule(),
        # ExampleModuleFeedback(),
        # ExampleCustomTable(),
        MountChannelsGraph(),
        MountControls(),
        MountOutputsFolder(),
        MountPerspectiveTables(
            perspective_field="perspective",
            layouts={
                "Server Defined Layout": '{"sizes":[1],"detail":{"main":{"type":"split-area","orientation":"horizontal","children":[{"type":"split-area","orientation":"vertical","children":[{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_1"],"currentIndex":0},{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_4"],"currentIndex":0}],"sizes":[0.5,0.5]},{"type":"split-area","orientation":"vertical","children":[{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_3"],"currentIndex":0},{"type":"tab-area","widgets":["PERSPECTIVE_GENERATED_ID_5"],"currentIndex":0}],"sizes":[0.5,0.5]}],"sizes":[0.5,0.5]}},"mode":"globalFilters","viewers":{"PERSPECTIVE_GENERATED_ID_1":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"timestamp":"last","x":"last","id":"last","y":"last"},"master":false,"name":"basket","table":"basket","linked":false},"PERSPECTIVE_GENERATED_ID_4":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"timestamp":"last","x":"last","id":"last","y":"last"},"master":false,"name":"example_list","table":"example_list","linked":false},"PERSPECTIVE_GENERATED_ID_3":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"id":"last","x":"last","timestamp":"last","y":"last"},"master":false,"name":"example","table":"example","linked":false},"PERSPECTIVE_GENERATED_ID_5":{"plugin":"Datagrid","plugin_config":{"columns":{},"editable":false,"scroll_lock":true},"settings":false,"theme":"Pro Dark","group_by":["id"],"split_by":[],"columns":["timestamp","x","y"],"filter":[],"sort":[["timestamp","desc"]],"expressions":[],"aggregates":{"id":"last","timestamp":"last","x":"last","y":"last"},"master":false,"name":"never_ticks","table":"never_ticks","linked":false}}}'  # noqa: E501
            },
            update_interval=timedelta(seconds=1),
        ),
        MountRestRoutes(force_mount_all=True),
        MountWebSocketRoutes(),
        # For authentication
        MountAPIKeyMiddleware(),
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
    gateway.start(rest=True, ui=True)

    # You can also run this directly via cli
    # > pip install csp-gateway
    # > csp-gateway-start --config-dir=csp_gateway/server/demo +config=demo
