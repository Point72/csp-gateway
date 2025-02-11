"""
A Demo CSP Gateway application
"""

from datetime import timedelta

import csp
from csp import ts

from csp_gateway import GatewayChannels, GatewayModule, GatewayStruct

# Let's walk through a worked example.

# First, we want to define the edges that will be available to our modules.
# In `csp-gateway` dialect, these deferred edges are called `channels`.
# Let's define a few `csp.Struct` to go with them.

# NOTE: See __main__.py for the entry point to run this example

__all__ = (
    "ExampleData",
    "ExampleGatewayChannels",
    "ExampleModule",
)


class ExampleData(GatewayStruct):
    x: int


# `MyGatewayChannels` is the collection of lazily-connected `csp` edges that will be provided to all modules in our graph.
# The modules in our graph are `pydantic`-wrapped `csp` modules, that use the `channel` APIs to connect to edges.
# Let's define a simple one.


class ExampleGatewayChannels(GatewayChannels):
    example: ts[ExampleData] = None


# A `GatewayModule` has two important features.
# First, it is a typed `pydantic` model, so you can define attributes in the usual `pydantic` way.
# Second, it has a `connect` method that will be provided the `GatewayChannels` instance when the graph is eventually wired together.
# You can use `get_channel` and `set_channel` to read-from and publish-to `csp` edges, respectively.


class ExampleModule(GatewayModule):
    interval: timedelta = timedelta(seconds=1)

    # An example module that ticks some data in a struct
    @csp.node
    def subscribe(self, trigger: ts[bool]) -> ts[ExampleData]:
        with csp.state():
            last_x = 0
        if csp.ticked(trigger):
            last_x += 1
            return ExampleData(x=last_x)

    def connect(self, channels: ExampleGatewayChannels):
        # Create some CSP data streams
        data = self.subscribe(csp.timer(interval=self.interval, value=True))

        # Channels set via `set_channel`
        channels.set_channel(ExampleGatewayChannels.example, data)
