"""
A Demo CSP Gateway application

NOTE: The webserver tests use this code internally to validate rest endpoints,
and those tests in turn ensure that this demo works.
"""

import csp
import numpy as np
from csp import ts, Enum
from csp.typing import Numpy1DArray
from datetime import date, datetime, timedelta
from perspective import Server as PerspectiveServer, Table as PerspectiveTable
from pydantic import AfterValidator, Field, field_validator
from typing import Annotated, Dict, List

from csp_gateway import Controls, GatewayChannels, GatewayModule, GatewayStruct, State

SPEED = timedelta(seconds=1)
SCALE = 10

# Let's walk through a worked example. First, we want to define the edges that will be available to our modules.
# In `csp-gateway` dialect, these deferred edges are called `channels`.
# Let's define a few `csp` `Struct` and `Enum` to go with them.

# NOTE: See __main__.py for the entry point to run this example

__all__ = (
    "ExampleCspStruct",
    "ExampleData",
    "ExampleEnum",
    "ExampleGatewayChannels",
    "ExampleModule",
    "ExampleCustomTable",
)


class ExampleCspStruct(csp.Struct):
    z: int = 12


def nonnegative_check(v):
    if v < 0:
        raise ValueError("value must be non-negative.")
    return v


class ExampleData(GatewayStruct):
    x: Annotated[int, AfterValidator(nonnegative_check)]
    y: str = ""
    internal_csp_struct: ExampleCspStruct = ExampleCspStruct()
    data: Numpy1DArray[float] = np.array([])
    mapping: Dict[str, int] = {}
    dt: datetime = datetime.today()
    d: date = datetime.today().date()

    @classmethod
    def __get_validator_dict__(cls):
        return {"_validate_example": field_validator("x", mode="after")(nonnegative_check)}


class ExampleEnum(Enum):
    A = 1
    B = 2
    C = 3

    def __lt__(self, other):
        # so csp doesn't complain about memoization
        return self.value < other.value


# `MyGatewayChannels` is the collection of lazily-connected `csp` edges that will be provided to all modules in our graph.
# The modules in our graph are `pydantic`-wrapped `csp` modules, that use the `channel` APIs to connect to edges.
# Let's define a simple one.


class ExampleGatewayChannels(GatewayChannels):
    metadata: Dict[str, str] = {"name": "Demo"}

    example: ts[ExampleData] = None
    example_list: ts[List[ExampleData]] = None
    never_ticks: ts[ExampleData] = None

    s_example: ts[State[ExampleData]] = None

    basket: Dict[ExampleEnum, ts[ExampleData]] = None
    str_basket: Dict[str, ts[ExampleData]] = None

    # FIXME
    # basket_list: Dict[ExampleEnum, ts[[ExampleData]]] = None
    # NOTE: this second one is not populated with data so will 404

    # Controls channels for webserver/graph admin
    controls: ts[Controls] = None

    # Custom perspective manager, shared across modules to allow for custom table definitions
    perspective: PerspectiveServer = Field(default_factory=PerspectiveServer)


# A `GatewayModule` has two important features. First, it is a typed `pydantic` model, so you can define attributes
# in the usual `pydantic` way. Second, it has a `connect` method that will be provided the `GatewayChannels` instance
# when the graph is eventually wired together. You can use `get_channel` and `set_channel` to read-from and publish-to
# `csp` edges, respectively.


class ExampleModule(GatewayModule):
    interval: timedelta = SPEED

    # An example module that ticks some data in a struct
    @csp.node
    def subscribe(
        self,
        trigger: ts[bool],
        multiplier: int = 3,
    ) -> ts[ExampleData]:
        with csp.state():
            last_x = 0
        if csp.ticked(trigger):
            last_x += 1
            return ExampleData(
                x=last_x,
                y=str(last_x) * multiplier,
                data=np.random.random((SCALE,)),
                mapping={str(last_x): last_x},
            )

    # An example module that ticks some data in a [struct]
    @csp.node
    def subscribe_list(
        self,
        data: ts[ExampleData],
    ) -> ts[List[ExampleData]]:
        if csp.ticked(data):
            return [data]

    def dynamic_keys(self):
        return {ExampleGatewayChannels.str_basket: ["a", "b", "c"]}

    def connect(self, channels: ExampleGatewayChannels):
        # Create some CSP data streams
        data = self.subscribe(csp.timer(interval=self.interval, value=True))
        data_list = self.subscribe_list(data)

        # Channels set via `set_channel`
        channels.set_channel(ExampleGatewayChannels.example, data)
        channels.set_channel(ExampleGatewayChannels.example_list, data_list)

        # Generic channel for sending data from non-csp sources
        channels.add_send_channel(ExampleGatewayChannels.example)
        channels.add_send_channel(ExampleGatewayChannels.basket, ExampleEnum.A)
        channels.add_send_channel(ExampleGatewayChannels.basket, ExampleEnum.B)
        channels.add_send_channel(ExampleGatewayChannels.basket, ExampleEnum.C)
        channels.add_send_channel(ExampleGatewayChannels.basket)

        # Rudimentary state accumulation via `set_state`
        channels.set_state(ExampleGatewayChannels.example, "id")

        # Create some data streams for dict baskets
        data_a = self.subscribe(
            csp.timer(interval=self.interval, value=True),
            multiplier=ExampleEnum.A.value,
        )
        data_b = self.subscribe(
            csp.timer(interval=self.interval, value=True),
            multiplier=ExampleEnum.B.value,
        )
        data_c = self.subscribe(
            csp.timer(interval=self.interval, value=True),
            multiplier=ExampleEnum.C.value,
        )

        # Dict basket channels can be set as a whole, or via individual keys
        channels.set_channel(ExampleGatewayChannels.basket, data_a, ExampleEnum.A)
        channels.set_channel(ExampleGatewayChannels.basket, data_b, ExampleEnum.B)
        channels.set_channel(ExampleGatewayChannels.basket, data_c, ExampleEnum.C)

        channels.set_channel(ExampleGatewayChannels.str_basket, data_a, "a")
        channels.set_channel(ExampleGatewayChannels.str_basket, data_b, "b")
        channels.set_channel(ExampleGatewayChannels.str_basket, data_c, "c")


class ExampleModuleFeedback(GatewayModule):
    interval: timedelta = SPEED

    # An example module that ticks some data in a struct
    @csp.node
    def subscribe(
        self,
        data: ts[ExampleData],
    ) -> ts[ExampleData]:
        if csp.ticked(data):
            if data.x % 2 == 0:
                return ExampleData(
                    x=data.x + 1,
                    y=data.y,
                )

    def connect(self, channels: ExampleGatewayChannels):
        # Channels set via `set_channel`
        data = channels.get_channel(ExampleGatewayChannels.example)
        fb_data = self.subscribe(data)
        channels.set_channel(ExampleGatewayChannels.example, fb_data)

        # Dict basket channels can be set as a whole, or via individual keys
        channels.set_channel(ExampleGatewayChannels.basket, fb_data, ExampleEnum.A)


class ExampleCustomTable(GatewayModule):
    """This shows how you can customize the perspective tables."""

    table_name: str = "my_custom_table"

    def connect(self, channels: ExampleGatewayChannels):
        perspective_client = channels.perspective.new_local_client()
        my_table = perspective_client.table(dict(timestamp=datetime, x=int, y=str), limit=None, index="y", name=self.table_name)

        example = channels.get_channel(ExampleGatewayChannels.example)
        example_list = csp.unroll(channels.get_channel(ExampleGatewayChannels.example_list))
        # Merge multiple channels into a single stream for display
        # One could also do joins or any other custom combination/transformation of channels
        merged_data = csp.merge(example, example_list)
        self.push_to_perspective(merged_data, my_table)

    @csp.node
    def push_to_perspective(  # type: ignore[no-untyped-def]
        self,
        timeseries: ts[ExampleData],
        table: PerspectiveTable,
    ):
        with csp.alarms():
            alarm: ts[bool] = csp.alarm(bool)
        with csp.state():
            s_buffer = []

        with csp.start():
            csp.schedule_alarm(alarm, timedelta(seconds=0.5), True)

        if csp.ticked(timeseries):
            s_buffer.append(
                {
                    "timestamp": timeseries.timestamp.timestamp(),
                    "x": timeseries.x,
                    "y": timeseries.y,
                }
            )

        if csp.ticked(alarm):
            if len(s_buffer) > 0:
                table.update(s_buffer)
                s_buffer.clear()
            csp.schedule_alarm(alarm, timedelta(seconds=0.5), True)
