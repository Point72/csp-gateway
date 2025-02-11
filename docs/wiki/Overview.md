`csp-gateway` is a framework for building high-performance streaming applications.

It is is composed of four major components:

- Engine: [csp](https://github.com/point72/csp), a streaming, complex event processor core
- API: [FastAPI](https://fastapi.tiangolo.com) REST/WebSocket API
- UI: [Perspective](https://perspective.finos.org) and React based frontend with automatic table and chart visualizations
- Configuration: [ccflow](https://github.com/point72/ccflow), a [Pydantic](https://docs.pydantic.dev/latest/)/[Hydra](https://hydra.cc) based extensible, composeable dependency injection and configuration framework

## Table of Contents

- [Table of Contents](#table-of-contents)
- [First Example](#first-example)
- [Engine](#engine)
- [Modules](#modules)
- [Channels](#channels)
- [Gateway](#gateway)
- [What's Next](#whats-next)

## First Example

Before we look into the various parts of `csp-gateway`, lets look at a quick example.

```python
from csp_gateway import *
from csp_gateway.server.demo import ExampleGatewayChannels, ExampleModule

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

# Run the gateway
# UI available at http://localhost:8000
# REST Docs available at http://localhost:8000/redoc
gateway.start(rest=True, ui=True)
```

This example does a few things:

- Creates the settings for the [`Gateway`](#Gateway) object
- Instantiates the [`Gateway`](#Gateway) with this settings, [`Channels`](#Channels), and [`Modules`](#Modules)
- Runs the [`Gateway`](#Gateway), which will launch the `csp` graph, start the webserver, and mount the UI

Let's look at each of these components one by one.

> [!TIP]
>
> This example is available in the source code: [`csp_gateway/server/demo/__main__.py`](https://github.com/Point72/csp-gateway/blob/main/csp_gateway/server/demo/__main__.py).
>
> You can run it locally via: `csp-gateway-start --config-dir=csp_gateway/server/demo +config=demo`
> or `python -m csp_gateway.server.demo`

## Engine

As the name suggests, `csp-gateway` is built on [csp](https://github.com/Point72/csp).
`csp` is a high performance, reactive, stream-processing framework implemented in C++ and Python.
`csp` provides two major primitives: `node` and `graph`.

- **`node`**: a single, stateful python function that _ticks_ when its inputs update
- **`graph`**: a python function that wires together different nodes

Additionally, the connection between nodes is represented as an **`edge`** - the ticking data stream between nodes.
In `csp` we call this a `ts` for short - a `ts[int]` is a ticking edge of Python `int`s.

`csp` has a lot of [documentation](https://github.com/Point72/csp/wiki) and [examples](https://github.com/Point72/csp/tree/main/examples) available to learn more.
For those familiar with `csp`, more details on the relationship between `csp` and `csp-gateway` can be found in [CSP Notes](CSP-Notes).

## Modules

A `Module` (`csp_gateway.GatewayModule`) is just a [Pydantic](https://docs.pydantic.dev/latest/) wrapper around a `csp` `node` or `graph`.
Here is an example like the demo code above:

```python
import csp

class ExampleData(GatewayStruct):
    x: int

class ExampleModule(GatewayModule):
    interval: timedelta = timedelta(seconds=1)

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
```

It has a few important features:

- `GatewayModule`: All modules must be a subclass of `GatewayModule`, a [ccflow](https://github.com/Point72/ccflow) base model (an enhanced Pydantic `BaseModel`)
- `subscribe`: This is a normal `csp` `graph`. We could've named it anything
- `connect`: This is invoked when the gateway instance is launched
  - `connect` takes an instance of [`GatewayChannels`](#Channels), which is a named collection of `csp` `Edges` (or `ts` for short)
  - Data is subscribed from the channels by name, via `channels.get_channel(<name>)`
  - Data is published to the channels by name, via `channels.set_channel(<name>, <a ts of data matching what the channel expects>)`

Additionally, a `GatewayModule` can define methods and attributes:

- `rest(self, app: "GatewayWebApp")` which is invoked with an instance of the gateway's FastAPI webserver for mounting custom REST/Websocket endpoints
- `shutdown(self)` to deal with any clean shutdown routines
- `requires: ChannelSelection`, `disable: bool`, `block_set_channels_until: datetime`, `dynamic_keys(self)`, `dynamic_channels(self)`, `dynamic_state_channels(self)`: See [Advanced Usage notes](Develop#Advanced)

> [!TIP]
>
> A `GatewayModule` need not use `csp`! Some just interact with the webserver via `rest`.
> One example of this is the integrated logs viewer module `MountOutputsFolder`

`GatewayModule`s interact with data (and by extension, each other) via [`GatewayChannel`](#Channels), so let's look at that now.

## Channels

When a `Gateway` is built, it instantiates an instance of `GatewayChannels` (or a subclass), and passes it to each `GatewayModule` via the `connect` method.
`GatewayChannels` is a predefined collection of ticking `csp` edges - `ts` as described in [Engine](#Engine) above.

If `csp` is a ticking collection of nodes connected node-to-node, then a `csp-gateway` is more like a data bus.
`GatewayChannels` defines all of the available data on the bus, and `GatewayModules` connect and publish/subscribe to the channels they need.

Let's take a look at the `GatewayChannels` instance for the example above:

```python
class ExampleGatewayChannels(GatewayChannels):
    example: ts[ExampleData] = None
```

We can see our subclass `ExampleGatewayChannels` defines a single data stream, `example`, which is a ticking edge of `ExampleData` instances.
Any `GatewayModule` (and its underlying `csp` nodes or graphs) can access this data stream by name in its `connect` method.

> [!NOTE]
>
> Any channel data must derive from `GatewayStruct` to be included in the REST API.
> `GatewayStruct` is a union of [`csp.Struct`](https://github.com/Point72/csp/wiki/csp.Struct-API) and Pydantic `BaseModel`. It provides the performance and `csp` integration benefits of `csp.Struct`, while having the type validation properties of a Pydantic `BaseModel`.

Recall from above:

```python
    # Channels set via `set_channel`
    channels.set_channel(ExampleGatewayChannels.example, data)
```

`GatewayChannels` instances provide two methods for getting/setting data:

- `get_channel(self, field: str, indexer: Union[int, str] = None) -> Union[Edge, Dict[Any, Edge], List[Edge]]`: Get a channel by name and return the ticking edge for use in `csp` nodes and graphs
- `set_channel(self, field: str, edge: Union[Edge, Dict[Any, Edge], List[Edge]], indexer: Union[int, str] = None) -> None`: Set a channel by name to a given ticking edge, will be demultiplexed with other setters

> [!TIP]
>
> `indexer` in the above methods is for use with [csp dictionary baskets](https://github.com/Point72/csp/wiki/CSP-Node#basket-outputs)

`GatewayChannels` also have the ability to create and maintain state, which is particularly useful in the REST API. State is managed by an in-memory [DuckDB](https://duckdb.org/) instance.

- `set_state(self, field: str, keyby: Union[str, Tuple[str, ...]], indexer: Union[str, int] = None) -> None`: Collect state of an edge by a certain attribute indexer
- `get_state(self, field: str, indexer: Union[str, int] = None) -> Any`: Get the current state collected on an edge as a ticking object

`GatewayChannels` can tell the REST API to allow a certain channel to be sent in via POST requests:

- `add_send_channel(self, field: str, indexer: Union[str, int] = None) -> None`

Finally, `GatewayChannels` can be interacted with from outside `csp`.
This is the primary API for both the [REST API](API) and the [integrated Python client](Client):

- `last(self, field: str, indexer: Union[str, int] = None, *, timeout=None) -> None`: Get the last ticked value on a channel
- `next(self, field: str, indexer: Union[str, int] = None, *, timeout=None) -> None`: Get (wait for) the next ticked value on a channel
- `state(self, field: str, indexer: Union[str, int] = None, *, timeout=None) -> Any`: Get the state collected on a channel
- `query(self, field: str, indexer: Union[str, int] = None, query: "Query" = None) -> Any`: Query the state on a channel (see [API](API) for more about `Query`)
- `send(self, field: str, value: Any, indexer: Union[str, int] = None) -> None`: Send new data to a channel, from outside the `csp` graph

## Gateway

The final part of our example is the `Gateway` instance itself. It takes as arguments:

- `GatewaySettings`: a `pydantic.BaseSettings` instance containing static information about the `Gateway` including name, port, etc
- list of `GatewayModule` instances
- a `GatewayChannels` instance

It then runs through the following steps:

- Loop through the `GatewayModule` instances and call `connect` with the `GatewayChannels` instance
- Ensure that all channels requested by `GatewayModule` instances are provided by other `GatewayModule` instances (See [CSP Notes](CSP-Notes) for more details)
- Instantiate the FastAPI instance, if enabled
- Loop through the `GatewayModule` instances and call `rest`, if enabled
- Start the `csp` graph
- Start the FastAPI webserver

The `Gateway` instance has two main methods:

- `start(self, user_graph: Optional[Any] = None, realtime: bool = True, block: bool = True, show: bool = False, rest: bool = False, ui: bool = False, **kwargs)`: Start the gateway
- `stop(self, **kwargs)`: stop the gateway

At this point, we have a modular streaming graph-based application complete with a REST API and a web UI.

## What's Next

- [API](API) for more information on the integrated OpenAPI-compatible REST API, and the streaming Websocket API
- [Client](Client) for more information on the provided Python client
- [UI](UI) for more information on the [Perspective](https://perspective.finos.org)-based React frontend
- [Configuration](Configuration) for more information about driving your application completely from yaml-based configuration
- Check out the much more complicated [Omnibus Example](https://github.com/Point72/csp-gateway/blob/main/csp_gateway/server/demo/omnibus.py)
