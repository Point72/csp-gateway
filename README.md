# csp-gateway

[![PyPI](https://img.shields.io/pypi/v/csp-gateway.svg?style=flat)](https://pypi.python.org/pypi/csp-gateway)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](https://github.com/Point72/csp-gateway/LICENSE)
[![Build Status](https://github.com/Point72/csp-gateway/actions/workflows/build.yml/badge.svg)](https://github.com/Point72/csp-gateway/actions/workflows/build.yml)

# Overview
`csp` is a complex event processing framework for building declarative, reactive, forward propagating event graphs in python with a high-performance C++ core engine ([site](https://github.com/Point72/csp)). `csp` is an extremely powerful framework, but currently has a few limitations that can make it difficult to work with. In particular, graph architecture must be known in order to connect nodes together via statically-defined edges.

`csp-gateway` extends on the functionality of `csp` by introducing a layer to defer graph construction. Instead of eager connection of nodes, `csp-gateway` defers connections and injects `DelayedEdge`s for all interconnects. Once all nodes are ready, `DelayedEdge`s are directly connected with a few user conveniences:
  - self-loops are automatically identified and replaced with `csp.feedback`
  - optional and unused edges are replaced with `null_ts`
  - multiple edge producers will have their outputs demultiplexed with [`csp.collect`](https://github.com/Point72/csp/wiki/Base-Nodes-API#cspcollect)


On top of this functionality, `csp-gateway` provides generic APIs on top of the `csp` graph, including:
  - REST
  - Websocket
  - UNIX Socket (WIP)
  - Kafka


## Components
The core components of `csp-gateway` are:
  - `Channel` a named `csp` edge
  - `Channels` a collection of named `csp` channels
    - `get_channel`: get an `Channel` by name, starts with a `DelayedEdge` until connected to a setter
    - `set_channel`: set an `Channel` by name, automatically multiplexes across multiple setters
    - `get_state`: get a state tracking edge
    - `set_state`: set a state tracking edge via `State` object and a `str`/`tuple` to index attributes into structs on the edge
    - `query`: query a state tracking edge in a non-`csp` manner
    - `add_send_channel`: create a generic (non-`csp`) edge
    - `send`: send data to a generic (non-`csp`) edge
  - `Module` an object that is called against an `Channels` instance
    - `connect`: method called by the `Gateway` instance with the `Channels` instance. Used by the `Module` instance to connect to   `csp`
  - `Gateway`: wrapper around `csp` to run the underlying system
    - takes an `Channels` instance of all the data streams
    - takes a collection of `Module`s to which to connect
    - takes an optional user csp graph to connect
    - can `start` and `stop`
    - can interact in a non-`csp` way with the `channels` attribute
      - e.g. `gateway.channels.send(GatewayChannels.orders, Order(...))` to send an `Order` to the `orders` edge
      - e.g. `gateway.channels.query(GatewayEdge.orders, ...)` to query the `orders` state edge
    - optionally constructs a webserver to serve interfaces over `REST` / websocket

## Examples

### Server
Check out [this code](csp_gateway/server/demo/__init__.py)
which walks through building an example server.

### Client
This [notebook](examples/Client.ipynb) shows
how to connect to the server and demonstrates the fundamentals of the `GatewayClient` object.

## Securing the server
Right now, `csp-gateway` only supports API Key authentication. OIDC/OAuth2 will be implemented shortly.

To use API Key authentication, include the `MountAPIKeyMiddleware` module in your modules, set `API_KEY` in your gateway settings,
and then provide it to the `api_key` argument to your gateway clients. If you do not set `API_KEY`, a token will be auto-generated for you.
