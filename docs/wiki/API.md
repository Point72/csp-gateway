`csp-gateway` provides a [FastAPI](https://fastapi.tiangolo.com/) based REST API optionally for every instance.
This provides a few nice features out of the box:

- [OpenAPI](https://github.com/OAI/OpenAPI-Specification) based endpoints automatically derived from the underlying `csp` types into [JSON Schema](https://json-schema.org/) (`/openapi.json`)
- [Swagger](https://github.com/swagger-api/swagger-ui) / [Redoc](https://github.com/Redocly/redoc) API documentation based on the `GatewayModule` and `GatewayChannels` in the application (`/docs` / `/redoc`)

The `csp-gateway` REST API is designed to be simple to consume from outside `csp`, with a few fundamental methods.

> [!NOTE]
>
> The REST API is launched when starting the `Gateway` instance with `rest=True`

## API

As described in [Overview#Channels](Overview#Channels), the `csp-gateway` REST API has several methods for interacting with ticking / stateful data living on the `GatewayChannels` instance.

- **last** (`GET`, `/api/v1/last/<channel>`): Get the last tick of data on a channel
- **next** (`GET`, `/api/v1/next/<channel>`): Wait for the next tick of data on a channel: **WARNING**: blocks, and can often be misused into race conditions
- **state** (`GET`, `/api/v1/state/<channel>`): Get the accumulated state for any channel
- **stage** (`POST`/`DELETE`/`PATCH`/`GET`/`PUT`, `/api/v1/stage/<channel>`): Manage staged structs on a channel before releasing them into the graph
- **send** (`POST`, `/api/v1/send/<channel>`): Send a new datum as a tick into the running csp graph
- **lookup** (`POST`, `/api/v1/lookup/<channel>/<gateway struct ID>`): Lookup an individual GatewayStruct by its required `id` field

> [!NOTE]
>
> Channels are included in the REST API by using a `GatewayModule`.
> Most commonly, this is [`MountRestRoutes`](MountRestRoutes).

> [!IMPORTANT]
>
> `lookup` has substantial memory overhead, as we cache a copy of every instance of every datum.
> `GatewayModule` subclasses can disable it via the `classmethod` `omit_from_lookup`.

## State

State in `csp-gateway` exposes the accumulated history of a channel via the REST API as `/api/v1/state/<alias>`.
State is collected by one or more instance attributes into an in-memory [DuckDB](https://duckdb.org/) instance.

There are two ways to declare state on a channel:

1. **Annotation** on the channel definition, using `State(keyby, alias=...)`:

   ```python
   from typing import Annotated
   from csp_gateway import State, GatewayChannels, ts

   class MyChannels(GatewayChannels):
       # implicit alias "example_with_state" (matches the field name)
       example_with_state: Annotated[ts[ExampleData], State(("id", "x"))] = None

       # multiple state views on a single channel, each addressable by alias
       example_multi: Annotated[
           ts[ExampleData],
           State(("id", "x")),                          # alias = "example_multi"
           State(("id", "y"), alias="example_multi_alt"),
       ] = None
   ```

1. **Imperative** call from a `GatewayModule`'s `connect` method:

   ```python
   def connect(self, channels: MyChannels):
       edge = ...  # produce a csp.ts edge
       channels.set_channel(MyChannels.example, edge)
       channels.set_state(edge, "example_from_connect", ("id", "x", "z"))
   ```

For example, given:

```python
class ExampleData(GatewayStruct):
    x: str
    y: str
    z: str
```

Declaring `State(("x",))` collects the last tick of `ExampleData` per each unique value of `x`. Declaring `State(("x", "y"))` collects the last tick per each unique pair `(x, y)`, etc.

## Query

[State](#State) accepts an additional query parameter `query`.
This allows REST API users to query state and only return satisfying records.
Here are some examples from the autodocumentation illustrating the use of filters:

```raw
# Filter only records where `record.x` == 5
api/v1/state/example_with_state?query={"filters":[{"attr":"x","by":{"value":5,"where":"=="}}]}

# Filter only records where `record.x` < 10
/api/v1/state/example_with_state?query={"filters":[{"attr":"x","by":{"value":10,"where":"<"}}]}

# Filter only records where `record.timestamp` < "2023-03-30T14:45:26.394000"
/api/v1/state/example_with_state?query={"filters":[{"attr":"timestamp","by":{"when":"2023-03-30T14:45:26.394000","where":"<"}}]}

# Filter only records where `record.id` < `record.y`
/api/v1/state/example_with_state?query={"filters":[{"attr":"id","by":{"attr":"y","where":"<"}}]}

# Filter only records where `record.x` < 50 and `record.x` >= 30
/api/v1/state/example_with_state?query={"filters":[{"attr":"x","by":{"value":50,"where":"<"}},{"attr":"x","by":{"value":30,"where":">="}}]}
```

> [!IMPORTANT]
>
> This code and API will likely change a bit as we expose more DuckDB functionality.

## Staging

Staging in `csp-gateway` allows you to accumulate structs into named "staging areas" on a channel before atomically releasing them into the graph. This is useful for batch preparation workflows where you want to assemble a group of items and then release them all at once.

Staging is exposed via the REST API under `/api/v1/stage/<channel>`.

There are two ways to enable staging on a channel:

1. **Annotation** on the channel definition, using `Stage()`:

   ```python
   from typing import Annotated
   from csp_gateway import Stage, GatewayChannels, ts

   class MyChannels(GatewayChannels):
       orders: Annotated[ts[OrderData], Stage()] = None
   ```

1. **Imperative** call from a `GatewayModule`'s `connect` method:

   ```python
   def connect(self, channels: MyChannels):
       channels.set_channel(MyChannels.orders, edge)
       channels.set_stage(MyChannels.orders)
   ```

### REST Endpoints

| Method   | Endpoint                  | Description                                       |
| -------- | ------------------------- | ------------------------------------------------- |
| `GET`    | `/api/v1/stage/`          | List channels that have staging enabled           |
| `POST`   | `/api/v1/stage/<channel>` | Add a struct to staging (or create empty staging) |
| `DELETE` | `/api/v1/stage/<channel>` | Remove struct(s) from staging                     |
| `PATCH`  | `/api/v1/stage/<channel>` | Release staged structs into the channel           |
| `GET`    | `/api/v1/stage/<channel>` | List active staging IDs                           |
| `PUT`    | `/api/v1/stage/<channel>` | Look up contents of staging area(s)               |

All endpoints accept an optional `id` query parameter to target specific staging areas:

- **No `id` param**: operate on the latest staging area (or all, depending on the method)
- **`id=`** (empty string): operate on all staging areas
- **`id=abc,def`**: operate on specific staging area(s) by ID

### Lifecycle

1. **Create** a new staging area: `POST /api/v1/stage/<channel>` with no body
1. **Add** structs: `POST /api/v1/stage/<channel>?id=<staging_id>` with a JSON body
1. **Review** contents: `PUT /api/v1/stage/<channel>?id=<staging_id>`
1. **Release** into the graph: `PATCH /api/v1/stage/<channel>?id=<staging_id>`

Released structs are pushed into the CSP graph as individual ticks on the channel. Released staging areas remain accessible via `PUT` (lookup) for historical reference, but no longer appear in `GET` (list).

### Examples

```bash
# List channels with staging enabled
curl http://localhost:8000/api/v1/stage/

# Create an empty staging area
curl -X POST http://localhost:8000/api/v1/stage/orders
# Returns: {"<staging_id>": []}

# Add a struct to the latest staging
curl -X POST http://localhost:8000/api/v1/stage/orders \
  -H "Content-Type: application/json" \
  -d '{"symbol": "AAPL", "quantity": 10, "price": 190.5}'

# Look up contents of all staging areas (including released)
curl -X PUT http://localhost:8000/api/v1/stage/orders

# Release a specific staging into the graph
curl -X PATCH "http://localhost:8000/api/v1/stage/orders?id=<staging_id>"
```

## Websockets

In addition to a REST API, a more `csp`-like streaming API is also available via Websockets when the `MountWebSocketRoutes` module is included in a `Gateway` instance.

This API is bidirectional, providing the ability to receive data as it ticks or to tick in new data.
Any data available via `last`/`send` above is available via websocket.

### Subscribing to Channels

To subscribe to channels, send a JSON message of the form:

```json
{
    "action": "subscribe",
    "channel": "<channel name>"
}
```

For **dict basket channels** (channels keyed by an enum or string), you can subscribe to a specific key:

```json
{
    "action": "subscribe",
    "channel": "<channel name>",
    "key": "<basket key>"
}
```

If you omit the `key` for a dict basket channel, you will subscribe to **all keys** in that basket.

### Unsubscribing from Channels

To unsubscribe from channels, send a JSON message of the form:

```json
{
    "action": "unsubscribe",
    "channel": "<channel name>"
}
```

For dict basket channels, you can unsubscribe from a specific key:

```json
{
    "action": "unsubscribe",
    "channel": "<channel name>",
    "key": "<basket key>"
}
```

If you omit the `key` for a dict basket channel, you will unsubscribe from **all keys** in that basket.

### Receiving Data

Data will be sent across the websocket for all subscribed channels. It has the form:

```json
{
    "channel": "<channel name>",
    "data": "<the same data that would be transmitted over e.g. the last endpoint>"
}
```

For dict basket channels, the message also includes the key:

```json
{
    "channel": "<channel name>",
    "key": "<basket key>",
    "data": "<the data for this specific key>"
}
```

### Sending Data

To send data into a channel via websocket, use the `send` action:

```json
{
    "action": "send",
    "channel": "<channel name>",
    "data": {"field1": "value1", "field2": "value2"}
}
```

Data can also be sent as a list:

```json
{
    "action": "send",
    "channel": "<channel name>",
    "data": [{"field1": "value1"}, {"field1": "value2"}]
}
```

For dict basket channels, you **must** specify the key:

```json
{
    "action": "send",
    "channel": "<channel name>",
    "key": "<basket key>",
    "data": {"field1": "value1"}
}
```

### Heartbeat

A special `heartbeat` channel is always available. Subscribe to it to receive periodic `PING` messages:

```json
{"channel": "heartbeat", "data": "PING"}
```

This can be used to verify the connection is alive.

### Available Channels

You can query the list of available websocket channels via the REST endpoint:

```
GET /api/v1/stream
```

This returns a list of channel names. Dict basket channels are listed with their keys, e.g., `basket/A`, `basket/B`, etc.

## Python Client

See [Client](Client) for details on our integrated python client.
