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

A `GatewayModule` can call `set_state` in its `connect` method to allow for this API to be available.
State is collected by one or more instance attributes into an in-memory [DuckDB](https://duckdb.org/) instance.

For example, suppose I have the following type:

```python
class ExampleData(GatewayStruct):
    x: str
    y: str
    z: str
```

If my `GatewayModule` called `set_state("example", ("x",))`, state would be collected as the last tick of `ExampleData` per each unique value of `x`. If called with `set_state("example", ("x", "y"))`, it would be collected as the last tick per each unique pair `x,y`, etc.

> [!IMPORTANT]
>
> This code and API will likely change a bit as we allow for more granular collection of records,
> and expose more DuckDB functionality.

## Query

[State](#State) accepts an additional query parameter `query`.
This allows REST API users to query state and only return satisfying records.
Here are some examples from the autodocumentation illustrating the use of filters:

```raw
# Filter only records where `record.x` == 5
api/v1/state/example?query={"filters":[{"attr":"x","by":{"value":5,"where":"=="}}]}

# Filter only records where `record.x` < 10
/api/v1/state/example?query={"filters":[{"attr":"x","by":{"value":10,"where":"<"}}]}

# Filter only records where `record.timestamp` < "2023-03-30T14:45:26.394000"
/api/v1/state/example?query={"filters":[{"attr":"timestamp","by":{"when":"2023-03-30T14:45:26.394000","where":"<"}}]}

# Filter only records where `record.id` < `record.y`
/api/v1/state/example?query={"filters":[{"attr":"id","by":{"attr":"y","where":"<"}}]}

# Filter only records where `record.x` < 50 and `record.x` >= 30
/api/v1/state/example?query={"filters":[{"attr":"x","by":{"value":50,"where":"<"}},{"attr":"x","by":{"value":30,"where":">="}}]}
```

> [!IMPORTANT]
>
> This code and API will likely change a bit as we expose more DuckDB functionality.

## Websockets

In addition to a REST API, a more `csp`-like streaming API is also available via Websockets when the `MountWebSocketRoutes` module is included in a `Gateway` instance.

This API is bidirectional, providing the ability to receive data as it ticks or to tick in new data.
Any data available via `last`/`send` above is available via websocket.

To subscribe to channels, send a JSON message of the form:

```
{
    "action": "subscribe",
    "channel": "<channel name>"
}
```

To unsubscribe to channels, send a JSON message of the form:

```
{
    "action": "unsubscribe",
    "channel": "<channel name>"
}
```

Data will be sent across the websocket for all subscribed channels. It has the form:

```
{
    "channel": "<channel name>",
    "data": <the same data that would be transmitted over e.g. the `last` endpoint>
}
```

## Python Client

See [Client](Client) for details on our integrated python client.
