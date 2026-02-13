## Table Of Contents

- [Table Of Contents](#table-of-contents)
- [AddChannelsToGraphOutput](#addchannelstographoutput)
  - [Configuration](#configuration)
- [Initialize](#initialize)
  - [Configuration](#configuration-1)
- [Logfire](#logfire)
  - [Configuration](#configuration-2)
  - [Early Configuration](#early-configuration)
- [PublishLogfire](#PublishLogfire)
  - [Configuration](#configuration-3)
- [LogChannels](#logchannels)
  - [Configuration](#configuration-4)
- [Mirror](#mirror)
  - [Configuration](#configuration-5)
- [MountAPIKeyMiddleware](#mountapikeymiddleware)
  - [Configuration](#configuration-6)
  - [Usage](#usage)
    - [Server](#server)
    - [API](#api)
    - [Client](#client)
- [MountChannelsGraph](#mountchannelsgraph)
  - [Configuration](#configuration-7)
- [MountControls](#mountcontrols)
  - [Configuration](#configuration-8)
  - [Functionality](#functionality)
- [MountFieldRestRoutes](#mountfieldrestroutes)
  - [Configuration](#configuration-9)
- [MountOutputsFolder](#mountoutputsfolder)
  - [Configuration](#configuration-10)
- [MountPerspectiveTables](#mountperspectivetables)
  - [Configuration](#configuration-11)
- [MountRestRoutes](#mountrestroutes)
  - [Configuration](#configuration-12)
- [MountWebSocketRoutes](#mountwebsocketroutes)
  - [Configuration](#configuration-13)
- [PrintChannels](#printchannels)
  - [Configuration](#configuration-14)
- [PublishDatadog](#publishdatadog)
  - [Configuration](#configuration-15)
- [PublishOpsGenie](#publishopsgenie)
  - [Configuration](#configuration-16)
- [PublishSQLA](#publishsqla)
  - [Configuration](#configuration-17)
- [PublishSymphony](#publishsymphony)
  - [Configuration](#configuration-18)
- [ReplayEngineJSON](#replayenginejson)
  - [Configuration](#configuration-19)
- [ReplayEngineKafka](#replayenginekafka)
  - [Configuration](#configuration-20)

## AddChannelsToGraphOutput

`AddChannelsToGraphOutput` is a utility `GatewayModule` that adds selected channels to the CSP graph output, making them available after the graph run completes.

This is useful for debugging, testing, or collecting results from a Gateway run.

### Configuration

```yaml
modules:
  add_outputs:
    _target_: csp_gateway.AddChannelsToGraphOutput
    selection:
      include:
        - my_channel
        - other_channel
```

## Initialize

`Initialize` is a `GatewayModule` that initializes channels with static values at startup. This is useful for setting default values or configuration that should be available immediately when the graph starts.

### Configuration

```yaml
modules:
  initialize:
    _target_: csp_gateway.Initialize
    values:
      my_channel:
        field1: value1
        field2: value2
```

## Logfire

`Logfire` is a `GatewayModule` that integrates [Pydantic Logfire](https://logfire.pydantic.dev/) observability into your Gateway. It provides:

- **Early Configuration**: Configures Logfire at module instantiation time (during hydra config loading), capturing logs from the entire application lifecycle
- **Python Logging Integration**: Captures standard library `logging` calls and sends them to Logfire
- **FastAPI Instrumentation**: Automatically instruments FastAPI endpoints for request/response tracing
- **Pydantic Instrumentation**: Optional instrumentation for Pydantic model validation

### Configuration

```yaml
modules:
  logfire:
    _target_: csp_gateway.server.modules.logging.Logfire
    token: ${oc.env:LOGFIRE_TOKEN,null}  # Or set LOGFIRE_TOKEN env var
    service_name: my-gateway
    instrument_fastapi: true
    instrument_pydantic: false
    capture_logging: true
    log_level: 20  # logging.INFO
    send_to_logfire: true  # Set false for local dev without token
    console: null  # Or false to disable, or dict for options
```

Additional configuration options:

- **token** (`Optional[str]`): Logfire API token. Uses `LOGFIRE_TOKEN` env var if not set
- **service_name** (`str = "csp-gateway"`): Service name for Logfire traces
- **instrument_fastapi** (`bool = True`): Instrument FastAPI endpoints
- **instrument_pydantic** (`bool = False`): Instrument Pydantic validation
- **capture_logging** (`bool = True`): Capture Python logging to Logfire
- **log_level** (`int = logging.INFO`): Minimum log level to capture
- **send_to_logfire** (`Optional[bool]`): Whether to send to Logfire backend
- **console** (`Optional[bool | Dict]`): Console output configuration

### Early Configuration

The `Logfire` module automatically configures Logfire during its instantiation, which happens when hydra loads the configuration. This means logging is captured before the CSP graph is built.

For even earlier configuration (before hydra runs), you can use the helper function:

```python
from csp_gateway.server.modules.logging.logfire import configure_logfire_early

# Call before hydra.main()
configure_logfire_early(token="your-token", service_name="my-app")

# Then run your application
from csp_gateway.server.cli import main
main()
```

## PublishLogfire

`PublishLogfire` is a `GatewayModule` that logs CSP channel data to Logfire. Similar to `LogChannels`, but with rich Logfire integration including structured attributes and optional span tracing.

### Configuration

```yaml
modules:
  logfire_channels:
    _target_: csp_gateway.server.modules.logging.PublishLogfire
    selection:
      include:
        - prices
        - orders
    log_states: false
    log_level: 20  # logging.INFO
    service_name: channel-logger  # Optional override
    include_metadata: true
    use_spans: false  # Set true for span-based tracing
```

Configuration options:

- **selection** (`ChannelSelection`): Which channels to log
- **log_states** (`bool = False`): Whether to log state channels (`s_*`)
- **log_level** (`int = logging.INFO`): Log level for channel data
- **service_name** (`Optional[str]`): Override service name for these logs
- **include_metadata** (`bool = True`): Include CSP timestamps in logs
- **use_spans** (`bool = False`): Use Logfire spans instead of logs

## LogChannels

`LogChannels` is a simple `GatewayModule` to log channel ticks to a logger.

### Configuration

```yaml
log_channels:
  _target_: csp_gateway.LogChannels
  selection:
    include:
      - channel_one
      - channel_two
  log_states: false
  log_level: DEBUG
  log_name: MyCoolLogger
```

> [!TIP]
>
> You can instantiate multiple different instances.

## Mirror

`Mirror` is a `GatewayModule` that copies (mirrors) data from one channel to another. This is useful for creating derived channels or routing data between different parts of your application.

### Configuration

```yaml
modules:
  mirror:
    _target_: csp_gateway.Mirror
    source: source_channel
    target: target_channel
```

## MountAPIKeyMiddleware

`MountAPIKeyMiddleware` is a `GatewayModule` to add API Key based authentication to the `Gateway` REST API, Websocket API, and UI.

### Configuration

```yaml
modules:
  mount_api_key_middleware:
    _target_: csp_gateway.MountAPIKeyMiddleware
    api_key_timeout: 60:00:00 # Cookie timeout
    unauthorized_status_message: unauthorized
```

### Usage

#### Server

When you instantiate your `Gateway`, ensure that the `GatewaySettings` instance has `authenticate=True`. By default, a unique token will be generated and displayed in the logging output, similar to how `Jupyter` works by default. To customize, change the `GatewaySettings` instance's `api_key` to whatever you like:

E.g. in configuration:

```yaml
gateway:
  settings:
    AUTHENTICATE: True
    API_KEY: my-secret-api-key
```

Or from the CLI

```bash
csp-gateway-start <your arguments> ++gateway.settings.AUTHENTICATE=True ++gateway.settings.API_KEY=my-secret-api-key
```

#### API

For REST and Websocket APIs, append the `token` query parameter for all requests to authenticate.

#### Client

When instantiating your Python client, pass in the same arguments as the server:

```python
config = GatewayClientConfig(
    host="localhost",
    port=8000,
    authenticate=True,
    api_key="my-secret-api-key"
)
client = GatewayClient(config)
```

The client will automatically include the API Key on all requests.

## MountChannelsGraph

`MountChannelsGraph` adds a small UI for visualizing your `csp-gateway` graph, available by default at `/channels_graph`.

### Configuration

```yaml
modules:
  mount_channels_graph:
    _target_: csp_gateway.MountChannelsGraph
```

## MountControls

`MountControls` adds additional REST utilities for various application-oriented functionality.

### Configuration

```yaml
modules:
  mount_outputs:
    _target_: csp_gateway.MountOutputsFolder
```

### Functionality

This adds an additional top-level REST API group `controls`. By default, it contains 3 subroutes:

- `heartbeat`: check if the `csp` graph is still alive and running
- `stats`: collect some host information including cpu usage, memory usage, csp time, wall time, active threads, username, etc
- `shutdown`: initiate a shutdown of the running server, used in the [_"Big Red Button"_](UI#Settings)

## MountFieldRestRoutes

`MountFieldRestRoutes` adds REST API endpoints for individual fields within channels. This provides fine-grained access to specific data points.

### Configuration

```yaml
modules:
  mount_field_rest_routes:
    _target_: csp_gateway.MountFieldRestRoutes
    selection:
      include:
        - my_channel
```

## MountOutputsFolder

`MountOutputsFolder` adds a small UI for visualizing your log outputs and your hydra configuration graph, available by default at `/outputs`.

### Configuration

```yaml
modules:
  mount_outputs:
    _target_: csp_gateway.MountOutputsFolder
```

## MountPerspectiveTables

`MountPerspectiveTables` enables Perspective in the [UI](UI).

### Configuration

```yaml
modules:
  mount_perspective_tables:
    _target_: csp_gateway.MountPerspectiveTables
    layouts:
      Server Defined Layout: "<a custom layout JSON>"
    update_interval: 00:00:02
```

Additional configuration is available:

- **limits** (`Dict[str, int] = {}`): configuration of Perspective table limits
- **indexes** (`Dict[str, str] = {}`): configuration of Perspective table indexes
- **update_interval** (`timedelta = Field(default=timedelta(seconds=2)`): default perspective table update interval
- **default_index** (`Optional[str]`): default index on all perspective tables, e.g. `id`
- **perspective_field** (`str`): Optional field to allow a `perspective.Server` to be mounted on a `GatewayChannels` instance, to allow `GatewayModules` to interact with Perspective independent of this module

## MountRestRoutes

`MountRestRoutes` enables the [REST API](API).

> [!NOTE]
>
> The REST API is launched when starting the `Gateway` instance with `rest=True`

### Configuration

```yaml
modules:
  mount_rest_routes:
    _target_: csp_gateway.MountRestRoutes
    force_mount_all: True
```

> [!WARNING]
>
> `force_mount_all: True` force mounts all channels as read/write.
> This is convenient for debugging, but might not be ideal in production.

[API](API) endpoints can also be configured individually:

- **mount_last** (`ChannelSelection`): channels to include in last routes
- **mount_next** (`ChannelSelection`): channels to include in next routes
- **mount_send** (`ChannelSelection`): channels to include in send routes
- **mount_state** (`ChannelSelection`): channels to include in state routes
- **mount_lookup** (`ChannelSelection`): channels to include in lookup routes

> [!IMPORTANT]
>
> `send` is only available if a `GatewayModule` has called `add_send_channel` or `force_mount_all` is `True`.

## MountWebSocketRoutes

`MountWebSocketRoutes` enables the [Websocket API](API).

> [!NOTE]
>
> The Websocket API is launched when starting the `Gateway` instance with `rest=True`

### Configuration

```yaml
modules:
  mount_websocket_routes:
    _target_: csp_gateway.MountWebSocketRoutes
```

It has a few additional configuration options:

- **readonly** (`bool=False`): disallow sending in data back to the `Gateway`
- **ping_time_s** (`int=1`): configure the default websocket ping (keepalive) interval in seconds
- **selection** (`ChannelSelection`): configure which channels are available for websocket streaming
- **prefix** (`str="/stream"`): configure the websocket endpoint path

## PrintChannels

`PrintChannels` is a simple `GatewayModule` to print channel ticks to stdout.

### Configuration

```yaml
print_channels:
  _target_: csp_gateway.PrintChannels
  selection:
    include:
      - channel_one
      - channel_two
```

## PublishDatadog

`PublishDatadog` is a `GatewayModule` for publishing events and metrics to [Datadog](https://www.datadoghq.com/). It integrates with Datadog's API to send monitoring data from your Gateway.

### Configuration

```yaml
modules:
  datadog:
    _target_: csp_gateway.PublishDatadog
    events_channel: my_events_channel
    metrics_channel: my_metrics_channel
    dd_tags:
      environment: production
      service: my-gateway
    dd_latency_log_threshold_seconds: 30
```

Configuration options:

- **events_channel** (`Optional[str]`): Channel containing `MonitoringEvent` objects to publish
- **metrics_channel** (`Optional[str]`): Channel containing `MonitoringMetric` objects to publish
- **dd_tags** (`Optional[Dict[str, str]]`): Tags to include with all Datadog submissions
- **dd_latency_log_threshold_seconds** (`int = 30`): Log a warning if Datadog API calls exceed this duration

> [!NOTE]
>
> Requires the `datadog` package to be installed.

## PublishOpsGenie

`PublishOpsGenie` is a `GatewayModule` for creating alerts in [OpsGenie](https://www.atlassian.com/software/opsgenie). It monitors specified channels and creates alerts based on the data.

### Configuration

```yaml
modules:
  opsgenie:
    _target_: csp_gateway.PublishOpsGenie
    api_key: ${oc.env:OPSGENIE_API_KEY}
    alerts_channel: my_alerts_channel
```

Configuration options:

- **api_key** (`str`): OpsGenie API key
- **alerts_channel** (`str`): Channel containing alert data

> [!NOTE]
>
> Requires the `opsgenie-sdk` package to be installed.

## PublishSQLA

`PublishSQLA` is a `GatewayModule` for persisting channel data to a SQL database using SQLAlchemy. It writes channel ticks to database tables for persistence and later analysis.

### Configuration

```yaml
modules:
  sql:
    _target_: csp_gateway.PublishSQLA
    connection_string: postgresql://user:pass@localhost/db
    selection:
      include:
        - my_channel
    table_prefix: gateway_
```

Configuration options:

- **connection_string** (`str`): SQLAlchemy database connection string
- **selection** (`ChannelSelection`): Which channels to persist
- **table_prefix** (`str`): Prefix for generated table names

## PublishSymphony

`PublishSymphony` is a `GatewayModule` for publishing messages to [Symphony](https://symphony.com/), an enterprise communication platform.

### Configuration

```yaml
modules:
  symphony:
    _target_: csp_gateway.PublishSymphony
    bot_username: my-bot
    bot_private_key_path: /path/to/key.pem
    stream_id: stream123
    messages_channel: my_messages_channel
```

> [!NOTE]
>
> Requires Symphony SDK packages to be installed.

## ReplayEngineJSON

`ReplayEngineJSON` is a `GatewayModule` for replaying recorded JSON data through channels. This is useful for testing, backtesting, or debugging with historical data.

### Configuration

```yaml
modules:
  replay_json:
    _target_: csp_gateway.ReplayEngineJSON
    file_path: /path/to/data.json
    selection:
      include:
        - channel_one
        - channel_two
```

Configuration options:

- **file_path** (`str`): Path to the JSON file containing recorded data
- **selection** (`ChannelSelection`): Which channels to replay

## ReplayEngineKafka

`ReplayEngineKafka` is a `GatewayModule` for replaying data from Kafka topics through Gateway channels. It consumes messages from Kafka and injects them into the CSP graph.

### Configuration

```yaml
modules:
  replay_kafka:
    _target_: csp_gateway.ReplayEngineKafka
    broker: localhost:9092
    topics:
      - my_topic
    selection:
      include:
        - channel_one
```

Configuration options:

- **broker** (`str`): Kafka broker address
- **topics** (`List[str]`): Topics to consume from
- **selection** (`ChannelSelection`): Which channels to populate
- **group_id** (`Optional[str]`): Kafka consumer group ID
- **start_offset** (`str`): Where to start consuming (earliest, latest, etc.)

> [!NOTE]
>
> Requires the `csp[kafka]` package to be installed.
