## Table Of Contents

- [Table Of Contents](#table-of-contents)
- [AddChannelsToGraphOutput](#addchannelstographoutput)
  - [Configuration](#configuration)
- [Initialize](#initialize)
  - [Configuration](#configuration-1)
- [Logging](#logging)
  - [Configuration](#configuration-2)
  - [Early Configuration](#early-configuration)
- [LogChannels](#logchannels)
  - [Configuration](#configuration-5)
- [Logfire](#logfire)
  - [Configuration](#configuration-3)
  - [Early Configuration](#early-configuration-1)
- [PublishLogfire](#PublishLogfire)
  - [Configuration](#configuration-4)
- [Mirror](#mirror)
  - [Configuration](#configuration-6)
- [MountAPIKeyMiddleware](#mountapikeymiddleware)
  - [Configuration](#configuration-7)
  - [Usage](#usage)
    - [Server](#server)
    - [API](#api)
    - [Client](#client)
- [MountExternalAPIKeyMiddleware](#mountexternalapikeymiddleware)
  - [Configuration](#configuration-6a)
  - [Usage](#usage-1)
    - [External Validator Function](#external-validator-function)
    - [Server](#server-1)
- [MountChannelsGraph](#mountchannelsgraph)
  - [Configuration](#configuration-8)
- [MountControls](#mountcontrols)
  - [Configuration](#configuration-9)
  - [Functionality](#functionality)
- [MountFieldRestRoutes](#mountfieldrestroutes)
  - [Configuration](#configuration-10)
- [MountOutputsFolder](#mountoutputsfolder)
  - [Configuration](#configuration-11)
- [MountPerspectiveTables](#mountperspectivetables)
  - [Configuration](#configuration-12)
- [MountRestRoutes](#mountrestroutes)
  - [Configuration](#configuration-13)
- [MountWebSocketRoutes](#mountwebsocketroutes)
  - [Configuration](#configuration-14)
- [PrintChannels](#printchannels)
  - [Configuration](#configuration-15)
- [PublishDatadog](#publishdatadog)
  - [Configuration](#configuration-16)
- [PublishOpsGenie](#publishopsgenie)
  - [Configuration](#configuration-17)
- [PublishSQLA](#publishsqla)
  - [Configuration](#configuration-18)
- [PublishSymphony](#publishsymphony)
  - [Configuration](#configuration-19)
- [ReplayEngineJSON](#replayenginejson)
  - [Configuration](#configuration-20)
- [ReplayEngineKafka](#replayenginekafka)
  - [Configuration](#configuration-21)

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

## Logging

`Logging` is a `GatewayModule` that configures Python's standard library logging. It provides:

- **Early Configuration**: Configures logging at module instantiation time (during hydra config loading), capturing logs from the entire application lifecycle
- **Console and File Handlers**: Flexible configuration of console and file logging outputs
- **Colored Output**: Optional colorlog integration for colored console output
- **Per-Logger Configuration**: Fine-grained control over individual logger levels

This module replaces the previous approach of configuring logging via hydra's `job_logging` configuration (custom.yaml), providing a more consistent pattern with other observability modules like `Logfire`.

### Configuration

```yaml
modules:
  logging:
    _target_: csp_gateway.server.modules.logging.Logging
    console_level: INFO
    file_level: DEBUG
    root_level: DEBUG
    console_formatter: colorlog  # 'simple', 'colorlog', or 'whenAndWhere'
    file_formatter: whenAndWhere
    log_file: null  # Or explicit path like "/tmp/app.log"
    use_hydra_output_dir: true  # Log to hydra output directory
    use_colors: true
    logger_levels:
      uvicorn.error: CRITICAL
```

Configuration options:

- **console_level** (`int | str = logging.INFO`): Log level for console output
- **file_level** (`int | str = logging.DEBUG`): Log level for file output
- **root_level** (`int | str = logging.DEBUG`): Root logger level
- **console_formatter** (`str = "colorlog"`): Formatter for console output (`simple`, `colorlog`, `whenAndWhere`)
- **file_formatter** (`str = "whenAndWhere"`): Formatter for file output
- **log_file** (`Optional[str] = None`): Explicit path to log file
- **use_hydra_output_dir** (`bool = True`): If True and log_file is None, log to hydra's output directory
- **use_colors** (`bool = True`): Whether to use colorlog for colored console output
- **logger_levels** (`Dict[str, int | str]`): Per-logger level configuration

### Early Configuration

The `Logging` module automatically configures logging during its instantiation, which happens when hydra loads the configuration. This ensures logging is configured before the CSP graph is built.

For even earlier configuration (before hydra runs), you can use the helper function:

```python
from csp_gateway.server.modules.logging.stdlib import configure_stdlib_logging

# Call before hydra.main()
configure_stdlib_logging(
    console_level="INFO",
    log_file="/tmp/app.log",
    logger_levels={"uvicorn.error": "CRITICAL"},
)

# Then run your application
from csp_gateway.server.cli import main
main()
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
    api_key: ${oc.env:API_KEY,null}  # Or set API_KEY env var
    # Can also specify multiple API keys:
    # api_key:
    #   - key1
    #   - key2
    #   - key3
    api_key_timeout: 60:00:00 # Cookie timeout
    unauthorized_status_message: unauthorized
    # Scope: glob pattern(s) to restrict which routes require authentication
    # scope: "*"  # Reserved for future use
```

### Usage

#### Server

When you instantiate your `Gateway`, it will mount all modules. Mounting the API Key middleware ensures
that the rest api methods will require API key authentication.

You can configure a single API key or multiple valid API keys:

```python
# Single API key
MountAPIKeyMiddleware(api_key="my-secret-api-key")

# Multiple API keys
MountAPIKeyMiddleware(api_key=["key1", "key2", "key3"])
```

> **Note:** The `scope` parameter is available for configuration but scope-based filtering
> is not automatically enforced due to WebSocket compatibility constraints. All configured
> middlewares will validate credentials for all routes.

#### API

For REST and Websocket APIs, append the `token` query parameter for all requests to authenticate.

#### Client

When instantiating your Python client, pass in the same arguments as the server:

```python
config = GatewayClientConfig(
    host="localhost",
    port=8000,
    api_key="my-secret-api-key"
)
client = GatewayClient(config)
```

The client will automatically include the API Key on all requests.

## MountExternalAPIKeyMiddleware

`MountExternalAPIKeyMiddleware` is a `GatewayModule` that extends `MountAPIKeyMiddleware` to support API key validation against an external service. Instead of validating against a static list of keys, it invokes a user-provided function (specified via `ccflow.PyObjectPath`) to validate API keys and retrieve user identity information.

### Configuration

```yaml
modules:
  mount_external_api_key_middleware:
    _target_: csp_gateway.MountExternalAPIKeyMiddleware
    external_validator: "my_module.validators:validate_api_key"
    api_key_timeout: 12:00:00  # Cookie timeout
    unauthorized_status_message: unauthorized
    # Scope: glob pattern(s) to restrict which routes require authentication
    # scope: "*"  # Default: all routes
    # scope: "/api/*"  # Only /api/* routes require auth
```

### Usage

#### External Validator Function

The `external_validator` must point to a callable function that accepts three arguments:

- `api_key` (str): The API key provided by the user
- `settings` (GatewaySettings): The gateway settings object
- `module`: The gateway web app module

The function should return a dictionary containing user identity information if the key is valid, or `None` if the key is invalid.

```python
# my_module/validators.py
def validate_api_key(api_key: str, settings, module) -> dict | None:
    """Validate an API key against an external service.

    Args:
        api_key: The API key to validate
        settings: Gateway settings
        module: The gateway web app module

    Returns:
        A dictionary with user identity info if valid, None otherwise
    """
    # Call your external validation service
    response = my_auth_service.validate(api_key)
    if response.is_valid:
        return {
            "user": response.username,
            "role": response.role,
            "permissions": response.permissions,
        }
    return None
```

#### Server

When you instantiate your `Gateway`, the external validator will be called for each authentication attempt:

```python
from ccflow import PyObjectPath
from csp_gateway import Gateway, MountExternalAPIKeyMiddleware

MountExternalAPIKeyMiddleware(
    external_validator=PyObjectPath("my_module.validators:validate_api_key")
)
```

When a valid API key is provided:

1. The external validator function is called with the API key
1. If the validator returns a dictionary (user identity), a UUID session token is generated
1. The user identity is stored in memory, keyed by the UUID
1. The UUID is set as a cookie for subsequent requests
1. On logout, the UUID is removed from the identity store

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
