## Table Of Contents

- [Table Of Contents](#table-of-contents)
- [AddChannelsToGraphOutput](#addchannelstographoutput)
- [Initialize](#initialize)
- [LogChannels](#logchannels)
  - [Configuration](#configuration)
- [Mirror](#mirror)
- [MountAPIKeyMiddleware](#mountapikeymiddleware)
  - [Configuration](#configuration-1)
  - [Usage](#usage)
    - [Server](#server)
    - [API](#api)
    - [Client](#client)
- [MountChannelsGraph](#mountchannelsgraph)
  - [Configuration](#configuration-2)
- [MountControls](#mountcontrols)
  - [Configuration](#configuration-3)
  - [Functionality](#functionality)
- [MountFieldRestRoutes](#mountfieldrestroutes)
- [MountOutputsFolder](#mountoutputsfolder)
  - [Configuration](#configuration-4)
- [MountPerspectiveTables](#mountperspectivetables)
  - [Configuration](#configuration-5)
- [MountRestRoutes](#mountrestroutes)
  - [Configuration](#configuration-6)
- [MountWebSocketRoutes](#mountwebsocketroutes)
  - [Configuration](#configuration-7)
- [PrintChannels](#printchannels)
  - [Configuration](#configuration-8)
- [PublishDatadog](#publishdatadog)
- [PublishOpsGenie](#publishopsgenie)
- [PublishSQLA](#publishsqla)
- [PublishSymphony](#publishsymphony)
- [ReplayEngineJSON](#replayenginejson)
- [ReplayEngineKafka](#replayenginekafka)

## AddChannelsToGraphOutput

Documentation coming soon!

## Initialize

Documentation coming soon!

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

Documentation coming soon!

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

Documentation coming soon!

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
> The REST API is launched when starting the `Gateway` instance with `rest=True`

### Configuration

```yaml
modules:
  mount_websocket_routes:
    _target_: csp_gateway.MountRestRoutes
```

It has a few additional configuration options:

- **readonly** (`bool=False`): disallow sending in data back to the `Gateway`
- **ping_time_s** (`int=1`): configure the default websocket ping (keepalive) interval in seconds

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

Documentation coming soon!

## PublishOpsGenie

Documentation coming soon!

## PublishSQLA

Documentation coming soon!

## PublishSymphony

Documentation coming soon!

## ReplayEngineJSON

Documentation coming soon!

## ReplayEngineKafka

Documentation coming soon!
