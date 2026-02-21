## Table Of Contents

- [Table Of Contents](#table-of-contents)
- [AddChannelsToGraphOutput](#addchannelstographoutput)
  - [Configuration](#configuration)
- [Initialize](#initialize)
  - [Configuration](#configuration-1)
- [Logging](#logging)
  - [Configuration](#configuration-2)
  - [Early Configuration](#early-configuration)
- [Logfire](#logfire)
  - [Configuration](#configuration-3)
  - [Early Configuration](#early-configuration-1)
- [PublishLogfire](#publishlogfire)
  - [Configuration](#configuration-4)
- [LogChannels](#logchannels)
  - [Configuration](#configuration-5)
- [Mirror](#mirror)
  - [Configuration](#configuration-6)
- [MountAPIKeyMiddleware](#mountapikeymiddleware)
  - [Configuration](#configuration-7)
  - [Usage](#usage)
    - [Server](#server)
    - [API](#api)
    - [Client](#client)
- [MountExternalAPIKeyMiddleware](#mountexternalapikeymiddleware)
  - [Configuration](#configuration-8)
  - [Usage](#usage-1)
    - [External Validator Function](#external-validator-function)
    - [Server](#server-1)
  - [Credential Sources](#credential-sources)
  - [Authentication Flow](#authentication-flow)
- [AuthFilterMiddleware](#authfiltermiddleware)
  - [Multiple Authentication Middlewares](#multiple-authentication-middlewares)
  - [Configuration](#configuration-9)
  - [Usage](#usage-2)
    - [Example Scenario](#example-scenario)
    - [Server Configuration](#server-configuration)
  - [Multiple Filter Fields](#multiple-filter-fields)
  - [How It Works](#how-it-works)
  - [Per-Identity Cache for `/last` Endpoints](#per-identity-cache-for-last-endpoints)
  - [Send Validation](#send-validation)
  - [Next Filtering](#next-filtering)
- [MountOAuth2Middleware](#mountoauth2middleware)
  - [Configuration](#configuration-10)
  - [Attributes](#attributes)
  - [Example](#example)
  - [Credential Sources](#credential-sources-1)
- [MountSimpleAuthMiddleware](#mountsimpleauthmiddleware)
  - [Configuration](#configuration-11)
  - [Attributes](#attributes-1)
  - [Host/System Authentication](#hostsystem-authentication)
  - [Validator Function](#validator-function)
  - [Example](#example-1)
  - [Credential Sources](#credential-sources-2)
- [MountChannelsGraph](#mountchannelsgraph)
  - [Configuration](#configuration-12)
- [MountControls](#mountcontrols)
  - [Configuration](#configuration-13)
  - [Functionality](#functionality)
- [MountFieldRestRoutes](#mountfieldrestroutes)
  - [Configuration](#configuration-14)
- [MountOutputsFolder](#mountoutputsfolder)
  - [Configuration](#configuration-15)
- [MountPerspectiveTables](#mountperspectivetables)
  - [Configuration](#configuration-16)
- [MountRestRoutes](#mountrestroutes)
  - [Configuration](#configuration-17)
- [MountWebSocketRoutes](#mountwebsocketroutes)
  - [Configuration](#configuration-18)
- [PrintChannels](#printchannels)
  - [Configuration](#configuration-19)
- [PublishDatadog](#publishdatadog)
  - [Configuration](#configuration-20)
- [PublishOpsGenie](#publishopsgenie)
  - [Configuration](#configuration-21)
- [PublishSQLA](#publishsqla)
  - [Configuration](#configuration-22)
- [PublishSymphony](#publishsymphony)
  - [Configuration](#configuration-23)
- [ReplayEngineJSON](#replayenginejson)
  - [Configuration](#configuration-24)
- [ReplayEngineKafka](#replayenginekafka)
  - [Configuration](#configuration-25)

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

### Credential Sources

API keys can be provided via (in order of precedence):

1. **Cookie**: Session cookie set after initial login (default name: `token`)
1. **Query parameter**: `?token=your-api-key`
1. **Header**: `X-API-Key: your-api-key`

### Authentication Flow

When a valid API key is provided:

1. The external validator function is called with the API key
1. If the validator returns a dictionary (user identity), a UUID session token is generated
1. The user identity is stored in memory, keyed by the UUID
1. The UUID is set as a cookie for subsequent requests
1. On logout, the UUID is removed from the identity store

## AuthFilterMiddleware

`AuthFilterMiddleware` is a `GatewayModule` that filters REST API and WebSocket responses based on the authenticated user's identity. When a struct has an attribute matching an identity field (e.g., "user"), only records where that attribute matches the authenticated user's value are returned.

This middleware is designed to work with any authentication middleware that implements the `IdentityAwareMiddlewareMixin` interface:

- `MountExternalAPIKeyMiddleware`
- `MountOAuth2Middleware`
- `MountSimpleAuthMiddleware`

### Multiple Authentication Middlewares

`AuthFilterMiddleware` supports multiple authentication middlewares. When configured, it will try each middleware in registration order until one returns a valid identity:

```python
gateway = Gateway(
    modules=[
        MountRestRoutes(force_mount_all=True),
        # Both auth middlewares implement IdentityAwareMiddlewareMixin
        MountExternalAPIKeyMiddleware(
            external_validator=PyObjectPath("my_module:validate_api_key")
        ),
        MountOAuth2Middleware(
            issuer="https://auth.example.com",
            client_id="my-client-id",
            client_secret="my-client-secret",
        ),
        AuthFilterMiddleware(
            filter_fields=["user"],
        ),
    ],
)
```

With this configuration, requests can authenticate via either API key or OAuth2 token.

### Configuration

```yaml
modules:
  auth_filter:
    _target_: csp_gateway.AuthFilterMiddleware
    filter_fields:
      - user  # Filter structs by "user" field
    cookie_name: token  # Should match auth middleware's api_key_name
```

### Usage

#### Example Scenario

Suppose you have a struct with a `user` field:

```python
class TradeData(GatewayStruct):
    user: str
    symbol: str
    price: float
```

And your external validator returns identity like:

```python
def validate_api_key(api_key: str, settings, module) -> dict | None:
    if api_key == "alice_key":
        return {"user": "alice", "role": "trader"}
    return None
```

When Alice authenticates with `alice_key`, the `AuthFilterMiddleware` will:

1. Extract her identity `{"user": "alice", ...}` from the auth middleware's store
1. Filter all REST responses to only include `TradeData` records where `user == "alice"`
1. Filter all WebSocket messages similarly

#### Server Configuration

```python
from ccflow import PyObjectPath
from csp_gateway import (
    Gateway,
    MountRestRoutes,
    MountExternalAPIKeyMiddleware,
    AuthFilterMiddleware,
)

gateway = Gateway(
    modules=[
        # ... your data modules ...
        MountRestRoutes(force_mount_all=True),
        MountExternalAPIKeyMiddleware(
            external_validator=PyObjectPath("my_module:validate_api_key")
        ),
        AuthFilterMiddleware(
            filter_fields=["user"],  # Filter on user field
            cookie_name="token",      # Match auth middleware
        ),
    ],
    # ...
)
```

### Multiple Filter Fields

You can specify multiple fields to filter on. All specified fields must match for a record to be included:

```yaml
modules:
  auth_filter:
    _target_: csp_gateway.AuthFilterMiddleware
    filter_fields:
      - user
      - tenant
```

With this configuration, if identity is `{"user": "alice", "tenant": "acme"}`, only records where both `user == "alice"` AND `tenant == "acme"` will be returned.

### How It Works

1. **REST Responses**: The middleware installs a Starlette middleware that intercepts JSON responses, parses them, filters records based on identity, and returns filtered results.

1. **WebSocket Responses**: The middleware integrates with `MountWebSocketRoutes` to filter messages before they are sent to clients.

1. **Identity Extraction**: Identity is retrieved via the `IdentityAwareMiddlewareMixin` interface. Each auth middleware implements async `get_identity_from_credentials()` which extracts credentials from cookies, headers, or query params and returns the user identity. This supports both local identity stores and external validation services.

### Per-Identity Cache for `/last` Endpoints

By default, `/last` returns the most recent record on a channel, then filters it. This can result in empty responses if the last record doesn't match the user's identity.

For channels where you need per-identity "last" values, use `identity_cache_channels`:

```yaml
modules:
  auth_filter:
    _target_: csp_gateway.AuthFilterMiddleware
    filter_fields:
      - user
    identity_cache_channels:
      include:
        - user_data
        - trades
```

When enabled, the middleware:

1. Subscribes to the specified channels via CSP
1. Maintains a per-identity cache: `{channel: {identity_value: last_record}}`
1. Intercepts `/last` requests for cached channels and serves from cache

This ensures Alice always gets her most recent `user_data` record, even if Bob's record arrived more recently.

```python
AuthFilterMiddleware(
    filter_fields=["user"],
    identity_cache_channels=ChannelSelection(include=["user_data", "trades"]),
)
```

### Send Validation

For channels where you want to ensure users can only send data with their own identity, use `send_validation_channels`:

```yaml
modules:
  auth_filter:
    _target_: csp_gateway.AuthFilterMiddleware
    filter_fields:
      - user
    send_validation_channels:
      include:
        - user_data
```

When enabled for a channel, the middleware validates that the identity field in the POST body matches the authenticated user. If Alice tries to send data with `user: "bob"`, the request is rejected with a 403 Forbidden response.

```python
AuthFilterMiddleware(
    filter_fields=["user"],
    send_validation_channels=ChannelSelection(include=["user_data"]),
)
```

### Next Filtering

For channels where you want `/next` to wait for a matching record (rather than just filtering), use `next_filter_channels`:

```yaml
modules:
  auth_filter:
    _target_: csp_gateway.AuthFilterMiddleware
    filter_fields:
      - user
    next_filter_channels:
      include:
        - user_events
    next_filter_timeout: 30.0  # Timeout in seconds
```

When enabled, `/next` requests will loop internally until a record matching the user's identity arrives, or until the timeout is reached (returning 408 Request Timeout).

```python
AuthFilterMiddleware(
    filter_fields=["user"],
    next_filter_channels=ChannelSelection(include=["user_events"]),
    next_filter_timeout=30.0,  # Default is 30 seconds
)
```

## MountOAuth2Middleware

`MountOAuth2Middleware` provides OAuth2/OIDC authentication for the Gateway REST API, WebSocket API, and UI. It supports authorization code flow with OIDC discovery and token introspection/validation.

### Configuration

```yaml
modules:
  oauth:
    _target_: csp_gateway.MountOAuth2Middleware
    issuer: "https://auth.example.com"
    client_id: "my-client-id"
    client_secret: "my-client-secret"
    scopes:
      - openid
      - profile
      - email
```

### Attributes

| Attribute           | Type        | Description                                                 |
| ------------------- | ----------- | ----------------------------------------------------------- |
| `issuer`            | `str`       | The OAuth2/OIDC issuer URL (e.g., https://auth.example.com) |
| `client_id`         | `str`       | OAuth2 client identifier                                    |
| `client_secret`     | `str`       | OAuth2 client secret (required for confidential clients)    |
| `scopes`            | `List[str]` | OAuth2 scopes to request (default: openid, profile, email)  |
| `token_url`         | `str`       | Token endpoint URL (auto-discovered from issuer if not set) |
| `authorize_url`     | `str`       | Authorization endpoint URL (auto-discovered if not set)     |
| `userinfo_url`      | `str`       | Userinfo endpoint URL (auto-discovered if not set)          |
| `introspection_url` | `str`       | Token introspection endpoint (optional)                     |
| `audience`          | `str`       | Expected audience claim for JWT validation                  |
| `verify_ssl`        | `bool`      | Whether to verify SSL certificates (default: True)          |

### Example

```python
from csp_gateway import Gateway, MountRestRoutes, MountOAuth2Middleware

gateway = Gateway(
    modules=[
        MountRestRoutes(),
        MountOAuth2Middleware(
            issuer="https://auth.example.com",
            client_id="my-client-id",
            client_secret="my-client-secret",
        ),
    ],
    # ...
)
```

### Credential Sources

OAuth2 tokens can be provided via:

1. **Cookie**: Session cookie set after authorization code flow (default name: `token`)
1. **Authorization header**: `Authorization: Bearer <access_token>`

When using Bearer token authentication, the middleware validates the token against the introspection or userinfo endpoint and returns the user identity.

## MountSimpleAuthMiddleware

`MountSimpleAuthMiddleware` provides simple username/password or custom credential-based authentication using an external validation function. It supports both HTTP Basic Auth and form-based login.

### Configuration

```yaml
modules:
  simple_auth:
    _target_: csp_gateway.MountSimpleAuthMiddleware
    external_validator: "myapp.auth:my_validator"
    enable_basic_auth: true
    enable_form_login: true
```

### Attributes

| Attribute            | Type           | Description                                          |
| -------------------- | -------------- | ---------------------------------------------------- |
| `external_validator` | `PyObjectPath` | Path to external validation function                 |
| `use_host_auth`      | `bool`         | Use host/system authentication (default: False)      |
| `domain`             | `str`          | Cookie domain for session cookies                    |
| `cookie_name`        | `str`          | Cookie name for session storage (default: "session") |
| `session_timeout`    | `timedelta`    | Session timeout duration (default: 12 hours)         |
| `enable_basic_auth`  | `bool`         | Whether to enable HTTP Basic Auth (default: True)    |
| `enable_form_login`  | `bool`         | Whether to enable form-based login (default: True)   |

> **Note:** At least one of `external_validator` or `use_host_auth` must be configured.

### Host/System Authentication

For system user authentication, enable `use_host_auth`:

```yaml
modules:
  simple_auth:
    _target_: csp_gateway.MountSimpleAuthMiddleware
    use_host_auth: true
```

This allows users to authenticate with their system username and password. The authentication method is platform-specific:

**Unix/Linux/macOS (PAM)**

Requires `pamela` or `python-pam` package:

```bash
pip install pamela  # or: pip install python-pam
```

The identity dict includes Unix user information:

```python
{
    "user": "alice",
    "uid": 1001,
    "gid": 1001,
    "home": "/home/alice",
    "shell": "/bin/bash",
    "gecos": "Alice Smith",
}
```

**Windows**

Requires `pywin32` package:

```bash
pip install pywin32
```

The identity dict includes Windows user information:

```python
{
    "user": "alice",
    "full_name": "Alice Smith",
    "home": "C:\\Users\\alice",
    "comment": "",
}
```

> **Note:** Host authentication requires appropriate system permissions. The process running the gateway must have access to authenticate users.

### Validator Function

The external validator function should have the following signature:

```python
def my_validator(username: str, password: str, settings: GatewaySettings, module) -> dict | None:
    """Validate credentials and return identity dict or None."""
    if username == "admin" and password == "secret":
        return {"user": username, "role": "admin"}
    return None
```

### Example

```python
from ccflow import PyObjectPath
from csp_gateway import Gateway, MountRestRoutes, MountSimpleAuthMiddleware

gateway = Gateway(
    modules=[
        MountRestRoutes(),
        MountSimpleAuthMiddleware(
            external_validator=PyObjectPath("myapp.auth:my_validator"),
        ),
    ],
    # ...
)
```

### Credential Sources

Credentials can be provided via:

1. **Cookie**: Session cookie set after form login (default name: `session`)
1. **HTTP Basic Auth header**: `Authorization: Basic <base64(username:password)>`
1. **Form POST**: Submit credentials to the login endpoint

When using Basic Auth, the middleware decodes the credentials and validates them against the external validator on each request.

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
