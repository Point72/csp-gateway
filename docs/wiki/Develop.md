## Writing Modules

Modules are subclasses of `GatewayModule`, and can be written easily.

Let's start with an example:

```python
class ExampleModule(GatewayModule):
    some_attribute: int = 0

    def connect(self, channels: ExampleGatewayChannels):
        # get channels with channels.get_channel
        # set channels with channels.set_channel
        ...

    def rest(self, app: "GatewayWebApp") -> None:
        # add APIs to `app`
        # GatewayWebApp is a subclass of FastAPI
        ...

    def shutdown(self) -> None:
        # anything to run on clean shutdown
        # of the Gateway instance
        ...
```

`GatewayModule` is a subclass of Pydantic `BaseModel`, and so has type validation and Hydra-driven configuration.

## Extending the API

When you write a `GatewayModule`, you can provide a method `rest` to add or modify FastAPI routes.

Here is a simple example that just adds a "hello, world" route.

```python
class ExampleModule(GatewayModule):
    def connect(self, channels: ExampleGatewayChannels):
        pass

    def rest(self, app: GatewayWebApp) -> None:
        # Get API Router
        api_router: APIRouter = app.get_router("api", self.api_version)

        # add route to return "hello world"
        @api_router.get("hello", responses=get_default_responses(), response_model=str, tags=["Utility"])
        async def hello_world() -> str:
            return "hello world!"

```

## API versions

Routes are served under `/{API_PREFIX}/{version}`, `/api/v1` by default. `GatewaySettings.API_PREFIX`
and `GatewaySettings.API_VERSION_DEFAULT` change the default for the whole gateway. The old
`API_STR` setting is deprecated: pass it and it is split into those two fields with a warning, and it
remains readable as a derived property.

Every `GatewayModule` has an `api_version` field. Leave it `None` to follow the gateway default, or
set it to mount that module's routes somewhere else:

```python
Gateway(
    modules=[
        MountRestRoutes(mount_last=["example"]),                     # /api/v1/last/example
        MountRestRoutes(mount_last=["example"], api_version="v2"),   # /api/v2/last/example
    ],
    ...
)
```

Versions are created on demand — asking for a router under a version that does not exist yet
registers it, and it is mounted when the app is finalized. The `app` and `public` routers hold
routes outside the API prefix and are shared by every version.

`GET /api` (or `/{API_PREFIX}`) lists the versions the gateway serves and where each is mounted, so
clients can discover them rather than guess.

Auth is the exception: login and logout always live on the default version, so there is a single
login path no matter which versions the rest of the gateway serves. Setting `api_version` on an auth
middleware has no effect.

A subclass that owns a versioned surface can pin the version rather than leaving it to configuration:

```python
class MyV2Routes(MountRestRoutes):
    api_version: str = "v2"
```

To serve the same routes on more than one version, add the module more than once with different
`api_version` values.

Build URLs with `app.api_path(path, self.api_version)` (or `app.api_url(...)` from a `ui()` hook,
which additionally applies `ROOT_PATH`) instead of interpolating `settings.API_STR`, so links follow
the routes the module actually mounted.

A module whose UI links to routes *another* module mounted — `MountSendForm` posting to the send
routes, say — should resolve the version rather than assume its own:

```python
version = app.web_app.api_version_for("send", self.api_version)
```

That returns `self.api_version` when it is set, and otherwise the version those routes were actually
mounted under. Every module's `rest()` runs before any module's `ui()`, so the answer is complete by
the time a `ui()` hook asks.

## Extending the UI

`csp-gateway` is designed as an all-in-one application builder.
However, sometimes it is convenient to white-label the frontend beyond what is currently exposed.

There are two ways to customize the UI, neither of which needs a Javascript build:

1. **Server-side configuration** — set fields on `GatewaySettings`.
1. **Component packages** — load your own spaday components alongside the ones the gateway ships.

### Server-side configuration

The simplest way to white-label the UI is through settings. The gateway renders the page from them
and exposes the same values at `GET /ui-config`.

- `TITLE`: Page title and header title.
- `HEADER_LOGO` / `FOOTER_LOGO`: Logo image, given as an `http(s)` URL, a `data:` URI, an
  already-served URL path, or a local file path. Local files are served automatically.
- `CUSTOM_CSS`: List of CSS files to inject (URLs or local file paths).
- `CUSTOM_JS`: List of Javascript files to inject (URLs or local file paths), imported as ES modules
  after the UI's own scripts.
- `CUSTOM_STATIC_DIR`: A local directory served at `/custom`. The entire directory is exposed as
  public static content (useful for assets like logos, e.g. `/custom/logo.svg`); its top-level `*.js`
  and `*.css` files are additionally auto-injected into the UI in sorted filename order. Do not point
  this at a directory containing private files.
- `UI_PACKAGES`: Extra spaday component packages to load, each given as the name a package registers
  under its spaday entry point or a dotted path to a `ComponentPackage` (or a callable returning
  one). Adds to the packages the gateway ships rather than replacing them.
- `ROOT_PATH`: URL path prefix the app is served under when behind a reverse proxy that strips the
  prefix (e.g. `/watchtower`). It is passed to the ASGI server as `root_path` and used to prefix all
  server-rendered asset and API URLs (the UI runtime, logos, custom JS/CSS, `/ui-config`, docs) so the
  UI works under a sub-path. Leave empty when served at a domain root.

### Component packages

For deeper customization, point `UI_PACKAGES` at your own
[spaday](https://github.com/1kbgz/spaday) component package. Its elements are then available to the
page alongside the gateway's own, and a module's `ui()` hook can place them.

## Advanced Usage

### Dynamic Channels

`Gateway` instances require a static `GatewayChannels` instance in order to connect the list of `GatewayModule` instances.
In layman's terms, all data channels need to be known in advance.

However, it is sometimes convenient to allow a `GatewayModule` to create channels dynamically, e.g. not literally in code.
Although these can't be consumed by other `GatewayModule` instances, they are still valuable for the API/UI.

A `GatewayModule` may overload the `dynamic_channels` method and return a dictionary mapping `str` to `GatewayStruct` subclass,
and these channels will become available in the `GatewayChannels` instance and thus the REST API and UI.

```python
def dynamic_channels(self) -> Optional[Dict[str, Union[Type[GatewayStruct], Type[List[GatewayStruct]]]]]:
    """
    Channels that this module dynamically adds to the gateway channels when this module is included into the gateway.

    Returns:
        Dictionary keyed by channel name and type of the timeseries of the channel as values.
    """
```

### Custom Struct Validators

`GatewayStruct` can have **validators** attached to a struct type. They run automatically during pydantic validation — whenever a struct is deserialized from the REST `/send` endpoint, from `type_adapter().validate_python(...)`, from JSON snapshot replay, or from Kafka and filedrop ingestion — and for nested structs when a containing struct is validated. They do **not** run on native (non-pydantic) Python construction (`MyStruct(...)`).

Registrations accept arbitrary callables (functions, lambdas, bound methods), may be added dynamically at graph-build time, and are aggregated across the class hierarchy (base-class and subclass registrations both run). Registering on `GatewayStruct` or `GatewayPydanticMixin` therefore instruments **every** struct in the process, and only `clear_validators()` on that same class removes it.

A validator receives a value and returns the (possibly transformed) value. It rejects the input by raising `ValueError` (or `AssertionError`), which the REST API reports as a `422`. **Any other exception type propagates uncaught and reaches the client as a `500`** — so a validator handling untrusted input must raise `ValueError` explicitly rather than letting a `KeyError` escape from a dictionary lookup. Returning `None` is an error unless the incoming value was itself `None`, and an `after` validator must return an instance of the class being validated (returning some other type raises `TypeError`).

`mode="before"` (alias `"pre"`) runs on the raw input (typically a dict) prior to construction — useful for validating or reshaping legacy/aliased input shapes — while `mode="after"` (alias `"post"`, the default) runs on the constructed struct.

When the value being validated is *already* a constructed struct — a nested field holding an instance, or re-validating an object — there is no raw input to reshape, so `before` validators are skipped for that value. `after` validators always run. This means a `before` validator only ever sees unconstructed input and does not need to guard against being handed a struct.

```python
class MyOrder(GatewayStruct):
    quantity: float = 0.0

# "after" (default): validate the constructed struct — raise to reject
def _require_qty(order):
    if order.quantity <= 0:
        raise ValueError("quantity must be positive")
    return order

MyOrder.add_validator(_require_qty)

# "before": validate/reshape the raw input (e.g. accept a legacy field name)
MyOrder.add_validator(
    lambda d: ({k: v for k, v in d.items() if k != "qty"} | {"quantity": d["qty"]}) if "qty" in d else d,
    mode="before",
)

# bound methods work too (e.g. to close over a secmaster), as do the decorator forms:
@MyOrder.add_validator                 # bare -> "after"
def _normalize(order):
    return order

@MyOrder.add_validator(mode="before")  # decorator factory with a mode
def _accept_legacy(d):
    return d
```

Per validation the order is: `before` validators → construct → `after` validators → the struct's built-in after-validation hook (`_validate_gateway_struct_after`, which a subclass may override). Because `after` validators run before that hook, they may normalize data the hook then checks.

Both `after` validators and the hook are dispatched on the *concrete* type of the constructed struct. A field annotated with a base class that holds a subclass instance still runs the subclass's rules, so a subclass cannot have them bypassed by being passed through a base-typed field.

When a caller asks for a fresh `id` or `timestamp` (the `force_new_id` / `force_new_timestamp` validation context, used by Kafka and filedrop ingestion), those values are stripped both before and after the `before` validators run — a validator that rebuilds the input dict cannot reinstate a caller-supplied `id`.

Use `clear_validators(mode=None)` to remove registrations — handy for teardown or idempotent re-registration when they are attached at gateway-build time:

```python
MyOrder.clear_validators()               # clears both "before" and "after"
MyOrder.clear_validators(mode="before")  # or "pre" / "after" / "post"
```

Because native construction bypasses pydantic, a struct built inside a csp graph never has its validators run. Call `run_validators` to apply them explicitly:

```python
order = MyOrder.run_validators(MyOrder(quantity=10))  # raises if a validator rejects
```

### Module Requirements

`GatewayModule` instances can get/set arbitrary channels from a `GatewayChannels` instance.
By default, if any `GatewayModule` gets a channel that no other `GatewayChannel` sets, an exception will be thrown during graph construction.

Sometimes a `GatewayModule` wants to `get_channel` a channel in a `GatewayChannels`, but not require that that channel ever tick.
For Example, a module like `PrintChannels` wants to get every channel, but doesn't require that any tick.

For this purpose, any `GatewayModule` can configure its attribute `requires: Optional[ChannelSelection]` with the name of the channels it requires.
Any other channels that it gets will be considered optional.

For example, the `PrintChannels` module set its default to be empty, indicating that it does not require any channels - all are optional.

```python
requires: Optional[ChannelSelection] = []
```

#### Channel Selection

`ChannelSelection` is a class to representing channel selection options for filtering channels based on inclusion and exclusion criteria.

It is coercible from a python list, and has the following attributes:

- **include** (`Optional[List[str]]`): A list of channel names to include in the selection.
- **exclude** (`Set[str]`): A list of channel names to exclude from the selection.

### Module Disable

Any module in a `csp-gateway` application can be disabled via configuration, or via the `disabled: bool` attribute.

For example, in the following yaml configuration, the `MountPerspectiveTables` module is disabled.

```yaml
modules:
  example_module:
    _target_: csp_gateway.server.demo.simple.ExampleModule
  mount_perspective_tables:
    _target_: csp_gateway.MountPerspectiveTables
    disabled: true
  mount_rest_routes:
    _target_: csp_gateway.MountRestRoutes
    force_mount_all: True
```

> [!TIP]
>
> This attribute, like all others, can be overridden for config.
> This makes it very convenient to write things like debug/instrumentation modules!

### Block Setting Channels

Documentation coming soon!

## Testing Gateway Applications

Testing CSP-based applications requires a different approach than traditional unit testing. Because CSP operates on time-series data with sequenced events, tests need to simulate the passage of time and verify that the correct values are produced at the correct times. Simply checking inputs and outputs at a single point in time is insufficient—you need to ensure that your modules respond correctly to events as they unfold over time.

### Why Time-Sequenced Testing Matters

In a CSP graph:

- Events arrive at specific times
- Modules react to events and may produce outputs at the same or later times
- The order and timing of events affects the behavior of the system
- State accumulates over time

Traditional unit tests that call a function and check its return value cannot capture this temporal behavior. The `GatewayTestHarness` solves this by allowing you to:

1. **Send data at specific times** - Simulate events arriving at your module
1. **Advance time** - Move forward in simulated time to trigger time-based logic
1. **Assert on values** - Verify that channels contain expected values
1. **Assert on tick counts** - Verify that channels ticked the expected number of times

### GatewayTestHarness

The `GatewayTestHarness` is a special `GatewayModule` that you include in your test gateway. It allows you to script a sequence of events and assertions that will be executed during the CSP graph's runtime.

#### Key Methods

| Method                                       | Description                                                           |
| -------------------------------------------- | --------------------------------------------------------------------- |
| `send(channel, value)`                       | Send a value to a channel                                             |
| `delay(timedelta\|datetime)`                 | Move forward in time                                                  |
| `advance(delay, msg, pre_msg)`               | Reset state and advance time (combines `reset`, `print`, and `delay`) |
| `reset()`                                    | Reset tick counts and tracked values                                  |
| `assert_ticked(channel, count)`              | Assert a channel ticked a specific number of times                    |
| `assert_equal(channel, value)`               | Assert the last value on a channel equals expected                    |
| `assert_attr_equal(channel, attr, value)`    | Assert an attribute of the last value equals expected                 |
| `assert_attrs_equal(channel, values)`        | Assert multiple attributes equal expected values (dict)               |
| `assert_type(channel, type)`                 | Assert the last value is of a specific type                           |
| `assert_len(channel, length)`                | Assert the length of a list channel                                   |
| `assert_ticked_values(channel, assert_func)` | Apply a custom assertion function to all ticked values                |
| `assert_value(channel, assert_func)`         | Apply a custom assertion function to the current value                |
| `print(msg)`                                 | Print a message during test execution                                 |
| `print_ticked()`                             | Print all ticked values (useful for debugging)                        |
| `print_tick_counts()`                        | Print tick counts for all channels                                    |

### Basic Example

Here's a simple example testing a custom module that doubles input values:

```python
from datetime import datetime, timedelta
from typing import Type

import csp
from csp import ts

from csp_gateway import Gateway, GatewayChannels, GatewayModule, GatewayStruct
from csp_gateway.testing import GatewayTestHarness


# Define your struct
class MyData(GatewayStruct):
    value: float


# Define your channels
class MyChannels(GatewayChannels):
    input_data: ts[MyData] = None
    output_data: ts[MyData] = None


# Define your module under test
class DoublerModule(GatewayModule):
    def connect(self, channels: MyChannels):
        input_channel = channels.get_channel(MyChannels.input_data)

        @csp.node
        def double_value(data: ts[MyData]) -> ts[MyData]:
            if csp.ticked(data):
                return MyData(value=data.value * 2)

        channels.set_channel(MyChannels.output_data, double_value(input_channel))


# Define your gateway
class MyGateway(Gateway):
    channels_model: Type[MyChannels] = MyChannels


# Write the test
def test_doubler_module():
    # Create harness watching both input and output channels
    h = GatewayTestHarness(test_channels=["input_data", "output_data"])

    # Send a value and assert on the output
    h.send(MyChannels.input_data, MyData(value=5.0))
    h.assert_attr_equal(MyChannels.output_data, "value", 10.0)
    h.assert_ticked(MyChannels.output_data, 1)

    # Advance time and send another value
    h.advance(delay=timedelta(seconds=1))
    h.send(MyChannels.input_data, MyData(value=7.5))
    h.assert_attr_equal(MyChannels.output_data, "value", 15.0)
    h.assert_ticked(MyChannels.output_data, 1)  # Count reset after advance

    # Create and run the gateway
    gateway = MyGateway(
        modules=[h, DoublerModule()],
        channels=MyChannels(),
    )
    csp.run(gateway.graph, starttime=datetime(2024, 1, 1), endtime=timedelta(hours=1))
```

### Using Custom Assertion Functions

For more complex assertions, use `assert_ticked_values` or `assert_value`:

```python
def test_with_custom_assertions():
    h = GatewayTestHarness(test_channels=["output_data"])

    h.send(MyChannels.input_data, MyData(value=5.0))
    h.delay(timedelta(seconds=1))
    h.send(MyChannels.input_data, MyData(value=10.0))

    # Custom assertion on all ticked values
    def check_all_values(ticked_values):
        # ticked_values is a list of (datetime, value) tuples
        assert len(ticked_values) == 2
        assert ticked_values[0][1].value == 10.0  # First output (5 * 2)
        assert ticked_values[1][1].value == 20.0  # Second output (10 * 2)

    h.assert_ticked_values(MyChannels.output_data, check_all_values)

    # Or assert on just the current value
    def check_current(value):
        assert value.value == 20.0

    h.assert_value(MyChannels.output_data, check_current)

    gateway = MyGateway(modules=[h, DoublerModule()], channels=MyChannels())
    csp.run(gateway.graph, starttime=datetime(2024, 1, 1), endtime=timedelta(hours=1))
```

### Testing with Dictionary Baskets

For channels that are dictionary baskets, use a tuple of `(channel, key)` to reference specific basket entries:

```python
from csp import Enum


class Side(Enum):
    BUY = 1
    SELL = 2


class OrderChannels(GatewayChannels):
    orders: Dict[Side, ts[MyData]] = None


def test_basket_channel():
    h = GatewayTestHarness(test_channels=["orders"])

    # Send to specific basket keys
    h.send(OrderChannels.orders, {Side.BUY: MyData(value=100.0)})
    h.assert_attr_equal((OrderChannels.orders, Side.BUY), "value", 100.0)

    h.delay(timedelta(seconds=1))
    h.send(OrderChannels.orders, {Side.SELL: MyData(value=50.0)})
    h.assert_attr_equal((OrderChannels.orders, Side.SELL), "value", 50.0)

    # ... run gateway
```

### Testing Tips

1. **Use `advance()` between test sections** - This resets tick counts and makes assertions clearer
1. **Use `verbose=True`** for debugging - `GatewayTestHarness(test_channels=[...], verbose=True)` prints all channel updates
1. **Use `print_ticked()` and `print_tick_counts()`** - Helpful for debugging test failures
1. **Test edge cases with timing** - Use `delay()` to test time-dependent behavior
1. **Keep tests focused** - Test one behavior per test function
