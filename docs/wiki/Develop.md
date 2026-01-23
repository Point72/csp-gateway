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

`GatewayModule` is a subclass of Pydantic `BaseModel`, and so has type validation ands Hydra-driven configuration.

## Extending the API

When you write a `GatewayModule`, you can provide a method `rest` to add or modify FastAPI routes.

Here is a simple example that just adds a "hello, world" route.

```python
class ExampleModule(GatewayModule):
    def connect(self, channels: ExampleGatewayChannels):
        pass

    def rest(self, app: GatewayWebApp) -> None:
        # Get API Router
        api_router: APIRouter = app.get_router("api")

        # add route to return "hello world"
        @api_router.get("hello", responses=get_default_responses(), response_model=str, tags=["Utility"])
        async def hello_world() -> str:
            return "hello world!"

```

## Extending the UI

`csp-gateway` is designed as an all-in-one application builder.
However, sometimes it is convenient to white-label the frontend beyond what is currently exposed.

To this end, `csp-gateway` publishes its Javascript frontend as a library to [npmjs.com](https://www.npmjs.com/).

You can extend the frontend with customizations like so:

### Install

Install the Javascript library `@point72/csp-gateway` into your project.

### React

Here is an example React app which replaces the default `csp-gateway` logo with a logo of a gate:

```javascript
import React from "react";
import { createRoot } from "react-dom/client";
import { FaToriiGate } from "react-icons/fa";

import App from "@point72/csp-gateway";

function HeaderLogo() {
  return <FaToriiGate size={40} />;
}

window.addEventListener("load", () => {
  const container = document.getElementById("gateway-root");
  const root = createRoot(container);

  root.render(<App headerLogo={<HeaderLogo />} />);
});
```

### Customization

Right now, the Javascript application exposes a small number of customizations, provided as `props` to the `App` React component.
We may extend these more in the future.

- `headerLogo`: React component to replace the top bar logo
- `footerLogo`: React component to add a bottom bar logo (bottom left)
- `processTables`: Custom function to preprocess Perspective tables, e.g. to configure default views
  - `processTables(default_perspective_layout_json, table_list, perspective_workspace, theme)`
- `overrideSettingsButtons`: Customize [settings buttons](UI#Settings) in the right-hand settings drawer
- `extraSettingsButtons`: Add additional settings buttons in the right-hand settings drawer
- `shutdown`: Customize the function invoked when calling the [_"Big Red Button"_](UI#Settings)

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
