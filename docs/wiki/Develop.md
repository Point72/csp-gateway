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

It is coercable from a python list, and has the following attributes:

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
