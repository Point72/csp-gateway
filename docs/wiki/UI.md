`csp-gateway` provides an automatically generated UI based on React and [Perspective](https://perspective-dev.github.io/).

> [!NOTE]
> To enable the UI, ensure you run your [`Gateway`](Overview#Gateway) with `ui=True` and include the `MountPerspectiveTables` module.

## Perspective

Perspective is an interactive analytics and data visualization component, which is especially well-suited for large and/or streaming datasets.
See the [Perspective Documentation](https://perspective-dev.github.io/guide/) (and the media section in particular) for more information on how to use Perspective.

## Top Bar

The top bar has several buttons on the righthand side for selecting/saving/downloading layouts, toggling light/dark mode, and opening the settings drawer.

### Layouts

Perspective layouts are driven via JSON.
You can drag/drop to build your own layout, and click the save button to store it locally in your browser.
Layouts can also be downloaded as a JSON, and integrated into the server-side configuration for sharing across multiple users.

```yaml
modules:
  mount_perspective_tables:
    _target_: csp_gateway.MountPerspectiveTables
    layouts:
      A Layout Name: "<The JSON you downloaded>"
```

## Settings

The rightmost top bar button opens the settings drawer. Depending on your server configuration, this has one or more [Controls](MountControls).

- _"Big Red Button"_: Shut down the backend `Gateway` server
- Email: if your server settings have an email contact, this will generate a `mailto:` link
- Logs: if your server includes the [`MountOutputsFolder`](MountOutputsFolder) module, this will link to an integrated log and configuration viewer
- Graph View: if your server includes the [`MountChannelsGraph`](MountChannelsGraph) module, this will link to an integrated graph viewer

## Frontend

The UI above is served by [spaday](https://github.com/1kbgz/spaday). It renders from the same
modules that serve the REST API — the Perspective workspace, layout selector, theme toggle, the
"send to a channel" form, and the settings-drawer actions (shutdown, logs, channels graph, email).

The legacy React/Perspective frontend, selected with `UI_PROVIDER: default`, was removed after
3.0.0, along with the bundled Javascript build it needed. `UI_PROVIDER` is kept, and only accepts
`spaday`, so a configuration that names the provider still loads:

```yaml
port: 8000

gateway:
  settings:
    UI_PROVIDER: spaday
```

The white-labeling settings (`TITLE`, `HEADER_LOGO`, `FOOTER_LOGO`, `CUSTOM_CSS`, `CUSTOM_JS`,
`CUSTOM_STATIC_DIR`) all still apply. Note that `CUSTOM_JS` files are imported as ES modules rather
than loaded as classic `<script>` tags, so a custom script cannot rely on being in global scope.

The spaday UI takes its colours from the shell's own light and dark palettes, which are published as the `--spa-surface`, `--spa-surface-2`, `--spa-border` and `--spa-muted` custom properties at zero specificity. A `CUSTOM_CSS` file is linked after them, so redefining those properties is enough to rebrand the chrome:

```css
spa-app { --spa-surface: #ffffff; --spa-border: #dde3ec; }
html.wa-dark spa-app { --spa-surface: #222b39; --spa-border: #3b4860; }
```

Component internals are shadow DOM and cannot be selected from an external stylesheet, so restyling those means setting the WebAwesome custom properties they document rather than writing rules against their markup.

### Bringing your own components

Restyling only goes as far as the elements the page already loads. A deployment with its own element library adds it with `UI_PACKAGES`, which takes either the name a distribution registers under its `spaday.components` entry point, or a dotted path to a `ComponentPackage` (or to a callable returning one):

```yaml
gateway:
  settings:
    UI_PACKAGES:
      - my_component_library
      - my_app.ui.PACKAGE
```

A module that ships its own elements can load them from its `ui()` hook instead, which keeps the module self-contained rather than requiring every config that uses it to remember the setting:

```python
def ui(self, app: GatewayUI) -> None:
    app.package(my_app.ui.PACKAGE)
    app.add(Region.MAIN, MyElement())
```

Either way the package's assets are served alongside the built-in ones, and the gateway's own packages are always loaded, so a contributed package can rely on them. Loading the same package twice is de-duplicated.

Loading the package is what makes its elements *work*: the browser treats an unregistered tag as an inert unknown element, so a component built from an unloaded package renders an empty panel without raising anything. If a contributed panel is blank, check that its package is loaded before looking anywhere else.
