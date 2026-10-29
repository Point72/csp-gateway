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

## Frontend providers

The UI above is served by [spaday](https://github.com/1kbgz/spaday), the default frontend provider. The legacy React/Perspective frontend is still available, selected per gateway with the `UI_PROVIDER` setting. Both render the same pieces from the same modules — the Perspective workspace, layout selector, theme toggle, and the settings-drawer actions (shutdown, logs, channels graph, email) — and the spaday provider adds a "send to a channel" form panel.

Select a provider in your gateway configuration:

```yaml
port: 8000

gateway:
  settings:
    UI_PROVIDER: spaday
```

`UI_PROVIDER` defaults to `spaday`; set it to `default` for the legacy React/Perspective UI, which requires the bundled Javascript build and is slated for removal. Everything else — modules, the REST API, authentication, and `ROOT_PATH` sub-path serving — behaves the same.

The white-labeling settings (`TITLE`, `HEADER_LOGO`, `FOOTER_LOGO`, `CUSTOM_CSS`, `CUSTOM_JS`, `CUSTOM_STATIC_DIR`) apply to both providers, with one difference under spaday: `CUSTOM_JS` files are imported as ES modules rather than loaded as classic `<script>` tags, so a custom script cannot rely on being in global scope.

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

### Module panels and row actions

A module contributes to the spaday UI from its `ui(self, app)` hook, which runs once at startup after every module's `rest()`.

A main panel opens beside the Perspective workspace, the way the channels graph and logs do. Register it with `add_tab`, and give users a way to open it, such as a button in the settings drawer:

```python
from csp_gateway.server.web.spaday_ui import Region

def ui(self, app):
    app.add_tab("tickets", "Tickets", self._ticket_panel())
    app.add(Region.DRAWER_RIGHT, app.tab_button("Tickets", "tickets"))
```

By default the main tabs open, select and close but cannot be dragged. Set `UI_LOCK_LAYOUT: false` to let users split and stack them beside the workspace. Tabs inside the Perspective workspace stay inside it either way.

Live state reaches the browser through `app.model(namespace, Model, scope="session")`, called from `ui()`. It returns a handle whose `publish()` is safe to call from any thread. Fields arrive under `<namespace>.`, so several modules can each publish a model; namespaces must be Python identifiers. All of a page's models share one websocket at `/ws`.

UI state is never shared between visitors. Each page load is its own session, and `scope` decides how far its copy of a model reaches:

- `"session"` (the default): each page load has its own copy, so a half-filled form in one tab is not seen in another.
- `"user"`: one copy per authenticated user, shared by that user's tabs and no one else's. Without authentication there is no user to share with, so it behaves like `"session"`.

`publish` accepts either a value or a callable that receives the page's identity (`None` when unauthenticated), so a module can show each user only their own data. Identity comes from the `AuthFilterMiddleware` when one is configured, and otherwise from any identity-aware auth middleware (API key, OAuth, simple auth).

`add_row_action` puts a button on every row of a workspace table and runs a spaday action when it is clicked. The click event's `detail` carries `table`, `action` and `key`, the row's index value:

```python
from spaday.actions import CallEndpoint, concat, event_prop, field, obj

app.add_row_action(
    "orders",
    "cancel",
    concat("Cancel into ", field("draft")),  # tooltip; labels may follow the store
    icon="delete",  # or text="..."; built-in icons are copy, delete and add
    handler=CallEndpoint("POST", "/api/v1/my_module/cancel", obj({"id": event_prop("detail.key")})),
)
```

A table's buttons share one `actions` column at the start of its grids, next to the real columns. Only tables with an index get buttons, and they are disabled while a view is grouped or split.

`app.focus_table(table, filter=None)` is an action that brings the workspace forward and selects the panel already showing `table`, opening a new tab only when none does. `filter` takes Perspective filter clauses, which may hold expressions, and applies them to that panel alone.
