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

## Alternative frontend: spaday

The React/Perspective UI above is the default. `csp-gateway` can optionally serve an alternative frontend built with [spaday](https://github.com/1kbgz/spaday), selected per gateway with the `UI_PROVIDER` setting. It renders the same pieces from the same modules — the Perspective workspace, layout selector, theme toggle, and the settings-drawer actions (shutdown, logs, channels graph, email), plus a "send to a channel" form panel — only the frontend technology differs.

It is an optional extra (it pulls in the `spaday` dependency):

```bash
pip install 'csp-gateway[spaday]'
```

Select it in your gateway configuration:

```yaml
port: 8000

gateway:
  settings:
    UI_PROVIDER: spaday
```

`UI_PROVIDER` defaults to `default` (the React/Perspective UI); set it to `spaday` to use the spaday frontend. Everything else — modules, the REST API, authentication, and `ROOT_PATH` sub-path serving — behaves the same. Selecting `spaday` without the extra installed raises a clear error at startup.

### Theming the spaday UI

The spaday shell is themed with design tokens rather than a stylesheet, set per mode with `THEME` and `THEME_DARK`:

```yaml
gateway:
  settings:
    UI_PROVIDER: spaday
    THEME:
      page: "#f7f2ea"
      surface: "#ffffff"
      wa_color_brand_fill_loud: "#8b1f2f"
    THEME_DARK:
      page: "#1a1412"
```

The recognized slots are `surface`, `surface_2`, `border`, `muted`, `text` and `page`; any key not in that list is emitted as a CSS custom property with underscores turned into dashes, so WebAwesome's own tokens (`wa_color_brand_fill_loud` above) can be set the same way. Unset slots fall back to that mode's built-in default, so `THEME_DARK` only needs the values that differ.

Tokens are the right tool for branding because the UI is built from web components whose internals are shadow DOM: they cannot be reached by an external stylesheet, but they do inherit custom properties.
