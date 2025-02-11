`csp-gateway` provides an automatically generated UI based on React and [Perspective](https://perspective.finos.org).

> [!NOTE]
> To enable the UI, ensure you run your [`Gateway`](Overview#Gateway) with `ui=True` and include the `MountPerspectiveTables` module.

## Perspective

Perspective is an interactive analytics and data visualization component, which is especially well-suited for large and/or streaming datasets.
See the [Perspective Documentation](https://perspective.finos.org/guide/) (and the media section in particular) for more information on how to use Perspective.

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
