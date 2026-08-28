"""spaday-based frontend provider for the Gateway web application.

This is the default UI, selected via `Settings.UI_PROVIDER == "spaday"` (the legacy
Perspective/React frontend remains available as `"default"`). A `GatewayUI` handle is passed to
each module's `ui()` hook (mirroring how `GatewayWebApp` is passed to `rest()`); modules register a
main panel or add header actions, and `GatewayUI` assembles a single spaday page and
mounts it onto the FastAPI app.

This module imports `spaday` at import time, so it is imported only when the spaday provider is
selected — from `GatewayWebApp` when `UI_PROVIDER == "spaday"`, and lazily from the modules' `ui()`
hooks (which only run under that provider) — never from `csp_gateway.server.web` at large.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field as _dc_field
from typing import TYPE_CHECKING, Any

from pydantic import TypeAdapter
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount, WebSocketRoute
from starlette.websockets import WebSocket

try:
    import spaday  # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The spaday UI provider (Settings.UI_PROVIDER='spaday') requires the 'spaday' "
        "dependency and its companion packages. Install them with: pip install 'csp-gateway[server]'."
    ) from exc

from spaday import Js, Wire, element
from spaday.actions import (
    CallEndpoint,
    Download,
    If,
    Invoke,
    Sequence,
    SetField,
    SetStorage,
    Toggle,
    ToggleField,
    all_,
    any_,
    by_id,
    concat,
    cond,
    eq,
    event_prop,
    event_value,
    field,
    not_,
    obj,
)
from spaday.backends.starlette import mount as _spaday_mount
from spaday.components.shell import AppShell, Column, Region, Row, Show, Toast
from spaday_perspective import PerspectivePanel
from spaday_regular_layout import RegularLayout, RegularLayoutFrame
from spaday_webawesome import (
    FormField,
    Tabs,
    WaButton,
    WaCallout,
    WaDialog,
    WaDrawer,
    WaIcon,
    WaOption,
    WaSelect,
    form,
)

if TYPE_CHECKING:
    from csp_gateway.server.web import GatewayWebApp

__all__ = (
    "GatewayUI",
    "Region",
    "SendSpec",
)

log = logging.getLogger(__name__)

# The tenant every connection shares when no auth middleware can identify it.
_ANONYMOUS_TENANT = "__anonymous__"
_CUSTOM_LAYOUT_NAME = "Custom Layout"
_CUSTOM_LAYOUT_STORAGE_KEY = "csp_gateway_demo_config"
_MAIN_LAYOUT_ID = "gateway-main-layout"
_WORKSPACE_ID = "gateway-workspace"
_WORKSPACE_TAB = "workspace"
_SEND_TAB = "send"
_TOAST_ID = "gateway-toasts"
_ACTION_RESULT = "action_result"
_GRAPH_FOCUS = "graph_focus"
_PERSPECTIVE_READY = "perspective_ready"


# Page-level resets that spaday's document template does not ship. The shell supplies its own light
# and dark values for the ``spa-*`` tokens, keyed off the ``wa-dark`` class that
# ``App().bind_root_class("wa-dark", "dark")`` toggles, and WebAwesome sets the matching
# ``color-scheme`` so the page canvas follows. Only the few tokens below are restated, to take the
# blue out of the chrome; ``:where()`` gives the shell's own values zero specificity, so a plain
# class selector wins.
PAGE_CSS = """<style>
      html, body { height: 100%; }
      body { margin: 0; font-family: system-ui, sans-serif; }
      spa-app { --spa-gap: 0.75rem; }
      /* Perspective's Pro themes are near-neutral greys (its surface is #242526), so the shell's
         blue-leaning neutrals read as a colour clash against the data. These keep each token's
         lightness and drop the hue, leaving the chrome a shade darker than the tables. Light is
         the unclassed default -- only ``wa-dark`` is toggled on the root -- so the base values go
         on ``:root`` and the dark block must follow it to win on source order. */
      :root {
        --spa-border: #e5e6e7;
        --spa-muted: #58595b;
      }
      .wa-dark {
        --spa-surface: #121314;
        --spa-surface-2: color-mix(in oklab, #121314, black 20%);
        --spa-border: #313234;
        --spa-muted: #949597;
      }
      /* The main region's tab layout: the workspace tab is full-bleed, and with a single open
         tab the chrome disappears entirely (the "only tab when there are more tabs" rule). */
      #gateway-main-layout { height: 100%; }
      #gateway-main-layout regular-layout-frame::part(container) { overflow: auto; }
      #gateway-main-layout regular-layout-frame[name="workspace"]::part(container) {
        padding: 0; overflow: hidden;
      }
      /* Tabs nothing could reopen (the workspace, add_tab(closeable=False)) hide their
         close control — the engine's close handler lives on the button, so hiding it
         removes the gesture entirely. */
      #gateway-main-layout regular-layout-frame[data-no-close]::part(close) { display: none; }
      #gateway-main-layout.spa-solo regular-layout-frame::part(titlebar) { display: none; }
      #gateway-main-layout.spa-solo regular-layout-frame::part(container) {
        margin: 0; border: none; border-radius: 0; box-shadow: none;
      }
      /* Channels graph: match the classic dagre-d3 page — red edges into a channel
         (setters), dashed edges out of a channel (getters). Arrowheads pick up the
         edge color via context-stroke. */
      .gateway-sets .spaday-dagre-edge-line { stroke: #f66; stroke-width: 2; }
      .gateway-gets .spaday-dagre-edge-line { stroke-width: 2; stroke-dasharray: 5 5; }
    </style>"""


@dataclass
class SendSpec:
    """One sendable channel for `send_panel`: the channel struct model plus its POST url, keys, overrides."""

    channel: str
    url: str
    model: Any
    keys: list[str] = _dc_field(default_factory=list)
    overrides: dict[str, dict[str, Any]] = _dc_field(default_factory=dict)


@dataclass
class _Contribution:
    """A component injected into a `Region`, with an ordering key (lower renders first)."""

    component: Any
    order: int = 0
    label: str | None = None


class ModelHandle:
    """A module's live UI state: one transports model, mirrored per authenticated tenant.

    Obtained from `GatewayUI.model()` in a module's `ui()` hook, which runs once at startup, and used
    afterwards to push updates from wherever the state actually changes -- a csp node, a REST handler.

    `publish` is safe to call from any thread. Values are computed per tenant, so a deployment running
    `AuthFilterMiddleware` keeps its per-identity filtering: pass a callable to derive each tenant's
    view of the state from its identity, or a plain value when every tenant may see the same thing.
    """

    def __init__(self, ui: GatewayUI, namespace: str, model: Any) -> None:
        self._ui = ui
        self._namespace = namespace
        self._model = model

    @property
    def namespace(self) -> str:
        return self._namespace

    def publish(self, value: Any) -> None:
        """Push new state to every connected tenant.

        ``value`` is either the state itself, or a callable taking a tenant's identity (``None`` when
        unauthenticated) and returning that tenant's view of it.
        """
        self._ui._publish(self._namespace, value)


class GatewayUI:
    """Collects UI contributions from modules and builds/mounts the spaday page.

    A single instance lives on `GatewayWebApp.ui` when the spaday provider is selected.
    Modules populate it from their `ui()` hook; `GatewayWebApp` calls `mount()` at
    finalization to attach the page to the FastAPI app.
    """

    def __init__(self, web_app: GatewayWebApp, settings: Any) -> None:
        self._web_app = web_app
        self._settings = settings
        self._regions: dict[Region, list[_Contribution]] = {}
        self._tabs: list[tuple[int, str, str, Any, bool]] = []
        self._store_seeds: dict[str, Any] = {}
        # Tables the workspace can show, recorded by `perspective_panel` so later contributions
        # (the channels graph) can drive it without knowing how it was configured.
        self._workspace_tables: list[str] = []
        # Live UI state: namespace -> (model, latest value factory). The hub and its models only exist
        # once a module declares one, so a gateway with no live state serves no websocket.
        self._models: dict[str, Any] = {}
        self._latest: dict[str, Any] = {}
        self._tenant_models: dict[Any, dict[str, tuple]] = {}
        self._tenant_identity: dict[Any, Any] = {}
        self._hub: Any = None
        self._loop: Any = None
        self._autosync: Any = None

    def model(self, namespace: str, model: Any) -> ModelHandle:
        """Declare live UI state this module publishes, mirrored into the page's signal store.

        `ui()` runs once at startup, so a module declares its state here and pushes to the returned
        handle later. Fields arrive in the browser under ``<namespace>.``, so several modules can
        publish without colliding, and a component binds to them like any other state::

            self._staging = app.model("staging", StagingView)
            app.add(Region.GUTTER_RIGHT, Table().compute("rows", field("staging.rows")))

        Each authenticated identity gets its own copy of the model, so what one user is shown is never
        broadcast to another.
        """
        if namespace in self._models:
            raise ValueError(f"UI model namespace already declared: {namespace}")
        self._models[namespace] = model
        return ModelHandle(self, namespace, model)

    @property
    def settings(self) -> Any:
        return self._settings

    @property
    def web_app(self) -> GatewayWebApp:
        return self._web_app

    def add(self, region: Region, component: Any, *, order: int = 0, label: str | None = None) -> None:
        """Inject a spaday `component` into a named shell `region`.

        This is the single contribution API. Multiple contributions to the same region render
        in ascending `order` (ties keep insertion order). The built-in chrome (logo, theme
        toggle, footer text, drawer toggles) occupies reserved order bands so module
        contributions slot in around them predictably. Build the component with one of the
        helpers (`perspective_panel`, `layout_selector`, `send_panel`, `link_button`,
        `post_button`, `confirm_button`) or hand-author any spaday component.

        `component` may also be a zero-argument callable returning one. Module `ui()` hooks run
        once at startup, so a callable is the way to render server-side state that changes after
        that (it is re-invoked on each page build, i.e. per page load).

        `label` names the contribution for regions that present their panels as tabs (the bottom
        drawer). It is ignored elsewhere, and the drawer only tabs when every panel in it is
        labelled -- otherwise an unlabelled panel would get a blank tab.
        """
        self._regions.setdefault(Region(region), []).append(_Contribution(component=component, order=order, label=label))

    def add_tab(self, name: str, label: str, component: Any, *, order: int = 0, closeable: bool = True) -> None:
        """Register a tab for the main window's tab layout.

        The main region always shows the workspace; registered tabs open on demand (via a
        `tab_button`) and get a labelled tab beside it. Tab chrome only appears while more
        than one tab is open — a lone workspace renders exactly as it did before tabs
        existed. ``component`` may be a zero-arg callable, re-invoked per page build like
        region contributions. ``name`` is the frame identity (also what a `tab_button`
        opens); ``label`` is the tab text. ``closeable=False`` hides the tab's close
        control for tabs nothing could reopen (the workspace is always non-closeable).
        """
        if any(existing == name for _, existing, _, _, _ in self._tabs):
            raise ValueError(f"main tab already registered: {name}")
        self._tabs.append((order, name, label, component, closeable))

    def tab_button(self, label: str, tab: str, *, icon: str | None = None, appearance: str = "outlined") -> Any:
        """A button that opens (or focuses) a registered main tab. Add it to any region."""
        button = (
            WaButton(appearance=appearance, title=label)
            .prop("data-tab", tab)
            .on("click", Invoke(by_id(_MAIN_LAYOUT_ID), "openPanel", event_prop("currentTarget.dataset.tab")))
        )
        button = button.child(WaIcon(name=icon)) if icon else button.text(label).style(width="100%")
        return button

    def seed_store(self, **fields: Any) -> None:
        """Seed initial values into the page's reactive signal store (merged across callers)."""
        self._store_seeds.update(fields)

    def url(self, path: str | None) -> str | None:
        """Prefix a root-relative URL with the gateway's ``ROOT_PATH`` (for reverse-proxy sub-paths).

        Absolute URLs (``http(s)://``, ``mailto:``, …) and non-root-relative values are returned
        unchanged. The spaday page is built once, so the static ``settings.ROOT_PATH`` is used (rather
        than the per-request ``root_path`` the default UI reads); this covers a fixed proxy prefix.
        """
        root = getattr(self._settings, "ROOT_PATH", "") or ""
        if root and path and path.startswith("/"):
            return f"{root}{path}"
        return path

    def _custom_assets(self) -> tuple[list[str], list[str]]:
        """The configured `Settings.CUSTOM_CSS` / `CUSTOM_JS` as stylesheet and script URLs.

        Both are resolved by `GatewayWebApp._resolve_ui_assets` first, so local paths have already
        been mounted and turned into URLs, and anything discovered under ``CUSTOM_STATIC_DIR`` is
        included. Scripts are handed to spaday as ES modules rather than the classic ``<script>``
        tags the default UI emits.
        """
        ui_config = getattr(self._web_app, "_ui_config_raw", None) or {}
        stylesheets = [self.url(href) for href in ui_config.get("customCss") or []]
        scripts = [self.url(src) for src in ui_config.get("customJs") or []]
        return stylesheets, scripts

    def _region(self, region: Region, *builtin: Any) -> list[Any]:
        """The composed, order-sorted components for a region.

        ``builtin`` is a list of ``(order, component)`` pairs for the provider's own default
        pieces; they are merged with the module contributions and sorted by order. ``None``
        components (e.g. an omitted optional logo) are dropped. A contribution may be a zero-arg
        callable, resolved here so it re-renders from current server state on every page build.
        """
        items: list[tuple] = [(o, c) for (o, c) in builtin if c is not None]
        items += [(c.order, c.component) for c in self._regions.get(region, []) if c.component is not None]
        items.sort(key=lambda t: t[0])
        resolved = [c() if callable(c) else c for _, c in items]
        return [c for c in resolved if c is not None]

    def _labeled_region(self, region: Region) -> list[tuple[str | None, Any]]:
        """The composed components for a region, each paired with its contribution's tab label."""
        items = [(c.order, c.label, c.component) for c in self._regions.get(region, []) if c.component is not None]
        items.sort(key=lambda t: t[0])
        labeled = [(label, component() if callable(component) else component) for _, label, component in items]
        return [(label, component) for label, component in labeled if component is not None]

    def perspective_panel(
        self,
        *,
        route: str,
        tables: list[str] | None = None,
        default_tables: list[str] | None = None,
        layouts: dict[str, str] | None = None,
        schemas: dict[str, dict[str, str]] | None = None,
        default_layout: dict[str, Any] | None = None,
        table_options: dict[str, dict[str, Any]] | None = None,
    ) -> Any:
        """A Perspective workspace panel (the primary data view), bound to the theme + `view` state.

        Data rides Perspective's own websocket at ``route``; the panel only carries the workspace
        layout/theme config. ``default_layout`` replaces the generated initial layout when supplied.
        Otherwise ``default_tables`` are the ones the generated layout opens, defaulting to all of
        ``tables``. ``schemas`` (table name -> column name -> type) lets the generated layout apply
        per-table defaults (timestamp sort, hidden id column). ``table_options`` carries each table's
        ``architecture``/``index``/``limit``, which is what puts a ``client-server`` table in a local
        worker rather than reading it off the websocket. Add it to `Region.MAIN`.
        """
        tables = list(tables or [])
        self._workspace_tables = list(tables)
        options = table_options or {}
        table_specs: list[Any] = [{"name": name, **options[name]} if options.get(name) else name for name in tables]
        default_layout = default_layout or self._default_layout(list(default_tables) if default_tables is not None else tables, schemas=schemas)
        layout_expr: Any = default_layout
        for name, layout_json in (layouts or {}).items():
            try:
                parsed = json.loads(layout_json)
            except (TypeError, ValueError):
                continue
            layout_expr = cond(eq(field("layout_view"), name), parsed, layout_expr)
        fallback = json.dumps(default_layout).replace("<", "\\u003c")
        storage_key = json.dumps(_CUSTOM_LAYOUT_STORAGE_KEY)
        self._store_seeds["custom_layout"] = Js(
            "(() => { "
            f"const fallback = {fallback}; "
            f'try {{ const value = JSON.parse(localStorage.getItem({storage_key}) ?? "null"); '
            'return value && typeof value === "object" && !Array.isArray(value) '
            '&& value.layout && typeof value.layout === "object" && !Array.isArray(value.layout) '
            '&& value.panels && typeof value.panels === "object" && !Array.isArray(value.panels) ? value : fallback; } '
            "catch { return fallback; } "
            "})()"
        )
        layout_expr = cond(eq(field("layout_view"), _CUSTOM_LAYOUT_NAME), field("custom_layout"), layout_expr)

        # Focusing a table (from a channels-graph node) wins over the selected layout until the
        # selector or a save clears it, so these branches wrap the others.
        for name in tables:
            layout_expr = cond(eq(field(_GRAPH_FOCUS), name), self._default_layout([name], schemas=schemas), layout_expr)
        self._store_seeds.setdefault(_GRAPH_FOCUS, "")
        self._store_seeds.setdefault(_PERSPECTIVE_READY, False)

        return (
            PerspectivePanel()
            .prop("id", _WORKSPACE_ID)
            .style(height="100%", display="block", overflow="hidden")
            .compute("theme", cond(field("dark"), "dark", "light"))
            .compute("config", obj({"ws_url": self.url(route), "tables": table_specs, "layout": layout_expr}))
            # Applying a config can fail (a saved layout that no longer matches the tables); the
            # panel reports it and otherwise nothing would. The detail is whatever was thrown --
            # an Error for JS failures, a bare string for the ones raised inside Perspective.
            .on(
                "perspective-error",
                Invoke(
                    by_id(_TOAST_ID),
                    "notify",
                    obj(
                        {
                            "message": concat(
                                "Perspective error: ",
                                cond(event_prop("detail.message"), event_prop("detail.message"), event_prop("detail")),
                            ),
                            "tone": "danger",
                        }
                    ),
                ),
            )
            .on("perspective-ready", SetField(_PERSPECTIVE_READY, True))
        )

    def focus_table_action(self, *, event_path: str = "detail.id") -> Any:
        """An action that shows one table in the workspace, named by ``event_path`` on the event.

        For components that identify a channel (the channels graph's node clicks). Names that are
        not workspace tables are ignored, so clicking a module does nothing. Returns ``None`` when
        no workspace has been registered, so callers can skip binding it.
        """
        if not self._workspace_tables:
            return None
        name = event_prop(event_path)
        return If(
            any_(*[eq(name, table) for table in self._workspace_tables]),
            Sequence(SetField(_GRAPH_FOCUS, name), Invoke(by_id(_MAIN_LAYOUT_ID), "openPanel", _WORKSPACE_TAB)),
        )

    def layout_selector(self, layouts: dict[str, str], *, value: str | None = None) -> Any:
        """A dropdown bound to `view`, listing the generated, saved, and custom layouts.

        Add it to `Region.HEADER_RIGHT` (and `seed_store(view=...)`).
        """
        select = (
            WaSelect(value=value, size="s")
            .prop("id", "gateway-layout-selector")
            .bind("value", "view", mode="two-way")
            .on("change", Sequence(SetField("layout_view", event_value()), SetField(_GRAPH_FOCUS, "")))
            .style(width="220px")
        )
        select = select.child(WaOption(value="__default__").text("All Tables"))
        for name in layouts:
            select = select.child(WaOption(value=name).text(name))
        return select.child(WaOption(value=_CUSTOM_LAYOUT_NAME).text(_CUSTOM_LAYOUT_NAME))

    def save_layout_button(self) -> Any:
        """A header button that saves the current Perspective workspace in the browser.

        `saveClean` strips the transient fields (theme, column size overrides) before the layout is
        persisted to localStorage; writing `result="custom_layout"` updates the store field the
        workspace's layout expression reads, and selecting the custom layout re-renders it.
        """
        return (
            WaButton(appearance="plain", title="Save current layout")
            .compute("disabled", not_(field(_PERSPECTIVE_READY)))
            .on(
                "click",
                Sequence(
                    Invoke(by_id(_WORKSPACE_ID), "saveClean", result="custom_layout"),
                    SetStorage(_CUSTOM_LAYOUT_STORAGE_KEY, field("custom_layout")),
                    SetField(_GRAPH_FOCUS, ""),
                    SetField("view", _CUSTOM_LAYOUT_NAME),
                    SetField("layout_view", _CUSTOM_LAYOUT_NAME),
                ),
            )
            .child(WaIcon(name="floppy-disk"))
        )

    def download_layout_button(self) -> Any:
        """A header button that downloads the current Perspective workspace as a JSON file.

        The file is assembled client-side from `saveClean` — no server round-trip.
        """
        return (
            WaButton(appearance="plain", title="Download layout")
            .compute("disabled", not_(field(_PERSPECTIVE_READY)))
            .on(
                "click",
                Sequence(
                    Invoke(by_id(_WORKSPACE_ID), "saveClean", result="download_layout"),
                    Download("layout.json", field("download_layout")),
                ),
            )
            .child(WaIcon(name="download"))
        )

    def link_button(self, label: str, href: str, *, target: str = "_blank", variant: str | None = None) -> Any:
        """A full-width link button (opens `href`), for a drawer/gutter. Add it to a region."""
        return WaButton(appearance="outlined", variant=variant).text(label).prop("href", self.url(href)).prop("target", target).style(width="100%")

    def post_button(self, label: str, url: str, *, variant: str = "neutral") -> Any:
        """A full-width button that POSTs to `url`, reporting a rejection in a toast. Add it to a region."""
        action = CallEndpoint("POST", self.url(url), result=_ACTION_RESULT)
        return WaButton(variant=variant).text(label).on("click", action).style(width="100%")

    def confirm_button(self, label: str, url: str, *, variant: str = "danger") -> Any:
        """A full-width button that POSTs to `url` behind a modal confirm dialog.

        Returns a single component (a ``display:contents`` wrapper holding the button and its
        dialog, which renders in the top layer), so it can be added to one region.
        """
        dialog_id = f"gateway-confirm-{abs(hash((label, url))) % 100000}"
        button = WaButton(variant=variant).text(label).on("click", Toggle(by_id(dialog_id), "open")).style(width="100%")
        dialog = (
            WaDialog(label=f"Confirm {label}")
            .prop("id", dialog_id)
            .child(element("p").text(f"Are you sure you want to {label.lower()}?"))
            .child(
                element("div")
                .style(display="flex", gap="0.5rem", justify_content="flex-end", margin_top="1rem")
                .child(WaButton(appearance="outlined").text("Cancel").on("click", Toggle(by_id(dialog_id), "open")))
                .child(
                    WaButton(variant="danger")
                    .text(label)
                    .on(
                        "click",
                        Sequence(
                            CallEndpoint("POST", self.url(url), result=_ACTION_RESULT),
                            Toggle(by_id(dialog_id), "open"),
                        ),
                    )
                )
            )
        )
        return element("span").style(display="contents").child(button).child(dialog)

    @staticmethod
    def _schema_props(model: Any) -> dict[str, Any]:
        """The JSON-schema ``properties`` for a channel struct model (empty if it can't be introspected)."""
        try:
            return TypeAdapter(model).json_schema().get("properties", {})
        except (TypeError, ValueError):
            return {}

    @classmethod
    def _all_field_names(cls, model: Any) -> list[str]:
        props = cls._schema_props(model)
        if props:
            return list(props.keys())
        metadata = model.metadata() if hasattr(model, "metadata") else {}
        return list(metadata.keys())

    @classmethod
    def _send_fields(cls, spec: SendSpec):
        """The scalar fields to send for a channel (minus id/timestamp/excluded) and which are booleans.

        Nested/array/object fields are skipped: spaday's ``form()`` flattens them to dotted keys, which
        the flat ``obj({name: field(name)})`` POST body doesn't compose, so both must agree on scalars.
        """
        scalar = {"string", "number", "integer", "boolean"}
        props = cls._schema_props(spec.model)
        included: list[str] = []
        bool_fields: set = set()
        for name in cls._all_field_names(spec.model):
            if name in ("id", "timestamp"):
                continue
            if (spec.overrides.get(name) or {}).get("exclude"):
                continue
            prop = props.get(name, {})
            schema_type = prop.get("type")
            if props and schema_type is not None and schema_type not in scalar and prop.get("enum") is None:
                continue
            included.append(name)
            if schema_type == "boolean":
                bool_fields.add(name)
        return included, bool_fields

    @staticmethod
    def _form_overrides(overrides: dict[str, dict[str, Any]], form_field_cls: Any) -> dict[str, Any]:
        """Map csp-gateway per-field overrides to spaday `FormField`s (label + a component `control`).

        ``exclude`` is applied via ``form(exclude=...)``; a control-*kind* string is ignored (spaday's
        ``form()`` derives the control from the JSON schema, including date/date-time calendars).
        """
        result: dict[str, Any] = {}
        for name, cfg in (overrides or {}).items():
            if cfg.get("exclude"):
                continue
            kwargs: dict[str, Any] = {}
            if cfg.get("label"):
                kwargs["label"] = cfg["label"]
            control = cfg.get("control")
            if control is not None and not isinstance(control, str):
                kwargs["control"] = control
            if kwargs:
                result[name] = form_field_cls(**kwargs)
        return result

    @staticmethod
    def _default_layout(tables: list[str], schemas: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
        """A perspective workspace config that shows every table in its own datagrid tab.

        With ``schemas`` (table name -> column name -> type), panels match the legacy UI's defaults:
        sorted by ``timestamp`` descending when the table has one, and the ``id`` column hidden.
        """
        panels: dict[str, Any] = {}
        panel_ids: list[str] = []
        for i, table in enumerate(tables):
            panel_id = f"CSP_GATEWAY_{i}"
            panel: dict[str, Any] = {"table": table, "plugin": "Datagrid", "title": table}
            schema = (schemas or {}).get(table) or {}
            if "timestamp" in schema:
                panel["sort"] = [["timestamp", "desc"]]
            if "id" in schema:
                panel["columns"] = [column for column in schema if column != "id"]
            panels[panel_id] = panel
            panel_ids.append(panel_id)
        return {
            "layout": {"type": "tab-layout", "tabs": panel_ids, "selected": 0},
            "panels": panels,
        }

    def send_panel(self, specs: list[SendSpec]) -> Any:
        """A "send data to a channel" panel: one spaday `form()` per sendable channel.

        A channel selector drives `send_channel`; a `Show` per channel mounts only the selected
        channel's form. Each form is `spaday.components.form.form(model, ...)` — controls and native
        validation are generated from the channel struct's JSON schema and two-way bound to the store.
        Submit is a declarative `CallEndpoint` that composes the bound fields into the POST body
        (`obj` + `field`) and captures the outcome (`{status, ok, body}`) into `send_result`, which a
        callout binds to; a dict-basket channel's key selector builds the `/{key}` URL via `concat`.
        Add it to `Region.DRAWER_BOTTOM` (and `seed_store(send_channel=...)`).
        """
        specs = [spec for spec in specs if self._send_fields(spec)[0]]
        default_channel = specs[0].channel if specs else None
        selector = WaSelect(value=default_channel, label="Channel").bind("value", "send_channel", mode="two-way").style(width="100%")
        for spec in specs:
            selector = selector.child(WaOption(value=spec.channel).text(spec.channel))

        channel_forms: list[Any] = []
        for spec in specs:
            included, bool_fields = self._send_fields(spec)
            exclude = tuple(name for name in self._all_field_names(spec.model) if name not in included)
            overrides = self._form_overrides(spec.overrides, FormField)

            controls: list[Any] = []
            key_field = f"send_key_{spec.channel}"
            if spec.keys:
                key_select = WaSelect(label="Key", value=spec.keys[0]).bind("value", key_field, mode="two-way").style(width="100%")
                for key in spec.keys:
                    key_select = key_select.child(WaOption(value=key).text(key))
                controls.append(key_select)
            controls.append(form(TypeAdapter(spec.model), exclude=exclude, overrides=overrides))

            body = obj({name: field(name) for name in included})
            base_url = self.url(spec.url)
            url: Any = concat(base_url, "/", field(key_field)) if spec.keys else base_url
            submit = WaButton(variant="brand").text("Submit").style(width="100%").on("click", CallEndpoint("POST", url, body, result="send_result"))
            clear = (
                WaButton(appearance="outlined")
                .text("Clear")
                .on("click", Sequence(*[SetField(name, False if name in bool_fields else "") for name in included]))
            )
            actions_row = Row(justify="flex-end", gap="0.5rem").child(clear).child(submit)
            channel_forms.append(Show(Column(*controls, actions_row, gap="0.7rem"), when=eq(field("send_channel"), spec.channel)))

        # A shared, declarative status line: the CallEndpoint result ({status, ok, body}) drives a callout.
        have = field("send_result")
        ok = field("send_result.ok")
        status = Column(
            Show(WaCallout(variant="success").text("Sent to the channel."), when=all_(have, ok)),
            Show(
                WaCallout(variant="danger").child(
                    element("span").compute("textContent", concat("Rejected (HTTP ", field("send_result.status"), ")."))
                ),
                when=all_(have, not_(ok)),
            ),
            gap="0",
        )

        return Column(selector, *channel_forms, status, gap="0.9rem").style(max_width="460px", margin="0 auto", padding="0.25rem")

    def build_page(self) -> Any:
        """Assemble the full spaday page from the region registry plus the built-in shell chrome."""
        ui_config = getattr(self._web_app, "_ui_config_raw", None) or {}
        title = ui_config.get("title") or getattr(self._settings, "TITLE", "Gateway")
        version = getattr(self._settings, "VERSION", None)
        header_logo = ui_config.get("headerLogo") or "/favicon.ico"
        footer_logo = ui_config.get("footerLogo")
        right_drawer_id = "gateway-settings"

        # Built-in chrome components (shell, not module contributions).
        logo_img = element("img", src=self.url(header_logo), alt=title).style(height="1.8rem")
        title_el = element("strong").text(title).style(font_size="1.1rem", letter_spacing=".02em")
        version_el = element("span").text(str(version)).style(opacity="0.6", font_size="0.8rem") if version else None
        # Theme toggle: an icon-only button that flips the `dark` field via ToggleField; the WebAwesome
        # icon reactively follows it (sun when dark -> click for light; moon when light -> click for dark).
        theme_toggle = (
            WaButton(appearance="plain", title="Toggle theme")
            .on("click", ToggleField("dark"))
            .child(WaIcon().compute("name", cond(field("dark"), "sun", "moon")))
        )
        email = getattr(self._settings, "EMAIL", None)
        email_button = self.link_button("Email", f"mailto:{email}?subject={title} Support") if email else None
        attribution = (
            element("span")
            .child("Built with ")
            .child(element("a", href="https://github.com/perspective-dev/perspective", target="_blank").text("Perspective").style(color="inherit"))
            .child(" and ")
            .child(element("a", href="https://github.com/1kbgz/spaday", target="_blank").text("spaday").style(color="inherit"))
        )

        # Compose region contents (built-in chrome merged with module contributions, order-sorted).
        right_drawer_items = self._region(Region.DRAWER_RIGHT, (100, email_button))
        bottom_drawer_panels = self._labeled_region(Region.DRAWER_BOTTOM)
        bottom_drawer_items = [component for _, component in bottom_drawer_panels]
        # Several labelled panels share the drawer, so they become tabs rather than a tall stack.
        bottom_tabbed = len(bottom_drawer_panels) > 1 and all(label for label, _ in bottom_drawer_panels)
        bottom_label = "Channel data" if bottom_tabbed else "Send data to a channel"
        gutter_left = self._region(Region.GUTTER_LEFT)
        gutter_right = self._region(Region.GUTTER_RIGHT)
        main_items = self._region(Region.MAIN)
        overlay_items = self._region(Region.OVERLAY)

        # Header-right built-ins: theme toggle, plus the drawer toggles when their drawers have content.
        settings_button = (
            WaButton(appearance="plain", title="Settings").text("\u2630").on("click", Toggle(by_id(right_drawer_id), "open"))
            if right_drawer_items
            else None
        )
        # "+" opens the send panel as a main tab (the drawer it used to toggle is retired here;
        # the legacy UI provider keeps the old behavior for this release).
        plus_button = (
            WaButton(appearance="plain", title=bottom_label)
            .prop("data-tab", _SEND_TAB)
            .on("click", Invoke(by_id(_MAIN_LAYOUT_ID), "openPanel", event_prop("currentTarget.dataset.tab")))
            .child(WaIcon(name="plus"))
            if bottom_drawer_items
            else None
        )

        header_left = self._region(Region.HEADER_LEFT, (-30, logo_img), (-20, title_el), (-10, version_el))
        header_center = self._region(Region.HEADER_CENTER)
        header_right = self._region(Region.HEADER_RIGHT, (110, theme_toggle), (120, plus_button), (130, settings_button))

        # Main content: the panel(s), full-bleed (the MAIN container is styled padding:0 below).
        if not main_items:
            workspace: Any = element("div").style(padding="2rem").child(element("p").text("No UI panels are configured."))
        elif len(main_items) == 1:
            workspace = main_items[0]
        else:
            workspace = Column(*main_items, gap="1rem").style(height="100%")

        # On-demand main tabs: registered tabs (`add_tab`) plus the send panel behind "+". The
        # workspace sits in a regular-layout whose layout starts as just the workspace tab; opening
        # a tab inserts its frame (closeable, but not draggable -- the layout is locked below), and
        # the chrome only exists while more
        # than one tab is open — `regular-layout-update` keeps `main_tabbed` in sync, driving the
        # solo-mode class. With no tabs registered and no send panel, the main region is exactly
        # the plain workspace it always was.
        registered_tabs = sorted(self._tabs, key=lambda t: t[0])
        tab_entries: list[tuple[str, str, Any, bool]] = [
            (name, label, component, closeable) for _, name, label, component, closeable in registered_tabs
        ]
        if bottom_drawer_items:
            if bottom_tabbed:
                send_tabs = Tabs()
                for label, component in bottom_drawer_panels:
                    send_tabs.tab(label, component)
                send_body: Any = send_tabs
            else:
                send_body = Column(*bottom_drawer_items, gap="1rem")
            tab_entries.append((_SEND_TAB, bottom_label, send_body.style(max_width="640px", margin="0 auto"), True))
        if tab_entries:
            # Nothing reopens a closed workspace, so its close control is hidden.
            frames = [RegularLayoutFrame(workspace, name=_WORKSPACE_TAB).prop("data-no-close", "true")]
            titles = [f'--regular-layout-{_WORKSPACE_TAB}--title: "Workspace"']
            for name, label, component, closeable in tab_entries:
                resolved = component() if callable(component) else component
                frame = RegularLayoutFrame(resolved, name=name, style="box-sizing: border-box")
                if not closeable:
                    frame = frame.prop("data-no-close", "true")
                frames.append(frame)
                titles.append(f"--regular-layout-{name}--title: {json.dumps(label)}")
            open_count = cond(event_value("children"), 2, event_value("tabs.length"))
            main_content: Any = (
                RegularLayout(*frames, layout={"type": "tab-layout", "tabs": [_WORKSPACE_TAB]})
                .prop("id", _MAIN_LAYOUT_ID)
                # Tabs open, select, and close, but drag-rearranging is disabled: the nested
                # Perspective workspace is itself a regular-layout, which makes drags confusing.
                .prop("locked", True)
                .prop("style", "; ".join(titles))
                .compute("class", cond(field("main_tabbed"), "spa", "spa spa-solo"))
                .on("regular-layout-update", SetField("main_tabbed", not_(eq(open_count, 1))))
            )
            self._store_seeds.setdefault("main_tabbed", False)
        else:
            main_content = workspace

        footer_logo_el = element("img", src=self.url(footer_logo), alt=title).style(height="1.2rem") if footer_logo else None
        footer_left = self._region(Region.FOOTER_LEFT, (-10, footer_logo_el))
        footer_right = self._region(Region.FOOTER_RIGHT, (100, attribution))

        # Compose via spaday's AppShell: it lays out Nav / Body(Gutter, Main, Gutter) / Footer and places
        # the drawer/overlay contributions at the App root. `containers` styles the region wrappers
        # (full-bleed Main, scrollable gutters) since those aren't stylable through the contribution API.
        shell = AppShell(
            containers={
                Region.MAIN: {"style": "padding:0;overflow:hidden"},
                Region.GUTTER_LEFT: {"style": "overflow-y:auto"},
                Region.GUTTER_RIGHT: {"style": "overflow-y:auto"},
            }
        )
        shell.add(Region.HEADER_LEFT, *header_left)
        if header_center:
            shell.add(Region.HEADER_CENTER, *header_center)
        shell.add(Region.HEADER_RIGHT, *header_right)
        if gutter_left:
            shell.add(Region.GUTTER_LEFT, *gutter_left)
        shell.add(Region.MAIN, main_content)
        if gutter_right:
            shell.add(Region.GUTTER_RIGHT, *gutter_right)
        shell.add(Region.FOOTER_LEFT, *footer_left)
        shell.add(Region.FOOTER_RIGHT, *footer_right)

        if right_drawer_items:
            shell.add(
                Region.DRAWER_RIGHT,
                WaDrawer(label="Settings", placement="end", light_dismiss=True)
                .prop("id", right_drawer_id)
                .child(Column(*right_drawer_items, gap="0.6rem")),
            )
        if overlay_items:
            shell.add(Region.OVERLAY, *overlay_items)

        # `post_button`/`confirm_button` are otherwise fire-and-forget, so a rejected POST looks
        # exactly like a successful one. The result field is unset until the first call, and an
        # empty message enqueues nothing, so this stays quiet until something actually fails.
        shell.add(
            Region.OVERLAY,
            Toast(tone="danger")
            .prop("id", _TOAST_ID)
            .compute(
                "message",
                cond(
                    all_(field(_ACTION_RESULT), not_(field(f"{_ACTION_RESULT}.ok"))),
                    concat("Request failed (HTTP ", field(f"{_ACTION_RESULT}.status"), ")."),
                    "",
                ),
            ),
        )

        return shell.build().style(height="100vh").bind_root_class("wa-dark", "dark")

    @property
    def _auth_filter(self) -> Any:
        """The configured `AuthFilterMiddleware`, if any -- the same one the REST and websocket paths use."""
        return getattr(self._web_app.app.state, "auth_filter_middleware", None)

    async def _tenant_for(self, websocket: Any) -> tuple[Any, Any]:
        """The ``(tenant key, identity)`` a connection belongs to.

        Identity resolution is async (an external validator may do I/O), which is why it happens here
        rather than in the hub's key function -- that one is called synchronously.
        """
        auth_filter = self._auth_filter
        if auth_filter is None:
            return _ANONYMOUS_TENANT, None
        try:
            identity = await auth_filter.get_identity_from_websocket(websocket)
        except Exception:
            log.exception("Failed to resolve UI websocket identity; serving the anonymous tenant")
            return _ANONYMOUS_TENANT, None
        if not identity:
            return _ANONYMOUS_TENANT, None
        return json.dumps(identity, sort_keys=True, default=str), identity

    def _view_for(self, namespace: str, identity: Any) -> Any:
        """One tenant's view of a namespace's latest published state."""
        value = self._latest.get(namespace)
        return value(identity) if callable(value) else value

    def _apply(self, target: Any, value: Any) -> None:
        """Copy a published value onto a tenant's hosted model instance."""
        if value is None:
            return
        fields = value if isinstance(value, dict) else getattr(value, "__dict__", {})
        for name, field_value in fields.items():
            setattr(target, name, field_value)

    def _host_tenant(self, tenant: Any, identity: Any) -> None:
        """Give a tenant its own instance of every declared model, seeded with current state."""
        if tenant in self._tenant_models:
            return
        session = self._hub.tenant(tenant)
        hosted: dict[str, tuple] = {}
        for namespace, model in self._models.items():
            instance = model()
            self._apply(instance, self._view_for(namespace, identity))
            hosted[namespace] = (instance, session.host(instance))
        self._tenant_models[tenant] = hosted
        self._tenant_identity[tenant] = identity

    def _publish(self, namespace: str, value: Any) -> None:
        """Push new state for a namespace to every connected tenant, from any thread."""
        self._latest[namespace] = value
        if self._hub is None:
            return

        # Apply to each tenant's model here, so state is correct even before a loop exists; only the
        # emit needs to be marshalled onto the server loop.
        updates = []
        for tenant, hosted in self._tenant_models.items():
            entry = hosted.get(namespace)
            if entry is None:
                continue
            instance, mid = entry
            self._apply(instance, self._view_for(namespace, self._tenant_identity.get(tenant)))
            updates.append((tenant, mid))

        loop = self._loop
        if not updates or loop is None or not loop.is_running():
            return

        def _emit() -> None:
            for tenant, mid in updates:
                self._hub.tenant(tenant).update(mid)

        loop.call_soon_threadsafe(_emit)

    def _ws_endpoint(self) -> Any:
        """The websocket serving the hub, with each connection routed to its authenticated tenant."""
        import transports

        self._hub = transports.Hub(key=lambda conn: getattr(conn.state, "csp_gateway_tenant", _ANONYMOUS_TENANT))
        inner = transports.ws_endpoint(self._hub)

        # Annotated, not `Any`: FastAPI resolves the signature and would treat an unrecognised
        # annotation as a required query parameter, rejecting every connection with a 1008.
        async def endpoint(websocket: WebSocket) -> None:
            tenant, identity = await self._tenant_for(websocket)
            websocket.state.csp_gateway_tenant = tenant
            self._loop = asyncio.get_running_loop()
            self._host_tenant(tenant, identity)
            if self._autosync is None:
                self._autosync = asyncio.create_task(transports.autosync(self._hub))
            await inner(websocket)

        return endpoint

    def mount(self) -> None:
        """Build the spaday page and register its routes on the gateway app.

        The dynamic page and ``tree.json`` routes are registered on the gateway's authenticated
        ``app`` router, so they sit behind the same middleware (API key / auth filter / OAuth) as
        the default UI; the static ``/js`` runtime bundle is served publicly like the other UI
        assets. Called from ``GatewayWebApp.add_static_files`` before the ``app`` router is
        finalized with ``dependencies=self._middlewares``.
        """
        title = getattr(self._settings, "TITLE", "Gateway")
        root = getattr(self._settings, "ROOT_PATH", "") or ""
        custom_css, custom_scripts = self._custom_assets()
        # spaday's mount() appends plain Starlette routes, which do not carry the FastAPI auth
        # dependencies. Build them on a scratch app under the ROOT_PATH prefix (so the emitted page URLs
        # — /js runtime, wasm — resolve under a proxied sub-path), then re-register with the prefix
        # stripped: the routes themselves stay unprefixed (the app's root_path handles the proxy strip),
        # like every other gateway route. The dynamic page/tree go on the authenticated app router; the
        # static /js mount stays public, like other UI assets.
        scratch = Starlette()
        # Only wire a transports model when a module actually declared live state; otherwise the page is a
        # static tree and no websocket is served.
        wire: Any = None
        routes: list = []
        if self._models:
            wire = [Wire("/ws", namespace=namespace) for namespace in self._models]
            routes = [WebSocketRoute("/ws", self._ws_endpoint())]
        _spaday_mount(
            scratch,
            self.build_page,
            # Component libraries ship as their own distributions and are resolved by entry point.
            packages=["webawesome", "perspective", "regular-layout", "dagre"],
            # spaday infers "source checkout" from a `js/` dir next to itself, which any distribution
            # shipping a top-level `js/` package (plotly does) satisfies -- serving assets we consume
            # from the wheel, never from a spaday checkout.
            layout="installed",
            wire=wire,
            routes=routes,
            # `dark` matches the browser preference at boot (client-evaluated, like the legacy UI's
            # prefers-color-scheme detection), and a manual toggle is persisted per browser and takes
            # precedence on later loads.
            store={"dark": Js('matchMedia("(prefers-color-scheme: dark)").matches'), **self._store_seeds},
            persist={"dark": "csp-gateway:dark"},
            # Emitted after the component packages' own CSS, so a custom stylesheet can override the
            # shell palette, and before `head`, which carries only document resets.
            stylesheets=custom_css,
            scripts=custom_scripts,
            head=PAGE_CSS,
            title=title,
            prefix=root,
        )
        app_router = self._web_app.get_router("app")

        def _authed_route(endpoint):
            async def _serve(request: Request):
                return await endpoint(request)

            return _serve

        for route in scratch.routes:
            path = route.path
            if root and path.startswith(root):
                path = path[len(root) :] or "/"
            if isinstance(route, Mount):
                self._web_app.app.routes.append(Mount(path, app=route.app))
                continue
            if isinstance(route, WebSocketRoute):
                # The wire carries gateway state, so it sits behind the same dependencies as the page
                # and tree rather than being registered as a plain (and, on this router, GET) route.
                app_router.add_api_websocket_route(path, route.endpoint, name=f"spaday:ws:{path}")
                continue
            app_router.add_api_route(path, _authed_route(route.endpoint), methods=["GET"], include_in_schema=False, name=f"spaday:{path}")
