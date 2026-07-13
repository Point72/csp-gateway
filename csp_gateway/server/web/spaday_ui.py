"""spaday-based frontend provider for the Gateway web application.

This is the optional alternative to the built-in Perspective/React UI, selected via
`Settings.UI_PROVIDER == "spaday"`. A `GatewayUI` handle is passed to each module's
`ui()` hook (mirroring how `GatewayWebApp` is passed to `rest()`); modules register a
main panel or add header actions, and `GatewayUI` assembles a single spaday page and
mounts it onto the FastAPI app.

This module imports `spaday` at import time, so it is imported only when the spaday provider is
selected — from `GatewayWebApp` when `UI_PROVIDER == "spaday"`, and lazily from the modules' `ui()`
hooks (which only run under that provider) — never from `csp_gateway.server.web` at large. It requires
the optional `spaday` extra (`pip install 'csp-gateway[spaday]'`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as _dc_field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from pydantic import TypeAdapter
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount

try:
    import spaday  # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The spaday UI provider (Settings.UI_PROVIDER='spaday') requires the optional 'spaday' "
        "dependency. Install it with: pip install 'csp-gateway[spaday]'."
    ) from exc

from spaday import element
from spaday.actions import (
    CallEndpoint,
    Sequence,
    SetField,
    Toggle,
    ToggleField,
    all_,
    by_id,
    concat,
    cond,
    eq,
    field,
    not_,
    obj,
)
from spaday.backends.starlette import mount as _spaday_mount
from spaday.components.form import FormField, form
from spaday.components.perspective import PerspectivePanel
from spaday.components.shell import AppShell, Column, Region, Row, Show
from spaday.components.webawesome import (
    WaButton,
    WaCallout,
    WaDialog,
    WaDrawer,
    WaIcon,
    WaOption,
    WaSelect,
)

if TYPE_CHECKING:
    from csp_gateway.server.web import GatewayWebApp

__all__ = (
    "GatewayUI",
    "Region",
    "SendSpec",
)


# Minimal shell theming so the spaday page looks reasonable in both light and dark modes.
# Keyed off the ``wa-dark`` class that ``App().bind_root_class("wa-dark", "dark")`` toggles.
THEME_CSS = """<style>
      html, body { height: 100%; }
      body { margin: 0; font-family: system-ui, sans-serif; }
      spa-app { --spa-gap: 0.75rem; height: 100vh; }
      html:not(.wa-dark) { background: #eef1f5; }
      html:not(.wa-dark) spa-app {
        --spa-surface: #ffffff; --spa-surface-2: #f3f5f8; --spa-border: #dde3ec; --spa-muted: #5a6a80;
        color: #1a2230; background: #eef1f5;
      }
      html.wa-dark { background: #1b222e; }
      html.wa-dark spa-app {
        --spa-surface: #222b39; --spa-surface-2: #2a3445; --spa-border: #3b4860; --spa-muted: #8fa3c0;
        color: #e6eefb; background: #1b222e;
      }
    </style>"""


@dataclass
class SendSpec:
    """One sendable channel for `send_panel`: the channel struct model plus its POST url, keys, overrides."""

    channel: str
    url: str
    model: Any
    keys: List[str] = _dc_field(default_factory=list)
    overrides: Dict[str, Dict[str, Any]] = _dc_field(default_factory=dict)


@dataclass
class _Contribution:
    """A component injected into a `Region`, with an ordering key (lower renders first)."""

    component: Any
    order: int = 0


class GatewayUI:
    """Collects UI contributions from modules and builds/mounts the spaday page.

    A single instance lives on `GatewayWebApp.ui` when the spaday provider is selected.
    Modules populate it from their `ui()` hook; `GatewayWebApp` calls `mount()` at
    finalization to attach the page to the FastAPI app.
    """

    def __init__(self, web_app: "GatewayWebApp", settings: Any) -> None:
        self._web_app = web_app
        self._settings = settings
        self._regions: Dict[Region, List[_Contribution]] = {}
        self._store_seeds: Dict[str, Any] = {}

    @property
    def settings(self) -> Any:
        return self._settings

    @property
    def web_app(self) -> "GatewayWebApp":
        return self._web_app

    def add(self, region: Region, component: Any, *, order: int = 0) -> None:
        """Inject a spaday `component` into a named shell `region`.

        This is the single contribution API. Multiple contributions to the same region render
        in ascending `order` (ties keep insertion order). The built-in chrome (logo, theme
        toggle, footer text, drawer toggles) occupies reserved order bands so module
        contributions slot in around them predictably. Build the component with one of the
        helpers (`perspective_panel`, `layout_selector`, `send_panel`, `link_button`,
        `post_button`, `confirm_button`) or hand-author any spaday component.
        """
        self._regions.setdefault(Region(region), []).append(_Contribution(component=component, order=order))

    def seed_store(self, **fields: Any) -> None:
        """Seed initial values into the page's reactive signal store (merged across callers)."""
        self._store_seeds.update(fields)

    def url(self, path: Optional[str]) -> Optional[str]:
        """Prefix a root-relative URL with the gateway's ``ROOT_PATH`` (for reverse-proxy sub-paths).

        Absolute URLs (``http(s)://``, ``mailto:``, …) and non-root-relative values are returned
        unchanged. The spaday page is built once, so the static ``settings.ROOT_PATH`` is used (rather
        than the per-request ``root_path`` the default UI reads); this covers a fixed proxy prefix.
        """
        root = getattr(self._settings, "ROOT_PATH", "") or ""
        if root and path and path.startswith("/"):
            return f"{root}{path}"
        return path

    def _region(self, region: Region, *builtin: Any) -> List[Any]:
        """The composed, order-sorted components for a region.

        ``builtin`` is a list of ``(order, component)`` pairs for the provider's own default
        pieces; they are merged with the module contributions and sorted by order. ``None``
        components (e.g. an omitted optional logo) are dropped.
        """
        items: List[tuple] = [(o, c) for (o, c) in builtin if c is not None]
        items += [(c.order, c.component) for c in self._regions.get(region, []) if c.component is not None]
        items.sort(key=lambda t: t[0])
        return [c for _, c in items]

    def perspective_panel(
        self,
        *,
        route: str,
        tables: Optional[List[str]] = None,
        layouts: Optional[Dict[str, str]] = None,
    ) -> Any:
        """A Perspective workspace panel (the primary data view), bound to the theme + `view` state.

        Data rides Perspective's own websocket at ``route``; the panel only carries the workspace
        layout/theme config. Add it to `Region.MAIN`.
        """
        tables = list(tables or [])
        layout_expr: Any = self._default_layout(tables)
        for name, layout_json in (layouts or {}).items():
            try:
                parsed = json.loads(layout_json)
            except (TypeError, ValueError):
                continue
            layout_expr = cond(eq(field("view"), name), parsed, layout_expr)

        return (
            PerspectivePanel()
            .prop("id", "gateway-workspace")
            .style(height="100%", display="block", overflow="hidden")
            .compute("theme", cond(field("dark"), "dark", "light"))
            .compute("config", obj({"ws_url": self.url(route), "tables": tables, "layout": layout_expr}))
        )

    def layout_selector(self, layouts: Dict[str, str], *, value: Optional[str] = None) -> Any:
        """A dropdown two-way bound to the `view` state, listing "All Tables" + each named layout.

        Add it to `Region.HEADER_RIGHT` (and `seed_store(view=...)`).
        """
        select = WaSelect(value=value, size="s").bind("value", "view", mode="two-way").style(width="220px")
        select = select.child(WaOption(value="__default__").text("All Tables"))
        for name in layouts:
            select = select.child(WaOption(value=name).text(name))
        return select

    def link_button(self, label: str, href: str, *, target: str = "_blank", variant: Optional[str] = None) -> Any:
        """A full-width link button (opens `href`), for a drawer/gutter. Add it to a region."""
        return WaButton(appearance="outlined", variant=variant).text(label).prop("href", self.url(href)).prop("target", target).style(width="100%")

    def post_button(self, label: str, url: str, *, variant: str = "neutral") -> Any:
        """A full-width button that POSTs to `url` (fire-and-forget). Add it to a region."""
        return WaButton(variant=variant).text(label).on("click", CallEndpoint("POST", self.url(url))).style(width="100%")

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
                    .on("click", Sequence(CallEndpoint("POST", self.url(url)), Toggle(by_id(dialog_id), "open")))
                )
            )
        )
        return element("span").style(display="contents").child(button).child(dialog)

    @staticmethod
    def _schema_props(model: Any) -> Dict[str, Any]:
        """The JSON-schema ``properties`` for a channel struct model (empty if it can't be introspected)."""
        try:
            return TypeAdapter(model).json_schema().get("properties", {})
        except Exception:
            return {}

    @classmethod
    def _all_field_names(cls, model: Any) -> List[str]:
        props = cls._schema_props(model)
        if props:
            return list(props.keys())
        metadata = model.metadata() if hasattr(model, "metadata") else {}
        return list(metadata.keys())

    @classmethod
    def _send_fields(cls, spec: "SendSpec"):
        """The scalar fields to send for a channel (minus id/timestamp/excluded) and which are booleans.

        Nested/array/object fields are skipped: spaday's ``form()`` flattens them to dotted keys, which
        the flat ``obj({name: field(name)})`` POST body doesn't compose, so both must agree on scalars.
        """
        scalar = {"string", "number", "integer", "boolean"}
        props = cls._schema_props(spec.model)
        included: List[str] = []
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
    def _form_overrides(overrides: Dict[str, Dict[str, Any]], form_field_cls: Any) -> Dict[str, Any]:
        """Map csp-gateway per-field overrides to spaday `FormField`s (label + a component `control`).

        ``exclude`` is applied via ``form(exclude=...)``; a control-*kind* string is ignored (spaday's
        ``form()`` derives the control from the JSON schema, including date/date-time calendars).
        """
        result: Dict[str, Any] = {}
        for name, cfg in (overrides or {}).items():
            if cfg.get("exclude"):
                continue
            kwargs: Dict[str, Any] = {}
            if cfg.get("label"):
                kwargs["label"] = cfg["label"]
            control = cfg.get("control")
            if control is not None and not isinstance(control, str):
                kwargs["control"] = control
            if kwargs:
                result[name] = form_field_cls(**kwargs)
        return result

    @staticmethod
    def _default_layout(tables: List[str]) -> Dict[str, Any]:
        """A perspective-workspace layout that shows every table in its own datagrid tab."""
        widgets: Dict[str, Any] = {}
        widget_ids: List[str] = []
        for i, table in enumerate(tables):
            widget_id = f"CSP_GATEWAY_{i}"
            widgets[widget_id] = {"table": table, "plugin": "Datagrid", "title": table}
            widget_ids.append(widget_id)
        return {
            "sizes": [1],
            "detail": {"main": {"type": "tab-area", "widgets": widget_ids, "currentIndex": 0}},
            "master": {"sizes": [], "widgets": []},
            "mode": "globalFilters",
            "viewers": widgets,
        }

    def send_panel(self, specs: List["SendSpec"]) -> Any:
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

        channel_forms: List[Any] = []
        for spec in specs:
            included, bool_fields = self._send_fields(spec)
            exclude = tuple(name for name in self._all_field_names(spec.model) if name not in included)
            overrides = self._form_overrides(spec.overrides, FormField)

            controls: List[Any] = []
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
        bottom_drawer_id = "gateway-send"

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
        bottom_drawer_items = self._region(Region.DRAWER_BOTTOM)
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
        plus_button = (
            WaButton(appearance="plain", title="Send data to a channel")
            .on("click", Toggle(by_id(bottom_drawer_id), "open"))
            .child(WaIcon(name="plus"))
            if bottom_drawer_items
            else None
        )

        header_left = self._region(Region.HEADER_LEFT, (-30, logo_img), (-20, title_el), (-10, version_el))
        header_center = self._region(Region.HEADER_CENTER)
        header_right = self._region(Region.HEADER_RIGHT, (110, theme_toggle), (120, plus_button), (130, settings_button))

        # Main content: the panel(s), full-bleed (the MAIN container is styled padding:0 below).
        if not main_items:
            main_content: Any = element("div").style(padding="2rem").child(element("p").text("No UI panels are configured."))
        elif len(main_items) == 1:
            main_content = main_items[0]
        else:
            main_content = Column(*main_items, gap="1rem").style(height="100%")

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
        if bottom_drawer_items:
            shell.add(
                Region.DRAWER_BOTTOM,
                WaDrawer(label="Send data to a channel", placement="bottom", light_dismiss=True)
                .prop("id", bottom_drawer_id)
                .css(size="70vh")
                .child(Column(*bottom_drawer_items, gap="1rem")),
            )
        if overlay_items:
            shell.add(Region.OVERLAY, *overlay_items)

        return shell.build().style(height="100vh").bind_root_class("wa-dark", "dark")

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
        # spaday's mount() appends plain Starlette routes, which do not carry the FastAPI auth
        # dependencies. Build them on a scratch app under the ROOT_PATH prefix (so the emitted page URLs
        # — /js runtime, wasm — resolve under a proxied sub-path), then re-register with the prefix
        # stripped: the routes themselves stay unprefixed (the app's root_path handles the proxy strip),
        # like every other gateway route. The dynamic page/tree go on the authenticated app router; the
        # static /js mount stays public, like other UI assets.
        scratch = Starlette()
        _spaday_mount(
            scratch,
            self.build_page,
            bundles=["webawesome", "perspective"],
            store={"dark": False, **self._store_seeds},
            head=THEME_CSS,
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
            app_router.add_api_route(path, _authed_route(route.endpoint), methods=["GET"], include_in_schema=False, name=f"spaday:{path}")
