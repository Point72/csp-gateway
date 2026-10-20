from typing import TYPE_CHECKING

from csp_gateway.server import GatewayChannels, GatewayModule

# Imported from the leaf module, not the `csp_gateway.server` package: that package re-exports
# `.modules` before `.web`, so it is only partially initialized while this module is imported.
from csp_gateway.server.web import GatewayWebApp

if TYPE_CHECKING:
    from csp_gateway.server.web.spaday_ui import GatewayUI

#: The stats the panel renders, as (label, key into the control's payload). The control also
#: reports `now` and `csp-now`, which arrive as epoch floats rather than formatted times, so they
#: are left out until there is somewhere to format them.
_ROWS = (
    ("Host", "host"),
    ("User", "user"),
    ("PID", "pid"),
    ("CPU %", "cpu"),
    ("Memory %", "memory"),
    ("Memory available %", "memory-total"),
    ("Active threads", "active_threads"),
    ("Max threads", "max_threads"),
)


class MountProcessMonitor(GatewayModule):
    """Spaday UI: a "Process" tab showing what the `stats` control reports.

    This is a **presentation** module for the spaday UI provider only -- its `ui()` hook is a no-op
    under the default (React) UI, and it mounts no routes. It reads the `stats` control that
    `MountControls(mount_stats=True)` provides, so the gateway keeps one answer for what it reports
    about itself; without that module the endpoint is absent and the panel says so rather than
    rendering an empty table.
    """

    def connect(self, channels: GatewayChannels) -> None:
        # NO-OP: the panel reads the controls API rather than any channel.
        ...

    def rest(self, app: GatewayWebApp) -> None:
        # NO-OP: no routes of its own; it calls the stats route MountControls mounts.
        ...

    def ui(self, app: "GatewayUI") -> None:
        from spaday import element
        from spaday.actions import CallEndpoint, field, item

        from csp_gateway.server.web.spaday_ui import Region

        stats_url = app.api_url("/controls/stats", app.web_app.api_version_for("controls", self.api_version, "/stats"))
        # Seeded ok so the "no stats" callout stays hidden until a call has actually failed. The
        # seeded entry carries an `id` because the table repeats over this list and a repeater key
        # that is missing on any entry fails the whole page render, not just this panel.
        app.seed_store(monitor={"ok": True, "body": [{"id": "stats", "data": {}}]})
        # Each refresh round-trips the csp engine, so it is driven by a gesture rather than a timer.
        refresh = CallEndpoint("GET", stats_url, result="monitor")

        def panel():
            from spaday.components.shell import Each
            from spaday_webawesome import WaButton, WaCallout

            # The controls API answers with a list of one `Controls`, so the table is repeated over
            # that list rather than reaching into it by index -- an index segment in a field path is
            # not part of the expression vocabulary, and `item()` reads the entry directly.
            rows = [
                element("tr")
                .child(element("th").style(text_align="left", padding="0.25rem 1rem 0.25rem 0", font_weight="500").text(label))
                .child(element("td").style(padding="0.25rem 0", font_family="ui-monospace, monospace").compute("textContent", item(f"data.{key}")))
                for label, key in _ROWS
            ]
            missing = (
                WaCallout(variant="warning")
                .text("No stats available. Mount MountControls(mount_stats=True) to populate this panel.")
                .compute("hidden", field("monitor.ok"))
            )
            return (
                element("div")
                .style(display="flex", flex_direction="column", gap="0.75rem", padding="0.75rem", height="100%", overflow="auto")
                .child(
                    element("div")
                    .style(display="flex", gap="0.5rem", align_items="center")
                    .child(element("strong").text("Process"))
                    .child(element("span").style(flex="1"))
                    .child(WaButton(appearance="outlined", size="s").text("Refresh").on("click", refresh))
                )
                .child(missing)
                .child(Each(element("table").child(element("tbody").child(*rows)), field="monitor.body", key="id"))
            )

        app.add_tab("monitor", "Process", panel, on_open=refresh)
        app.add(Region.DRAWER_RIGHT, app.tab_button("Process", "monitor"))
