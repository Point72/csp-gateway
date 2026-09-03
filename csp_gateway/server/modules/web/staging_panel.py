from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from csp_gateway.server import ChannelSelection, GatewayChannels, GatewayModule

# Imported from the leaf module, not the `csp_gateway.server` package: that package re-exports
# `.modules` before `.web`, so it is only partially initialized while this module is imported.
from csp_gateway.server.web import GatewayWebApp

if TYPE_CHECKING:
    from csp_gateway.server.web.spaday_ui import GatewayUI

#: The namespace the panel's state rides under on the UI's transports wire.
NAMESPACE = "staging"


class StagingCell(BaseModel):
    """One record field, rendered as a table cell."""

    id: str
    value: str


class StagingRecord(BaseModel):
    """One staged record."""

    id: str
    cells: list[StagingCell] = []


class StagingColumn(BaseModel):
    """One table column, keyed by the struct field it shows."""

    id: str


class StagingArea(BaseModel):
    """One pending staging area on one channel."""

    id: str
    channel: str
    url: str
    summary: str
    overflow: str = ""
    columns: list[StagingColumn] = []
    records: list[StagingRecord] = []


class StagingState(BaseModel):
    """Every pending staging the viewer is allowed to see.

    ``empty`` and ``staged`` are complements, published rather than derived so each branch of the panel
    binds a plain field.
    """

    empty: bool = True
    staged: bool = False
    areas: list[StagingArea] = []


class MountStagingPanel(GatewayModule):
    """Spaday UI: a live "Staged data" tab, with per-record removal and per-staging release.

    This is a **presentation** module for the spaday UI provider only -- its `ui()` hook is a no-op under
    the default (React) UI, and it mounts no routes (it relies on the stage endpoints that
    `MountRestRoutes` provides). It shares the bottom drawer (the header's `+`) with the send form.
    Each staged channel contributes one block per staging area: a table with a column per struct field and
    a row per staged record, each row ending in an X that `DELETE`s just that record, plus a button that
    `PATCH`es the whole staging into the channel.

    The tree is reactive: it subscribes to each channel's `StagingEvent` stream and republishes the
    staging snapshot over the UI's transports wire, so stagings and records appear and disappear as they
    are staged and released, without a page reload.
    """

    mount_staging: ChannelSelection = Field(
        default_factory=ChannelSelection,
        description=(
            "Staged channels to render a panel for. Should match the channels `MountRestRoutes` actually "
            "mounts stage routes for, so the UI never shows a control that calls a route that was "
            "intentionally not mounted. Defaults to every channel with staging enabled."
        ),
    )

    max_records: int = Field(
        default=50,
        description=(
            "Maximum records rendered per staging area. Staging areas are prepared by hand and are "
            "expected to be small; this only bounds the payload for a runaway staging."
        ),
    )

    excluded_columns: list[str] = Field(
        default_factory=lambda: ["id", "timestamp"],
        description="Struct fields omitted from the table's columns.",
    )

    # GatewayModule is a pydantic model, so the runtime handles need declared fields to live on.
    handle: Any = None
    channels: Any = None
    app: Any = None

    def connect(self, channels: GatewayChannels) -> None:
        self.channels = channels

    def rest(self, app: GatewayWebApp) -> None:
        # NO-OP: no REST routes; the panel calls the stage routes mounted by MountRestRoutes.
        ...

    def ui(self, app: "GatewayUI") -> None:
        from csp_gateway.server.web.spaday_ui import Region

        self.app = app
        self.handle = app.model(NAMESPACE, StagingState)
        # Listeners attach here rather than in `connect`, because stages declared by annotation are not
        # wired until the graph is finalized -- after every module's `connect` has run.
        for channel in self._selected(self.channels):
            self.channels.add_stage_listener(channel, self._on_stage_event)
        app.add(Region.DRAWER_BOTTOM, self._panel(), order=50, label="Staged data")
        self.republish()

    def _on_stage_event(self, events: list) -> None:
        self.republish()

    def republish(self) -> None:
        """Send the current staging snapshot to every connected viewer."""
        if self.handle is not None:
            self.handle.publish(self._snapshot())

    def _selected(self, channels: GatewayChannels) -> list[str]:
        allowed = set(self.mount_staging.select_from(channels))
        return [channel for channel in channels.staged_channels() if channel in allowed]

    def _snapshot(self) -> "StagingState":
        """The pending stagings, flattened into the shape the reactive tree renders."""
        channels = self.channels
        areas = []
        for channel in self._selected(channels):
            # `stage_list` is the pending-only view; `stage_lookup` alone would keep reporting stagings
            # that have already been released.
            for staging_id in channels.stage_list(channel):
                records = channels.stage_lookup(channel, staging_id).get(staging_id, [])
                shown = records[: self.max_records]
                columns = self._columns(shown)
                areas.append(
                    StagingArea(
                        id=f"{channel}:{staging_id}",
                        channel=channel,
                        url=self._stage_url(channel, staging_id),
                        summary=f"{len(records)} staged",
                        overflow=f"+{len(records) - self.max_records} more" if len(records) > self.max_records else "",
                        columns=[StagingColumn(id=name) for name in columns],
                        records=[
                            StagingRecord(
                                id=record.id,
                                cells=[StagingCell(id=name, value=self._cell_text(record, name)) for name in columns],
                            )
                            for record in shown
                        ],
                    )
                )
        return StagingState(empty=not areas, staged=bool(areas), areas=areas)

    def _columns(self, records: list) -> list[str]:
        """The struct fields to show, in declaration order, skipping ones no record has set."""
        excluded = set(self.excluded_columns)
        if not records:
            return []
        return [name for name in type(records[0]).metadata() if name not in excluded and any(hasattr(r, name) for r in records)]

    def _cell_text(self, record: Any, name: str) -> str:
        value = getattr(record, name, None)
        return "" if value is None else str(value)

    def _stage_url(self, channel: str, staging_id: str) -> str:
        return self.app.url(f"{self.app.web_app.settings.API_STR}/stage/{channel}?id={staging_id}")

    def _panel(self) -> Any:
        """The reactive tree: an empty-state callout, or one block per pending staging area."""
        from spaday.actions import field
        from spaday.components.shell import Column, Each, Show
        from spaday_webawesome import WaCallout

        return Column(
            Show(WaCallout().text("Nothing staged."), when=field(f"{NAMESPACE}.empty")),
            Show(
                Each(self._area_block(), field=f"{NAMESPACE}.areas", key="id", scope="area"),
                when=field(f"{NAMESPACE}.staged"),
            ),
            gap="0.75rem",
        ).style(padding="0.5rem")

    def _area_block(self) -> Any:
        """One staging area: a header, its record table, and the button that releases the whole thing."""
        from spaday import element
        from spaday.actions import CallEndpoint, item
        from spaday.components.shell import Column, Each, Row
        from spaday_webawesome import WaButton

        header = (
            Row(justify="space-between", gap="0.5rem")
            .child(element("strong").compute("textContent", item("channel")))
            .child(element("small").compute("textContent", item("summary")).style(opacity="0.7"))
        )
        table = element(
            "table",
            element("thead", element("tr", Each(self._header_cell(), items=item("columns"), key="id"), self._header_cell(blank=True))),
            element("tbody", Each(self._record_row(), items=item("records"), key="id", scope="record")),
        ).style(width="100%", border_collapse="collapse", font_size="0.8rem")
        # Struct fields are unbounded in number, so the table scrolls rather than squeezing its columns.
        scroller = element("div", table).style(overflow_x="auto")
        overflow = element("small").compute("textContent", item("overflow")).style(opacity="0.7")
        release = WaButton(variant="brand").text("Submit staging").style(width="100%").on("click", CallEndpoint("PATCH", item("url")))

        return Column(header, scroller, overflow, release, gap="0.4rem").style(
            border="1px solid var(--spa-border)", border_radius="6px", padding="0.5rem"
        )

    def _header_cell(self, blank: bool = False) -> Any:
        from spaday import element
        from spaday.actions import item

        cell = element("th").style(
            text_align="left",
            font_weight="600",
            opacity="0.7",
            white_space="nowrap",
            padding="0.15rem 0.4rem 0.25rem 0",
            border_bottom="1px solid var(--spa-border)",
        )
        # The trailing column heads the X buttons, so it has no label to bind.
        return cell if blank else cell.compute("textContent", item("id"))

    def _record_row(self) -> Any:
        """One staged record: a cell per column and an X that removes just that record."""
        from spaday import element
        from spaday.actions import CallEndpoint, item, obj, scope
        from spaday.components.shell import Each
        from spaday_webawesome import WaButton

        # `Staging.remove` matches on id, so the id alone identifies the record to drop.
        remove = (
            WaButton(appearance="plain", variant="danger")
            .text("\u00d7")
            .on("click", CallEndpoint("DELETE", scope("area.url"), obj({"id": scope("record.id")})))
        )
        cell = (
            element("td")
            .compute("textContent", item("value"))
            .style(
                white_space="nowrap",
                padding="0.2rem 0.4rem 0.2rem 0",
                border_bottom="1px solid var(--spa-border)",
                max_width="30ch",
                overflow="hidden",
                text_overflow="ellipsis",
            )
        )
        return element(
            "tr",
            Each(cell, items=item("cells"), key="id"),
            element("td", remove).style(text_align="right", padding="0"),
        )
