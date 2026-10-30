from collections import OrderedDict
from collections.abc import Iterable
from datetime import timedelta
from hashlib import sha256
from logging import getLogger
from typing import (
    TYPE_CHECKING,
    Any,
    Literal,
    TypeVar,
)
from urllib.parse import parse_qs

import csp
import orjson
from csp import ts
from fastapi import APIRouter, HTTPException, Request, Response, WebSocket
from perspective import Client, Server, Table
from perspective.handlers.starlette import PerspectiveStarletteHandler
from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator
from starlette.websockets import WebSocketDisconnect
from typing_extensions import TypeAliasType

from csp_gateway.server import ChannelSelection, GatewayChannels, GatewayModule
from csp_gateway.server.web import GatewayWebApp, get_default_responses
from csp_gateway.utils import PickleableQueue, get_args, get_origin, get_thread
from csp_gateway.utils.struct.psp import PspArrowEncoder

if TYPE_CHECKING:
    from csp_gateway.server.web.spaday_ui import GatewayUI

__all__ = (
    "MountPerspectiveTables",
    "TableConfig",
)

T = TypeVar("T")

log = getLogger(__name__)

_MAX_LAYOUT_DOWNLOAD_BYTES = 16 * 1024 * 1024
_MAX_SHARED_LAYOUT_BYTES = 1024 * 1024
_MAX_SHARED_LAYOUTS = 1000


def pull_data_thread(queue: PickleableQueue, table_insts, encoders):
    while True:
        try:
            for table_name, timeserieses in queue.get().items():
                table_insts[table_name].update(encoders[table_name].encode(timeserieses))
        except KeyboardInterrupt:
            raise
        except Exception:
            log.exception("Error processing perspective")


ExcludedColumns = TypeAliasType("ExcludedColumns", "set[str] | dict[str, bool | ExcludedColumns]")

ListFlatten = Literal["cartesian", "zip", "stringify", "stringify_formatted"]
MapFlatten = Literal["pivot", "stringify", "stringify_formatted"]

ViewConfig = dict[
    Literal["table", "group_by", "split_by", "aggregates", "columns", "sort", "filter", "expressions"],
    (
        str  # table
        | list[str]  # group_by, split_by, columns, expressions
        | dict[str, str]  # aggregates
        | list[dict[str, str | Literal["asc", "desc"]]]  # sort
        | list[dict[str, str | list[str | int | float]]]  # filter
    ),
]


class TableConfig(BaseModel):
    """Configuration for a perspective table. When channel is omitted, defaults to using the table name as the channel."""

    channel: str | None = Field(None, description="The source channel name. Defaults to the table name if omitted.")
    limit: int | None = Field(None, description="Row limit for this table.")
    index: str | list[str] | None = Field(None, description="Index field for this table, or a list of fields for a composite index.")
    architecture: Literal["server", "client-server"] = Field("client-server", description="Perspective data architecture for this table.")
    excluded_columns: ExcludedColumns | None = Field(None, description="Columns to exclude from the schema.")
    list_flatten: ListFlatten = Field(
        "cartesian",
        description=("How Perspective flattens list columns."),
    )
    map_flatten: MapFlatten = Field(
        "stringify_formatted",
        description=("How Perspective shows dict fields sent as Arrow maps."),
    )


# Backwards compat alias
AdditionalTableConfig = TableConfig


def _migrate_layout_node(node: Any) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise TypeError("Layout nodes must be objects")
    if node.get("type") == "tab-area":
        return {"type": "tab-layout", "tabs": list(node.get("widgets") or []), "selected": node.get("currentIndex", 0)}
    if node.get("type") == "split-area":
        children = [_migrate_layout_node(child) for child in node.get("children") or []]
        sizes = node.get("sizes") or ([1 / len(children)] * len(children) if children else [])
        return {
            "type": "split-layout",
            "orientation": node.get("orientation", "horizontal"),
            "sizes": list(sizes),
            "children": children,
        }
    raise ValueError("Unsupported layout node type")


def migrate_perspective_layout(layout: str) -> str:
    """Rewrite a Perspective 4 workspace layout as the Perspective 5 equivalent.

    Layouts already in the version 5 shape, and anything unparseable, are returned untouched so this
    is safe to apply to every configured layout on every startup.
    """
    try:
        parsed = orjson.loads(layout)
        if not isinstance(parsed, dict) or "viewers" not in parsed or "layout" in parsed or "panels" in parsed:
            return layout

        migrated: dict[str, Any] = {"panels": parsed.get("viewers") or {}}
        detail = (parsed.get("detail") or {}).get("main")
        root = _migrate_layout_node(detail) if detail is not None else None
        master = parsed.get("master") or {}
        masters = list(master.get("widgets") or [])
        if masters:
            sidebar = {
                "type": "split-layout",
                "orientation": "vertical",
                "sizes": list(master.get("sizes") or [1 / len(masters)] * len(masters)),
                "children": [{"type": "tab-layout", "tabs": [name], "selected": 0} for name in masters],
            }
            root = (
                {
                    "type": "split-layout",
                    "orientation": "horizontal",
                    "sizes": list(parsed.get("sizes") or [0.25, 0.75]),
                    "children": [sidebar, root],
                }
                if root is not None
                else sidebar
            )
            migrated["masters"] = masters
        if root is not None:
            migrated["layout"] = root
        return orjson.dumps(migrated).decode()
    except (AttributeError, TypeError, ValueError):
        return layout


def _is_channel_selection_input(v) -> bool:
    """Detect whether a raw input value looks like a ChannelSelection (old-style tables field)."""
    if v is None or isinstance(v, list):
        return True
    if isinstance(v, ChannelSelection):
        return True
    if isinstance(v, dict):
        keys = set(v.keys())
        # Empty dict is ambiguous — treat as empty TableConfig dict (new-style)
        if len(keys) == 0:
            return False
        if keys <= {"include", "exclude"}:
            # Verify values aren't TableConfig-like dicts (handles edge case of channel named "include"/"exclude")
            for val in v.values():
                if isinstance(val, (dict, TableConfig)):
                    return False
            return True
    return False


class MountPerspectiveTables(GatewayModule):
    requires: ChannelSelection | None = []

    tables: dict[str, TableConfig] = Field(
        default={},
        description=(
            "Dictionary mapping table name to a TableConfig. Each entry configures a perspective table. "
            "If 'channel' is omitted in the config, the table name is used as the channel name. "
            "If 'channel' is set to a different name, an additional table is created mirroring that channel's data. "
            "Tables entries whose channel matches their name override per-table settings from legacy fields "
            "(limits, indexes, etc.). For backwards compatibility, this field also accepts a ChannelSelection "
            "(list or dict with include/exclude keys) which will be moved to 'channel_selection'."
        ),
    )
    channel_selection: ChannelSelection = Field(
        default_factory=ChannelSelection,
        description="Controls which channels are auto-discovered as perspective tables. "
        "Channels not explicitly listed in 'tables' will use defaults. "
        "This is the successor to the old 'tables' field when it was a ChannelSelection.",
    )
    _unused_tables: list[str] | None = PrivateAttr(default_factory=list)

    server_views: dict[str, ViewConfig] | None = Field(
        default_factory=dict, description="Optional dict mapping new table name to a dict with table and view information"
    )

    # Legacy per-table config fields (still functional; tables entries take precedence)
    limits: dict[str, int] = Field(
        description="Dict mapping table name to [perspective limit](https://perspective-dev.github.io/guide/explanation/table/options.html)",
        default={},
    )
    default_limit: int | None = Field(None, description="Default limit for all tables, i.e. 1000")
    indexes: dict[str, str | list[str] | None] = Field(
        description="Dict mapping table name to [perspective index](https://perspective-dev.github.io/guide/explanation/table/options.html). A list of fields makes a composite index.",
        default={},
    )
    default_index: str | list[str] | None = Field(
        None, description="Default index field for all tables, i.e. 'id'. A list of fields makes a composite index."
    )
    architectures: dict[str, Literal["server", "client-server"]] = Field(
        description="Dict mapping table name to [perspective data architecture](https://perspective-dev.github.io/guide/explanation/architecture.html), default is client-server",
        default={},
    )
    default_architecture: Literal["server", "client-server"] = Field(
        "client-server",
        description="Default architecture for all tables, i.e. 'client-server'",
    )
    excluded_table_columns: dict[str, ExcludedColumns] = Field(
        default={},
        description=(
            "Dictionary from table name to columns (which are attributes on a GatewayStruct) to exclude from perspective. "
            "The columns to exclude can be specified as either be a set of column names or as a dictionary. If specified "
            "as a dictionary, the dictionary is a mapping from attribute name to sub-attributes to exclude. This is defined "
            "recursively so it can be used to exclude fields that are structs of structs."
        ),
    )

    layouts: dict[str, str] = Field(default={})
    default_layout: str | None = Field(
        None,
        description="Default layout to use for all tables if no specific layout is provided.",
    )
    default_layout_tables: list[str] = Field(
        default_factory=list,
        description="Tables the generated default layout shows, by table name and in this order. "
        "Empty means the first `default_layout_max_tables` tables in name order. Names that are not "
        "registered tables are ignored.",
    )
    default_layout_max_tables: int = Field(
        5,
        description="How many tables the generated default layout shows when `default_layout_tables` "
        "is not set. Every table is still available to add by hand; this only bounds the generated "
        "layout, whose tabs get narrower the more it holds.",
    )
    share_layouts: bool = Field(
        False,
        description="Adds a share button to the UI that stores the current layout on the server and puts its id "
        "in the page URL (`?layout=<id>`), so the link opens the same layout for any user. Shared layouts are held "
        "in memory and lost on restart; use `layouts` or the downloaded JSON to keep one.",
    )

    @field_validator("layouts")
    @classmethod
    def _migrate_layouts(cls, layouts: dict[str, str]) -> dict[str, str]:
        return {name: migrate_perspective_layout(layout) for name, layout in layouts.items()}

    update_interval: timedelta = Field(default=timedelta(seconds=2))
    perspective_field: str = Field(
        None,
        description="Optional field on the channels which has an instance of perspective.Server to use, "
        "such that it can also be used by other GatewayModules with custom table preparation logic.",
    )
    layouts_field: str = Field(
        None,
        description="Optional field on the channels which has a dictionary of layouts to use, "
        "such that it can also be used by other GatewayModules with custom table preparation logic.",
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_tables_input(cls, data):
        if not isinstance(data, dict):
            return data

        tables_input = data.get("tables")
        if _is_channel_selection_input(tables_input):
            # Old style: `tables` was a ChannelSelection — move to channel_selection
            # Only do this if channel_selection is not already explicitly provided
            if tables_input is not None and "channel_selection" not in data:
                data["channel_selection"] = tables_input
            data.pop("tables", None)

        # Merge deprecated additional_tables into tables
        additional = data.pop("additional_tables", None)
        if additional:
            tables = data.setdefault("tables", {})
            tables.update(additional)

        return data

    _route: str = "/perspective"
    _server: Server = PrivateAttr(default=None)
    _client: Client = PrivateAttr(default=None)

    _layouts: dict[str, str] = PrivateAttr(default={})
    _shared_layouts: OrderedDict[str, dict] = PrivateAttr(default_factory=OrderedDict)
    _encoders: dict[str, PspArrowEncoder] = PrivateAttr(default_factory=dict)
    _table_insts: dict[str, Table] = PrivateAttr(default={})

    _queue: PickleableQueue = PrivateAttr(default_factory=PickleableQueue)

    @field_validator("server_views", mode="after")
    def _validate_server_views(cls, v: dict[str, ViewConfig]) -> dict[str, ViewConfig]:
        for new_table_name, view_config in v.items():
            # Must specify table
            if "table" not in view_config:
                raise ValueError(f"View config for {new_table_name} must specify a base 'table' to create the view from.")
            # Must specify at least one view operation
            if len(view_config.keys()) == 1:
                raise ValueError(f"View config for {new_table_name} must specify at least one view operation in addition to the base 'table'.")
        return v

    def _get_effective_config(self, table_name: str) -> TableConfig:
        """Get effective config for a table, merging tables dict entry with legacy fields and defaults.

        Perspective takes an `index` or a `limit` for a table, never both. A `default_limit` or a
        `default_index` gives way to anything set for the table itself. Setting both on one table is
        passed through, for Perspective to reject.
        """
        config = self.tables.get(table_name)
        limit = config.limit if config and config.limit is not None else self.limits.get(table_name)
        index = config.index if config and config.index is not None else self.indexes.get(table_name)
        # An index the table lists as None opts it out of `default_index`.
        if index is None and limit is None and table_name not in self.indexes:
            index = self.default_index
        if index is None and limit is None:
            limit = self.default_limit
        return TableConfig(
            channel=config.channel if config else None,
            limit=limit,
            index=index,
            architecture=(config.architecture if config else None) or self.architectures.get(table_name, self.default_architecture),
            list_flatten=config.list_flatten if config else "cartesian",
            map_flatten=config.map_flatten if config else "stringify_formatted",
            excluded_columns=config.excluded_columns
            if config and config.excluded_columns is not None
            else self.excluded_table_columns.get(table_name),
        )

    @staticmethod
    def _row_type(channels: GatewayChannels, channel: str):
        """The struct type of a channel."""
        edge = channels.get_channel(channel)
        if isinstance(edge, dict):
            if not edge:
                raise ValueError(f"No keys defined for dict basket channel {channel}.")
            ts_type = channels.get_channel(channel, next(iter(edge))).tstype.typ
        else:
            ts_type = edge.tstype.typ
        return get_args(ts_type)[0] if get_origin(ts_type) is list else ts_type

    def _push_channel(self, channels: GatewayChannels, channel: str, table_name: str) -> None:
        """Wire a channel (flattened into one stream if it is a dict basket) to a Table."""
        edge = channels.get_channel(channel)
        if isinstance(edge, dict):
            self.push_to_perspective(csp.flatten([channels.get_channel(channel, key) for key in edge]), table_name)
        elif get_origin(edge.tstype.typ) is list:
            self.push_to_perspective(csp.unroll(edge), table_name)
        else:
            self.push_to_perspective(edge, table_name)

    def _connect_all_tables(self, channels: GatewayChannels) -> None:
        # Determine primary channels from channel_selection + server_views + tables entries without explicit channel
        selected_channels = set(self.channel_selection.select_from(channels)) | {_["table"] for _ in self.server_views.values()}
        for table_name, config in self.tables.items():
            channel = config.channel or table_name
            if channel == table_name:
                selected_channels.add(table_name)

        # Register primary tables (table_name == channel_name)
        for field in selected_channels:
            config = self._get_effective_config(field)
            encoder = PspArrowEncoder(self._row_type(channels, field), config.excluded_columns)
            self._encoders[field] = encoder
            self.add_table(field, encoder, limit=config.limit, index=config.index, list_flatten=config.list_flatten, map_flatten=config.map_flatten)
            self._push_channel(channels, field, field)

        # Add server-defined views
        for new_table_name, view_config in self.server_views.items():
            # Copy: `self.server_views` is user configuration and is read again on a reconnect.
            view_config = dict(view_config)
            base_table = self._client.open_table(view_config.pop("table"))
            view = base_table.view(**view_config)
            self._table_insts[new_table_name] = self._client.table(view, name=new_table_name)

        # Register additional tables (tables entries where channel differs from table_name)
        for table_name, table_config in self.tables.items():
            channel = table_config.channel or table_name
            if channel == table_name:
                continue  # Already handled as a primary table above

            if channel not in self._encoders:
                raise ValueError(
                    f"Table '{table_name}' references channel '{channel}' which is not a registered table. "
                    f"Ensure '{channel}' is included in the channel selection or as a primary table."
                )
            config = self._get_effective_config(table_name)
            if config.excluded_columns is not None:
                # Recompute the schema with different exclusions
                encoder = PspArrowEncoder(self._row_type(channels, channel), config.excluded_columns)
            else:
                encoder = self._encoders[channel]
            self._encoders[table_name] = encoder
            self.add_table(
                table_name, encoder, limit=config.limit, index=config.index, list_flatten=config.list_flatten, map_flatten=config.map_flatten
            )
            # Wire up data flow: push same channel data to the additional table
            self._push_channel(channels, channel, table_name)

    def add_table(
        self,
        field: str,
        schema: "PspArrowEncoder | dict",
        limit: int | None = None,
        index: str | list[str] | None = None,
        list_flatten: ListFlatten = "cartesian",
        map_flatten: MapFlatten = "stringify_formatted",
    ):
        """Create a Perspective table, from an encoder or a Perspective schema.

        An encoder's table is created from its nested Arrow schema, so Perspective can check the
        index against the list columns here, at startup, rather than on the first update.
        """
        if isinstance(schema, PspArrowEncoder):
            schema = schema.empty_ipc()
        self._table_insts[field] = self._client.table(schema, limit, index, name=field, list_flatten=list_flatten, map_flatten=map_flatten)

    def connect(self, channels: GatewayChannels) -> None:
        if self.perspective_field:
            self._server = getattr(channels, self.perspective_field)
        else:
            self._server = Server()
        self._client = self._server.new_local_client()
        self._layouts = self.layouts.copy()
        if self.layouts_field:
            # Not reachable from the field validator, so migrate on the way in.
            self._layouts.update({name: migrate_perspective_layout(layout) for name, layout in getattr(channels, self.layouts_field).items()})
        self._connect_all_tables(channels)

        # Run perspective on background daemon threads
        self.run_perspective()

    @csp.node
    def push_to_perspective(  # type: ignore[no-untyped-def]
        self,
        timeseries: ts["T"],
        table_name: str,
    ):
        with csp.alarms():
            alarm: ts[bool] = csp.alarm(bool)
        with csp.state():
            s_buffer = []

        with csp.start():
            csp.schedule_alarm(alarm, self.update_interval, True)

        if csp.ticked(timeseries):
            s_buffer.append(timeseries)

        if csp.ticked(alarm):
            if len(s_buffer) > 0:
                self._queue.put({table_name: s_buffer})
                s_buffer = []
            csp.schedule_alarm(alarm, self.update_interval, True)

    def _get_tables(self) -> dict[str, dict[str, str]]:
        # Sorted: tables are registered from a set, so the hosted order varies between runs and
        # the generated layout would put panels in a different order on every restart.
        names = sorted(name for name in self._client.get_hosted_table_names() if name not in self._unused_tables)
        all_tables: dict[str, dict[str, str] | None] = {name: None for name in names}
        for table_name in all_tables:
            table = self._client.open_table(table_name)
            schema = table.schema()
            all_tables[table_name] = {col: schema[col] for col in table.columns()}
        return all_tables

    def _get_table_sizes(self) -> dict[str, int]:
        all_tables = {table_name: None for table_name in self._client.get_hosted_table_names()}
        for table_name in all_tables:
            table = self._client.open_table(table_name)
            all_tables[table_name] = table.size()
        return all_tables

    def _check_unused_tables(self, channels: GatewayChannels) -> None:
        for table, key in channels._null_ts:
            # NOTE: if only a single key is not bound, we consider the table
            # in-use since we flatten the keys
            # TODO: if all keys are unused, we could consider the table unused
            if key is not None or table in self._unused_tables:
                continue
            self._unused_tables.append(table)

    def rest(self, app: GatewayWebApp) -> None:
        # NOTE: We use an internal API here
        self._check_unused_tables(object.__getattribute__(app.gateway, "channels"))

        async def websocket_handler(websocket: WebSocket) -> None:
            handler = PerspectiveStarletteHandler(perspective_server=self._server, websocket=websocket)
            try:
                await handler.run()
            except WebSocketDisconnect:
                # ignore
                ...

        # Get API Router
        api_router: APIRouter = app.get_router("api", self.api_version)

        # Mount the perspective websocket handler
        api_router.add_api_websocket_route(self._route, websocket_handler)

        # add route to fetch table names
        @api_router.get(
            "{}/{}".format(self._route, "tables"),
            responses=get_default_responses(),
            response_model=dict[str, dict[str, str]],
            tags=["Utility"],
        )
        async def get_perspective_table_names():
            """
            This endpoint exposes the served [perspective](https://github.com/perspective-dev/perspective) table names and schemas.

            It can be used for `perspective`-based dashboards to build interactive visualization,
            such as the one provided as an example for the `csp-gateway` project.
            Depending on your server's configuration, this might be available at [`/`](/)
            """
            return self._get_tables()

        # add route to fetch layouts
        @api_router.get(
            "{}/{}".format(self._route, "layouts"),
            responses=get_default_responses(),
            response_model=dict[str, str],
            tags=["Utility"],
        )
        async def get_perspective_layouts():
            """
            This endpoint exposes saved [perspective](https://github.com/perspective-dev/perspective) workspace layouts.
            These layouts can be configured server side to be provided to all clients.
            """
            return self._layouts

        @api_router.post("{}/{}".format(self._route, "download-layout"), include_in_schema=False)
        async def download_perspective_layout(request: Request) -> Response:
            try:
                content_length = int(request.headers.get("content-length", 0))
                if content_length > _MAX_LAYOUT_DOWNLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Layout is too large")
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > _MAX_LAYOUT_DOWNLOAD_BYTES:
                        raise HTTPException(status_code=413, detail="Layout is too large")
                fields = parse_qs(body.decode("utf-8"), strict_parsing=True, max_num_fields=1)
                layout = fields["layout"][0]
                parsed = orjson.loads(layout)
                if not isinstance(parsed, dict) or not isinstance(parsed.get("layout"), dict) or not isinstance(parsed.get("panels"), dict):
                    raise TypeError
            except HTTPException:
                raise
            except (KeyError, TypeError, UnicodeDecodeError, ValueError, orjson.JSONDecodeError) as exc:
                raise HTTPException(status_code=400, detail="Invalid layout") from exc
            return Response(
                content=layout,
                media_type="application/json",
                headers={
                    "Cache-Control": "no-store",
                    "Content-Disposition": 'attachment; filename="layout.json"',
                    "X-Content-Type-Options": "nosniff",
                },
            )

        if self.share_layouts:

            @api_router.post("{}/{}".format(self._route, "shared-layouts"), include_in_schema=False)
            async def share_perspective_layout(request: Request) -> dict[str, str]:
                if int(request.headers.get("content-length", 0)) > _MAX_SHARED_LAYOUT_BYTES:
                    raise HTTPException(status_code=413, detail="Layout is too large")
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > _MAX_SHARED_LAYOUT_BYTES:
                        raise HTTPException(status_code=413, detail="Layout is too large")
                try:
                    layout = orjson.loads(body)
                except orjson.JSONDecodeError as exc:
                    raise HTTPException(status_code=400, detail="Invalid layout") from exc
                if not isinstance(layout, dict) or not isinstance(layout.get("layout"), dict) or not isinstance(layout.get("panels"), dict):
                    raise HTTPException(status_code=400, detail="Invalid layout")
                # Content-addressed, so sharing the same layout twice gives the same link.
                layout_id = sha256(orjson.dumps(layout, option=orjson.OPT_SORT_KEYS)).hexdigest()[:16]
                self._shared_layouts[layout_id] = layout
                self._shared_layouts.move_to_end(layout_id)
                while len(self._shared_layouts) > _MAX_SHARED_LAYOUTS:
                    self._shared_layouts.popitem(last=False)
                return {"id": layout_id}

            @api_router.get("{}/{}/{{layout_id}}".format(self._route, "shared-layouts"), include_in_schema=False)
            async def get_shared_perspective_layout(layout_id: str) -> dict:
                if layout_id not in self._shared_layouts:
                    raise HTTPException(status_code=404, detail="Unknown layout")
                self._shared_layouts.move_to_end(layout_id)
                return self._shared_layouts[layout_id]

        # add route to fetch layouts
        @api_router.get(
            "{}/{}".format(self._route, "meta"),
            responses=get_default_responses(),
            response_model=dict[
                str,
                (
                    None
                    | int  # limit
                    | str  # index, architecture
                    | list[str]  # index, unused tables
                    | dict[str, str | int | list[str] | dict[str, str]]
                ),
            ],
            tags=["Utility"],
        )
        async def get_perspective_meta():
            """
            This endpoint exposes perspective meta information, including limits,
            indexes, and architecture.
            """
            tables = self._get_tables()
            return {
                "limits": {**self.limits, **{k: v.limit for k, v in self.tables.items() if v.limit is not None}},
                "default_limit": self.default_limit,
                "indexes": {**self.indexes, **{k: v.index for k, v in self.tables.items() if v.index is not None}},
                "default_index": self.default_index,
                "architectures": {**self.architectures, **{k: v.architecture for k, v in self.tables.items()}},
                "default_architecture": self.default_architecture,
                "layouts": self.layouts,
                "default_layout": self.default_layout,
                "default_layout_tables": self._select_default_layout_tables(tables),
                "tables": tables,
                "unused_tables": self._unused_tables,
                "table_sizes": self._get_table_sizes(),
            }

    def _select_default_layout_tables(self, available: Iterable[str]) -> list[str]:
        """The tables the generated default layout shows, in display order."""
        names = list(available)
        if self.default_layout_tables:
            known = set(names)
            return [name for name in self.default_layout_tables if name in known]
        return sorted(names)[: self.default_layout_max_tables]

    def _ui_table_options(self, table_name: str) -> dict[str, Any]:
        """The per-table options the Spaday Perspective panel needs.

        The panel mirrors a `client-server` table as a replica of the server table's view, which
        inherits the server's index and limit.
        """
        config = self._get_effective_config(table_name)
        options: dict[str, Any] = {"architecture": config.architecture}
        if config.index is not None:
            options["index"] = config.index
        return options

    def build_default_ui_layout(self, tables: dict[str, dict[str, str]]) -> dict[str, Any] | None:
        """Return a custom default Spaday workspace layout, or `None` to use the generated layout."""
        return None

    def ui(self, app: "GatewayUI") -> None:
        # Register the Perspective workspace as the main panel of the spaday UI. Data rides
        # Perspective's own websocket (mounted by rest() under the module's API version); the
        # spaday page only carries the workspace layout/theme config.
        from csp_gateway.server.web.spaday_ui import Region

        layouts = dict(self._layouts)
        tables = self._get_tables()
        app.add(
            Region.MAIN,
            app.perspective_panel(
                route=app.web_app.api_path(self._route, self.api_version),
                tables=list(tables.keys()),
                default_tables=self._select_default_layout_tables(tables),
                layouts=layouts,
                schemas=tables,
                default_layout=self.build_default_ui_layout(tables),
                table_options={name: self._ui_table_options(name) for name in tables},
                shared_layouts_route=app.web_app.api_path(f"{self._route}/shared-layouts", self.api_version) if self.share_layouts else None,
            ),
        )
        default_view = self.default_layout or "__default__"
        app.seed_store(view=default_view, layout_view=default_view)
        app.add(Region.HEADER_RIGHT, app.layout_selector(layouts, value=default_view), order=90)
        app.add(Region.HEADER_RIGHT, app.save_layout_button(), order=100)
        app.add(Region.HEADER_RIGHT, app.download_layout_button(), order=101)
        if self.share_layouts:
            app.add(Region.HEADER_RIGHT, app.share_layout_button(app.web_app.api_path(f"{self._route}/shared-layouts", self.api_version)), order=102)

    def run_perspective(self):
        """Launch the perspective threads"""
        psp_load_thread = get_thread(
            target=pull_data_thread,
            args=(self._queue, self._table_insts, self._encoders),
        )
        psp_load_thread.start()
