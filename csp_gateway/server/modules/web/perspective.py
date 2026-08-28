import asyncio
from collections.abc import Iterable
from datetime import date, datetime, timedelta
from io import BytesIO
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
import pyarrow
import pyarrow.json
import uvloop
from csp import ts
from fastapi import APIRouter, HTTPException, Request, Response, WebSocket
from perspective import Client, Server, Table
from perspective.handlers.starlette import PerspectiveStarletteHandler
from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator
from starlette.websockets import WebSocketDisconnect
from typing_extensions import TypeAliasType

from csp_gateway.server import ChannelSelection, GatewayChannels, GatewayModule
from csp_gateway.server.web import GatewayWebApp, get_default_responses
from csp_gateway.utils import GatewayException, PickleableQueue, get_args, get_origin, get_thread

if TYPE_CHECKING:
    from csp_gateway.server.web.spaday_ui import GatewayUI

__all__ = (
    "MountPerspectiveTables",
    "TableConfig",
    "create_pyarrow_table",
    "psp_schema_to_arrow_schema",
)

T = TypeVar("T")

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

log = getLogger(__name__)

_MAX_LAYOUT_DOWNLOAD_BYTES = 16 * 1024 * 1024

_PSP_ARROW_MAP = {
    int: pyarrow.int64(),
    float: pyarrow.float64(),
    bool: pyarrow.bool_(),
    str: pyarrow.string(),
    date: pyarrow.string(),
    datetime: pyarrow.timestamp("us", tz="UTC"),
}


def psp_schema_to_arrow_schema(psp_schema):
    return pyarrow.schema([(k, _PSP_ARROW_MAP[v]) for k, v in psp_schema.items()])


def perspective_thread(client: Client) -> None:
    # Create event loop for perspective callbacks
    psp_loop = asyncio.new_event_loop()

    # Attach to manager
    client.set_loop_callback(psp_loop.call_soon_threadsafe)

    # Run the perspective callback loop
    psp_loop.run_forever()


def create_pyarrow_table(key_name, data, computed_index, arrow_schema, date_conversion_set):
    new_data = []
    for item in data:
        flattened_items = item.psp_flatten()
        if key_name:
            for f in flattened_items:
                # TODO better
                f["basket-key"] = key_name
        if computed_index:
            index_name, index_fields = computed_index
            for f in flattened_items:
                computed_index_value = "-".join(str(f[field]) for field in index_fields)
                f[index_name] = computed_index_value
        new_data.extend(flattened_items)

    # convert to arrow
    json = b"\n".join(orjson.dumps(_) for _ in new_data)
    b = BytesIO()
    b.write(json)
    b.seek(0)
    table = pyarrow.json.read_json(
        b,
        parse_options=pyarrow.json.ParseOptions(explicit_schema=arrow_schema, unexpected_field_behavior="ignore"),
    )
    if date_conversion_set:
        table = pyarrow.Table.from_arrays(
            [table.column(name).cast(pyarrow.date32()) if name in date_conversion_set else table.column(name) for name in table.column_names],
            names=table.column_names,
        )
    return table


def pull_data_thread(
    queue: PickleableQueue,
    table_insts,
    computed_indexes,
    arrow_schema_insts,
    arrow_schema_date_conversions,
):
    while True:
        try:
            for (table_name, key_name), timeserieses in queue.get().items():
                table = create_pyarrow_table(
                    key_name,
                    timeserieses,
                    computed_indexes.get(table_name),
                    arrow_schema_insts[table_name],
                    arrow_schema_date_conversions[table_name],
                )
                stream = pyarrow.BufferOutputStream()
                writer = pyarrow.RecordBatchStreamWriter(stream, table.schema)
                writer.write_table(table)
                writer.close()
                table_insts[table_name].update(stream.getvalue().to_pybytes())
        except KeyboardInterrupt:
            raise
        except Exception:
            log.exception("Error processing perspective")


ExcludedColumns = TypeAliasType("ExcludedColumns", "set[str] | dict[str, bool | ExcludedColumns]")

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
    index: str | list[str] | None = Field(None, description="Index field(s) for this table.")
    architecture: Literal["server", "client-server"] = Field("client-server", description="Perspective data architecture for this table.")
    excluded_columns: ExcludedColumns | None = Field(None, description="Columns to exclude from the schema.")


# Backwards compat alias
AdditionalTableConfig = TableConfig

# Perspective 4 stored a workspace layout as a Lumino widget tree (`detail`/`master` of `split-area`
# and `tab-area` nodes) alongside a `viewers` map. Perspective 5 folded the workspace into
# `<perspective-viewer>` itself, which takes a `layout` tree of `split-layout`/`tab-layout` nodes and
# a `panels` map. Per-panel bodies are unchanged -- the viewer migrates those from their own stamped
# `version` -- so only the envelope is rewritten here.
_LAYOUT_NODE_TYPES = {"split-area": "split-layout", "tab-area": "tab-layout"}


def _migrate_layout_node(node: Any) -> Any:
    if not isinstance(node, dict):
        return node
    node_type = _LAYOUT_NODE_TYPES.get(node.get("type"))
    if node_type == "tab-layout":
        migrated = {"type": node_type, "tabs": list(node.get("widgets") or [])}
        if "currentIndex" in node:
            migrated["selected"] = node["currentIndex"]
        return migrated
    if node_type == "split-layout":
        return {
            "type": node_type,
            "orientation": node.get("orientation", "horizontal"),
            "sizes": list(node.get("sizes") or []),
            "children": [_migrate_layout_node(child) for child in node.get("children") or []],
        }
    return node


def migrate_perspective_layout(layout: str) -> str:
    """Rewrite a Perspective 4 workspace layout as the Perspective 5 equivalent.

    Layouts already in the version 5 shape, and anything unparseable, are returned untouched so this
    is safe to apply to every configured layout on every startup.
    """
    try:
        parsed = orjson.loads(layout)
    except orjson.JSONDecodeError:
        return layout
    if not isinstance(parsed, dict) or "viewers" not in parsed:
        return layout

    migrated: dict[str, Any] = {"panels": parsed.get("viewers") or {}}
    root = (parsed.get("detail") or {}).get("main")
    if root is not None:
        migrated["layout"] = _migrate_layout_node(root)
    masters = (parsed.get("master") or {}).get("widgets") or []
    if masters:
        migrated["masters"] = list(masters)
    return orjson.dumps(migrated).decode()


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
        description="Dict mapping table name to [perspective index](https://perspective-dev.github.io/guide/explanation/table/options.html). If a multi-index is provided, will create a new computed index field.",
        default={},
    )
    default_index: str | list[str] | None = Field(
        None, description="Default index field for all tables, i.e. 'id'. If a multi-index is provided, will create a new computed index field."
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
    _schema_insts: dict[str, dict] = PrivateAttr(default_factory=dict)
    _arrow_schema_insts: dict[str, dict] = PrivateAttr(default_factory=dict)
    _arrow_schema_date_conversions: dict[str, set[str]] = PrivateAttr(default_factory=dict)
    _table_insts: dict[str, Table] = PrivateAttr(default={})
    # Mapping from table name to (computed index field name, list of fields used to compute index)
    _computed_indexes: dict[str, tuple[str, list[str]]] = PrivateAttr(default={})

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
        """Get effective config for a table, merging tables dict entry with legacy fields and defaults."""
        config = self.tables.get(table_name)
        if config:
            return TableConfig(
                channel=config.channel,
                limit=config.limit if config.limit is not None else self.limits.get(table_name, self.default_limit),
                index=config.index if config.index is not None else self.indexes.get(table_name, self.default_index),
                architecture=config.architecture or self.architectures.get(table_name, self.default_architecture),
                excluded_columns=config.excluded_columns if config.excluded_columns is not None else self.excluded_table_columns.get(table_name),
            )
        return TableConfig(
            limit=self.limits.get(table_name, self.default_limit),
            index=self.indexes.get(table_name, self.default_index),
            architecture=self.architectures.get(table_name, self.default_architecture),
            excluded_columns=self.excluded_table_columns.get(table_name),
        )

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
            edge = channels.get_channel(field)
            excluded_columns = config.excluded_columns
            if isinstance(edge, dict):
                if not edge:
                    raise ValueError(f"No keys defined for dict basket channel {field}.")

                to_flatten = []
                for subfield in edge:
                    to_flatten.append(channels.get_channel(field, subfield))

                # save perspective schema
                schema = channels.get_channel(field, subfield).tstype.typ.psp_schema(excluded_columns)

                # save pyarrow schema
                self.add_table(
                    field,
                    schema,
                    limit=config.limit,
                    index=config.index,
                )

                if hasattr(subfield, "name"):
                    self.push_to_perspective(csp.flatten(to_flatten), field, subfield.name)
                else:
                    self.push_to_perspective(csp.flatten(to_flatten), field, subfield)

            else:
                ts_type = channels.get_channel(field).tstype.typ
                if get_origin(ts_type) is list:
                    schema = get_args(ts_type)[0].psp_schema(excluded_columns)
                    edge = csp.unroll(channels.get_channel(field))
                else:
                    schema = ts_type.psp_schema(excluded_columns)
                    edge = channels.get_channel(field)

                self.add_table(
                    field,
                    schema,
                    limit=config.limit,
                    index=config.index,
                )
                self.push_to_perspective(
                    edge,
                    field,
                )
            self._schema_insts[field] = schema
            self._arrow_schema_insts[field] = psp_schema_to_arrow_schema(schema)
            self._arrow_schema_date_conversions[field] = set()
            # annoying workaround for pyarrow reading dates
            for k, v in self._schema_insts[field].items():
                if v is date:
                    self._arrow_schema_date_conversions[field].add(k)

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

            if channel not in self._schema_insts:
                raise ValueError(
                    f"Table '{table_name}' references channel '{channel}' which is not a registered table. "
                    f"Ensure '{channel}' is included in the channel selection or as a primary table."
                )
            config = self._get_effective_config(table_name)
            excluded_columns = config.excluded_columns
            if excluded_columns is not None:
                # Recompute schema with different exclusions
                edge = channels.get_channel(channel)
                if isinstance(edge, dict):
                    a_subfield = next(iter(edge.keys()))
                    ts_type = channels.get_channel(channel, a_subfield).tstype.typ
                else:
                    ts_type = edge.tstype.typ
                    if get_origin(ts_type) is list:
                        ts_type = get_args(ts_type)[0]
                schema = ts_type.psp_schema(excluded_columns)
            else:
                schema = self._schema_insts[channel].copy()

            self.add_table(
                table_name,
                schema,
                limit=config.limit,
                index=config.index,
            )
            self._schema_insts[table_name] = schema
            self._arrow_schema_insts[table_name] = psp_schema_to_arrow_schema(schema)
            self._arrow_schema_date_conversions[table_name] = set()
            for k, v in schema.items():
                if v is date:
                    self._arrow_schema_date_conversions[table_name].add(k)

            # Wire up data flow: push same channel data to the additional table
            edge = channels.get_channel(channel)
            if isinstance(edge, dict):
                to_flatten = []
                for subfield in edge:
                    to_flatten.append(channels.get_channel(channel, subfield))
                if hasattr(subfield, "name"):
                    self.push_to_perspective(csp.flatten(to_flatten), table_name, subfield.name)
                else:
                    self.push_to_perspective(csp.flatten(to_flatten), table_name, subfield)
            else:
                ts_type = channels.get_channel(channel).tstype.typ
                if get_origin(ts_type) is list:
                    edge = csp.unroll(channels.get_channel(channel))
                else:
                    edge = channels.get_channel(channel)
                self.push_to_perspective(edge, table_name)

    def get_schema_from_field(self, channels: GatewayChannels, field: str):
        edge = channels.get_channel(field)

        if isinstance(edge, dict):
            a_subfield = next(iter(edge.keys()))
            edge = channels.get_channel(field, a_subfield)

        ts_type = edge.tstype.typ

        # if its a list of structs
        if get_origin(ts_type) is list:
            struct_type = get_args(ts_type)[0]
        else:
            struct_type = ts_type

        if not hasattr(struct_type, "psp_schema"):
            raise GatewayException(f"Type has no conversion to perspective: {struct_type}")

        excluded_columns = self.excluded_table_columns.get(field, None)
        return struct_type.psp_schema(excluded_columns)

    def add_table(self, field: str, schema, limit: int | None = None, index: str | None = None):
        if isinstance(index, list):
            # create a new computed index field
            index_fields = index
            index = "index" if "index" not in schema else "-".join(index)
            schema[index] = str
            self._computed_indexes[field] = (index, index_fields)
        self._table_insts[field] = self._client.table(schema, limit, index, name=field)

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
        key_name: str = "",
    ):
        with csp.alarms():
            alarm: ts[bool] = csp.alarm(bool)
        with csp.state():
            s_buffer = {}

        with csp.start():
            csp.schedule_alarm(alarm, self.update_interval, True)

        if csp.ticked(timeseries):
            if (table_name, key_name) not in s_buffer:
                s_buffer[(table_name, key_name)] = []
            s_buffer[(table_name, key_name)].append(timeseries)

        if csp.ticked(alarm):
            if len(s_buffer) > 0:
                self._queue.put(s_buffer)
                s_buffer = {}
            csp.schedule_alarm(alarm, self.update_interval, True)

    def _get_tables(self) -> dict[str, dict[str, str]]:
        all_tables = {table_name: None for table_name in self._client.get_hosted_table_names() if table_name not in self._unused_tables}
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
        api_router: APIRouter = app.get_router("api")

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
            return {
                "limits": {**self.limits, **{k: v.limit for k, v in self.tables.items() if v.limit is not None}},
                "default_limit": self.default_limit,
                "indexes": {
                    **self.indexes,
                    **{k: v.index for k, v in self.tables.items() if v.index is not None},
                    **{k: v[0] for k, v in self._computed_indexes.items()},
                },
                "default_index": self.default_index,
                "architectures": {**self.architectures, **{k: v.architecture for k, v in self.tables.items()}},
                "default_architecture": self.default_architecture,
                "layouts": self.layouts,
                "default_layout": self.default_layout,
                "default_layout_tables": self._select_default_layout_tables(self._get_tables()),
                "tables": self._get_tables(),
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
        """The per-table `architecture`/`index`/`limit` the Spaday Perspective panel needs.

        A multi-index table is indexed client-side by the computed field, not the fields it is
        computed from, so those tables report the computed name here.
        """
        config = self._get_effective_config(table_name)
        index = self._computed_indexes[table_name][0] if table_name in self._computed_indexes else config.index
        options: dict[str, Any] = {"architecture": config.architecture}
        if isinstance(index, str):
            options["index"] = index
        if config.limit is not None:
            options["limit"] = config.limit
        return options

    def build_default_ui_layout(self, tables: dict[str, dict[str, str]]) -> dict[str, Any] | None:
        """Return a custom default Spaday workspace layout, or `None` to use the generated layout."""
        return None

    def ui(self, app: "GatewayUI") -> None:
        # Register the Perspective workspace as the main panel of the spaday UI. Data rides
        # Perspective's own websocket (mounted by rest() at {API_STR}/perspective); the spaday
        # page only carries the workspace layout/theme config.
        from csp_gateway.server.web.spaday_ui import Region

        layouts = dict(self._layouts)
        tables = self._get_tables()
        app.add(
            Region.MAIN,
            app.perspective_panel(
                route=f"{app.settings.API_STR}{self._route}",
                tables=list(tables.keys()),
                default_tables=self._select_default_layout_tables(tables),
                layouts=layouts,
                schemas=tables,
                default_layout=self.build_default_ui_layout(tables),
                table_options={name: self._ui_table_options(name) for name in tables},
            ),
        )
        default_view = self.default_layout or "__default__"
        app.seed_store(view=default_view, layout_view=default_view)
        app.add(Region.HEADER_RIGHT, app.layout_selector(layouts, value=default_view), order=90)
        app.add(Region.HEADER_RIGHT, app.save_layout_button(), order=100)
        app.add(Region.HEADER_RIGHT, app.download_layout_button(), order=101)

    def run_perspective(self):
        """Launch the perspective threads"""
        psp_load_thread = get_thread(
            target=pull_data_thread,
            args=(
                self._queue,
                self._table_insts,
                self._computed_indexes,
                self._arrow_schema_insts,
                self._arrow_schema_date_conversions,
            ),
        )
        psp_load_thread.start()
