import asyncio
from datetime import date, datetime, timedelta
from io import BytesIO
from logging import getLogger
from typing import (
    Dict,
    Literal,
    Optional,
    Set,
    TypeVar,
    Union,
)

import csp
import orjson
import pyarrow
import pyarrow.json
import uvloop
from csp import ts
from fastapi import APIRouter, WebSocket
from perspective import Client, Server, Table
from perspective.handlers.starlette import PerspectiveStarletteHandler
from pydantic import Field, PrivateAttr
from starlette.websockets import WebSocketDisconnect
from typing_extensions import TypeAliasType

from csp_gateway.server import ChannelSelection, GatewayChannels, GatewayModule
from csp_gateway.server.web import GatewayWebApp, get_default_responses
from csp_gateway.utils import PickleableQueue, get_args, get_origin, get_thread

__all__ = (
    "psp_schema_to_arrow_schema",
    "create_pyarrow_table",
    "MountPerspectiveTables",
)

T = TypeVar("T")

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

log = getLogger(__name__)

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


def create_pyarrow_table(key_name, data, arrow_schema, date_conversion_set):
    new_data = []
    for item in data:
        flattened_items = item.psp_flatten()
        if key_name:
            for f in flattened_items:
                # TODO better
                f["basket-key"] = key_name
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


def pull_data_thread(queue: PickleableQueue, table_insts, arrow_schema_insts, arrow_schema_date_conversions):
    while True:
        try:
            for (table_name, key_name), timeserieses in queue.get().items():
                table = create_pyarrow_table(
                    key_name,
                    timeserieses,
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


ExcludedColumns = TypeAliasType("ExcludedColumns", "Union[Set[str], Dict[str, Union[bool, ExcludedColumns]]]")


class MountPerspectiveTables(GatewayModule):
    requires: Optional[ChannelSelection] = []

    tables: ChannelSelection = Field(default_factory=ChannelSelection)

    limits: Dict[str, int] = Field(
        description="Dict mapping table name to [perspective limit](https://perspective-dev.github.io/guide/explanation/table/options.html)",
        default={},
    )
    default_limit: Optional[int] = Field(None, description="Default limit for all tables, i.e. 1000")
    indexes: Dict[str, Optional[str]] = Field(
        description="Dict mapping table name to [perspective index](https://perspective-dev.github.io/guide/explanation/table/options.html)",
        default={},
    )
    default_index: Optional[str] = Field(None, description="Default index field for all tables, i.e. 'id'")
    architectures: Dict[str, Literal["server", "client-server"]] = Field(
        description="Dict mapping table name to [perspective data architecture](https://perspective-dev.github.io/guide/explanation/architecture.html), default is client-server",
        default={},
    )
    default_architecture: Literal["server", "client-server"] = Field(
        "client-server",
        description="Default architecture for all tables, i.e. 'client-server'",
    )

    layouts: Dict[str, str] = Field(default={})
    default_layout: Optional[str] = Field(
        None,
        description="Default layout to use for all tables if no specific layout is provided.",
    )

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
    excluded_table_columns: Dict[str, ExcludedColumns] = Field(
        default={},
        description=(
            "Dictionary from table name to columns (which are attributes on a GatewayStruct) to exclude from perspective. "
            "The columns to exclude can be specified as either be a set of column names or as a dictionary. If specified "
            "as a dictionary, the dictionary is a mapping from attribute name to sub-attributes to exclude. This is defined "
            "recursively so it can be used to exclude fields that are structs of structs."
        ),
    )

    _route: str = "/perspective"
    _server: Server = PrivateAttr(default=None)
    _client: Client = PrivateAttr(default=None)

    _layouts: Dict[str, str] = PrivateAttr(default={})
    _schema_insts: Dict[str, Dict] = PrivateAttr(default_factory=dict)
    _arrow_schema_insts: Dict[str, Dict] = PrivateAttr(default_factory=dict)
    _arrow_schema_date_conversions: Dict[str, Set[str]] = PrivateAttr(default_factory=dict)
    _table_insts: Dict[str, Table] = PrivateAttr(default={})
    _queue: PickleableQueue = PrivateAttr(default_factory=PickleableQueue)

    def _connect_all_tables(self, channels: GatewayChannels) -> None:
        for field in self.tables.select_from(channels):
            edge = channels.get_channel(field)
            excluded_columns = self.excluded_table_columns.get(field, None)
            if isinstance(edge, dict):
                if not edge:
                    raise ValueError(f"No keys defined for dict basket channel {field}.")

                to_flatten = []
                for subfield in edge.keys():
                    to_flatten.append(channels.get_channel(field, subfield))

                # save perspective schema
                schema = channels.get_channel(field, subfield).tstype.typ.psp_schema(excluded_columns)

                # save pyarrow schema
                self.add_table(
                    field,
                    schema,
                    limit=self.limits.get(field, self.default_limit),
                    index=self.indexes.get(field, self.default_index),
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
                    limit=self.limits.get(field, self.default_limit),
                    index=self.indexes.get(field, self.default_index),
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

    def get_schema_from_field(self, channels: GatewayChannels, field: str):
        edge = channels.get_channel(field)

        if isinstance(edge, dict):
            a_subfield = list(edge.keys())[0]
            edge = channels.get_channel(field, a_subfield)

        ts_type = edge.tstype.typ

        # if its a list of structs
        if get_origin(ts_type) is list:
            struct_type = get_args(ts_type)[0]
        else:
            struct_type = ts_type

        if not hasattr(struct_type, "psp_schema"):
            raise Exception(f"Type has no conversion to perspective: {struct_type}")

        excluded_columns = self.excluded_table_columns.get(field, None)
        return struct_type.psp_schema(excluded_columns)

    def add_table(self, field: str, schema, limit: int = None, index: str = None):
        self._table_insts[field] = self._client.table(schema, limit, index, name=field)

    def connect(self, channels: GatewayChannels) -> None:
        if self.perspective_field:
            self._server = getattr(channels, self.perspective_field)
        else:
            self._server = Server()
        self._client = self._server.new_local_client()
        self._layouts = self.layouts.copy()
        if self.layouts_field:
            self._layouts.update(getattr(channels, self.layouts_field))
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

    def _get_tables(self) -> Dict[str, Dict[str, str]]:
        all_tables = {table_name: None for table_name in self._client.get_hosted_table_names()}
        for table_name in all_tables:
            table = self._client.open_table(table_name)
            schema = table.schema()
            all_tables[table_name] = {col: schema[col] for col in table.columns()}
        return all_tables

    def _get_table_sizes(self) -> Dict[str, int]:
        all_tables = {table_name: None for table_name in self._client.get_hosted_table_names()}
        for table_name in all_tables:
            table = self._client.open_table(table_name)
            all_tables[table_name] = table.size()
        return all_tables

    def rest(self, app: GatewayWebApp) -> None:
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
            response_model=Dict[str, Dict[str, str]],
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
            response_model=Dict[str, str],
            tags=["Utility"],
        )
        async def get_perspective_layouts():
            """
            This endpoint exposes saved [perspective](https://github.com/perspective-dev/perspective) workspace layouts.
            These layouts can be configured server side to be provided to all clients.
            """
            return self._layouts

        # add route to fetch layouts
        @api_router.get(
            "{}/{}".format(self._route, "meta"),
            responses=get_default_responses(),
            response_model=Dict[str, Union[None, int, str, Dict[str, Union[str, int]], Dict[str, Dict[str, str]]]],
            tags=["Utility"],
        )
        async def get_perspective_meta():
            """
            This endpoint exposes perspective meta information, including limits,
            indexes, and architecture.
            """
            return {
                "limits": self.limits,
                "default_limit": self.default_limit,
                "indexes": self.indexes,
                "default_index": self.default_index,
                "architectures": self.architectures,
                "default_architecture": self.default_architecture,
                "layouts": self.layouts,
                "default_layout": self.default_layout,
                "tables": self._get_tables(),
                "table_sizes": self._get_table_sizes(),
            }

    def run_perspective(self):
        """Launch the perspective threads"""
        psp_load_thread = get_thread(
            target=pull_data_thread,
            args=(
                self._queue,
                self._table_insts,
                self._arrow_schema_insts,
                self._arrow_schema_date_conversions,
            ),
        )
        psp_load_thread.start()
