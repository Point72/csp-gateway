import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, TypeVar

import csp
from csp import ts
from pydantic import BaseModel

from csp_gateway import GatewayChannels, GatewayModule

if TYPE_CHECKING:
    from sqlalchemy.engine.base import Engine

logger = logging.getLogger(__name__)


T = TypeVar("T")


class SQLACnxDetails(BaseModel):
    username: str = ""
    password: str = ""
    host: str = ""
    db: str = ""
    port: int = 5432
    engine: str = "postgresql"  # TODO: this should be enum probably
    driver: str = "ODBC Driver 17 for SQL Server"  # pyodbc.drivers()[-1]

    def get_cnx_string(self) -> str:
        if self.engine == "mssql+pyodbc":  # requires the odbc str and driver
            return f"{self.engine}://{self.host}/{self.db}?driver={self.driver.replace(' ', '+')}&trusted_connection=yes"
        elif self.engine == "sqlite":
            return f"{self.engine}:///{self.host}"
        else:
            return f"{self.engine}://{self.username}:{self.password}@{self.host}:{self.port}/{self.db}"


class ChannelSchemaConfig(BaseModel):
    """
    channel_name: str
        name of channel to check for ticks
    table: str
        name of table to write to
    fields: List[str] = []
        specific of list of fields to check the channel underlying attribute for
        if empty, will use all known attributes from object
    rename_fields: Dict[str, str] = {}
        rename any fields from the attribute to the table name ( e.x. { 'attr_field': 'table_field', ...} )
    augmentation_fields: Dict[str, str] = {}
        add additional details to the insert query (e.x. {'trader_id': 'ZZZZ'})
    """

    channel_name: str  # name of channel to write
    table: str
    fields: List[str] = []  # if empty will just utilize all fields
    rename_fields: Dict[str, str] = {}
    augmentation_fields: Dict[str, str] = {}


class PublishSQLA(GatewayModule):
    """
    The PublishSQLA module allows for formatted writing of items to tables.

    Note: requires sqlalchemy

    ...

    Kwargs
    ------
    cnx_details: SQLACnxDetails
        the struct detailing how to create the connection string
    schema_configs: List[ChannelSchemaConfig]
        configuration for each channel to write to tables
    n_tries: int (default = 1)
        how many times should it try to write to the db before giving up
    fail_after_retry: bool (default=False)
        if we pass n_tries without success, should we raise an error in the node


    Example
    -------
    ```python
    from csp_gateway.server.modules.sql import SQLACnxDetails, ChannelSchemaConfig, PublishSQLA
    cnx_detail = SQLACnxDetails(
        engine='mssql+pydobc',
        host='MYSQLCONNECTIONENGINE',
        db='MyDatabase'
    )
    schema_configs = [
        ChannelSchemaConfig(
            channel_name='my_channel',
            table='my_channels_table',
            fields=['a','b','c'],
            rename_fields={'a':'not_a'},
            augmentation_fields= {'trader_id': 'ZZZZ'} # add this to every record
        )
    ]
    modules.append(
        PublishSQLA(cnx_details=cnx_details, schema_configs=schema_configs)
    )
    ```

    """

    cnx_details: SQLACnxDetails
    schema_configs: List[ChannelSchemaConfig] = []
    n_tries: int = 1
    fail_after_retry: bool = False

    # not to be set
    channel_map: Dict[str, ChannelSchemaConfig] = {}
    engine: "Engine" = None

    def __init__(self, *args, **kwargs):
        from sqlalchemy.engine.base import Engine  # noqa: F401

        PublishSQLA.model_rebuild()
        super().__init__(*args, **kwargs)

    def connect(self, channels: GatewayChannels):
        from sqlalchemy import create_engine

        self.engine = create_engine(self.cnx_details.get_cnx_string(), pool_pre_ping=True)
        for config in self.schema_configs:
            self.channel_map[config.channel_name] = config
            _ = self.writer_node(config.channel_name, channels.get_channel(config.channel_name))

    def _enrich(self, val: Any):
        if isinstance(val, list):
            return json.dumps([self._enrich(x) for x in val])
        elif isinstance(val, dict):
            return json.dumps({k: self._enrich(v) for k, v in val.items()})
        elif isinstance(val, datetime):
            return val.strftime("%Y-%m-%d %H:%M:%S.%f")
        elif not isinstance(val, (int, float, str)):  # kind of lazy but non prims get moved to str
            return str(val)

        return val

    def _write_single_item(self, channel_name: str, x: Any):
        from sqlalchemy import create_engine, exc, text

        schema = self.channel_map.get(channel_name)
        xjson = x.to_dict()

        insert_cols = []
        insert_values = []

        fields = schema.fields
        if len(fields) == 0:
            fields = xjson.keys()

        for k, v in schema.augmentation_fields.items():
            insert_cols.append(k)
            insert_values.append(v)

        for field in fields:
            val = xjson.get(field)
            if val is not None:
                insert_cols.append(schema.rename_fields.get(field, field))  # if the field is in the rename_fields rename it otherwise return it
                insert_values.append(self._enrich(val))

        insert_q = f"""INSERT INTO {schema.table} ({", ".join(insert_cols)}) values ({str(insert_values).strip("[]")})"""

        for _ in range(self.n_tries):
            try:
                with self.engine.begin() as connection:
                    connection.execute(text(insert_q))
                logger.info(insert_q)
                return
            except exc.OperationalError as e:
                logger.error(f"Cannot execute query due to {e}, retrying...")
                self.engine = create_engine(self.cnx_details.get_cnx_string(), pool_pre_ping=True)
        if self.fail_after_retry:
            raise exc.OperationalError(f"Unable to insert query {insert_q} after {self.n_tries} tries.")

    @csp.node
    def writer_node(self, channel_name: str, channel: ts["T"]):
        if csp.ticked(channel):
            if isinstance(channel, list):
                for item in channel:
                    self._write_single_item(channel_name, item)
            else:
                self._write_single_item(channel_name, channel)
