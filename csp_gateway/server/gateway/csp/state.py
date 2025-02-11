import abc
import datetime
import logging
import threading
import typing
from collections import deque
from enum import Enum as PyEnum
from functools import lru_cache
from pprint import pformat
from typing import Any, Deque, Dict, List, Tuple, Union

import csp
import duckdb
import fsspec
import numpy
import orjson
from atomic_counter import Counter
from ccflow.enums import BaseEnum as CoreBaseEnum, Enum as CoreEnum
from csp import Struct, ts
from csp.impl.enum import EnumMeta as CspEnumMeta
from pydantic import BaseModel
from typing_extensions import override

if typing.TYPE_CHECKING:
    from csp_gateway.utils import Query

_DUCKDB_BUFFER_THRESHOLD_ORIGINAL = 1000000
_DUCKDB_BUFFER_THRESHOLD_CURRENT = _DUCKDB_BUFFER_THRESHOLD_ORIGINAL
_USE_DUCKDB_STATE = True

log = logging.getLogger(__name__)

__all__ = [
    "StateType",
    "State",
    "DefaultState",
    "DuckDBState",
    "build_track_state_node",
    "modify_buffer_threshold",
    "restore_buffer_threshold",
    "enable_duckdb_state",
    "disable_duckdb_state",
]


# NOTE: Consider using a singleton class for configuration settings for DuckDB
def modify_buffer_threshold(new_threshold: int) -> None:
    """Set DuckDB buffer threshold to a new value"""

    global _DUCKDB_BUFFER_THRESHOLD_CURRENT
    if new_threshold < 0:
        raise ValueError("Threshold should be a non-negative number")
    _DUCKDB_BUFFER_THRESHOLD_CURRENT = new_threshold


def restore_buffer_threshold() -> None:
    """Reset DuckDB buffer threshold to original value"""

    global _DUCKDB_BUFFER_THRESHOLD_CURRENT
    _DUCKDB_BUFFER_THRESHOLD_CURRENT = _DUCKDB_BUFFER_THRESHOLD_ORIGINAL


def enable_duckdb_state() -> None:
    """Enable using DuckDBState as State class specialization"""

    global _USE_DUCKDB_STATE
    _USE_DUCKDB_STATE = True


def disable_duckdb_state() -> None:
    """Disable using DuckDBState as State class specialization"""

    global _USE_DUCKDB_STATE
    _USE_DUCKDB_STATE = False


class StateType(CoreEnum):
    UNKNOWN = 0
    DEFAULT = 1
    DUCKDB = 2


class StateQueryParams(BaseModel):
    # TODO
    ...


class BaseState(abc.ABC):
    """Abstract class for State"""

    @abc.abstractmethod
    def query(self, query: "Query" = None) -> List[Any]: ...

    @abc.abstractmethod
    def __iter__(self) -> Any: ...

    @abc.abstractmethod
    def insert(self, record: Any) -> None: ...

    @abc.abstractmethod
    def __repr__(self) -> str: ...


class DefaultState(BaseState):
    def __init__(self, keyby: Union[Tuple[str, ...], str]) -> None:
        super().__init__()
        # TODO psp?
        self._records: Dict = {}
        self._keyby = keyby if isinstance(keyby, tuple) else (keyby,)

    @override
    def query(self, query: "Query" = None) -> List[Any]:
        # TODO
        max_depth = len(self._keyby)
        flattened = []

        to_visit: Deque[Tuple[list, dict, int]] = deque()
        to_visit.append(([], self._records, 0))

        while to_visit:
            key, structure, depth = to_visit.pop()

            if depth == max_depth:
                flattened.append(key + [structure])
            else:
                for subkey in structure:
                    to_visit.append((key + [subkey], structure[subkey], depth + 1))

        # Since elements of the key might be None, need to be careful.
        # We choose to have None records appear at the beginning
        # Taking str(subkey) handles the Enum case, as < not implemented for Enums
        flattened.sort(key=lambda e: [(subkey is not None, str(subkey)) for subkey in e[:-1]])
        to_return = [_[-1] for _ in flattened]

        # TODO parse query
        if query and query.filters:
            to_return = query.calculate(to_return)
        return to_return

    @override
    def __iter__(self) -> Any:
        for _ in self._records:
            yield _

    @override
    def insert(self, record: Any) -> None:
        place = self._records

        for subkey in self._keyby:
            # extract the key from the record
            subkey_to_use = getattr(record, subkey, None)

            if subkey == self._keyby[-1]:
                # Put the element there if last
                place[subkey_to_use] = record

            if subkey_to_use not in place:
                place[subkey_to_use] = {}

            place = place[subkey_to_use]

    @override
    def __repr__(self) -> str:
        return pformat(self.query())


class DuckDBState(object):
    """State implementation using DuckDB as the object store and query engine"""

    # NOTE: The duckdb system here is pretty fragile, we should think of building a generict DuckDB interface
    # so that other parts of the codebase and use duckdb through the generic interface

    # NOTE: DuckDB is an OLAP database and not meant to be used as a OLTP database for frequent inserts.
    # We use DuckDB here for its strong analytics capabilities. Row by row insertions into DuckDB are not
    # recommended and will cause major slow downs, instead we bulk load new records into duckdb at certain
    # events: on query call, <more to be added>. This ensures that insert path is fast.
    # For bulk loading, we push json versions of the records into a memory base file. When a bulk loading
    # event occurs, we load the data from the memory file and truncate it.

    # Counter for creating new tables ids for the same type object. This is needed to create an independent
    # table for each instance of the DuckDBState class for any particular type
    TABLE_ID = Counter(1)

    def __init__(self, typ: Struct, keyby: Union[Tuple[str, ...], str], schema: Dict[str, str] = {}) -> None:
        super().__init__()
        # Type of record
        self._typ = typ
        # Table name for this instance of DuckDBState[<self._typ>] class
        self._table_name = f"{typ.__name__}_{DuckDBState.TABLE_ID.next()}"
        # Name of the ID column
        self._id_name = "duck_id"
        # Name of the record column
        self._col_name = "state"
        # Store the schema
        self._schema = schema
        self._schema_str = orjson.dumps(self._schema).decode()
        # NOTE: We make a new connection object for each state object. Using the same state connection across
        #  multiple state objects leads to issues in DuckDB's python API related to pending query results not
        #  being fully executed. This should be okay since we are doing this once during the initialization
        self._con = duckdb.connect()
        self._keyby = keyby
        # ID generator for new records. We cannot rely on the id in the record as that might or might not exist
        self._obj_id_generator = Counter(1)
        # Memory filename to use for bulk loading data into DuckDB
        self._mem_file_name = f"{self._table_name}.json"
        # Tree like structure to store the ids for records using the keys in self._keyby
        self._key_to_id = {}
        # Temporary structure to buffer records before bulk loading into DuckDB
        self._id_record_buffer = {}
        # Lock to prevent race conditions as multiple threads modify the record buffer
        self._buffer_lock = threading.Lock()
        # Lock to prevent race conditions as multiple threads modify the DB
        self._db_lock = threading.Lock()
        self._query_lock = threading.Lock()
        # Object store to recover the original struct. This links our generated ID with the record python object
        # Needed because there is no way to cleanly build the python object from the json dictionary
        self._obj_store = {}

        # Pre-build the group by part of the query, since the keyby values are passed during initialization
        # This is based on the keyby values passed during initialization of the state instance
        key_cols = []
        if isinstance(self._keyby, str):
            self._keyby = (self._keyby,)
        if isinstance(self._keyby, tuple):
            for keyby_term in self._keyby:
                if not DuckDBState.check_attr_schema(keyby_term, self._schema):
                    log.warning(f"Ignoring keyby with {keyby_term}, column not found")
                    continue
                key_cols.append(f"{self._col_name}.{keyby_term}")
        if key_cols:
            key_cols_str = ", ".join(key_cols)
            sort_cols_str = ", ".join([f"{item} ASC NULLS FIRST" for item in key_cols])
            self._group_str = f"GROUP BY {key_cols_str} ORDER BY {sort_cols_str}"
        else:
            self._group_str = ""

        # Create a type for the state object
        duckdb_type = self._con.sql(f"SELECT typeof(json_transform('{{}}', '{self._schema_str}'))").fetchall()[0][0]

        # Create the table
        self._con.sql(
            f"CREATE OR REPLACE TABLE '{self._table_name}' \
                ({self._id_name} BIGINT PRIMARY KEY, {self._col_name} {duckdb_type})"
        )

        # Construct column structure for json parsing
        self._columns_duckdb = str(f"{{'{self._id_name}':'BIGINT','{self._col_name}':'{duckdb_type}'}}")

        # Open the memory file for buffering data before bulk loading
        self._mem_file = fsspec.filesystem("memory").open(self._mem_file_name, "wb")

        # Register memory filesystem so that duckdb can read from memory
        self._con.register_filesystem(fsspec.filesystem("memory"))

    # TODO: Improve this to support querying dicts and lists as well, currently it only
    # works with structs and primitive types
    @classmethod
    def check_attr_schema(cls, attr: str, schema: dict) -> bool:
        """Check if the attr being queried exists in the schema"""

        keys = attr.split(".")
        cur = schema
        try:
            for key in keys:
                cur = cur[key]
        except (TypeError, KeyError):
            return None
        if isinstance(cur, dict):
            return None
        else:
            return cur

    def query_schema(self) -> str:
        """Returns the schema for the duckdb table"""
        return self._schema_str

    #  TODO: Make Query hashable so that we can add @lru_cache() here, to avoid reconstructing an already seen query
    def construct_query(self, query: "Query") -> str:
        """Construct the query from the passed query object, and validate the query attributes by comparing to schema"""

        # Construct the filter part of the query
        conds = []
        # TODO: This is just a copy of the Filter behaviour, find a cleaner way so as to NOT duplicate code
        #  and provide a more generic query functionality
        if query:
            for filter in query.filters:
                attr_type = DuckDBState.check_attr_schema(filter.attr, self._schema)
                if not attr_type:
                    log.warning(f"Ignoring filter with {filter.attr}, column not found")
                    continue
                cond = "TRUE"
                if filter.by.value is not None:
                    by_val = filter.by.value
                    if isinstance(by_val, str):
                        by_val = f"'{by_val}'"
                    cond = f"{self._col_name}.{filter.attr} {filter.by.where} CAST({by_val} AS {attr_type})"
                elif filter.by.when is not None:
                    cond = f"{self._col_name}.{filter.attr} {filter.by.where} CAST('{filter.by.when}' AS TIMESTAMP)"
                elif filter.by.attr:
                    if not DuckDBState.check_attr_schema(filter.by.attr, self._schema):
                        log.warning(f"Ignoring filter with {filter.by.attr}, column not found")
                        continue
                    cond = f"{self._col_name}.{filter.attr} {filter.by.where} {self._col_name}.{filter.by.attr}"
                conds.append(cond)
        if conds:
            filter_str = "WHERE " + " AND ".join(conds)
        else:
            filter_str = ""

        # Combine the filter and groupby to get the final query
        if self._group_str:
            duckdb_query = f"SELECT last({self._id_name}) FROM '{self._table_name}' {filter_str} {self._group_str}"
        else:
            duckdb_query = f"SELECT {self._id_name} FROM '{self._table_name}' {filter_str}"
        return duckdb_query

    def load_data(self) -> None:
        with self._db_lock:
            with self._buffer_lock:
                buffer = self._id_record_buffer
                # Clear the record buffer
                self._id_record_buffer = {}

            # Early breakout if nothing new was added
            if len(buffer) == 0:
                return

            # TODO: Move this to a common place
            def default(obj: Any) -> Any:
                if isinstance(obj, set):
                    return list(obj)
                elif isinstance(obj, numpy.ndarray):
                    return obj.tolist()
                elif isinstance(obj, (PyEnum, CoreBaseEnum, CoreEnum)):
                    return obj.name
                else:
                    logging.warning(f"Type({type(obj)}) cannot be json serialized please provide serializer: {obj} serializing to '' for now")
                    return ""

            for id, record in buffer.items():
                # Insert into object store
                self._obj_store[id] = record

                # Convert the record to json
                record_json_str = record.to_json(default)
                record_json = orjson.loads(record_json_str)
                json_dict = {self._id_name: id, self._col_name: record_json}
                json_str = orjson.dumps(json_dict)

                # Write to buffer instead of DuckDB because single row inserts are slow
                # by buffering we can bulk load the data making it much faster
                self._mem_file.write(json_str)

            # Flush memory buffer
            self._mem_file.flush()

            # Upsert data into the table
            self._con.sql(
                f"INSERT OR REPLACE INTO {self._table_name}\
                            SELECT * FROM read_json_auto('memory://{self._mem_file_name}',\
                                                        columns = {self._columns_duckdb})"
            )

            # Clear data from the memory file
            self._mem_file.seek(0)
            self._mem_file.truncate(0)

    @override
    def query(self, query: "Query" = None) -> List[Any]:
        """Run the query on the duckdb table and return results"""
        # Build the query to run
        query_str = self.construct_query(query)
        with self._query_lock:
            # Bulk load data from the memory file
            self.load_data()

            # Run query
            res = self._con.sql(query_str).fetchall()

            # Fetch the python objects from the object store using returned ids
            obj_res = [self._obj_store[row[-1]] for row in res]

        return obj_res

    @override
    def __iter__(self) -> Any:
        buf = self.query()
        for _ in buf:
            yield _

    @override
    def insert(self, record: Struct) -> None:
        """Insert new record into the table

        Create a new entry for the record in the table using the schema for the record type,
        and store the record in the object store. The record and the new table row are linked by a
        unique id in the table.
        """

        #  NOTE: Currently this methods keep approximately 2 copies of the record so that the orignal record
        # can be fully recovered and returned. There is work to improve the memory utilization of the
        # state class

        with self._buffer_lock:
            place = self._key_to_id

            obj_id = None
            for subkey in self._keyby:
                # extract the key from the record
                subkey_to_use = getattr(record, subkey, None)

                if subkey == self._keyby[-1]:
                    if subkey_to_use not in place.keys():
                        place[subkey_to_use] = self._obj_id_generator.next()
                    obj_id = place[subkey_to_use]
                    self._id_record_buffer[obj_id] = record

                if subkey_to_use not in place:
                    place[subkey_to_use] = {}

                place = place[subkey_to_use]

        # If the buffer is large enough load into DuckDB
        if len(self._id_record_buffer) >= _DUCKDB_BUFFER_THRESHOLD_CURRENT:
            self.load_data()

    @override
    def __repr__(self) -> str:
        return pformat(self.query())


def get_duckdb_schema_obj(parent: Any, key: Any, cls: Any) -> Tuple[Any, bool]:
    """Create a schema for the passed type object"""

    if not isinstance(cls, type):
        if isinstance(cls, list):
            cls = list
        elif isinstance(cls, dict):
            cls = dict
        elif isinstance(cls, set):
            cls = set
        else:
            return (cls, False)

    if issubclass(cls, Struct):
        # Recursive handling
        return get_duckdb_schema_struct(cls)

    if issubclass(cls, set):
        cls = list

    if issubclass(cls, list):
        #  NOTE: Need to find a clean way to handle different list types (list, numpy arrays, etc)
        #  NOTE: List updates are not supported by duckdb at the moment, so just keep them as strings instead
        #  try:
        #      annotation = parent.__full_metadata_typed__[key]
        #      val_type = typing.get_args(annotation)[0]
        #      new_val_type = get_duckdb_schema_obj(None, None, val_type)
        #      cls = list[val_type]
        #  except (KeyError, IndexError, AttributeError):
        #      log.warning(f"Cannot handle list schema in DuckDB {parent}[{key}]{cls}")
        cls = str
    elif issubclass(cls, dict):
        #  NOTE: Need to find a clean way to handle different dict types (dict, typing.Dict, OrderedDict, etc)
        #  NOTE: Dictionary updates are not supported by duckdb yet, so just keep them as strings instead
        #  try:
        #      annotation = parent.__full_metadata_typed__[key]
        #      key_type = typing.get_args(annotation)[0]
        #      new_key_type = get_duckdb_schema_obj(None, None, key_type)
        #      val_type = typing.get_args(annotation)[1]
        #      new_val_type = get_duckdb_schema_obj(None, None, val_type)
        #      cls = dict[key_type, val_type]
        #  except (KeyError, IndexError):
        #      log.warning(f"Cannot handle dict schema in DuckDB {parent}[{key}]{cls}")
        cls = str
    elif issubclass(cls, (csp.Enum, CoreBaseEnum, CspEnumMeta, PyEnum)):
        # Enums become strings
        cls = str
    elif issubclass(cls, datetime.datetime):
        cls = "datetime"
    elif issubclass(cls, datetime.date):
        cls = "date"
    elif issubclass(cls, datetime.time):
        cls = "time"
    elif issubclass(cls, datetime.timedelta):
        # NOTE: timedelta not supported in duckdb
        cls = str

    try:
        # Convert type to a duckdb type
        return (str(duckdb.typing.DuckDBPyType(cls)), True)
    except Exception:
        # TODO: Be more specific in the exception we need to handle here
        return (cls, False)


def get_duckdb_schema_struct(cls: Struct) -> Tuple[Dict, bool]:
    """Create a partial schema for the struct consisting of parts that can be json_serialized and
    stored in duckdb"""

    orig_type_info = {k: v for k, v in cls.metadata().items() if not k.startswith("_")}
    new_type_info = {}
    use_duckdb = False

    for k, v in orig_type_info.items():
        item_schema, use_duckdb_item = get_duckdb_schema_obj(cls, k, v)
        if use_duckdb_item:
            new_type_info[k] = item_schema
            use_duckdb = True
        else:
            log.warning(f"Cannot support {cls.__name__}.{k}:{v} in duckdb")

    return (new_type_info, use_duckdb)


# NOTE: NEVER access State object directly, always access through the __class_getitem__ API
class State(BaseState):
    def __init__(self, keyby: Union[Tuple[str, ...], str] = ("id",)) -> None:
        """Switch case between different state specializations based on the type of the records"""

        global _USE_DUCKDB_STATE
        try:
            typ = self._typ
            if _USE_DUCKDB_STATE and isinstance(typ, type) and issubclass(typ, Struct):
                schema, use_duckdb = get_duckdb_schema_struct(typ)
                if use_duckdb:
                    self._state_impl = DuckDBState(typ, keyby, schema)
                    self._state_type = StateType.DUCKDB
                    return
        except AttributeError:
            log.warning("Do not create object directly from State use the State[<typ>] API instead for performance reasons")
            log.warning("Using DefaultStateClass")
        self._state_impl = DefaultState(keyby)
        self._state_type = StateType.DEFAULT

    def state_type(self) -> StateType:
        """Return the state type being used internally"""
        return self._state_type

    @override
    def query(self, query: "Query" = None) -> List[Any]:
        # NOTE: These try catch blocks for the experimental duckdb state specialization
        #       Remove them when duckdb state has become stable
        try:
            return self._state_impl.query(query)
        except Exception as err:
            log.error(f"Querying state raised exception {err}")
            return []

    @override
    def __iter__(self) -> Any:
        self._state_impl.__iter__()

    @override
    def insert(self, record: Any) -> None:
        # NOTE: These try catch blocks for the experimental duckdb state specialization
        #       Remove them when duckdb state has become stable
        try:
            self._state_impl.insert(record)
        except Exception as err:
            log.error(f"Inserting state raised exception {err}")

    @override
    def __repr__(self) -> str:
        return self._state_impl.__repr__()

    @classmethod
    @lru_cache()
    def __class_getitem__(cls: type, typ: type) -> Any:
        new_cls = type("State[{}]".format(typ.__name__), (State,), {})
        new_cls._typ = typ
        return new_cls


def build_track_state_node(edge: Any, keyby: Union[str, Tuple[str, ...]]) -> Any:
    @csp.node
    def _track_state_node(  # type: ignore[no-untyped-def]
        ts: ts[edge.tstype.typ], keyby: object
    ) -> ts[State[edge.tstype.typ]]:
        with csp.state():
            s_tracker = State[edge.tstype.typ](keyby)
        if csp.ticked(ts):
            s_tracker.insert(ts)
            csp.output(s_tracker)

    return _track_state_node(edge, keyby)
