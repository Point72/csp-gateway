import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, TypeVar, Union

import csp
import numpy as np
from ccflow import BaseModel
from ccflow.serialization import make_ndarray_orjson_valid
from csp import Struct, ts
from csp.impl.enum import Enum, EnumMeta
from csp.impl.types.tstype import isTsType
from pydantic import Field, PrivateAttr, TypeAdapter

from csp_gateway.server.gateway.csp import ChannelsType
from csp_gateway.server.gateway.csp.channels import _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD
from csp_gateway.utils import (
    get_dict_basket_value_tstype,
    is_dict_basket,
    is_list_basket,
)

__all__ = (
    "JSONConverter",
    "EncodedEngineCycle",
    "read_engine_encoding_json_with_duckdb",
)

_KEY_TYPE = Union[str, Enum]
T = TypeVar("T")
K = TypeVar("K")

_TIMEDELTA_TYPE_ADAPTER = TypeAdapter(timedelta)


class ChannelValueModel(BaseModel):
    """Pydantic model representing a tick on a specific channel."""

    channel: str
    value: Any
    dict_basket_key: Optional[_KEY_TYPE] = None
    timestamp: datetime


class EncodedEngineCycle(csp.Struct):
    """This is a csp struct representing a single engine cycle."""

    encoding: str
    csp_timestamp: datetime


def read_engine_encoding_json_with_duckdb(channels: ChannelsType, filename: str):
    """Helper function to read a newline-delimited json file containing engine cycle ticks into duckdb."""
    import duckdb

    channel_names = channels._snapshot_model.model_fields.keys()
    columns = {channel: "JSON" if channel != _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD else "TIMESTAMP" for channel in channel_names}
    return duckdb.read_json(filename, columns=columns, format="newline_delimited")


def _from_pydantic(obj: Any, typ: Optional[type] = None, exclude: Optional[set] = None) -> Any:
    if isinstance(obj, (list, tuple, set)):
        return obj.__class__(val.csp(exclude=exclude) for val in obj)
    if isinstance(typ, type) and (issubclass(typ, Enum) or typ is str):
        return obj
    return obj.csp(exclude=exclude)


def _convert_orjson_compatible(obj: Any):
    if isinstance(obj, Struct):
        pydantic_type = getattr(obj.__class__, "__pydantic_model__", None)
        return {
            _convert_orjson_compatible(k): _convert_orjson_compatible(getattr(obj, k))
            for k in obj.__full_metadata__
            if (pydantic_type is None or k in pydantic_type.model_fields) and hasattr(obj, k)
        }
    if isinstance(obj, dict):
        return {_convert_orjson_compatible(k): _convert_orjson_compatible(v) for k, v in obj.items()}
    if isinstance(obj, (list, set, tuple)):
        return [_convert_orjson_compatible(val) for val in obj]
    if isinstance(obj, (Enum, EnumMeta)):
        return obj.name
    if isinstance(obj, timedelta):
        return _TIMEDELTA_TYPE_ADAPTER.dump_python(obj, mode="json")
    if isinstance(obj, np.ndarray):
        return make_ndarray_orjson_valid(obj)
    return obj


def _create_snapshot_dict(all_data: List[ChannelValueModel]) -> Dict[str, Any]:
    res = defaultdict(dict)
    res[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD] = all_data[0].timestamp
    for data in all_data:
        channel = data.channel
        value = _convert_orjson_compatible(data.value)
        if key := data.dict_basket_key:
            res[channel][_convert_orjson_compatible(key)] = value
        else:
            res[channel] = value
        res[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD] = min(res.get(_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD), data.timestamp)
    return res


@csp.node
def _create_tuple_not_dict_basket(
    channel: str,
    value: ts[object],
) -> ts[tuple]:
    return (channel, (value,))


@csp.node
def _create_tuple_dict_basket(
    channel: str,
    value: ts[object],
    dict_basket_key: _KEY_TYPE,
) -> ts[tuple]:
    return (channel, (dict_basket_key, value))


@csp.node
def _deserialize_snapshot_dict(encoded_snapshot: ts[dict], typ: "T", log_lagging_engine_cycles: bool) -> ts["T"]:
    with csp.alarms():
        # Define an alarm time-series of type bool
        alarm = csp.alarm(bool)

    with csp.start():
        stack = deque()

    if csp.ticked(encoded_snapshot):
        snapshot = typ.model_validate(encoded_snapshot)
        timestamp = getattr(snapshot, _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD).replace(tzinfo=None)
        csp_now = csp.now()
        if timestamp > csp_now:
            csp.schedule_alarm(alarm, timestamp, True)
            stack.append(snapshot)
        else:
            if timestamp < csp_now and log_lagging_engine_cycles:
                logging.info(
                    f"Timestamp for a replayed engine cycle is: {timestamp} "
                    + f"which is behind csp engine time: {csp_now}. Engine cycle is: {snapshot}"
                )
            return snapshot

    if csp.ticked(alarm):
        return stack.popleft()


@csp.node
def _deserialize_snapshot_str(encoded_snapshot: ts[str], typ: "T", log_lagging_engine_cycles: bool) -> ts["T"]:
    with csp.alarms():
        # Define an alarm time-series of type bool
        alarm = csp.alarm(bool)

    with csp.start():
        stack = deque()

    if csp.ticked(encoded_snapshot):
        snapshot = typ.model_validate_json(encoded_snapshot)
        timestamp = getattr(snapshot, _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD).replace(tzinfo=None)
        csp_now = csp.now()
        if timestamp > csp_now:
            csp.schedule_alarm(alarm, timestamp, True)
            stack.append(snapshot)
        else:
            if timestamp < csp_now and log_lagging_engine_cycles:
                logging.info(
                    f"Timestamp for a replayed engine cycle is: {timestamp} "
                    + f"which is behind csp engine time: {csp_now}. Engine cycle is: {snapshot}"
                )
            return snapshot

    if csp.ticked(alarm):
        return stack.popleft()


def _deserialize_snapshot(
    encoded_snapshot: Union[ts[str], ts[Dict[str, Any]]],
    typ: Any,
    log_lagging_engine_cycles: bool = False,
):
    if encoded_snapshot.tstype.typ is str:
        return _deserialize_snapshot_str(encoded_snapshot, typ, log_lagging_engine_cycles)
    return _deserialize_snapshot_dict(encoded_snapshot, typ, log_lagging_engine_cycles)


class JSONConverter(BaseModel):
    """
    This class is instantiated within a Gateway Module to wire the channel for
    json encoding/decoding. The encode/decode functions are called to perform the
    respective wirings. Only channels in the snapshot model of the channels class
    are included.
    """

    decode_channels: List[str]
    encode_channels: List[str]
    channels: ChannelsType
    flag_updates: Dict[str, List[Tuple[str, bool]]] = Field(
        default_factory=dict,
        description="""
        A mapping of channels to a list of tuples each containing:
        A field name and the flag it should be updated to, when in Read mode.
        Only works for non-dict basket channels
        """,
    )
    decode_exclude_fields: Optional[Set[str]] = Field(
        None,
        description="""
        Set of fields to exclude when we are decoding from a source.
        Does not throw an error if the field does not exist.
        """,
    )
    log_lagging_engine_cycles: bool = Field(False, description="Whether we log when engine cycles are lagging from the current engine time.")
    _decode_channel_dict_basket_keys: Dict[str, List[_KEY_TYPE]] = PrivateAttr(default_factory=dict)
    _snapshot_type: type = PrivateAttr(default=None)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._snapshot_type = type(self.channels)._snapshot_model

        # get the keys for every channel we are decoding
        for field in self.decode_channels:
            outer_type = self.channels.get_outer_type(field)
            if is_dict_basket(outer_type):
                edge = self.channels.get_channel(field)
                self._decode_channel_dict_basket_keys[field] = list(edge.keys())

    def get_channel_from_snapshot(
        self,
        snapshot: ts[object],
        field: _KEY_TYPE,
        value_type: type,
        keys: Optional[List[_KEY_TYPE]] = None,
    ):
        if keys:
            if updates := self.flag_updates.get(field):
                raise ValueError("Flag updates cannot be called on csp dict baskets" + f"Got flag {updates = }")
            return self._get_dict_basket(snapshot, field, keys, value_type)
        return self._get_non_dict_basket(snapshot, field, value_type)

    @csp.node
    def _get_dict_basket(
        self,
        snapshot: ts[object],
        field: _KEY_TYPE,
        keys: ["K"],
        value_type: "T",
    ) -> csp.OutputBasket(Dict["K", ts["T"]], shape="keys"):  # noqa
        if csp.ticked(snapshot):
            dict_basket = getattr(snapshot, field)
            if dict_basket is not None:
                return {k: v for k, v in dict_basket.items() if v is not None}

    @csp.node
    def _get_non_dict_basket(
        self,
        snapshot: ts[object],
        field: _KEY_TYPE,
        value_type: "T",
    ) -> ts["T"]:
        if csp.ticked(snapshot):
            pydantic_value = getattr(snapshot, field)
            if pydantic_value is not None:
                channel_flag_updates = self.flag_updates.get(field, [])
                value = pydantic_value
                # TODO: ponder how to better do this
                if self.decode_exclude_fields:
                    for field in self.decode_exclude_fields:
                        if field == "id":
                            value.id = value.generate_id()
                        elif field == "timestamp":
                            value.timestamp = datetime.utcnow()
                        elif hasattr(value, field):
                            delattr(value, field)
                if isinstance(value, (list, tuple)):
                    for attribute, updated_flag in channel_flag_updates:
                        for obj in value:
                            setattr(obj, attribute, updated_flag)
                else:
                    for attribute, updated_flag in channel_flag_updates:
                        setattr(value, attribute, updated_flag)
                return value

    def encode(self, writing_mode: ts[bool] = None) -> ts[EncodedEngineCycle]:
        """Given the channels object and the channels we are encoding, we combine
        them all into a fat pipe that is a long ts[str] object that stores all the
        ticks for every specified channel in each engine cycle.

        writing_mode: ts[bool]
            This ts object is provided by the Gateway Module that instantiates the Json Handler to
            specify when to encode or decode. We want to avoid encoding channel ticks that are
            caused by a json string that we are decoding
        """
        # If we don't specify a writing mode, we will assume we write
        if writing_mode is None:
            writing_mode = csp.const(True)

        snapshot_model_fields = self._snapshot_type.model_fields

        all_data = []  # input as (field, data) where data is a ticked channel, or a tuple (key, ticked_edge) in a dict basket
        for field in self.encode_channels:
            if field not in snapshot_model_fields:
                continue

            outer_type = self.channels.get_outer_type(field)
            edge = self.channels.get_channel(field)

            # TODO: list baskets not supported yet in channels model
            if is_list_basket(outer_type):
                raise TypeError("List Baskets not yet supported in channels model")

            # We do this so that when we collect at the bottom, we get all channels that ticked together
            # at once. Different values in a dict basket can tick out of sync with each other
            elif is_dict_basket(outer_type):
                data = [_create_tuple_dict_basket(channel=field, value=csp.filter(writing_mode, v), dict_basket_key=k) for k, v in edge.items()]
                all_data.extend(data)

            elif isTsType(outer_type):
                all_data.append(_create_tuple_not_dict_basket(channel=field, value=csp.filter(writing_mode, edge)))

        return self._create_encoding(csp.collect(all_data))

    def decode(self, fat_pipe: Union[ts[str], ts[Dict[str, Any]]]) -> None:
        """
        Takes in the fat pipe with all of the encoded channel ticks,
        then demultiplexes them, deserializes the values, and
        sets the channels accordingly.
        """
        ts_snapshot_model = _deserialize_snapshot(
            fat_pipe,
            self._snapshot_type,
            log_lagging_engine_cycles=self.log_lagging_engine_cycles,
        )
        for field in self.decode_channels:
            outer_type = self.channels.get_outer_type(field)
            # having basket_keys means the channel is a dict_basket
            if basket_keys := self._decode_channel_dict_basket_keys.get(field):
                outer_type = get_dict_basket_value_tstype(outer_type)

            output = self.get_channel_from_snapshot(
                ts_snapshot_model,
                field,
                outer_type.typ,
                basket_keys,
            )
            self.channels.set_channel(field, output)

    @csp.node
    def _create_encoding(self, all_data: ts[List[tuple]]) -> ts[EncodedEngineCycle]:
        if csp.ticked(all_data):
            values = defaultdict(dict)
            for field, val in all_data:
                if len(val) == 1:
                    values[field] = val[0]
                else:
                    values[field][val[0]] = val[1]
            values[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD] = csp.now()
            res = self._snapshot_type.model_validate(values).model_dump_json()
            return EncodedEngineCycle(encoding=res + "\n", csp_timestamp=csp.now())  # we manually add the new line at the end

    def __hash__(self):
        # So that csp doesn't complain about inability to memoize
        return id(self)
