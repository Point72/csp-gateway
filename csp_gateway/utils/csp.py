from datetime import datetime, timedelta
from typing import List, TypeVar, Union, get_args, get_origin  # noqa: TYP001

import csp
from csp import Outputs, ts
from csp.impl.types.tstype import TsType, isTsType
from deprecation import deprecated

T = TypeVar("T")
K = TypeVar("K")
V = TypeVar("V")

__all__ = (
    "_get_dict_basket_key_type",
    "_get_dict_basket_value_tstype",
    "_get_dict_basket_value_type",
    "_is_dict_basket",
    "_is_list_basket",
    "get_dict_basket_key_type",
    "get_dict_basket_value_tstype",
    "get_dict_basket_value_type",
    "is_dict_basket",
    "is_list_basket",
    "get_args",
    "get_origin",
    "set_alarm_and_fetch_alarm_time",
    "to_list",
)


def is_dict_basket(val: type) -> bool:
    return get_origin(val) is dict and isTsType(get_args(val)[1])


def is_list_basket(val: type) -> bool:
    return get_origin(val) is list and isTsType(get_args(val)[0])


def get_dict_basket_key_type(val: type) -> type:
    if not is_dict_basket(val):
        raise TypeError(f"object is not a Dict Basket but is of type: {type(val)}")
    return get_args(val)[0]


def get_dict_basket_value_tstype(val: type) -> TsType:
    if not is_dict_basket(val):
        raise TypeError(f"object is not a Dict Basket but is of type: {type(val)}")
    return get_args(val)[1]


def get_dict_basket_value_type(val: type) -> type:
    return get_dict_basket_value_tstype(val).typ


@deprecated(details="Use is_dict_basket instead.")
def _is_dict_basket(val: type) -> bool:
    return is_dict_basket(val)


@deprecated(details="Use is_list_basket instead.")
def _is_list_basket(val: type) -> bool:
    return is_list_basket(val)


@deprecated(details="Use get_dict_basket_key_type instead.")
def _get_dict_basket_key_type(val: type) -> type:
    return get_dict_basket_key_type(val)


@deprecated(details="Use get_dict_basket_value_tstype instead.")
def _get_dict_basket_value_tstype(val: type) -> TsType:
    return get_dict_basket_value_tstype(val)


@deprecated(details="Use get_dict_basket_value_type instead.")
def _get_dict_basket_value_type(val: type) -> type:
    return get_dict_basket_value_type(val)


@csp.node
def to_list(x: ts["T"]) -> ts[List["T"]]:
    if csp.ticked(x):
        return [x]


@csp.node
def set_alarm_and_fetch_alarm_time(time: Union[datetime, timedelta]) -> Outputs(alarm_time=ts[datetime], alarm_ticked=ts[bool]):
    with csp.alarms():
        engine_start: ts[bool] = csp.alarm(bool)
        alarm: ts[bool] = csp.alarm(bool)
    with csp.state():
        s_time = None

    with csp.start():
        csp.schedule_alarm(engine_start, timedelta(), True)
        csp.schedule_alarm(alarm, time, True)
        if isinstance(time, datetime):
            s_time = time
        else:
            s_time = csp.now() + time

    if csp.ticked(engine_start):
        csp.output(alarm_time=s_time)
    if csp.ticked(alarm):
        csp.output(alarm_ticked=True)
