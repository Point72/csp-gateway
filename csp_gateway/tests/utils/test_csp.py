from datetime import datetime, timedelta
from typing import Dict, List

import csp
import pytest

from csp_gateway.utils import (
    get_dict_basket_key_type,
    get_dict_basket_value_tstype,
    get_dict_basket_value_type,
    is_dict_basket,
    is_list_basket,
    set_alarm_and_fetch_alarm_time,
    to_list,
)


def test_dict_basket_type_checks():
    test_dict_typ = Dict[int, str]
    test_dict_basket_typ = Dict[int, csp.ts[int]]
    assert not is_dict_basket(test_dict_typ)
    assert is_dict_basket(test_dict_basket_typ)

    with pytest.raises(TypeError):
        get_dict_basket_key_type(test_dict_typ)

    with pytest.raises(TypeError):
        get_dict_basket_value_tstype(test_dict_typ)

    assert get_dict_basket_key_type(test_dict_basket_typ) is int
    assert get_dict_basket_value_tstype(test_dict_basket_typ) is csp.ts[int]
    assert get_dict_basket_value_type(test_dict_basket_typ) is int


def test_is_list_basket():
    test_list_typ = List[int]
    test_list_basket_typ = List[csp.ts[int]]
    assert not is_list_basket(test_list_typ)
    assert is_list_basket(test_list_basket_typ)


def test_to_list():
    out = csp.run(
        to_list,
        csp.const(9),
        starttime=datetime(2020, 1, 1),
        endtime=timedelta(1),
    )
    assert out[0] == [(datetime(2020, 1, 1), [9])]


def test_set_alarm_and_fetch_alarm_time():
    out = csp.run(
        set_alarm_and_fetch_alarm_time,
        timedelta(),
        starttime=datetime(2020, 1, 1),
        endtime=timedelta(1),
    )
    assert out["alarm_time"] == [(datetime(2020, 1, 1), datetime(2020, 1, 1))]
    assert out["alarm_ticked"] == [(datetime(2020, 1, 1), True)]

    out = csp.run(
        set_alarm_and_fetch_alarm_time,
        timedelta(minutes=1),
        starttime=datetime(2020, 1, 1),
        endtime=timedelta(1),
    )
    assert out["alarm_time"] == [(datetime(2020, 1, 1), datetime(2020, 1, 1, 0, 1))]
    assert out["alarm_ticked"] == [(datetime(2020, 1, 1, 0, 1), True)]

    out = csp.run(
        set_alarm_and_fetch_alarm_time,
        datetime(2020, 1, 7),
        starttime=datetime(2020, 1, 1),
        endtime=timedelta(days=14),
    )
    assert out["alarm_time"] == [(datetime(2020, 1, 1), datetime(2020, 1, 7))]
    assert out["alarm_ticked"] == [(datetime(2020, 1, 7), True)]

    out = csp.run(
        set_alarm_and_fetch_alarm_time,
        datetime(2021, 1, 1),
        starttime=datetime(2020, 1, 1),
        endtime=timedelta(days=14),
    )
    assert out["alarm_time"] == [(datetime(2020, 1, 1), datetime(2021, 1, 1))]
    assert out["alarm_ticked"] == []
