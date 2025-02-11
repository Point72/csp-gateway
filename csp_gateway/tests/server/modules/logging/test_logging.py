import logging
from datetime import datetime, timedelta

import csp
import pytest

from csp_gateway import Gateway, LogChannels
from csp_gateway.testing.shared_helpful_classes import (
    MyDictBasketModule,
    MyExampleModule,
    MyGateway,
    MyGatewayChannels,
    MyGetModule,
    MyNoTickDictBasket,
    MySetModule,
    MySmallGatewayChannels,
    MyStruct,
)


@pytest.mark.parametrize("which_channels", [[MySmallGatewayChannels.example], {}])
def test_LogChannels(which_channels, caplog):
    logger = LogChannels(selection=which_channels)
    gateway = Gateway(
        modules=[MyExampleModule(), logger],
        channels=MySmallGatewayChannels(),
    )
    with caplog.at_level(logging.INFO):
        gateway.start(starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=1))
    expected = (
        "csp_gateway.server.modules.logging.logging",
        logging.INFO,
        "2020-01-01 00:00:01 example:1",
    )
    assert expected in caplog.record_tuples


def test_LogChannels_dict_basket(caplog):
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = Gateway(
        modules=[
            MyDictBasketModule(my_data=csp.const(2.0)),
            logger,
        ],
        channels=MySmallGatewayChannels(),
    )
    with caplog.at_level(logging.INFO, logger="gateway_modules_test_logger"):
        gateway.start(starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=1))
    expected = (
        "gateway_modules_test_logger",
        20,
        "2020-01-01 00:00:00 my_str_basket[my_key]:2.0",
    )
    assert expected in caplog.record_tuples


def test_LogChannels_no_tick_dict_basket(caplog):
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = Gateway(
        modules=[
            MyNoTickDictBasket(my_data=csp.const(2.0)),
            logger,
        ],
        channels=MySmallGatewayChannels(),
    )
    with caplog.at_level(logging.INFO, logger="gateway_modules_test_logger"):
        gateway.start(starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=1))
    for logger, _level, _message in caplog.record_tuples:
        assert logger != "gateway_modules_test_logger"


def test_LogChannels_state(caplog):
    logger = LogChannels(
        log_name="gateway_modules_test_logger",
        log_states=True,
    )
    gateway = MyGateway(modules=[MyExampleModule(), logger], channels=MySmallGatewayChannels())
    with caplog.at_level(logging.INFO):
        csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=3))
    # why do we have use 'caplog.text' here? The record_tuples uses some interpolation
    # and for recording state that makes the actual captured log_calls different from
    # the ones in caplog.record_tuples
    assert "2020-01-01 00:00:02 s_example:[2]" in caplog.text


def test_LogChannels_no_state(caplog):
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = MyGateway(modules=[MyExampleModule(), logger], channels=MySmallGatewayChannels())
    with caplog.at_level(logging.INFO):
        csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=3))
    assert "s_example" not in caplog.text


@pytest.mark.parametrize("by_key", [True, False])
def test_get_set_LogChannels_doesnt_break(by_key, caplog):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule()
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = MyGateway(modules=[getter, setter, logger], channels=MyGatewayChannels())
    with caplog.at_level(logging.INFO, logger="gateway_modules_test_logger"):
        out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert len(out["my_channel"]) == 1
    assert len(out["my_list_channel"]) == 1
    assert len(out["my_list_channel"][0][1]) == 2
    assert len(out["my_array_channel"]) == 1
    assert len(out["my_array_channel"][0][1]) == 2
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 1
    assert len(out["my_str_basket[my_key]"]) == 1
    assert len(out["my_str_basket[my_key2]"]) == 1
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 1
    assert len(out["my_enum_basket_ONE"]) == 1
    assert len(out["my_enum_basket_TWO"]) == 1
    assert len(out["my_str_basket_my_key"]) == 1
    assert len(out["my_str_basket_my_key2"]) == 1


def test_LogChannels_nothing_set(caplog):
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = Gateway(
        modules=[
            logger,
        ],
        channels=MySmallGatewayChannels(),
    )
    with caplog.at_level(logging.INFO, logger="gateway_modules_test_logger"):
        gateway.start(starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=1))
    for logger, _level, _message in caplog.record_tuples:
        assert logger != "gateway_modules_test_logger"
