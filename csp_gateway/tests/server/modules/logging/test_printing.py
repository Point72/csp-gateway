from datetime import datetime, timedelta
from typing import Dict, List

import csp
import numpy as np
import pytest
from csp import ts
from csp.typing import Numpy1DArray

from csp_gateway import PrintChannels
from csp_gateway.testing.shared_helpful_classes import (
    GatewayChannels,
    GatewayModule,
    MyEnum,
    MyGateway,
    State,
)


class MyPrintGatewayChannels(GatewayChannels):
    my_static: float = 0.0
    my_static_dict: Dict[str, float] = {}
    my_static_list: List[str] = []
    my_channel: ts[int] = None
    s_my_channel: ts[State[int]] = None
    my_list_channel: ts[[int]] = None
    s_my_list_channel: ts[State[int]] = None
    my_enum_basket: Dict[MyEnum, ts[int]] = None
    my_str_basket: Dict[str, ts[int]] = None
    my_enum_basket_list: Dict[MyEnum, ts[[int]]] = None
    my_array_channel: ts[Numpy1DArray[float]] = None


class MyPrintSetModule(GatewayModule):
    my_data: ts[int]
    my_data2: ts[int]
    my_list_data: List[int]
    by_key: bool = True

    def dynamic_keys(self):
        return {MyPrintGatewayChannels.my_str_basket: ["my_key", "my_key2"]}

    def connect(self, channels: MyPrintGatewayChannels) -> None:
        # Build a set of inputs based on the test cases
        channels.set_channel(MyPrintGatewayChannels.my_channel, self.my_data)
        channels.set_channel(
            MyPrintGatewayChannels.my_list_channel,
            csp.const(self.my_list_data),
        )
        channels.add_send_channel(MyPrintGatewayChannels.my_channel)
        channels.set_state(MyPrintGatewayChannels.my_channel, "id")
        channels.add_send_channel(MyPrintGatewayChannels.my_list_channel)
        channels.set_state(MyPrintGatewayChannels.my_list_channel, "id")

        channels.set_channel(MyPrintGatewayChannels.my_array_channel, csp.const(np.array([1.0, 2.0])))

        if self.by_key:
            channels.set_channel(MyPrintGatewayChannels.my_enum_basket, self.my_data, MyEnum.TWO)
            channels.set_channel(MyPrintGatewayChannels.my_str_basket, self.my_data2, "my_key2")
            channels.set_channel(
                MyPrintGatewayChannels.my_enum_basket_list,
                csp.const(self.my_list_data),
                MyEnum.ONE,
            )
        else:
            channels.set_channel(
                MyPrintGatewayChannels.my_enum_basket,
                {
                    MyEnum.TWO: self.my_data,
                },
            )
            channels.set_channel(
                MyPrintGatewayChannels.my_str_basket,
                {
                    "my_key2": self.my_data2,
                },
            )
            channels.set_channel(
                MyPrintGatewayChannels.my_enum_basket_list,
                {
                    MyEnum.ONE: csp.const(self.my_list_data),
                },
            )


@pytest.mark.parametrize("by_key", [True, False])
def test_PrintChannels(by_key, capsys):
    setter = MyPrintSetModule(
        my_data=csp.const(9),
        my_data2=csp.const(8),
        my_list_data=[8, 9],
        by_key=by_key,
    )
    getter = PrintChannels()
    gateway = MyGateway(modules=[getter, setter], channels=MyPrintGatewayChannels())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    captured = capsys.readouterr()
    printed_set = set(captured.out.split("\n"))
    expected_results = [
        "2020-01-01 00:00:00 my_array_channel:[1. 2.]",
        "2020-01-01 00:00:00 my_str_basket:{'my_key2': 8}",
        "2020-01-01 00:00:00 my_enum_basket:{<MyEnum.TWO: 2>: 9}",
        "2020-01-01 00:00:00 my_enum_basket_list:{<MyEnum.ONE: 1>: [8, 9]}",
        "2020-01-01 00:00:00 my_channel:9",
        "2020-01-01 00:00:00 my_list_channel:[8, 9]",
        "",
    ]
    assert len(expected_results) == len(printed_set)
    for result in expected_results:
        assert result in printed_set


@pytest.mark.parametrize("by_key", [True, False])
def test_specific_channels_PrintChannels(by_key, capsys):
    setter = MyPrintSetModule(
        my_data=csp.const(9),
        my_data2=csp.const(8),
        my_list_data=[8, 9],
        by_key=by_key,
    )
    getter = PrintChannels(
        selection=[
            MyPrintGatewayChannels.my_array_channel,
            MyPrintGatewayChannels.my_enum_basket,
            MyPrintGatewayChannels.my_static_list,
        ]
    )
    gateway = MyGateway(modules=[getter, setter], channels=MyPrintGatewayChannels())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    captured = capsys.readouterr()
    printed_set = set(captured.out.split("\n"))
    expected_results = [
        "2020-01-01 00:00:00 my_array_channel:[1. 2.]",
        "2020-01-01 00:00:00 my_enum_basket:{<MyEnum.TWO: 2>: 9}",
        "",
    ]
    assert len(expected_results) == len(printed_set)
    for result in expected_results:
        assert result in printed_set
