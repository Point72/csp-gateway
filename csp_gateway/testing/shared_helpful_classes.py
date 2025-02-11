from datetime import timedelta
from typing import Dict, List, Optional, Type

import csp
import numpy as np
from csp import Enum, ts
from csp.typing import Numpy1DArray

from csp_gateway import (
    Channels,
    ChannelSelection,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewayStruct,
    State,
)

__all__ = (
    "MyEnum",
    "MyStruct",
    "MyGatewayChannels",
    "MySmallGatewayChannels",
    "MySmallGateway",
    "MyGateway",
    "MySetModule",
    "MyGetModule",
    "MyExampleModule",
    "MyDictBasketModule",
    "MyNoTickDictBasket",
)


class MyEnum(Enum):
    ONE = 1
    TWO = 2


class MyStruct(GatewayStruct):
    foo: float
    time: timedelta
    my_flag: bool = True
    _new: bool = True


class MyGatewayChannels(GatewayChannels):
    my_static: float = 0.0
    my_static_dict: Dict[str, float] = {}
    my_static_list: List[str] = []
    my_channel: ts[MyStruct] = None
    s_my_channel: ts[State[MyStruct]] = None
    my_list_channel: ts[List[MyStruct]] = None
    s_my_list_channel: ts[State[MyStruct]] = None
    my_enum_basket: Dict[MyEnum, ts[MyStruct]] = None
    my_str_basket: Dict[str, ts[MyStruct]] = None
    my_enum_basket_list: Dict[MyEnum, ts[List[MyStruct]]] = None
    my_array_channel: ts[Numpy1DArray[float]] = None


class MySmallGatewayChannels(GatewayChannels):
    example: ts[int] = None
    s_example: ts[State[int]] = None
    my_str_basket: Dict[str, ts[float]] = None


class MySmallGateway(Gateway):
    channels_model: Type[Channels] = MySmallGatewayChannels


class MyGateway(Gateway):
    channels_model: Type[Channels] = MyGatewayChannels  # type: ignore[assignment]


class MySetModule(GatewayModule):
    my_data: ts[MyStruct]
    my_data2: ts[MyStruct]
    my_list_data: ts[List[MyStruct]]
    by_key: bool = True

    def dynamic_keys(self):
        return {MyGatewayChannels.my_str_basket: ["my_key", "my_key2"]}

    def connect(self, channels: MyGatewayChannels) -> None:
        # Build a set of inputs based on the test cases
        channels.set_channel(MyGatewayChannels.my_channel, self.my_data)
        channels.set_channel(
            MyGatewayChannels.my_list_channel,
            self.my_list_data,
        )
        channels.add_send_channel(MyGatewayChannels.my_channel)
        channels.set_state(MyGatewayChannels.my_channel, "id")
        channels.add_send_channel(MyGatewayChannels.my_list_channel)
        channels.set_state(MyGatewayChannels.my_list_channel, "id")

        channels.set_channel(MyGatewayChannels.my_array_channel, csp.const(np.array([1.0, 2.0])))

        if self.by_key:
            channels.set_channel(MyGatewayChannels.my_enum_basket, self.my_data, MyEnum.ONE)
            channels.set_channel(MyGatewayChannels.my_enum_basket, self.my_data2, MyEnum.TWO)
            channels.set_channel(MyGatewayChannels.my_str_basket, self.my_data, "my_key")
            channels.set_channel(MyGatewayChannels.my_str_basket, self.my_data2, "my_key2")
            channels.set_channel(MyGatewayChannels.my_enum_basket_list, self.my_list_data, MyEnum.ONE)
            channels.set_channel(MyGatewayChannels.my_enum_basket_list, self.my_list_data, MyEnum.TWO)
        else:
            channels.set_channel(
                MyGatewayChannels.my_enum_basket,
                {
                    MyEnum.ONE: self.my_data,
                    MyEnum.TWO: self.my_data2,
                },
            )
            channels.set_channel(
                MyGatewayChannels.my_str_basket,
                {
                    "my_key": self.my_data,
                    "my_key2": self.my_data2,
                },
            )
            channels.set_channel(
                MyGatewayChannels.my_enum_basket_list,
                {
                    MyEnum.ONE: self.my_list_data,
                    MyEnum.TWO: self.my_list_data,
                },
            )


class MyGetModule(GatewayModule):
    requires: Optional[ChannelSelection] = []

    def connect(self, channels: MyGatewayChannels) -> None:
        # Build a set of inputs based on the test cases
        csp.add_graph_output("my_channel", channels.get_channel(MyGatewayChannels.my_channel))
        csp.add_graph_output("my_list_channel", channels.get_channel(MyGatewayChannels.my_list_channel))
        csp.add_graph_output("my_array_channel", channels.get_channel(MyGatewayChannels.my_array_channel))
        # Get by basket
        for k, v in channels.get_channel(MyGatewayChannels.my_enum_basket).items():
            csp.add_graph_output(f"my_enum_basket[{k}]", v)
        for k, v in channels.get_channel(MyGatewayChannels.my_str_basket).items():
            csp.add_graph_output(f"my_str_basket[{k}]", v)
        for k, v in channels.get_channel(MyGatewayChannels.my_enum_basket_list).items():
            csp.add_graph_output(f"my_enum_basket_list[{k}]", v)

        # Get by indexer
        csp.add_graph_output(
            "my_enum_basket_ONE",
            channels.get_channel(MyGatewayChannels.my_enum_basket, MyEnum.ONE),
        )
        csp.add_graph_output(
            "my_enum_basket_TWO",
            channels.get_channel(MyGatewayChannels.my_enum_basket, MyEnum.TWO),
        )
        csp.add_graph_output(
            "my_str_basket_my_key",
            channels.get_channel(MyGatewayChannels.my_str_basket, "my_key"),
        )
        csp.add_graph_output(
            "my_str_basket_my_key2",
            channels.get_channel(MyGatewayChannels.my_str_basket, "my_key2"),
        )


class MyExampleModule(GatewayModule):
    interval: timedelta = timedelta(seconds=1)

    @csp.node
    def subscribe(
        self,
        trigger: ts[bool],
    ) -> ts[int]:
        with csp.state():
            last_x = 0
        if csp.ticked(trigger):
            last_x += 1
            return last_x

    def connect(self, channels: MySmallGatewayChannels):
        channels.set_channel(
            MySmallGatewayChannels.example,
            self.subscribe(csp.timer(interval=self.interval, value=True)),
        )
        channels.add_send_channel(MySmallGatewayChannels.example)
        channels.set_state(MySmallGatewayChannels.example, "id")


class MyDictBasketModule(GatewayModule):
    my_data: ts[float]

    def dynamic_keys(self):
        return {MySmallGatewayChannels.my_str_basket: ["my_key"]}

    def connect(self, channels: MySmallGatewayChannels):
        channels.set_channel(MySmallGatewayChannels.my_str_basket, {"my_key": self.my_data})
        for k, v in channels.get_channel(MySmallGatewayChannels.my_str_basket).items():
            csp.add_graph_output(f"my_str_basket[{k}]", v)


class MyNoTickDictBasket(GatewayModule):
    my_data: ts[float]

    def dynamic_keys(self):
        return {MySmallGatewayChannels.my_str_basket: ["my_key"]}

    @csp.node
    def subscribe(
        self,
        trigger: ts[bool],
        keys: List[str],
    ) -> csp.OutputBasket(Dict[str, ts[float]], shape="keys"):
        if csp.ticked(trigger):
            csp.output({"my_key": self.my_data})

    def connect(self, channels: MySmallGatewayChannels):
        channels.set_channel(
            MySmallGatewayChannels.my_str_basket,
            self.subscribe(
                csp.timer(interval=timedelta(seconds=5), value=True),
                self.dynamic_keys()[MySmallGatewayChannels.my_str_basket],
            ),
        )
        for k, v in channels.get_channel(MySmallGatewayChannels.my_str_basket).items():
            csp.add_graph_output(f"my_str_basket[{k}]", v)
