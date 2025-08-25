import logging
import multiprocessing
import time
from datetime import datetime, timedelta
from io import StringIO
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union

import csp
import numpy as np
import pytest
from ccflow import ModelRegistry
from csp import Enum, ts
from csp.typing import Numpy1DArray
from omegaconf import OmegaConf
from pydantic import Field, ValidationError

from csp_gateway import (
    Channels,
    ChannelSelection,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewayStruct,
    State,
)
from csp_gateway.testing import GatewayTestHarness
from csp_gateway.utils import NoProviderException


class MyEnum(Enum):
    ONE = 1
    TWO = 2


class MyStruct(GatewayStruct):
    foo: float


class MyChildStruct(MyStruct):
    foo2: int


class MyGatewayChannels(GatewayChannels):
    my_channel_final: ts[MyStruct] = None
    my_channel_mid: ts[MyStruct] = None
    my_channel_dup: ts[MyStruct] = None

    my_keys: List[str] = []
    my_static: float = 0.0
    my_static_dict: Dict[str, float] = {}
    my_static_list: List[str] = []
    my_static_dict_of_objects: Dict[str, Any] = {}
    my_channel: ts[MyStruct] = None
    s_my_channel: ts[State[MyStruct]] = None
    my_list_channel: ts[List[MyStruct]] = None
    s_my_list_channel: ts[State[MyStruct]] = None
    my_enum_basket: Dict[MyEnum, ts[MyStruct]] = None
    my_str_basket: Dict[str, ts[MyStruct]] = None
    my_enum_basket_list: Dict[MyEnum, ts[List[MyStruct]]] = None
    my_array_channel: ts[Numpy1DArray[float]] = None

    def dynamic_keys(self):
        return {MyGatewayChannels.my_str_basket: self.my_keys}


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


class MyStatefulGetSetModule(GatewayModule):
    @csp.node
    def state_node_pre(
        self,
        data_to_send: ts[MyStruct],
    ) -> ts[MyStruct]:
        if csp.ticked(data_to_send):
            # Mimics doing some calculations
            return data_to_send.copy()

    def connect(self, channels: MyGatewayChannels) -> None:
        channels.add_send_channel(MyGatewayChannels.my_channel)
        res_pre = self.state_node_pre(
            channels.get_channel(MyGatewayChannels.my_channel),
        )
        # channels.set_channel(MyGatewayChannels.my_channel_mid, res_pre)
        res = self.state_node(
            channels.get_channel(MyGatewayChannels.my_channel_dup),
            res_pre,
        )
        channels.set_channel(MyGatewayChannels.my_channel_final, res)
        """
        This line below used to be problematic. If commented out, everything
        worked normally. If it was there, then, depending on the ordering
        of this module and the GatewayTestHarness, the ticks generated would
        sometimes occur in the same engine cycle, and sometimes not. This has been fixed.
        """
        channels.set_channel(MyGatewayChannels.my_channel_mid, res_pre)

    @csp.node
    def state_node(
        self,
        data_to_update: ts[MyStruct],
        data_to_send: ts[MyStruct],
    ) -> csp.Outputs(
        ts[MyStruct],
    ):
        val = []
        if csp.ticked(data_to_send):
            val.append(data_to_send.copy())

        if csp.ticked(data_to_update):
            if val:
                val[0].foo += data_to_update.foo
            else:
                # BAD THIS SHOULDVE TICKED WITH DATA_TO_SEND
                ...
        if val:
            csp.output(val[0])


class MyGetModule(GatewayModule):
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


class MyGetModuleDynamicKeys(MyGetModule):
    requires: Optional[ChannelSelection] = []
    my_keys: List[str] = []

    def dynamic_keys(self):
        return {MyGatewayChannels.my_str_basket: self.my_keys}


class MyFastShutdownModule(GatewayModule):
    shutdown_called: bool = False

    def connect(self, channels: MyGatewayChannels):
        return

    def shutdown(self):
        self.shutdown_called = True


class MySlowShutdownModule(GatewayModule):
    shutdown_called: bool = False

    def connect(self, channels: MyGatewayChannels):
        return

    def shutdown(self):
        time.sleep(10)


class MyInfiniteShutdownModule(GatewayModule):
    def connect(self, channels):
        return

    def shutdown(self):
        time.sleep(100000)


class MyGetModuleListRequires(MyGetModule):
    requires: Optional[ChannelSelection] = []


class MyGetModuleListRequiresAnnotated(MyGetModule):
    requires: Optional[ChannelSelection] = []


class MyBuildFailureModule(GatewayModule):
    def connect(self, channels: MyGatewayChannels) -> None:
        raise ValueError("Cannot build graph")


class MyAssertStartDetectorModule(GatewayModule):
    gateway: Dict[str, Gateway] = Field(default_factory=dict)

    @csp.node
    def _assert_started(self, timer: ts[bool]):
        with csp.state():
            # NOTE: The last csp.start() that runs will be the one that sets `running`
            assert self.gateway["value"].running is False
        if csp.ticked(timer):
            assert self.gateway["value"].running

    def connect(self, channels: MyGatewayChannels) -> None:
        self._assert_started(csp.const(True))


def test_run_no_modules():
    gateway = MyGateway(modules=[])
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_user_modules():
    gateway = MyGateway(user_modules=[])
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


@pytest.mark.parametrize("by_key", [True, False])
def test_set_get(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[setter, getter], channels=MyGatewayChannels())
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


def test_run_user_modules():
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    getter = MyGetModule()
    gateway = MyGateway(user_modules=[setter, getter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert len(out["my_channel"]) == 1
    assert len(out["my_list_channel"]) == 1


# TODO: We can't pass in a subclass to a channel that takes a specific class
def test_set_get_fails_with_subclass():
    setter = MySetModule(
        my_data=csp.const(MyChildStruct(foo=1.0, foo2=9)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[setter, getter], channels=MyGatewayChannels())
    with pytest.raises(TypeError):
        csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


@pytest.mark.parametrize("by_key", [True, False])
def test_get_set(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[getter, setter], channels=MyGatewayChannels())
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


@pytest.mark.parametrize("by_key", [False, True])
def test_get_set_block_set_past(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule()
    gateway = MyGateway(
        modules=[getter, setter],
        channels=MyGatewayChannels(),
        block_set_channels_until=datetime(1969, 1, 2),
    )
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


@pytest.mark.parametrize("by_key", [False, True])
@pytest.mark.parametrize("override", [datetime(2020, 1, 1), None])
def test_get_set_block_set(by_key, override):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule(block_set_channels_until=override)
    gateway = MyGateway(
        modules=[getter, setter],
        channels=MyGatewayChannels(),
        block_set_channels_until=datetime(2020, 1, 2),
    )
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    for _, output in out.items():
        assert len(output) == 0


@pytest.mark.parametrize("by_key", [False, True])
def test_get_set_block_set_override(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
        block_set_channels_until=datetime(2020, 1, 1),
    )
    getter = MyGetModule(block_set_channels_until=datetime(2020, 1, 1))
    gateway = MyGateway(
        modules=[getter, setter],
        channels=MyGatewayChannels(),
        block_set_channels_until=datetime(2020, 1, 2),
    )
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


def test_get_module_dynamic_keys():
    """Set dynamic keys at the module level, and make sure building the channels works"""
    getter = MyGetModuleDynamicKeys(my_keys=["my_key", "my_key2"])
    gateway = MyGateway(modules=[getter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    for v in out.values():
        assert len(v) == 0


def test_get_channels_dynamic_keys():
    """Set dynamic keys at the channel level, and make sure building the channels works"""
    getter = MyGetModuleDynamicKeys()
    gateway = MyGateway(modules=[getter], channels=MyGatewayChannels(my_keys=["my_key", "my_key2"]))
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    for v in out.values():
        assert len(v) == 0


def test_requires_default_conversion():
    getter = MyGetModuleDynamicKeys()
    assert isinstance(getter.requires, ChannelSelection)


def test_requires_fails():
    """Require a channel not set"""
    with pytest.raises(ValidationError):
        MyGetModuleDynamicKeys(requires=99)

    getter = MyGetModuleDynamicKeys(requires=dict(exclude=[MyGatewayChannels.my_array_channel]))
    gateway = MyGateway(modules=[getter], channels=MyGatewayChannels(my_keys=["my_key", "my_key2"]))
    with pytest.raises(NoProviderException):
        csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_requires_backwards_compatible():
    for GetterClass in [MyGetModuleListRequires, MyGetModuleListRequiresAnnotated]:
        getter = GetterClass()
        gateway = MyGateway(modules=[getter], channels=MyGatewayChannels(my_keys=["my_key", "my_key2"]))
        csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))

        getter = GetterClass(requires=[MyGatewayChannels.my_array_channel])
        gateway = MyGateway(modules=[getter], channels=MyGatewayChannels(my_keys=["my_key", "my_key2"]))
        with pytest.raises(NoProviderException):
            csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


@pytest.mark.parametrize("by_key", [True, False])
def test_get_set_set(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[getter, setter, setter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert len(out["my_channel"]) == 2
    assert len(out["my_list_channel"]) == 2
    assert len(out["my_list_channel"][0][1]) == 2
    assert len(out["my_list_channel"][1][1]) == 2
    assert len(out["my_array_channel"]) == 2
    assert len(out["my_array_channel"][0][1]) == 2
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 2
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 2
    assert len(out["my_str_basket[my_key]"]) == 2
    assert len(out["my_str_basket[my_key2]"]) == 2
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 2
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 2
    assert len(out["my_enum_basket_ONE"]) == 2
    assert len(out["my_enum_basket_TWO"]) == 2
    assert len(out["my_str_basket_my_key"]) == 2
    assert len(out["my_str_basket_my_key2"]) == 2


@pytest.mark.parametrize("by_key", [True, False])
def test_get_set_set_block_set_on_one(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    setter2 = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
        block_set_channels_until=datetime(2020, 2, 1),
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[getter, setter, setter2], channels=MyGatewayChannels())
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


def test_start_stop():
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[getter, setter], channels=MyGatewayChannels())
    gateway.start(block=False, realtime=True, rest=False)
    gateway.stop()


@pytest.mark.parametrize("by_key", [True, False])
def test_last(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[getter, setter], channels=MyGatewayChannels())
    gateway.start(block=False, realtime=True, rest=False)
    try:
        time.sleep(0.5)
        assert isinstance(gateway.channels.last("my_channel"), MyStruct)
        assert isinstance(gateway.channels.last("my_list_channel"), list)
        assert isinstance(gateway.channels.last("my_array_channel"), np.ndarray)

        output = gateway.channels.last("my_enum_basket")
        assert isinstance(output, dict)
        assert len(output) == 2
        output = gateway.channels.last("my_enum_basket", MyEnum.ONE)
        assert isinstance(output, MyStruct)

        output = gateway.channels.last("my_str_basket")
        assert isinstance(output, dict)
        assert len(output) == 2

        output = gateway.channels.last("my_str_basket", "my_key")
        assert isinstance(output, MyStruct)

        output = gateway.channels.last("my_enum_basket_list")
        assert isinstance(output, dict)
        assert len(output) == 2
    finally:
        gateway.stop()


@pytest.mark.parametrize("by_key", [True, False])
def test_state(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[getter, setter], channels=MyGatewayChannels())
    gateway.start(block=False, realtime=True, rest=False)
    try:
        time.sleep(0.5)
        state = gateway.channels.state("my_channel")
        assert isinstance(state, State)
        assert len(state.query()) == 1
        state = gateway.channels.state("my_list_channel")
        assert isinstance(state, State)
        assert len(state.query()) == 2
    finally:
        gateway.stop()


def test_build_failure():
    failure = MyBuildFailureModule()
    gateway = MyGateway(modules=[failure], channels=MyGatewayChannels())
    start = time.time()
    try:
        gateway.start(rest=True, _in_test=True, build_timeout=timedelta(seconds=10))
    except (SystemExit, RuntimeError):
        pass
    elapsed = time.time() - start
    assert elapsed < 5


def test_set_get_disable_set():
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    getter = MyGetModule(disable=True)
    gateway = MyGateway(modules=[setter, getter, setter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert out is None


def test_set_get_set_disable_all():
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        disable=True,
    )
    getter = MyGetModule(disable=True)
    gateway = MyGateway(modules=[setter, getter, setter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert out is None


def test_disable_get_after_module_initialization():
    getter = MyGetModule()
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
    )
    getter.disable = True
    assert getter.disable is True
    gateway = MyGateway(modules=[setter, getter, setter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert out is None


@pytest.mark.parametrize("by_key", [True, False])
def test_disable_fails_after_gateway_object_initialization(by_key):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[setter, getter, setter], channels=MyGatewayChannels())
    getter.disable = True
    assert getter.disable is True

    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert out is None


def test_start_detector_order():
    """Make sure start detector is started before all other nodes."""
    m = MyAssertStartDetectorModule()
    gateway = MyGateway(modules=[m], channels=MyGatewayChannels())
    m.gateway["value"] = gateway
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))


def test_shutdown_fast():
    """Test whether the shutdown logic is invoked"""
    getter = MyFastShutdownModule()
    assert getter.shutdown_called is False
    gateway = MyGateway(modules=[getter], channels=MyGatewayChannels())

    gateway.start(block=False, _in_test=True, realtime=True, rest=False)
    gateway.stop()

    assert getter.shutdown_called is True


def test_shutdown_slow():
    """Test whether the shutdown logic logs error"""
    root_logger = logging.getLogger()
    log_stream = StringIO()
    stream_handler = logging.StreamHandler(log_stream)
    root_logger.addHandler(stream_handler)
    getter = MySlowShutdownModule()
    assert getter.shutdown_called is False

    gateway = MyGateway(modules=[getter], channels=MyGatewayChannels())
    gateway.start(block=False, _in_test=True, realtime=True, rest=False, module_shutdown_timeout=5)
    gateway.stop()
    res = log_stream.getvalue()
    assert "Shutting down modules took more than " in res
    assert "forcefully shutting down..." in res


def run_gateway():
    getter = MyInfiniteShutdownModule()
    gateway = MyGateway(modules=[getter], channels=MyGatewayChannels())
    gateway.start(block=False, _in_test=True, realtime=True, rest=False, module_shutdown_timeout=5)
    gateway.stop()


def test_shutdown_infinite():
    """Test whether gateway shutdown leads to infinitely waiting ThreadPool shutting down"""
    p = multiprocessing.Process(target=run_gateway)
    p.start()
    i = 0
    while p.is_alive() and i < 30:
        time.sleep(1)
        i += 1
    assert not p.is_alive()


class MySetModuleDynamicChannels(GatewayModule):
    scalar_channel_name: str
    list_channel_name: str
    connect_channels_assertion: Optional[Callable[[MyGatewayChannels], None]] = None

    def dynamic_channels(self) -> Optional[Dict[str, Union[Type[GatewayStruct], Type[List[GatewayStruct]]]]]:
        return {
            self.list_channel_name: List[MyStruct],
            self.scalar_channel_name: MyStruct,
        }

    def dynamic_state_channels(self) -> Optional[Set[str]]:
        return {self.scalar_channel_name, self.list_channel_name}

    def connect(self, channels: MyGatewayChannels) -> None:
        channels.set_channel(
            self.scalar_channel_name,
            csp.const(MyStruct(foo=1.0)),
        )
        channels.set_channel(
            self.list_channel_name,
            csp.const([MyStruct(foo=2.0), MyStruct(foo=3.0)]),
        )
        channels.set_state(self.scalar_channel_name, keyby="id")
        channels.set_state(self.list_channel_name, keyby="id")
        if self.connect_channels_assertion:
            self.connect_channels_assertion(channels)


class MyGetModuleDynamicChannels(GatewayModule):
    scalar_channel_name: str
    list_channel_name: str

    def connect(self, channels: MyGatewayChannels) -> None:
        csp.add_graph_output(
            self.scalar_channel_name,
            channels.get_channel(self.scalar_channel_name),
        )
        csp.add_graph_output(
            self.list_channel_name,
            channels.get_channel(self.list_channel_name),
        )
        csp.add_graph_output(
            f"s_{self.scalar_channel_name}",
            channels.get_channel(f"s_{self.scalar_channel_name}"),
        )
        csp.add_graph_output(
            f"s_{self.list_channel_name}",
            channels.get_channel(f"s_{self.list_channel_name}"),
        )


@pytest.mark.parametrize("gateway_from_config", (False, True))
@pytest.mark.parametrize("explicit_channels", (True, False))
def test_dynamic_channels(explicit_channels, gateway_from_config):
    if gateway_from_config:
        config = {
            "gateway": {
                "_target_": "csp_gateway.Gateway",
                "modules": ["/modules/setter", "/modules/getter"],
            },
            "modules": {
                "setter": {
                    "_target_": "csp_gateway.tests.server.gateway.test_gateway.MySetModuleDynamicChannels",
                    "scalar_channel_name": "my_dynamic_scalar_channel",
                    "list_channel_name": "my_dynamic_list_channel",
                },
                "getter": {
                    "_target_": "csp_gateway.tests.server.gateway.test_gateway.MyGetModuleDynamicChannels",
                    "scalar_channel_name": "my_dynamic_scalar_channel",
                    "list_channel_name": "my_dynamic_list_channel",
                },
            },
        }
        if explicit_channels:
            config["gateway"]["channels"] = {
                "_target_": "csp_gateway.tests.server.gateway.test_gateway.MyGatewayChannels",
            }

        config = OmegaConf.create(config)
        registry = ModelRegistry.root()
        registry.load_config(cfg=config, overwrite=True)
        gateway = registry["gateway"]

    else:
        setter = MySetModuleDynamicChannels(
            scalar_channel_name="my_dynamic_scalar_channel",
            list_channel_name="my_dynamic_list_channel",
        )
        getter = MyGetModuleDynamicChannels(
            scalar_channel_name="my_dynamic_scalar_channel",
            list_channel_name="my_dynamic_list_channel",
        )
        channels = MyGatewayChannels() if explicit_channels else None
        gateway = MyGateway(modules=[setter, getter], channels=channels)

    for _ in range(2):
        out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
        assert len(out["my_dynamic_scalar_channel"]) == 1
        assert out["my_dynamic_scalar_channel"][0][1].foo == 1.0
        assert len(out["my_dynamic_list_channel"]) == 1
        assert out["my_dynamic_list_channel"][0][1][0].foo == 2.0
        assert out["my_dynamic_list_channel"][0][1][1].foo == 3.0
        assert len(out["s_my_dynamic_scalar_channel"]) == 1
        assert len(out["s_my_dynamic_list_channel"]) == 2
        assert out["my_dynamic_list_channel"][0][1][0].foo == 2.0
        assert out["my_dynamic_list_channel"][0][1][1].foo == 3.0


def test_conflicting_dynamic_channels():
    setter_1 = MySetModuleDynamicChannels(
        scalar_channel_name="channel_1",
        list_channel_name="channel_2",
    )
    setter_2 = MySetModuleDynamicChannels(
        scalar_channel_name="channel_2",
        list_channel_name="channel_1",
    )
    with pytest.raises(ValueError, match="Conflicting types for"):
        csp.build_graph(MyGateway(modules=[setter_1, setter_2], channels=MyGatewayChannels()).graph)


def test_dynamic_channels_same_static_properties():
    my_object = {}
    channel = MyGatewayChannels(my_static_dict_of_objects={"a": my_object})

    def assert_func(c: MyGatewayChannels):
        assert c.my_static_dict_of_objects["a"] is my_object

    setter = MySetModuleDynamicChannels(scalar_channel_name="channel_1", list_channel_name="channel_2", connect_channels_assertion=assert_func)
    csp.build_graph(MyGateway(modules=[setter], channels=channel).graph)


@pytest.mark.parametrize("harness_first", [False, True])
def test_harness_ordering(harness_first):
    set_get = MyStatefulGetSetModule(requires=[])
    CHANNELS = [
        MyGatewayChannels.my_channel_final,
        MyGatewayChannels.my_channel,
        MyGatewayChannels.my_channel_dup,
    ]
    h = GatewayTestHarness(test_channels=CHANNELS)
    h.send(
        MyGatewayChannels.my_channel,
        MyStruct(foo=1.0),
    )
    h.send(MyGatewayChannels.my_channel_dup, MyStruct(foo=1.0))
    """
    OK, so the expected behavior, is that since we dont have any timers or alarms
    And there is no unrolling, everything should tick the same engine cycle.

    If everything ticks the same engine cycle, as expected, then foo should be 2.0
    Previously, depending on the ordering of modules, sometimes "my_channel_final" had "foo" with value of 1.0
    """
    h.assert_ticked(MyGatewayChannels.my_channel_final, 1)
    h.assert_attr_equal(MyGatewayChannels.my_channel_final, "foo", 2.0)
    if harness_first:
        gateway = MyGateway(
            modules=[h, set_get],
            channels=MyGatewayChannels(),
        )
    else:
        gateway = MyGateway(
            modules=[set_get, h],
            channels=MyGatewayChannels(),
        )
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
