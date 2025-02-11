import itertools
from datetime import datetime, timedelta
from typing import Dict, Optional, Type

import csp
import pytest
from csp import ts

from csp_gateway import Channels, ChannelSelection, Gateway, GatewayChannels, GatewayModule, GatewayStruct


class MyStruct(GatewayStruct):
    foo: float


class MyGatewayChannels(GatewayChannels):
    my_str_basket: Dict[str, ts[MyStruct]] = None
    my_channel1: ts[MyStruct] = None
    my_channel2: ts[MyStruct] = None


class MyGateway(Gateway):
    channels_model: Type[Channels] = MyGatewayChannels  # type: ignore[assignment]


class MySetModuleFeedback(GatewayModule):
    my_data: ts[MyStruct]
    my_set_channel: str
    my_get_channel: str
    filter_ticks: int = 3

    def connect(self, channels: MyGatewayChannels) -> None:
        # Build a set of inputs based on the test cases
        input = channels.get_channel(self.my_get_channel)
        output = csp.merge(self.my_data, input)
        # We only tick output if input has only ticked once or less
        flag = csp.default(csp.count(input) < csp.const(self.filter_ticks), True)
        res = csp.filter(flag, output)
        channels.set_channel(self.my_set_channel, res)


class MySetModuleDict(GatewayModule):
    my_data: ts[MyStruct]
    my_dep: Optional[str] = None
    my_key: str
    by_key: bool = True
    filter_ticks: int = 2

    def dynamic_keys(self):
        return {MyGatewayChannels.my_str_basket: [self.my_key]}

    def connect(self, channels: MyGatewayChannels) -> None:
        # Build a set of inputs based on the test cases
        output = self.my_data
        input = None
        if self.my_dep is not None:
            input = channels.get_channel(MyGatewayChannels.my_str_basket, self.my_dep)
            output = csp.merge(output, input)
        if input is not None:
            flag = csp.default(csp.count(input) < csp.const(self.filter_ticks), True)
            output = csp.filter(flag, output)
        if self.by_key:
            channels.set_channel(MyGatewayChannels.my_str_basket, output, self.my_key)

        else:
            channels.set_channel(
                MyGatewayChannels.my_str_basket,
                {self.my_key: output},
            )


class MyGetModule(GatewayModule):
    requires: Optional[ChannelSelection] = []  # so that we dont error if a channel isnt provided

    def connect(self, channels: MyGatewayChannels) -> None:
        for k, v in channels.get_channel(MyGatewayChannels.my_str_basket).items():
            csp.add_graph_output(f"my_str_basket[{k}]", v)
        csp.add_graph_output("my_channel2", channels.get_channel(MyGatewayChannels.my_channel2))
        csp.add_graph_output("my_channel1", channels.get_channel(MyGatewayChannels.my_channel1))


@pytest.mark.parametrize("ordering", list(itertools.permutations([0, 1, 2])))
def test_set_get(ordering):
    """Test that two modules can get/set different keys of the same dict channel"""
    setter = MySetModuleDict(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_key="my_key",
    )
    setter2 = MySetModuleDict(
        my_data=csp.const(MyStruct(foo=2.0)),
        my_key="my_key2",
        my_dep="my_key",
    )
    getter = MyGetModule()
    base_order = [setter, setter2, getter]
    modules = [base_order[i] for i in ordering]
    gateway = MyGateway(modules=modules, channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert "my_str_basket[my_key]" in out
    assert len(out["my_str_basket[my_key]"]) == 1
    assert "my_str_basket[my_key2]" in out
    # This should be 1. We send in the data at the same time
    # Since csp.merge drops the right tick if both inputs tick
    # at the same time, we should actually get just 1 tick.
    assert len(out["my_str_basket[my_key2]"]) == 1


def test_set_get_loop_same_module():
    """Test that two modules can get/set the same channel (forms a cycle)."""
    setter = MySetModuleFeedback(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_set_channel=MyGatewayChannels.my_channel1,
        my_get_channel=MyGatewayChannels.my_channel1,
    )
    getter = MyGetModule()
    gateway = MyGateway(modules=[setter, getter], channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert "my_channel1" in out

    # We add a feedback since we now formed a cycle with the same channel
    # Since we filter out the ouput in our setter if the input ticks 3 times
    # (defined in the 'connect' method of MySetModuleFeedback)
    # We get 3 ticks here
    assert len(out["my_channel1"]) == 3


@pytest.mark.parametrize("ordering", list(itertools.permutations([0, 1, 2])))
def test_set_get_loop_across_modules(ordering):
    """Test that two modules can get/set different channels that form a cycle."""
    setter = MySetModuleFeedback(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_set_channel=MyGatewayChannels.my_channel1,
        my_get_channel=MyGatewayChannels.my_channel2,
    )
    setter2 = MySetModuleFeedback(
        my_data=csp.const(MyStruct(foo=2.0)),
        my_set_channel=MyGatewayChannels.my_channel2,
        my_get_channel=MyGatewayChannels.my_channel1,
    )
    getter = MyGetModule()
    base_order = [setter, setter2, getter]
    modules = [base_order[i] for i in ordering]
    gateway = MyGateway(modules=modules, channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert "my_channel1" in out
    assert "my_channel2" in out

    # We need to add a feedback since we now formed a cycle with channels across modules.
    # However, we only need the feedback on one edge.
    # We add feedbacks, as needed, in the order that modules are listed in the "modules" list
    # Thus, whichever module that is added first, it's "set_channel" call, which forms
    # a cycle, will get a feedback added. The addition of this feedback means that the
    # cycle is broken, so the other module will not get a new feedback.
    set_my_channel1_first = ordering.index(0) > ordering.index(1)
    if set_my_channel1_first:
        # The module that calls "set_channel" on "MyGatewayChannels.my_channel1"
        # is processed first. This means, we add the feedback right before
        # we call set. Thus, this input is delayed, so by the time it's
        # second tick comes, the other channel "MyGatewayChannels.my_channel2" has already ticked
        # so we filter out the output.
        assert len(out["my_channel1"]) == 2
        assert len(out["my_channel2"]) == 3
    else:
        # Similar logic as above, but flip the channels
        assert len(out["my_channel1"]) == 3
        assert len(out["my_channel2"]) == 2


@pytest.mark.parametrize("ordering", list(itertools.permutations([0, 1, 2])))
@pytest.mark.parametrize("by_key", [True, False])
def test_set_get_loop_dict(by_key, ordering):
    """Test that two modules can get/set different keys of the same dict channel that form a cycle."""
    setter = MySetModuleDict(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_key="my_key",
        my_dep="my_key2",
        by_key=by_key,
    )
    setter2 = MySetModuleDict(
        my_data=csp.const(MyStruct(foo=2.0)),
        my_key="my_key2",
        my_dep="my_key",
        by_key=by_key,
    )
    getter = MyGetModule()
    base_order = [setter, setter2, getter]
    modules = [base_order[i] for i in ordering]
    gateway = MyGateway(modules=modules, channels=MyGatewayChannels())
    out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert "my_str_basket[my_key]" in out
    assert "my_str_basket[my_key2]" in out

    # We need to add a feedback since we now formed a cycle with different dict keys
    # across modules. However, we only need the feedback on one edge.
    # We add feedbacks, as needed, in the order that modules are listed in the "modules" list
    # Thus, whichever module that is added first, it's "set_channel" call, which forms
    # a cycle, will get a feedback added. The addition of this feedback means that the
    # cycle is broken, so the other module will not get a new feedback.
    set_my_key_edge_first = ordering.index(0) > ordering.index(1)
    if set_my_key_edge_first:
        # The module that calls "set_channel" on key "my_key"
        # is processed first. This means, we add the feedback right before
        # we call set. Thus, this input is delayed, so by the time it's
        # second tick comes, the other key has already ticked so we filter
        # out the output.
        assert len(out["my_str_basket[my_key]"]) == 1
        assert len(out["my_str_basket[my_key2]"]) == 2
    else:
        # Similar logic as above, but flip "my_key" with "my_key2"
        assert len(out["my_str_basket[my_key]"]) == 2
        assert len(out["my_str_basket[my_key2]"]) == 1
