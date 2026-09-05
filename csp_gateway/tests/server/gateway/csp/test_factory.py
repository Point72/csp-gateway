from datetime import datetime, timedelta
from enum import Enum as PyEnum

import csp
import pytest
from csp import Enum as CspEnum, ts

from csp_gateway import Gateway, GatewayChannels, GatewayModule, GatewayStruct


class MyStruct(GatewayStruct):
    foo: float


class MyPyEnum(PyEnum):
    A = 0
    B = 1


class MyCspEnum(CspEnum):
    A = 0
    B = 1


class PyEnumChannels(GatewayChannels):
    basket: dict[MyPyEnum, ts[MyStruct]] = None


class CspEnumChannels(GatewayChannels):
    basket: dict[MyCspEnum, ts[MyStruct]] = None


class SendWholeBasketModule(GatewayModule):
    key_type: type
    seen: list = []

    @csp.node
    def _value(self, trigger: ts[bool]) -> ts[MyStruct]:
        if csp.ticked(trigger):
            return MyStruct(foo=1.0)

    def connect(self, channels: GatewayChannels) -> None:
        trigger = csp.timer(interval=timedelta(seconds=0.1), value=True)
        for key in self.key_type:
            channels.set_channel("basket", self._value(trigger), key)
        # No indexer: the factory has to expand this into a send channel per key.
        channels.add_send_channel("basket")
        self.seen.append(channels)


@pytest.mark.parametrize(
    "channels_type,key_type",
    [(PyEnumChannels, MyPyEnum), (CspEnumChannels, MyCspEnum)],
    ids=["python_enum", "csp_enum"],
)
def test_whole_basket_send_channel_expands_enum_keys(channels_type, key_type):
    module = SendWholeBasketModule(key_type=key_type, seen=[])
    gateway = Gateway(modules=[module], channels=channels_type())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=1))

    channels = module.seen[0]
    assert set(channels._send_channels) == {("basket", None)} | {("basket", key) for key in key_type}
