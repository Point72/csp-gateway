import time
from threading import Thread

import csp
from csp import ts

from csp_gateway import GatewayModule

__all__ = (
    "NeverDieModule",
    "CspDieModule",
    "LongStartModule",
)


def _never_die():
    while True:
        try:
            print("here")
            time.sleep(1)
        except:  # noqa: E722
            ...


class NeverDieModule(GatewayModule):
    def connect(self, *args, **kwargs) -> None:
        self._thread = Thread(target=_never_die, daemon=True)
        self._thread.start()


class CspDieModule(GatewayModule):
    count: int = 5
    channel_to_access: str = "example"
    attribute_to_access: str = "blerg"

    def connect(self, channels) -> None:
        self._tick(channels.get_channel(self.channel_to_access))

    @csp.node
    def _tick(self, thing: ts[object]):
        with csp.state():
            s_counter = 0
        if csp.ticked(thing):
            s_counter += 1
            if s_counter >= self.count:
                print("running getter to trigger problem")
                getattr(thing, self.attribute_to_access)


class LongStartModule(GatewayModule):
    sleep: int = 5
    channel_to_access: str = "example"

    def connect(self, channels) -> None:
        time.sleep(self.sleep)
        self._tick(channels.get_channel(self.channel_to_access))

    @csp.node
    def _tick(self, thing: ts[object]):
        with csp.start():
            time.sleep(self.sleep)
        if csp.ticked(thing):
            print("do nothing")
