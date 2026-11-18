import threading

import orjson
from typing_extensions import override

from ..struct import GatewayStruct


class Controls(GatewayStruct):
    name: str = "none"
    status: str = "none"
    data: dict = {}
    data_str: str = ""

    # TODO: all `GatewayStructs`` cross thread boundaries and should
    # have locks, but just doing `Controls`` for now
    _lock: object

    def lock(self, blocking=True, timeout=-1):
        # FIXME: first call is...not threadsafe
        if not hasattr(self, "_lock"):
            self._lock = threading.Lock()
        self._lock.acquire(blocking=blocking, timeout=timeout)

    def unlock(self):
        if not hasattr(self, "_lock"):
            self._lock = threading.Lock()
        if self._lock.locked():
            self._lock.release()

    def update_str(self):
        #  NOTE: Resolves a race between the Web API, which waits on `data`,
        #  and Perspective, which renders `data` as JSON text. `data_str` is
        #  the same JSON, set once so both see an identical value.
        self.lock()
        if self.data_str == "":
            self.data_str = orjson.dumps(self.data).decode()
        self.unlock()

    @override
    def psp_prepare(self):
        self.update_str()
