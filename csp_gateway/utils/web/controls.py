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
        #  NOTE: This is needed to resolve a race condition between
        #  Web API and Perspective. We need to create a data_str
        #  because perspective cannot read python dict types and
        #  csp.Structs.to_json creates dictionaries. This will
        #  be removed when better to_json support is added.
        self.lock()
        if self.data_str == "":
            self.data_str = orjson.dumps(self.data).decode()
        self.unlock()

    @override
    def psp_flatten(self, custom_jsonifier=None):
        self.update_str()
        res = super().psp_flatten(custom_jsonifier)
        return res
