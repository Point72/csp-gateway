from datetime import datetime

import orjson
from csp import ts
from csp.impl.pulladapter import PullInputAdapter
from csp.impl.wiring import py_pull_adapter_def

from csp_gateway.server.gateway.csp.channels import _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD

__all__ = ("JSONPullAdapter",)


# The Impl object is created at runtime when the graph is converted into the runtime engine
# it does not exist at graph building time!
class JSONPullAdapterImpl(PullInputAdapter):
    def __init__(self, filename: str):
        self._filename = filename
        self._file = None
        self._next_row = None
        super().__init__()

    def start(self, start_time, end_time):
        self._file = open(self._filename, "r")
        for line in self._file:
            self._next_row = line
            json_dict = orjson.loads(line)
            time_str = json_dict[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD]
            # since csp engine times are in utc we can just
            # drop the timezone info to compare it to start_time
            time = datetime.fromisoformat(time_str).replace(tzinfo=None)
            if time >= start_time:
                break

        super().start(start_time, end_time)

    def stop(self):
        self._file.close()

    def next(self):
        if self._next_row is None:
            return None

        while True:
            json_dict = orjson.loads(self._next_row)
            time_str = json_dict[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD]
            time = datetime.fromisoformat(time_str).replace(tzinfo=None)
            try:
                self._next_row = next(self._file)
            except StopIteration:
                self._next_row = None
            return time, json_dict


# MyPullAdapter is the graph-building time construct.  This is simply a representation of what the
# input adapter is and how to create it, including the Impl to use and arguments to pass into it upon construction
JSONPullAdapter = py_pull_adapter_def("JSONPullAdapter", JSONPullAdapterImpl, ts[dict], filename=str)
