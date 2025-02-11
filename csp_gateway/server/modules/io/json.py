from pathlib import Path
from queue import Queue
from threading import Thread
from typing import Any, Dict, Union

import csp
from csp import ts

from csp_gateway.server import EncodedEngineCycle
from csp_gateway.server.shared.engine_replay import EngineReplay

from .json_pull_adapter import JSONPullAdapter

__all__ = ("ReplayEngineJSON",)


class JSONWriterThread(Thread):
    def __init__(self, file_path: str, write_queue: Queue, file_mode: str):
        super().__init__()
        self.file_path = file_path
        self.write_queue = write_queue
        self.file_mode = file_mode

    def run(self):
        p = Path(self.file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open(self.file_mode) as f:
            while True:
                data = self.write_queue.get()
                f.write(data)
                f.flush()
                self.write_queue.task_done()


class ReplayEngineJSON(EngineReplay):
    overwrite_if_writing: bool = False
    filename: str

    @csp.node
    def _dump_to_json(self, to_store: ts[EncodedEngineCycle]):
        with csp.state():
            s_json_writer_thread = None
            s_queue = None

        with csp.start():
            file_mode = "w" if self.overwrite_if_writing else "a"
            s_queue = Queue()
            s_json_writer_thread = JSONWriterThread(self.filename, s_queue, file_mode)
            s_json_writer_thread.daemon = True
            s_json_writer_thread.start()

        with csp.stop():
            s_queue.join()

        if csp.ticked(to_store):
            s_queue.put(to_store.encoding)

    def subscribe(self) -> Union[ts[str], ts[Dict[str, Any]]]:
        return JSONPullAdapter(self.filename)

    def publish(self, encoded_channels: ts[EncodedEngineCycle]) -> None:
        self._dump_to_json(encoded_channels)
