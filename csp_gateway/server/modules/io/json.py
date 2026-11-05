from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from typing import Any, Literal

import csp
from csp import ts
from pydantic import Field, model_validator

from csp_gateway.server import EncodedEngineCycle
from csp_gateway.server.shared.engine_replay import EngineReplay

from .json_pull_adapter import JSONPullAdapter

__all__ = ("ReplayEngineJSON",)


class JSONWriterThread(Thread):
    def __init__(self, file_path: str, write_queue: Queue, file_mode: str, compression: str | None = None):
        super().__init__()
        self.file_path = file_path
        self.write_queue = write_queue
        self.file_mode = file_mode
        self.compression = compression
        self.daemon = True

    def run(self):
        p = Path(self.file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if self.compression == "zstd":
            self._run_zstd(p)
            return
        with p.open(self.file_mode) as f:
            while True:
                data = self.write_queue.get()
                f.write(data)
                f.flush()
                self.write_queue.task_done()

    def _run_zstd(self, p: Path) -> None:
        import zstandard

        compressor = zstandard.ZstdCompressor()
        with p.open(self.file_mode + "b") as f:
            while True:
                # Everything queued so far goes into one complete frame, so the file is always readable
                # up to the last write, and a later run can append after it.
                batch = [self.write_queue.get()]
                try:
                    while True:
                        batch.append(self.write_queue.get_nowait())
                except Empty:
                    pass
                f.write(compressor.compress("".join(batch).encode()))
                f.flush()
                for _ in batch:
                    self.write_queue.task_done()


class ReplayEngineJSON(EngineReplay):
    overwrite_if_writing: bool = False
    filename: str
    compression: Literal["zstd"] | None = Field(
        default=None,
        description="Compress the file as it is written, on the writer thread rather than the engine thread. The filename "
        "must end in .zst, which is how reading it back knows to decompress. Requires the zstandard package.",
    )

    @model_validator(mode="after")
    def _check_compressed_filename(self) -> "ReplayEngineJSON":
        # The reader decompresses by suffix, so the suffix and the setting must agree.
        if (self.compression == "zstd") != self.filename.endswith(".zst"):
            raise ValueError(
                f"compression='zstd' and a filename ending in .zst go together, got compression={self.compression!r} for {self.filename!r}"
            )
        if self.compression == "zstd":
            # Here rather than on the writer thread, where a failed import would leave the queue undrained.
            import zstandard  # noqa: F401
        return self

    @csp.node
    def _dump_to_json(self, to_store: ts[EncodedEngineCycle]):
        with csp.state():
            s_json_writer_thread = None
            s_queue = None

        with csp.start():
            file_mode = "w" if self.overwrite_if_writing else "a"
            s_queue = Queue()
            s_json_writer_thread = JSONWriterThread(self.filename, s_queue, file_mode, self.compression)
            s_json_writer_thread.start()

        with csp.stop():
            s_queue.join()

        if csp.ticked(to_store):
            s_queue.put(to_store.encoding)

    def subscribe(self) -> ts[str] | ts[dict[str, Any]]:
        return JSONPullAdapter(self.filename)

    def publish(self, encoded_channels: ts[EncodedEngineCycle]) -> None:
        self._dump_to_json(encoded_channels)
