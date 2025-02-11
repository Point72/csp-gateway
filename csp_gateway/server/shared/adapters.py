import logging
import time
from datetime import timedelta
from threading import Thread
from typing import Any, Callable, Optional

import pandas as pd
import pyarrow as pa
from csp import ts
from csp.impl.pushadapter import PushInputAdapter
from csp.impl.wiring import py_push_adapter_def

__all__ = (
    "sql_polling_adapter_def",
    "poll_sql_for_arrow_tbl",
    "poll_sql_for_pandas_df",
)


def poll_sql_for_arrow_tbl(connection: str, query: str, logger_name: str = __name__) -> pa.Table:
    from arrow_odbc import read_arrow_batches_from_odbc

    reader = read_arrow_batches_from_odbc(
        query=query,
        connection_string=connection,
        batch_size=10_000,
    )
    return pa.Table.from_batches(batches=reader, schema=reader.schema)


def poll_sql_for_pandas_df(connection: str, query: str, logger_name: str = __name__) -> pd.DataFrame:
    return poll_sql_for_arrow_tbl(connection, query, logger_name).to_pandas()


class PollingSQLAdapterImpl(PushInputAdapter):
    def __init__(
        self,
        interval: timedelta,
        connection: str,
        query: str,
        poll: Callable[[str, str, logging.Logger], Any],
        callback: Optional[Callable[[Any], Any]] = None,
        logger_name: str = __name__,
        failed_poll_msg: str = "Failed to poll sql database",
        connection_timeout_seconds: int = 0,
        query_timeout_seconds: int = 0,
    ):
        self._interval = interval
        self._connection = connection
        if connection_timeout_seconds:
            self._connection += f";timeout={connection_timeout_seconds}"

        if query_timeout_seconds:
            self._connection += f";commandTimeout={query_timeout_seconds}"

        self._query = query
        self._callback = callback
        self._last_update = 0
        self._poll = poll
        self._logger_name = logger_name
        self._failed_poll_msg = failed_poll_msg

        self._thread = None
        self._running = False
        self._paused = False

    def start(self, starttime, endtime):
        """start will get called at the start of the engine, at which point the push
        input adapter should start its thread that will push the data onto the adapter.  Note
        that push adapters will ALWAYS have a separate thread driving ticks into the csp engine thread
        """
        self._running = True
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """stop will get called at the end of the run, at which point resources should
        be cleaned up
        """
        if self._running:
            self._running = False
            # if it is paused, we just kill it
            if self._paused:
                self._thread.join(0.01)
            else:
                # we give it the interval time to finish
                self._thread.join(self._interval.total_seconds())

    def _run(self):
        log = logging.getLogger(self._logger_name)
        while self._running:
            self._paused = False
            try:
                now = time.time()
                res = self._poll(self._connection, self._query, self._logger_name)
                if self._callback is not None:
                    res = self._callback(res)
                self._last_update = now
                self.push_tick(res)

            except Exception:
                # TODO: What do we want to do here?
                log.warning(self._failed_poll_msg, exc_info=True)
                self.push_tick(None)  # None is a bad value

            # TODO: Handle what happens if it hangs, by having a separate thread listen for data in a queue
            #  and publish pd.DataFrame if it misses a heartbeat
            #  sleep interval
            self._paused = True
            time.sleep(self._interval.total_seconds())


sql_polling_adapter_def = py_push_adapter_def(
    "sql_polling_adapter_def",
    PollingSQLAdapterImpl,
    ts[object],
    interval=timedelta,
    connection=str,
    query=str,
    poll=object,
    callback=object,
    logger_name=str,
    failed_poll_msg=str,
    connection_timeout_seconds=int,
    query_timeout_seconds=int,
)
