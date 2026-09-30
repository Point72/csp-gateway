import logging
from datetime import UTC, datetime, timedelta
from unittest import mock

import csp
import pandas as pd
import pyarrow as pa
import pytest

from csp_gateway.server import poll_sql_for_pandas_df, sql_polling_adapter_def


@pytest.mark.parametrize("caplog_level", [logging.WARNING, logging.ERROR])
def test_sql_polling_adapter_error(caplog_level, caplog):
    failed_poll_msg = "Failed to poll, TESTING"

    def failing_poll(connection: str, query: str, logger_name: str):
        raise RuntimeError("poll failed")

    caplog.set_level(caplog_level, logger="my_logger")
    my_poll = sql_polling_adapter_def(
        interval=timedelta(seconds=1),
        connection="MY_MOCK_CONNECTION",
        query="MY_MOCK_QUERY",
        poll=failing_poll,
        callback=None,
        logger_name="my_logger",
        failed_poll_msg=failed_poll_msg,
        connection_timeout_seconds=0,
        query_timeout_seconds=0,
    )
    csp.run(
        my_poll,
        starttime=datetime.now(UTC),
        endtime=timedelta(seconds=1),
        realtime=True,
    )
    if caplog_level == logging.WARNING:
        assert failed_poll_msg in caplog.text
    else:
        assert "" == caplog.text


def test_sql_polling_adapter_poll():
    def custom_poll(connection: str, query: str, logger_name: str):
        return (connection, query, logger_name)

    connection = "MY_MOCK_CONNECTION"
    query = "MY_MOCK_QUERY"

    my_poll = sql_polling_adapter_def(
        interval=timedelta(seconds=1),
        connection=connection,
        query=query,
        poll=custom_poll,
        callback=None,
        logger_name="my_logger",
        failed_poll_msg="Failed to poll, TESTING",
        connection_timeout_seconds=0,
        query_timeout_seconds=0,
    )
    out = csp.run(
        my_poll,
        starttime=datetime.now(UTC),
        endtime=timedelta(seconds=1),
        realtime=True,
    )
    assert out[0][0][1] == (connection, query, "my_logger")


@mock.patch("csp_gateway.server.shared.adapters.poll_sql_for_arrow_tbl")
def test_sql_polling_adapter_poll_with_arrow(mock_arrow_table_db):
    mock_arrow_table_db.return_value = pa.Table.from_pandas(pd.DataFrame({"A": [1, 2, 3]}))

    connection = "MY_MOCK_CONNECTION"
    query = "MY_MOCK_QUERY"

    my_poll = sql_polling_adapter_def(
        interval=timedelta(seconds=1),
        connection=connection,
        query=query,
        poll=mock_arrow_table_db,
        callback=None,
        logger_name="my_logger",
        failed_poll_msg="Failed to poll, TESTING",
        connection_timeout_seconds=0,
        query_timeout_seconds=0,
    )
    out = csp.run(
        my_poll,
        starttime=datetime.now(UTC),
        endtime=timedelta(seconds=1),
        realtime=True,
    )
    pd.testing.assert_frame_equal(out[0][0][1].to_pandas(), mock_arrow_table_db.return_value.to_pandas())
    assert mock_arrow_table_db.call_args_list[0][0][0] == "MY_MOCK_CONNECTION"
    assert mock_arrow_table_db.call_args_list[0][0][1] == "MY_MOCK_QUERY"


@mock.patch("csp_gateway.server.shared.adapters.poll_sql_for_arrow_tbl")
def test_sql_polling_adapter_poll_with_pandas(mock_arrow_table_db):
    mock_arrow_table_db.return_value = pa.Table.from_pandas(pd.DataFrame({"A": [1, 2, 3]}))

    connection = "MY_MOCK_CONNECTION"
    query = "MY_MOCK_QUERY"

    my_poll = sql_polling_adapter_def(
        interval=timedelta(seconds=1),
        connection=connection,
        query=query,
        poll=poll_sql_for_pandas_df,
        callback=None,
        logger_name="my_logger",
        failed_poll_msg="Failed to poll, TESTING",
        connection_timeout_seconds=0,
        query_timeout_seconds=0,
    )
    out = csp.run(
        my_poll,
        starttime=datetime.now(UTC),
        endtime=timedelta(seconds=1),
        realtime=True,
    )
    pd.testing.assert_frame_equal(out[0][0][1], mock_arrow_table_db.return_value.to_pandas())
    assert mock_arrow_table_db.call_args_list[0][0][0] == "MY_MOCK_CONNECTION"
    assert mock_arrow_table_db.call_args_list[0][0][1] == "MY_MOCK_QUERY"


def test_sql_polling_adapter_poll_timeout():
    def custom_poll(connection: str, query: str, logger_name: str):
        return (connection, query, logger_name)

    connection = "MY_MOCK_CONNECTION"
    query = "MY_MOCK_QUERY"

    my_poll = sql_polling_adapter_def(
        interval=timedelta(seconds=1),
        connection=connection,
        query=query,
        poll=custom_poll,
        callback=None,
        logger_name="my_logger",
        failed_poll_msg="Failed to poll, TESTING",
        connection_timeout_seconds=5,
        query_timeout_seconds=10,
    )
    out = csp.run(
        my_poll,
        starttime=datetime.now(UTC),
        endtime=timedelta(seconds=1),
        realtime=True,
    )
    assert out[0][0][1] == (
        connection + ";timeout=5;commandTimeout=10",
        query,
        "my_logger",
    )


@pytest.mark.parametrize(
    ("connection_timeout_seconds", "query_timeout_seconds", "expected_connection_timeout", "expected_query_timeout"),
    [
        (5, 10, 5, 10),
        (0, 0, None, None),
    ],
)
def test_sql_polling_adapter_poll_timeout_forwarded_to_5arg_poll(
    connection_timeout_seconds,
    query_timeout_seconds,
    expected_connection_timeout,
    expected_query_timeout,
):
    def custom_poll(
        connection: str,
        query: str,
        logger_name: str,
        connection_timeout_seconds: int | None = None,
        query_timeout_seconds: int | None = None,
    ):
        return (connection, query, logger_name, connection_timeout_seconds, query_timeout_seconds)

    connection = "MY_MOCK_CONNECTION"
    query = "MY_MOCK_QUERY"

    my_poll = sql_polling_adapter_def(
        interval=timedelta(seconds=1),
        connection=connection,
        query=query,
        poll=custom_poll,
        callback=None,
        logger_name="my_logger",
        failed_poll_msg="Failed to poll, TESTING",
        connection_timeout_seconds=connection_timeout_seconds,
        query_timeout_seconds=query_timeout_seconds,
    )
    out = csp.run(
        my_poll,
        starttime=datetime.now(UTC),
        endtime=timedelta(seconds=1),
        realtime=True,
    )
    # Timeouts forwarded positionally (0 becomes None); connection string left unmodified
    assert out[0][0][1] == (connection, query, "my_logger", expected_connection_timeout, expected_query_timeout)


def test_sql_polling_adapter_poll_with_callback():
    def custom_poll(connection: str, query: str, logger_name: str):
        return (connection, query, logger_name)

    def callback(tup: tuple[str, str, str]):
        return tup[-1]

    connection = "MY_MOCK_CONNECTION"
    query = "MY_MOCK_QUERY"

    my_poll = sql_polling_adapter_def(
        interval=timedelta(seconds=1),
        connection=connection,
        query=query,
        poll=custom_poll,
        callback=callback,
        logger_name="my_logger",
        failed_poll_msg="Failed to poll, TESTING",
        connection_timeout_seconds=0,
        query_timeout_seconds=0,
    )
    out = csp.run(
        my_poll,
        starttime=datetime.now(UTC),
        endtime=timedelta(seconds=1),
        realtime=True,
    )
    assert out[0][0][1] == "my_logger"
