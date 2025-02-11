import logging
import threading

import numpy
import pandas
import polars
import pytest
from packaging import version

from csp_gateway import GatewayClient, ResponseWrapper

#  Struct for response wrapper
#  class MyTypeStruct(BaseModel):
#      d_str: str
#      d_int: int
#      d_float: float
#      d_datetime: datetime
#      d_int_or_float: Union[int, float]

list_data = [
    ("integer", [1, 2, 3, 4, 5]),
    ("string", ["data1", "data2", "data3", "data4", "data5"]),
]

data = [
    {
        "d_str": "A",
        "d_int": 1,
        "d_float": 1.0,
        "d_datetime": "2024-01-01 00:00:00+00:00",
        "d_int_or_float": 1,
    },
    {
        "d_str": "A",
        "d_int": 1,
        "d_float": 1.0,
        "d_datetime": "2024-01-01 00:00:00+00:00",
        "d_int_or_float": 1.0,
    },
    {
        "d_int": 1,
        "d_float": 1.0,
        "d_datetime": "2024-01-01 00:00:00+00:00",
        "d_int_or_float": 1,
    },
    # NOTE: as_pandas_df cannot handle unset int values
    #  {'d_str': 'A', 'd_float': 1.0, 'd_datetime': "2024-01-01 00:00:00+00:00", 'd_int_or_float': 1},
    {
        "d_str": "A",
        "d_int": 1,
        "d_datetime": "2024-01-01 00:00:00+00:00",
        "d_int_or_float": 1,
    },
    {"d_str": "A", "d_int": 1, "d_float": 1.0, "d_int_or_float": 1},
    {
        "d_str": "A",
        "d_int": 1,
        "d_float": 1.0,
        "d_datetime": "2024-01-01 00:00:00+00:00",
    },
]
schema = {
    "properties": {
        "d_str": {"anyOf": [{"type": "string"}, {"type": "null"}], "title": "d_str"},
        "d_datetime": {
            "anyOf": [{"type": "string", "format": "date-time"}, {"type": "null"}],
            "title": "d_datetime",
        },
        "d_int": {
            "anyOf": [{"type": "integer"}, {"type": "null"}],
            "title": "d_intArea",
        },
        "d_float": {
            "anyOf": [{"type": "number"}, {"type": "null"}],
            "title": "d_float",
        },
        "d_enum": {
            "anyOf": [
                {
                    "type": "string",
                    "enum": ["UNKNOWN", "ENUM_1", "ENUM_2"],
                    "title": "d_enum",
                },
                {"type": "null"},
            ],
            "title": "d_enum",
            "default": "UNKNOWN",
        },
        "d_int_or_float": {
            "anyOf": [{"type": "number"}, {"type": "integer"}, {"type": "null"}],
            "title": "Quantity",
            "default": 0,
        },
    },
    "additionalProperties": False,
    "type": "object",
    "title": "MyTypeStruct",
}


@pytest.mark.skipif(
    version.parse(numpy.__version__) < version.parse("1.25"),
    reason="NumPy version less than 1.25 does not have numpy.dtypes",
)
def test_response_wrapper_empty_pandas():
    resp = ResponseWrapper(json_data={}, openapi_schema=schema)
    # Test as_pandas_df
    assert resp.as_json() == {}
    assert isinstance(resp.as_pandas_df().dtypes["d_str"], pandas.core.arrays.string_.StringDtype)
    assert isinstance(resp.as_pandas_df().dtypes["d_int"], numpy.dtypes.Int64DType)
    assert isinstance(resp.as_pandas_df().dtypes["d_float"], numpy.dtypes.Float64DType)
    assert isinstance(resp.as_pandas_df().dtypes["d_datetime"], pandas.core.arrays.string_.StringDtype)
    assert isinstance(resp.as_pandas_df().dtypes["d_int_or_float"], numpy.dtypes.ObjectDType)


def test_response_wrapper_empty_polars():
    resp = ResponseWrapper(json_data={}, openapi_schema=schema)
    # Test as_polars_df
    assert resp.as_polars_df().schema["d_str"] == polars.Utf8
    assert resp.as_polars_df().schema["d_int"] == polars.Int64
    assert resp.as_polars_df().schema["d_float"] == polars.Float64
    assert resp.as_polars_df().schema["d_datetime"] == polars.Utf8
    assert resp.as_polars_df().schema["d_int_or_float"] == polars.Object


def test_get_event_loop_off_thread(caplog):
    caplog.set_level(logging.DEBUG)

    bad_log = "THIS LOG MESSAGE PROBABLY WOULD NEVER NATURALLY OCCUR"

    def instantiate_in_thread():
        try:
            GatewayClient()
        except Exception:
            # This should not be hit
            logging.error(bad_log)

    thread = threading.Thread(target=instantiate_in_thread)
    thread.start()
    thread.join()

    expected_message = "Attempted to get event loop without one running, creating a new one..."
    assert any(expected_message in record.message for record in caplog.records)
    assert all(bad_log not in record.message for record in caplog.records)


def test_response_wrapper():
    resp = ResponseWrapper(json_data=data, openapi_schema=schema)
    assert resp.as_json() == data

    # Test Dict Data
    pandas_df = resp.as_pandas_df()
    for idx, df_row in pandas_df.iterrows():
        for col in pandas_df.columns:
            if pandas.isnull(df_row[col]):
                assert col not in data[idx]
            else:
                assert df_row[col] == data[idx][col]

    polars_df = resp.as_polars_df()
    for idx in range(len(polars_df)):
        for col in polars_df.columns:
            if polars_df[col][idx] is None:
                assert col not in data[idx]
            else:
                assert polars_df[col][idx] == data[idx][col]

    # Test List Data
    for typ, lst in list_data:
        lst_schema = {"type": typ}
        lst_resp = ResponseWrapper(json_data=lst, openapi_schema=lst_schema)
        assert lst_resp.as_json() == lst

        pandas_df = lst_resp.as_pandas_df()
        assert pandas_df.iloc[:, 0].tolist() == lst

        polars_df = lst_resp.as_polars_df()
        assert polars_df[:, 0].to_list() == lst
