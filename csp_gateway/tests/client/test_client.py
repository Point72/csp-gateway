import logging

import numpy
import pandas
import polars
import pytest
from packaging import version

from csp_gateway import ClientConfig, GatewayClient, ResponseWrapper, ReturnType
from csp_gateway.client.client import _host
from csp_gateway.server.demo import ExampleData
from csp_gateway.utils import get_thread

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

    thread = get_thread(target=instantiate_in_thread)
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


def test_client_instantiation_convenenience():
    client = GatewayClient()
    assert client.config.host == "localhost"
    assert client.config.port == 8000
    assert client.config.protocol == "http"

    client = GatewayClient(host="https://my.test.gateway", port=None)
    assert client.config.host == "my.test.gateway"
    assert client.config.port is None
    assert client.config.protocol == "https"


def test_host_parsing():
    cfg = ClientConfig(host="localhost", port=8000, protocol="http")
    assert _host(cfg) == "http://localhost:8000"

    cfg = ClientConfig(host="https://my.host", port=None, protocol="http")
    assert _host(cfg) == "https://my.host"


def test_return_type_enum():
    """Test that ReturnType enum values are correct."""
    assert ReturnType.Raw == "raw"
    assert ReturnType.JSON == "json"
    assert ReturnType.Pandas == "pandas"
    assert ReturnType.Polars == "polars"
    assert ReturnType.Struct == "struct"
    assert ReturnType.Wrapper == "wrapper"


def test_client_config_return_type():
    """Test that ClientConfig accepts return_type parameter."""
    cfg = ClientConfig(return_type=ReturnType.Raw)
    assert cfg.return_type == ReturnType.Raw

    cfg = ClientConfig(return_type=ReturnType.JSON)
    assert cfg.return_type == ReturnType.JSON

    cfg = ClientConfig(return_type=ReturnType.Pandas)
    assert cfg.return_type == ReturnType.Pandas

    cfg = ClientConfig(return_type=ReturnType.Struct)
    assert cfg.return_type == ReturnType.Struct

    # Test string conversion (string values are promoted to enum)
    cfg = ClientConfig(return_type="wrapper")
    assert cfg.return_type == ReturnType.Wrapper

    cfg = ClientConfig(return_type="raw")
    assert cfg.return_type == ReturnType.Raw

    cfg = ClientConfig(return_type="json")
    assert cfg.return_type == ReturnType.JSON

    cfg = ClientConfig(return_type="pandas")
    assert cfg.return_type == ReturnType.Pandas

    cfg = ClientConfig(return_type="polars")
    assert cfg.return_type == ReturnType.Polars

    cfg = ClientConfig(return_type="struct")
    assert cfg.return_type == ReturnType.Struct


def test_response_wrapper_as_struct():
    """Test ResponseWrapper.as_struct() method."""
    # Create sample ExampleData JSON
    example_json = [
        {"id": "test-id-1", "x": 1, "y": "111", "data": [], "mapping": {}},
        {"id": "test-id-2", "x": 2, "y": "222", "data": [], "mapping": {}},
    ]

    # Create ResponseWrapper with type_name
    resp = ResponseWrapper(
        json_data=example_json,
        type_name="csp_gateway.server.demo.omnibus.ExampleData",
    )

    # Convert to structs
    structs = resp.as_struct()

    assert isinstance(structs, list)
    assert len(structs) == 2
    assert all(isinstance(s, ExampleData) for s in structs)
    assert structs[0].x == 1
    assert structs[0].y == "111"
    assert structs[1].x == 2
    assert structs[1].y == "222"


def test_response_wrapper_as_struct_single_item():
    """Test ResponseWrapper.as_struct() with a single item (not a list)."""
    example_json = {"id": "test-id-1", "x": 5, "y": "55555", "data": [], "mapping": {}}

    resp = ResponseWrapper(
        json_data=example_json,
        type_name="csp_gateway.server.demo.omnibus.ExampleData",
    )

    struct = resp.as_struct()

    assert isinstance(struct, ExampleData)
    assert struct.x == 5
    assert struct.y == "55555"


def test_response_wrapper_as_struct_empty():
    """Test ResponseWrapper.as_struct() with empty data."""
    resp = ResponseWrapper(
        json_data=[],
        type_name="csp_gateway.server.demo.omnibus.ExampleData",
    )

    structs = resp.as_struct()
    assert structs == []


def test_response_wrapper_as_struct_no_type_name():
    """Test ResponseWrapper.as_struct() raises error when type_name is missing."""
    resp = ResponseWrapper(json_data=[{"x": 1}])

    with pytest.raises(ValueError, match="no type_name available"):
        resp.as_struct()


def test_response_wrapper_as_struct_invalid_type():
    """Test ResponseWrapper.as_struct() raises error for invalid type name."""
    resp = ResponseWrapper(
        json_data=[{"x": 1}],
        type_name="nonexistent.module.SomeClass",
    )

    with pytest.raises(ValueError, match="Cannot import type"):
        resp.as_struct()
