from datetime import datetime, timedelta, timezone

import csp
import numpy as np
import orjson
from csp import ts

from csp_gateway import Gateway, GatewayChannels, GatewayModule, GatewayStruct
from csp_gateway.server import JSONPullAdapter
from csp_gateway.server.gateway.csp.channels import _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD
from csp_gateway.testing.harness import GatewayTestHarness
from csp_gateway.testing.shared_helpful_classes import MyEnum


class GWC(GatewayChannels):
    test_json: ts[dict] = None


class MyTestJSONGatewayModule(GatewayModule):
    filename: str

    def connect(self, channels: GWC):
        json_pull_adapter = JSONPullAdapter(self.filename)
        channels.set_channel(GWC.test_json, json_pull_adapter)


def _assert_equal(exp):
    def func(x):
        assert x == exp

    return func


def _write_to_jsonl(list_of_dicts, file):
    with open(file, "w") as test_file:
        for val in list_of_dicts:
            json_str = orjson.dumps(val, option=orjson.OPT_NAIVE_UTC | orjson.OPT_SERIALIZE_NUMPY).decode()
            test_file.write(json_str)
            test_file.write("\n")


def test_json_reading(tmpdir):
    test_json_values = [
        {_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1)},
        {
            _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 8),
            "float": 7.0,
            "str": "\nabc",
        },
    ]
    file = str(tmpdir.join("test_json_reading.json"))
    _write_to_jsonl(test_json_values, file)

    h = GatewayTestHarness(test_channels=[GWC.test_json])
    first_tick_value = (
        datetime(2020, 1, 1),
        {_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()},
    )
    h.assert_ticked_values(GWC.test_json, _assert_equal([first_tick_value]))
    h.delay(timedelta(days=7))

    second_tick_value = (
        datetime(2020, 1, 8),
        {
            _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 8, tzinfo=timezone.utc).isoformat(),
            "float": 7.0,
            "str": "\nabc",
        },
    )
    h.assert_ticked_values(GWC.test_json, _assert_equal([first_tick_value, second_tick_value]))

    json_input_adapter_module = MyTestJSONGatewayModule(filename=file)
    gateway = Gateway(modules=[h, json_input_adapter_module], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1))


def test_first_entries_before_start(tmpdir):
    test_json_values = [
        {_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1)},
        {
            _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 2),
            "float": 7.0,
            "str": "\nabc",
        },
        {_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 3)},
    ]
    file = str(tmpdir.join("test_first_entries_before_start.json"))
    _write_to_jsonl(test_json_values, file)
    h = GatewayTestHarness(test_channels=[GWC.test_json])
    first_tick_value = (
        datetime(2020, 1, 3),
        {_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 3, tzinfo=timezone.utc).isoformat()},
    )
    h.assert_ticked_values(GWC.test_json, _assert_equal([first_tick_value]))
    json_input_adapter_module = MyTestJSONGatewayModule(filename=file)
    gateway = Gateway(modules=[h, json_input_adapter_module], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 3))


def test_first_tick_after_start(tmpdir):
    test_json_values = [
        {_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1)},
        {
            _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 2),
            "float": 7.0,
            "str": "\nabc",
        },
    ]

    file = str(tmpdir.join("test_first_tick_after_start.json"))
    _write_to_jsonl(test_json_values, file)

    h = GatewayTestHarness(test_channels=[GWC.test_json])
    h.assert_ticked(GWC.test_json, count=0)
    h.delay(timedelta(days=1))
    first_tick_value = (
        datetime(2020, 1, 1),
        {_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()},
    )

    h.assert_ticked_values(GWC.test_json, _assert_equal([first_tick_value]))

    second_tick_value = (
        datetime(2020, 1, 2),
        {
            _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 2, tzinfo=timezone.utc).isoformat(),
            "float": 7.0,
            "str": "\nabc",
        },
    )
    h.delay(timedelta(days=1))
    h.assert_ticked_values(GWC.test_json, _assert_equal([first_tick_value, second_tick_value]))

    json_input_adapter_module = MyTestJSONGatewayModule(filename=file)
    gateway = Gateway(modules=[h, json_input_adapter_module], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2019, 12, 31))


def test_same_timestamp(tmpdir):
    test_json_values = [
        {_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1)},
        {
            _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1),
            "test_outer": 7.0,
        },
    ]
    file = str(tmpdir.join("test_same_timestamp.json"))
    _write_to_jsonl(test_json_values, file)

    h = GatewayTestHarness(test_channels=[GWC.test_json])
    ticked_values = [
        (
            datetime(2020, 1, 1),
            {_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()},
        ),
        (
            datetime(2020, 1, 1),
            {
                _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(),
                "test_outer": 7.0,
            },
        ),
    ]
    h.assert_ticked_values(GWC.test_json, _assert_equal([ticked_values[0]]))
    h.delay(timedelta())
    h.assert_ticked_values(GWC.test_json, _assert_equal(ticked_values))
    json_input_adapter_module = MyTestJSONGatewayModule(filename=file)
    gateway = Gateway(modules=[h, json_input_adapter_module], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1))


def test_gateway_struct(tmpdir):
    # GatewayStructs when automatically encoded
    # call the `to_dict()` method for us
    test_json_values = [
        {
            _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1),
            "test_outer": GatewayStruct(id="9", timestamp=datetime(2020, 1, 1)).to_dict(),
        },
    ]
    file = str(tmpdir.join("test_gateway_struct.json"))
    _write_to_jsonl(test_json_values, file)

    h = GatewayTestHarness(test_channels=[GWC.test_json])
    ticked_values = [
        (
            datetime(2020, 1, 1),
            {
                _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(),
                "test_outer": {
                    "id": "9",
                    "timestamp": datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(),
                },
            },
        ),
    ]
    h.assert_ticked_values(GWC.test_json, _assert_equal(ticked_values))
    json_input_adapter_module = MyTestJSONGatewayModule(filename=file)
    gateway = Gateway(modules=[h, json_input_adapter_module], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1))


def test_enum(tmpdir):
    # Enums aren't JSON-serializable so we use their names instead
    test_json_values = [
        {
            _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1),
            "enum": MyEnum.ONE.name,
        },
    ]
    file = str(tmpdir.join("test_gateway_struct.json"))
    _write_to_jsonl(test_json_values, file)

    h = GatewayTestHarness(test_channels=[GWC.test_json])
    ticked_values = [
        (
            datetime(2020, 1, 1),
            {
                _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(),
                "enum": MyEnum.ONE.name,
            },
        ),
    ]
    h.assert_ticked_values(GWC.test_json, _assert_equal(ticked_values))
    json_input_adapter_module = MyTestJSONGatewayModule(filename=file)
    gateway = Gateway(modules=[h, json_input_adapter_module], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1))


def test_numpy_array(tmpdir):
    test_json_values = [
        {
            _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD: datetime(2020, 1, 1),
            "np_array": np.array([5.0, 7.0]),
        },
    ]
    file = str(tmpdir.join("test_gateway_struct.json"))
    _write_to_jsonl(test_json_values, file)

    h = GatewayTestHarness(test_channels=[GWC.test_json])

    def assert_numpy_equal(x):
        assert x[0][0] == datetime(2020, 1, 1)
        assert x[0][1][_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD] == datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
        assert np.array_equal(x[0][1]["np_array"], np.array([5.0, 7.0]))
        assert len(x) == 1
        assert len(x[0]) == 2
        assert len(x[0][1]) == 2

    h.assert_ticked_values(GWC.test_json, assert_numpy_equal)
    json_input_adapter_module = MyTestJSONGatewayModule(filename=file)
    gateway = Gateway(modules=[h, json_input_adapter_module], channels=GWC())
    csp.run(gateway.graph, starttime=datetime(2020, 1, 1))
