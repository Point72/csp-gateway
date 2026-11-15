import hashlib
from datetime import UTC, datetime, timedelta
from enum import IntEnum

import numpy as np
import orjson
import pytest
from csp.typing import Numpy1DArray

from csp_gateway import GatewayStruct, KafkaConfiguration, ReadWriteKafka

_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_COUNT = 100_000


class _Status(IntEnum):
    READY = 1


class _Flat(GatewayStruct):
    x: int = 1
    price: float = 1.5
    label: str = "record"
    active: bool = True


class _Nested(_Flat):
    child: _Flat
    values: list[float]
    labels: dict[str, str]


class _Enums(_Flat):
    status: _Status = _Status.READY
    delay: timedelta = timedelta(seconds=3)


class _Array(_Flat):
    values: Numpy1DArray[float]


@pytest.mark.parametrize("shape", ["flat", "nested", "enums", "array", "list"])
@pytest.mark.benchmark(group="kafka-100k-records")
def test_kafka_publish_serialization(benchmark, shape):
    common = {"id": "record-1", "timestamp": _NOW}
    if shape == "nested":
        record = _Nested(**common, child=_Flat(**common), values=[1.0, 2.0, 3.0], labels={"a": "alpha", "b": "beta"})
    elif shape == "enums":
        record = _Enums(**common)
    elif shape == "array":
        record = _Array(**common, values=np.array([1.0, 2.0, 3.0]))
    else:
        record = _Flat(**common)
    value = [record, record] if shape == "list" else record
    serializer = ReadWriteKafka(config=KafkaConfiguration(broker="unused"))

    def serialize_records():
        return [serializer.serialize(value) for _ in range(_COUNT)]

    output = benchmark.pedantic(serialize_records, rounds=3, iterations=1)
    assert len(output) == _COUNT
    assert all(encoded == output[0] for encoded in output)
    decoded = orjson.loads(output[0])
    row = decoded[0] if shape == "list" else decoded
    assert row["x"] == 1
    assert row["timestamp"] == "2026-01-01T00:00:00+00:00"
    if shape == "enums":
        assert row["status"] == "READY"
        assert row["delay"] == 3.0
    if shape == "array":
        assert row["values"] == [1.0, 2.0, 3.0]
    benchmark.extra_info.update(records=_COUNT, sha256=hashlib.sha256("\n".join(output).encode()).hexdigest())
