import json
from enum import Enum, IntEnum, StrEnum
from typing import Annotated, Any

import csp
import numpy as np
import pytest
from csp.typing import Numpy1DArray, NumpyNDArray
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, PlainSerializer, PrivateAttr, create_model, field_serializer, model_serializer

from csp_gateway import GatewayStruct
from csp_gateway.server.web.routes.shared import _dump_records


class Status(Enum):
    READY = 1
    DONE = 2


class IntegerStatus(IntEnum):
    READY = 1
    DONE = 2


class TextStatus(StrEnum):
    READY = "ready"
    DONE = "done"


class CspStatus(csp.Enum):
    READY = 1
    DONE = 2


@pytest.mark.parametrize("enum", [Status, IntegerStatus, TextStatus, CspStatus])
def test_enum_names_and_values_roundtrip(enum):
    model: Any = create_model("Record", __base__=GatewayStruct, status=(enum, ...), history=(list[enum], ...), mapping=(dict[enum, enum], ...))
    record = model(status=enum.READY, history=[enum.READY, enum.DONE], mapping={enum.READY: enum.DONE})
    encoded = json.loads(record.to_json())
    assert encoded["status"] == "READY"
    assert encoded["history"] == ["READY", "DONE"]
    assert encoded["mapping"] == {"READY": "DONE"}
    restored = model.model_validate_json(record.to_json())
    assert restored.status is enum.READY
    assert restored.history == [enum.READY, enum.DONE]
    assert restored.mapping == {enum.READY: enum.DONE}
    assert model(status=enum.READY.value).status is enum.READY
    assert record.model_dump()["status"] is enum.READY
    assert record.model_dump(mode="json")["status"] == "READY"
    assert model._dump_json_list([record]) is not None
    assert json.loads(_dump_records([record])) == [json.loads(record.model_dump_json())]


@pytest.mark.parametrize("enum", [Status, IntegerStatus, TextStatus, CspStatus])
@pytest.mark.parametrize("array_type", [Numpy1DArray, NumpyNDArray])
def test_enum_arrays_roundtrip(enum, array_type):
    model: Any = create_model("Record", __base__=GatewayStruct, statuses=(array_type[enum], ...))
    members = [enum.READY, enum.DONE] if array_type is Numpy1DArray else [[enum.READY], [enum.DONE]]
    record = model(statuses=np.array(members, dtype=object))
    expected = ["READY", "DONE"] if array_type is Numpy1DArray else [["READY"], ["DONE"]]
    assert json.loads(record.to_json())["statuses"] == expected
    restored = model.model_validate_json(record.to_json())
    assert restored.statuses.tolist() == members
    assert isinstance(record.model_dump()["statuses"], list)  # Existing CSP Python-mode behavior.
    assert json.loads(_dump_records([record]))[0]["statuses"] == expected


@pytest.mark.parametrize("enum", [Status, IntegerStatus, TextStatus, CspStatus])
@pytest.mark.parametrize("array_type", [Numpy1DArray, NumpyNDArray])
@pytest.mark.parametrize("storage", ["name", "value"])
def test_enum_arrays_serialize_names_from_numpy_scalar_storage(enum, array_type, storage):
    model: Any = create_model("Record", __base__=GatewayStruct, statuses=(array_type[enum], ...))
    values = [getattr(enum.READY, storage), getattr(enum.DONE, storage)]
    expected = ["READY", "DONE"]
    if array_type is NumpyNDArray:
        values = [values]
        expected = [expected]
    array = np.array(values)
    record = model(statuses=array)
    assert json.loads(record.to_json())["statuses"] == expected
    assert json.loads(_dump_records([record]))[0]["statuses"] == expected
    assert record.statuses.tolist() == values


def test_nested_inherited_recursive_and_optional_enums():
    class Node(GatewayStruct):
        status: Status | None = None
        children: list["Node"] = []

    class Child(Node):
        other: Status = Status.DONE

    node = Child(status=Status.READY, children=[Node(status=Status.DONE), Node()])
    encoded = json.loads(node.to_json())
    assert encoded["status"] == "READY"
    assert encoded["other"] == "DONE"
    assert [child["status"] for child in encoded["children"]] == ["DONE", None]
    assert Child.model_validate_json(node.to_json()).children[0].status is Status.DONE
    for _ in range(2):
        Child.model_rebuild(force=True)
        assert json.loads(node.to_json()) == encoded


def test_explicit_serializers_and_instance_preferences_win():
    class Record(GatewayStruct):
        annotated: Annotated[Status, PlainSerializer(lambda value: value.value, return_type=int)]
        decorated: Status
        _names: bool = PrivateAttr(default=False)

        @field_serializer("decorated")
        def serialize_status(self, value):
            return value.name if self._names else value.value

    record = Record(annotated=Status.READY, decorated=Status.DONE)
    assert json.loads(record.to_json())["annotated"] == 1
    assert json.loads(record.to_json())["decorated"] == 2
    record._names = True
    assert json.loads(record.to_json())["decorated"] == "DONE"


def test_explicit_array_and_model_serializers_win():
    class Record(GatewayStruct):
        statuses: Numpy1DArray[Status]

        @field_serializer("statuses")
        def serialize_statuses(self, values):
            return [value.value for value in values]

    class Custom(GatewayStruct):
        status: Status

        @model_serializer
        def serialize(self):
            return {"custom": self.status.value}

    assert json.loads(Record(statuses=np.array([Status.READY], dtype=object)).to_json())["statuses"] == [1]
    assert Custom(status=Status.READY).to_json() == '{"custom":1}'


def test_other_models_and_enum_schemas_are_not_mutated():
    class Plain(BaseModel):
        status: Status

    before = Plain.model_json_schema()

    class Record(GatewayStruct):
        status: Status
        plain: Plain

    assert json.loads(Record(status=Status.READY, plain=Plain(status=Status.DONE)).to_json())["plain"] == {"status": 2}
    assert Plain(status=Status.READY).model_dump_json() == '{"status":1}'
    assert Plain.model_json_schema() == before
    assert Record.model_json_schema(mode="serialization")["properties"]["status"]["anyOf"][0]["enum"] == ["READY", "DONE"]


def test_enum_defaults_missing_fields_and_aliases():
    class Aliased(Enum):
        READY = 1
        AVAILABLE = 1  # noqa: PIE796 - exercise an enum alias
        DONE = 2

    class Record(GatewayStruct):
        status: Aliased
        default: Aliased = Aliased.READY

    assert "status" not in json.loads(Record.model_validate({}).to_json())
    record = Record(status="AVAILABLE")
    assert json.loads(record.to_json())["status"] == "READY"
    assert json.loads(record.to_json())["default"] == "READY"


def test_existing_string_values_keep_precedence_over_ambiguous_names():
    class Ambiguous(Enum):
        FIRST = "SECOND"
        SECOND = "other"

    class Record(GatewayStruct):
        status: Ambiguous

    assert Record(status="SECOND").status is Ambiguous.FIRST


def test_http_accepts_names_and_values_and_documents_name_output():
    class Record(GatewayStruct):
        status: Status

    app = FastAPI()

    @app.post("/record", response_model=Record)
    def echo(record: Record):
        return record

    with TestClient(app) as client:
        for status in (1, "READY"):
            response = client.post("/record", json={"status": status})
            assert response.status_code == 200
            assert response.json()["status"] == "READY"
        assert client.post("/record", json={"status": "UNKNOWN"}).status_code == 422
        spec = client.get("/openapi.json").json()
        output = spec["paths"]["/record"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
        if "$ref" in output:
            output = spec["components"]["schemas"][output["$ref"].split("/")[-1]]
        assert output["properties"]["status"]["anyOf"][0]["enum"] == ["READY", "DONE"]
