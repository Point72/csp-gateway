"""OpenAPI for gateway responses must match their per-model serialization settings."""

import json
from enum import Enum

import jsonref
import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, Field, computed_field

from csp_gateway import GatewayStruct
from csp_gateway.server.web.routes.last import add_last_routes
from csp_gateway.server.web.routes.lookup import add_lookup_routes
from csp_gateway.server.web.routes.next import add_next_routes
from csp_gateway.server.web.routes.send import add_send_routes
from csp_gateway.server.web.routes.shared import prepare_response, response_model_for
from csp_gateway.server.web.routes.state import add_state_routes


@pytest.mark.parametrize("by_alias", [False, True])
@pytest.mark.parametrize("mount", [add_last_routes, add_lookup_routes, add_next_routes, add_send_routes, add_state_routes])
def test_route_output_schema_matches_json_aliases_and_enum_names(mount, by_alias):
    class Status(Enum):
        READY = 1
        DONE = 2

    class Child(GatewayStruct):
        model_config = ConfigDict(serialize_by_alias=not by_alias)
        note: str = Field(default="child", serialization_alias="comment")

    class Record(GatewayStruct):
        model_config = ConfigDict(serialize_by_alias=by_alias)
        note: str = Field(default="parent", validation_alias="input_note", serialization_alias="comment")
        child: Child = Field(default_factory=Child)
        status: Status = Status.READY

        @computed_field(alias="twice")
        @property
        def repeated(self) -> str:
            return self.note * 2

    app = FastAPI()
    router = APIRouter()
    mount(router, field="rows", model=Record)
    app.include_router(router)

    # The same model remains usable on an ordinary FastAPI route with alias serialization.
    @app.post("/normal", response_model=Record)
    def echo(record: Record):
        return record

    spec = jsonref.replace_refs(app.openapi())
    method = "post" if mount is add_send_routes else "get"
    path = next(path for path in spec["paths"] if path.startswith("/rows"))
    output = spec["paths"][path][method]["responses"]["200"]["content"]["application/json"]["schema"]["items"]
    record = Record()
    payload = json.loads(prepare_response([record], is_list_model=True).body)[0]
    assert set(output["properties"]) == set(payload)
    assert set(output["properties"]["child"]["properties"]) == set(payload["child"])
    assert output["properties"]["status"]["enum"] == ["READY", "DONE"]
    assert ("comment" in output["properties"]) is by_alias
    assert ("twice" in output["properties"]) is by_alias
    assert "comment" in spec["paths"]["/normal"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
    request = spec["paths"]["/normal"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert "input_note" in request["properties"]
    with TestClient(app) as client:
        response = client.post("/normal", json={"input_note": "kept", "status": "READY"})
        assert response.status_code == 200
        assert response.json()["comment"] == "kept"


def test_recursive_response_definitions_remain_separate_from_normal_models():
    class Record(BaseModel):
        note: str = Field(default="", serialization_alias="comment")
        children: list["Record"] = []

    app = FastAPI()

    @app.get("/gateway", response_model=response_model_for(list[Record]))
    def gateway():
        return prepare_response([Record(children=[Record(note="child")])], is_list_model=True)

    @app.get("/normal", response_model=list[Record])
    def normal():
        return [Record()]

    spec = jsonref.replace_refs(app.openapi())
    output = spec["paths"]["/gateway"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["items"]
    assert "note" in output["properties"]
    assert "note" in output["properties"]["children"]["items"]["properties"]
    assert "comment" in spec["paths"]["/normal"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["items"]["properties"]
    with TestClient(app) as client:
        assert client.get("/gateway").json() == [{"note": "", "children": [{"note": "child", "children": []}]}]


def test_response_schema_preserves_defaults_and_original_model_schema():
    from pydantic import TypeAdapter

    class Record(BaseModel):
        type: str = "example"
        ref: str = Field(default="record", serialization_alias="reference")
        metadata: str = Field(default="data", serialization_alias="meta")
        config: str = Field(default="settings", serialization_alias="cfg")
        data: dict = {"type": "definition-ref", "schema_ref": "literal-value", "ref": "another-literal"}

    original = Record.model_json_schema(mode="serialization")
    output = TypeAdapter(response_model_for(Record)).json_schema(mode="serialization")
    assert set(output["properties"]) == {"type", "ref", "metadata", "config", "data"}
    assert output["properties"]["data"]["default"] == Record().data
    assert Record.model_json_schema(mode="serialization") == original
