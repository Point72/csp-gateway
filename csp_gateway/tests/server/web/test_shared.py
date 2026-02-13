import json
from typing import List

import pytest
import starlette.responses

from csp_gateway.server.demo import ExampleData
from csp_gateway.server.web import prepare_response
from csp_gateway.server.web.routes.shared import get_fully_qualified_type_name


def test_prepare_response():
    data = ExampleData()
    response = prepare_response(res=data, is_list_model=False, is_dict_basket=False, wrap_in_response=True)
    assert isinstance(response, starlette.responses.Response)
    response = prepare_response(res=data, is_list_model=False, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]


def test_prepare_response_list():
    data = ExampleData()
    response = prepare_response(res=[data], is_list_model=False, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]
    response = prepare_response(res=[data], is_list_model=True, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]
    response = prepare_response(res=(data,), is_list_model=True, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]


def test_prepare_response_dict():
    data = ExampleData()
    with pytest.raises(AttributeError):
        prepare_response(res={"foo": data}, is_list_model=False, is_dict_basket=False, wrap_in_response=False)

    response = prepare_response(res={"foo": data}, is_list_model=False, is_dict_basket=True, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.type_adapter().dump_json(data))]


def test_get_fully_qualified_type_name_with_model():
    """Test that get_fully_qualified_type_name returns the correct fully qualified type name."""
    fq_name = get_fully_qualified_type_name(ExampleData)
    assert fq_name == "csp_gateway.server.demo.omnibus.ExampleData"


def test_get_fully_qualified_type_name_with_list_model():
    """Test that get_fully_qualified_type_name extracts the type from a List."""
    fq_name = get_fully_qualified_type_name(List[ExampleData])
    assert fq_name == "csp_gateway.server.demo.omnibus.ExampleData"


def test_get_fully_qualified_type_name_with_none():
    """Test that get_fully_qualified_type_name returns empty string for None."""
    fq_name = get_fully_qualified_type_name(None)
    assert fq_name == ""
