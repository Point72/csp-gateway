import json
import pytest
import starlette.responses

from csp_gateway.server.demo import ExampleData
from csp_gateway.server.web import prepare_response


def test_prepare_response():
    data = ExampleData()
    response = prepare_response(res=data, is_list_model=False, is_dict_basket=False, wrap_in_response=True)
    assert isinstance(response, starlette.responses.Response)
    response = prepare_response(res=data, is_list_model=False, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.get_type_adapter().dump_json(data))]


def test_prepare_response_list():
    data = ExampleData()
    response = prepare_response(res=[data], is_list_model=False, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.get_type_adapter().dump_json(data))]
    response = prepare_response(res=[data], is_list_model=True, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.get_type_adapter().dump_json(data))]
    response = prepare_response(res=(data,), is_list_model=True, is_dict_basket=False, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.get_type_adapter().dump_json(data))]


def test_prepare_response_dict():
    data = ExampleData()
    with pytest.raises(AttributeError):
        prepare_response(res={"foo": data}, is_list_model=False, is_dict_basket=False, wrap_in_response=False)

    response = prepare_response(res={"foo": data}, is_list_model=False, is_dict_basket=True, wrap_in_response=False)
    assert json.loads(response) == [json.loads(data.get_type_adapter().dump_json(data))]
