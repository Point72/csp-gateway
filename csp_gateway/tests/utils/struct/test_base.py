import decimal
from datetime import date, datetime, timezone
from typing import Annotated, Any, Dict, List

import numpy as np
import pytest
from csp import Enum, Struct
from csp.typing import Numpy1DArray
from pydantic import BaseModel, BeforeValidator, Field, TypeAdapter, ValidationError, ValidatorFunctionWrapHandler, WrapValidator, field_validator

from csp_gateway import GatewayStruct


def nonnegative_check(cls, v):
    if v < 0:
        raise ValueError("value must be non-negative.")
    return v


class Symbology(Enum):
    ID = Enum.auto()


class SimpleOrder(GatewayStruct):
    _private: str
    symbol: str
    symbology: Symbology = Symbology.ID
    price: Annotated[float, Field(gt=0)]  # Note: yes we know prices can be negative, this is a test
    quantity: int
    filled: float = 0  # Note that default is an int
    settlement_date: date
    notes: str = ""
    algo_params: dict

    @classmethod
    def __get_validator_dict__(cls):
        # same as annotation
        return {"_validate_example": field_validator("price", mode="after")(nonnegative_check)}


class SimpleOrderChild(SimpleOrder):
    new_field: Annotated[float, Field(gt=0)]

    @classmethod
    def __get_validator_dict__(cls):
        # same as annotation
        return {"_validate_example": field_validator("new_field", mode="after")(nonnegative_check)}


class MyCspStruct(Struct):
    a: int
    csp_np_array: Numpy1DArray[float] = np.array([13.0]).view(Numpy1DArray)
    id: str


class MyCompositeStruct(GatewayStruct):
    order: SimpleOrder
    order_list: List[SimpleOrder]
    order_dict: Dict[str, SimpleOrder]
    csp_struct: MyCspStruct


class MyStruct(GatewayStruct):
    foo: float
    fav_num: int = 68
    my_np_array: Numpy1DArray[float] = np.array([6.0]).view(Numpy1DArray)
    my_csp_struct: MyCspStruct = MyCspStruct(a=9)


# For annotated testing
class MyPydanticModel(BaseModel):
    x: int
    y: str = ""


def wrap_validator(val: Any, handler: ValidatorFunctionWrapHandler):
    try:
        res = handler(val)
    except ValidationError:
        return None
    res.y = "VALIDATED"
    return res


class StructA(GatewayStruct):
    z: MyPydanticModel
    z_annotated: Annotated[MyPydanticModel, BeforeValidator(lambda v: MyPydanticModel(x=v), json_schema_input_type=MyPydanticModel)]
    z_annotated_field: Annotated[MyPydanticModel, Field(default=None, description="test"), WrapValidator(wrap_validator)]


# Define validators that work with containers
def wrap_validator_list(val: Any, handler: ValidatorFunctionWrapHandler):
    try:
        res = handler(val)
        # Modify each item in the list after validation
        for item in res:
            item.y = "VALIDATED_LIST"
        return res
    except ValidationError:
        return None


def wrap_validator_dict(val: Any, handler: ValidatorFunctionWrapHandler):
    try:
        res = handler(val)
        # Modify each value in the dict after validation
        for k in res:
            res[k].y = "VALIDATED_DICT"
        return res
    except ValidationError:
        return None


# Transform a number into a list of MyPydanticModel
def list_transformer(v: Any) -> List[MyPydanticModel]:
    if isinstance(v, int):
        return [MyPydanticModel(x=v)]
    return [MyPydanticModel(x=x) for x in v]


# Transform a number into a dict of MyPydanticModel
def dict_transformer(v: Any) -> Dict[str, MyPydanticModel]:
    if isinstance(v, int):
        return {"key": MyPydanticModel(x=v)}
    return {k: MyPydanticModel(x=v[k]) for k in v}


class StructB(GatewayStruct):
    # Test List annotations
    list_field: List[MyPydanticModel]
    list_annotated: Annotated[List[MyPydanticModel], BeforeValidator(list_transformer)]
    list_annotated_wrapped: Annotated[
        List[MyPydanticModel],
        Field(default=None),
        WrapValidator(wrap_validator_list),
    ]
    # Test Dict annotations
    dict_field: Dict[str, MyPydanticModel]
    dict_annotated: Annotated[Dict[str, MyPydanticModel], BeforeValidator(dict_transformer)]
    dict_annotated_wrapped: Annotated[Dict[str, MyPydanticModel], Field(default=None), WrapValidator(wrap_validator_dict)]


class InnerNestedModel(BaseModel):
    value: int
    description: str = ""


class MiddleNestedModel(BaseModel):
    inner: InnerNestedModel
    name: str = "default"


# Validator for the middle field
def middle_validator(val: Any, handler: ValidatorFunctionWrapHandler):
    try:
        # If we get a simple dict with just inner value, expand it
        if isinstance(val, dict) and "value" in val:
            val = {"inner": val, "name": "validated_middle"}
        res = handler(val)
        # Add validation marker
        res.inner.description = "MIDDLE_VALIDATED"
        return res
    except ValidationError:
        # Convert simple integer to full middle structure
        if isinstance(val, int):
            return MiddleNestedModel(inner=InnerNestedModel(value=val), name="converted_from_int")
        raise  # Re-raise if we can't handle the error


# Modified outer model with annotated middle field
class OuterPydanticModel(BaseModel):
    # Add validation to middle field using Annotated
    middle: Annotated[MiddleNestedModel, WrapValidator(middle_validator)]
    tags: Dict[str, str] = {}


# Create validators
def wrap_validator(val: Any, handler: ValidatorFunctionWrapHandler):
    try:
        res = handler(val)
    except ValidationError:
        return None
    return res


def before_validator(v: Any) -> OuterPydanticModel:
    # Convert simple dict to full nested structure
    if isinstance(v, dict):
        return OuterPydanticModel(middle=MiddleNestedModel(inner=InnerNestedModel(value=v.get("value", 0))))
    return v


# First create nested GatewayStruct structure
class InnerNestedStruct(GatewayStruct):
    # GatewayStruct fields
    value: int
    description: str = ""  # Default values work the same way


class MiddleNestedStruct(GatewayStruct):
    # Nested GatewayStruct
    inner: InnerNestedStruct
    name: str = "default"


class OuterStruct(GatewayStruct):
    # Top level struct with nested GatewayStruct
    middle: MiddleNestedStruct
    tags: Dict[str, str] = {}


# Create validators that work with pydantic models (since GatewayStruct.to_pydantic() converts to pydantic)
def wrap_validator_struct(val: Any, handler: ValidatorFunctionWrapHandler):
    try:
        res = handler(val)
    except ValidationError:
        return None
    return res


def before_validator_struct(v: Any) -> Any:
    # Convert simple dict to full nested structure
    # Note: The validator works with the pydantic version
    if isinstance(v, dict):
        return OuterStruct(middle=MiddleNestedStruct(inner=InnerNestedStruct(value=v.get("value", 0)))).to_pydantic()
    return v


def test_exclude_id():
    now = datetime.now()
    o = SimpleOrderChild(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date())
    # Since we exclude id from the set, the GatewayStruct automatically
    # consructs a new one on initialization
    o2 = SimpleOrderChild.type_adapter().validate_python(o.to_dict(), context=dict(force_new_id=True))
    assert o2.id != o.id


def test_exclude_id_timestamp_recursive():
    now = datetime.now()
    o = SimpleOrderChild(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date())
    o2 = SimpleOrder(timestamp=now, symbol="bar", quantity=200, settlement_date=now.date())

    m = MyCompositeStruct(order=o, order_list=[o, o2])
    m2 = MyCompositeStruct.type_adapter().validate_python(m.to_dict(), context=dict(force_new_timestamp=True, force_new_id=True))
    assert m2.id != m.id
    assert m2.order.id != o.id
    assert m2.order_list[0].id != o.id
    assert m2.order_list[1].id != o2.id

    assert m2.timestamp != m.timestamp
    assert m2.order.timestamp != o.timestamp
    assert m2.order_list[0].timestamp != o.timestamp
    assert m2.order_list[1].timestamp != o2.timestamp


def test_omit_structs_from_lookup():
    from csp_gateway.server.demo import ExampleData

    ExampleData.omit_from_lookup(True)
    d = ExampleData()
    assert ExampleData.lookup(d.id) is None

    ExampleData.omit_from_lookup(False)
    d = ExampleData()
    assert ExampleData.lookup(d.id) == d


def test_int_to_str_coercion():
    class SmallStruct(GatewayStruct):
        z: str

    my_model = SmallStruct.type_adapter().validate_python(dict(z=12345))
    assert my_model.z == "12345"


def test_gateway_struct_timestamp_serialization():
    target = '{"id":"","timestamp":"2020-01-01T00:00:00"}'
    g = GatewayStruct(id="", timestamp=datetime(2020, 1, 1))
    assert GatewayStruct.type_adapter().dump_json(g).decode("utf-8") == target

    g = GatewayStruct(id="", timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert GatewayStruct.type_adapter().dump_json(g).decode("utf-8") == target
    g = GatewayStruct(id="", timestamp=datetime.fromtimestamp(datetime(2020, 1, 1).timestamp()))
    assert GatewayStruct.type_adapter().dump_json(g).decode("utf-8") == target

    # With timezone
    g = GatewayStruct(id="", timestamp=datetime.fromisoformat("2020-01-01T00:00:00+05:00"))
    target = '{"id":"","timestamp":"2019-12-31T19:00:00"}'
    assert GatewayStruct.type_adapter().dump_json(g).decode("utf-8") == target


def test_number_to_string_coercion_extended():
    """Test various number types being coerced to strings in GatewayStruct"""

    class StringFieldStruct(GatewayStruct):
        int_field: str
        float_field: str
        scientific_field: str

    adapter = TypeAdapter(StringFieldStruct)

    # Test python dict validation
    struct = adapter.validate_python({"int_field": 42, "float_field": 3.14, "scientific_field": 1.23e-4})

    assert struct.int_field == "42"
    assert isinstance(struct.int_field, str)

    assert struct.float_field == "3.14"
    assert isinstance(struct.float_field, str)

    assert struct.scientific_field == "0.000123"
    assert isinstance(struct.scientific_field, str)

    # Test JSON validation
    json_data = """
    {
        "int_field": 42,
        "float_field": 3.14,
        "scientific_field": 1.23e-4
    }
    """
    struct = adapter.validate_json(json_data)

    assert struct.int_field == "42"
    assert struct.float_field == "3.14"
    assert struct.scientific_field == "0.000123"

    # Test with decimal
    struct = adapter.validate_python({"float_field": (0.1 + 0.2), "scientific_field": decimal.Decimal("1.23e-4")})

    assert not hasattr(struct, "int_field")
    assert struct.float_field == "0.30000000000000004"  # floating point arithmetic lol
    assert struct.scientific_field == "0.000123"


def test_validate_gateway_struct_after():
    """Test the _validate_gateway_struct classmethod validation"""

    class ValidatedStruct(GatewayStruct):
        value: int
        name: str

        @classmethod
        def _validate_gateway_struct_after(cls, val):
            if val.value < 0:
                raise ValueError("value must be non-negative")
            if not val.name:
                raise ValueError("name cannot be empty")
            # Modify the value
            val.name = val.name.upper()
            return val

    adapter = TypeAdapter(ValidatedStruct)

    # Test valid case with python dict
    struct = adapter.validate_python({"value": 42, "name": "test"})

    assert struct.value == 42
    assert struct.name == "TEST"  # Name was uppercased by validation

    # Test valid case with JSON
    json_data = '{"value": 42, "name": "test"}'
    struct = adapter.validate_json(json_data)

    assert struct.value == 42
    assert struct.name == "TEST"

    # Test negative value
    with pytest.raises(ValueError, match="value must be non-negative"):
        adapter.validate_python({"value": -1, "name": "test"})

    # Test empty name
    with pytest.raises(ValueError, match="name cannot be empty"):
        adapter.validate_python({"value": 42, "name": ""})


def test_validate_gateway_struct_after_inheritance():
    """Test that _validate_gateway_struct works with inheritance"""

    class BaseStruct(GatewayStruct):
        value: int

        @classmethod
        def _validate_gateway_struct_after(cls, val):
            if val.value < 0:
                raise ValueError("value must be non-negative")
            return val

    class ChildStruct(BaseStruct):
        name: str

        @classmethod
        def _validate_gateway_struct_after(cls, val):
            # First call parent validation
            val = super()._validate_gateway_struct_after(val)
            # Then do our own validation
            if not val.name:
                raise ValueError("name cannot be empty")
            val.name = val.name.upper()
            return val

    class ChildStructNoNewValidator(BaseStruct):
        name: str

    adapter = TypeAdapter(ChildStruct)
    adapter_no_new_validator = TypeAdapter(ChildStructNoNewValidator)

    # Test valid case with python dict
    struct = adapter.validate_python({"value": 42, "name": "test"})

    assert struct.value == 42
    assert struct.name == "TEST"
    assert isinstance(struct.id, str)
    assert isinstance(struct.timestamp, datetime)

    struct = adapter_no_new_validator.validate_python({"value": 42, "name": "test"})

    assert struct.value == 42
    assert struct.name == "test"
    assert isinstance(struct.id, str)
    assert isinstance(struct.timestamp, datetime)

    # Test valid case with JSON
    json_data = '{"value": 42, "name": "test"}'
    struct = adapter.validate_json(json_data)

    assert struct.value == 42
    assert struct.name == "TEST"
    assert isinstance(struct.id, str)
    assert isinstance(struct.timestamp, datetime)

    struct = adapter_no_new_validator.validate_json(json_data)

    assert struct.value == 42
    assert struct.name == "test"
    assert isinstance(struct.id, str)
    assert isinstance(struct.timestamp, datetime)

    # Test parent validation
    with pytest.raises(ValueError, match="value must be non-negative"):
        adapter.validate_python({"value": -1, "name": "test"})

    with pytest.raises(ValueError, match="value must be non-negative"):
        adapter_no_new_validator.validate_python({"value": -1, "name": "test"})

    # Test child validation
    with pytest.raises(ValueError, match="name cannot be empty"):
        adapter.validate_python({"value": 42, "name": ""})

    # Fine since no custom validation
    adapter_no_new_validator.validate_python({"value": 42, "name": ""})
