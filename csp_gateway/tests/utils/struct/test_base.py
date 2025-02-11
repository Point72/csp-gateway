import numpy as np
import orjson
import pytest
import time
from csp import Enum, Struct
from csp.typing import Numpy1DArray
from datetime import date, datetime, timezone
from pydantic import BaseModel, ValidationError, field_validator, BeforeValidator, Field, ValidatorFunctionWrapHandler, WrapValidator
from typing import Annotated, Any, Dict, List, Union

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
    price: float
    quantity: int
    filled: float = 0  # Note that default is an int
    settlement_date: date
    notes: str = ""
    algo_params: dict

    @classmethod
    def __get_validator_dict__(cls):
        return {"_validate_example": field_validator("price", mode="after")(nonnegative_check)}


class SimpleOrderChild(SimpleOrder):
    new_field: float

    @classmethod
    def __get_validator_dict__(cls):
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


def test_pydantic_csp_function_naming():
    assert GatewayStruct.to_pydantic.__name__ == "to_pydantic"
    assert GatewayStruct.__pydantic_model__.csp.__name__ == "csp"


def test_pydantic_construction_from_gateway_struct():
    now = datetime.utcnow()
    o = SimpleOrder(
        timestamp=now,
        symbol="foo",
        quantity=100,
        filled=0.5,
        settlement_date=now.date(),
        algo_params={"a": 0, "b": "x"},
    )
    o_pydantic = o.to_pydantic()
    assert "_private" not in o_pydantic.model_fields
    assert o_pydantic.id
    assert o_pydantic.timestamp == o.timestamp
    assert o_pydantic.symbol == o.symbol
    assert o_pydantic.symbology == o.symbology
    assert o_pydantic.price is None  # Not set on struct
    assert o_pydantic.quantity == o.quantity
    assert o_pydantic.filled == o.filled
    assert o_pydantic.settlement_date == o.settlement_date
    assert o_pydantic.notes == ""
    assert o_pydantic.algo_params == {"a": 0, "b": "x"}

    output = '{{"id": "{}", "timestamp": "{}", "symbol": "foo", "price": null, "quantity": 100, "filled": 0.5, "settlement_date": "{}", "algo_params": {{"a": 0, "b": "x"}}, "symbology": "ID", "notes": ""}}'.format(  # noqa: E501
        o.id,
        now.isoformat().replace("+00:00", ""),
        now.date(),
    )
    assert orjson.loads(o_pydantic.model_dump_json()) == orjson.loads(output)


def test_gateway_struct_construction_from_pydantic():
    now = datetime.utcnow()
    o = SimpleOrder(
        timestamp=now,
        symbol="foo",
        quantity=100,
        settlement_date=now.date(),
        algo_params={"a": 0, "b": "x"},
    )
    o_pydantic = o.to_pydantic()
    o2 = o_pydantic.csp()
    assert o == o2


def test_pydantic_validation():
    now = datetime.utcnow()
    o = SimpleOrder(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date())
    o_pydantic = o.to_pydantic()
    o_pydantic_validated = SimpleOrder.__pydantic_model__.model_validate(o)
    assert o_pydantic_validated == o_pydantic

    o.price = -0.5
    with pytest.raises(ValidationError):
        o.to_pydantic()

    o = SimpleOrderChild(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date(), new_field=-0.5)
    with pytest.raises(ValidationError):
        o.to_pydantic()


def test_pydantic_validation_skip_private_fields():
    now = datetime.utcnow()
    o = SimpleOrder(
        timestamp=now,
        symbol="foo",
        quantity=100,
        settlement_date=now.date(),
        _private="hello",
    )
    assert o._private == "hello"
    o_pydantic = o.to_pydantic()
    assert "_private" not in o_pydantic.model_fields

    o_pydantic._private = "hi"
    assert "_private" not in o_pydantic.model_fields


def test_recursive_pydantic_construction_from_gateway_struct():
    now = datetime.utcnow()
    o = SimpleOrder(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date())
    o2 = SimpleOrder(timestamp=now, symbol="bar", quantity=200, settlement_date=now.date())

    m = MyCompositeStruct(order=o, order_list=[o, o2], order_dict={"foo": o, "bar": o2}, csp_struct=MyCspStruct())
    m_pydantic = m.to_pydantic()
    assert isinstance(m_pydantic, BaseModel)
    assert m_pydantic.order == o.to_pydantic()
    assert m_pydantic.order_list == [o.to_pydantic(), o2.to_pydantic()]
    assert m_pydantic.order_dict == {"foo": o.to_pydantic(), "bar": o2.to_pydantic()}
    assert isinstance(m_pydantic.csp_struct, BaseModel)
    assert m_pydantic.csp_struct == m.csp_struct.to_pydantic()
    assert m_pydantic.model_dump_json()


def test_recursive_gateway_struct_construction_from_pydantic():
    now = datetime.utcnow()
    o = SimpleOrder(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date())
    o2 = SimpleOrder(timestamp=now, symbol="bar", quantity=200, settlement_date=now.date())

    m = MyCompositeStruct(order=o, order_list=[o, o2], order_dict={"foo": o, "bar": o2}, csp_struct=MyCspStruct())
    m_pydantic = m.to_pydantic()
    assert m_pydantic.csp() == m


@pytest.mark.parametrize("raw", [True, False])
def test_gateway_struct_with_csp_struct_from_pydantic(raw):
    now = datetime.utcnow()
    o = MyStruct(timestamp=now, my_csp_struct=MyCspStruct(a=12))
    o_pydantic = o.to_pydantic()
    assert o_pydantic.csp() == o

    o_json = o_pydantic.model_dump_json()
    if raw:
        o_pydantic_from_json = MyStruct.__pydantic_model__.model_validate_json(o_json)
    else:
        o_dict = orjson.loads(o_json)
        o_pydantic_from_json = MyStruct.__pydantic_model__.model_validate(o_dict)
    assert o_pydantic_from_json.csp() == o


@pytest.mark.parametrize("raw", [True, False])
def test_gateway_struct_with_composite_csp_struct_from_pydantic(raw):
    now = datetime.utcnow()
    now = datetime.utcnow()
    o = SimpleOrder(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date(), price=100)
    o2 = SimpleOrder(timestamp=now, symbol="bar", quantity=200, settlement_date=now.date(), price=200)

    m = MyCompositeStruct(timestamp=now, order=o, order_list=[o, o2], order_dict={"foo": o, "bar": o2})
    m_pydantic = m.to_pydantic()
    assert m_pydantic.csp() == m

    m_json = m_pydantic.model_dump_json()
    if raw:
        m_pydantic_from_json = MyCompositeStruct.__pydantic_model__.model_validate_json(m_json)
    else:
        m_dict = orjson.loads(m_json)
        m_pydantic_from_json = MyCompositeStruct.__pydantic_model__.model_validate(m_dict)
    assert m_pydantic_from_json.csp() == m


def test_pydantic_model_default_not_csp():
    pydantic_model_class = MyStruct.__pydantic_model__
    pydantic_model = pydantic_model_class()
    # MyCspStruct has a `__pydantic_model__` attribute
    # which was added when processing creating the
    # pydantic model for MyStruct, which is a subclass
    # of GatewayStruct
    struct_pydantic_type = MyCspStruct.__pydantic_model__
    assert isinstance(pydantic_model.my_csp_struct, struct_pydantic_type)


def test_recursive_inheritance_construction():
    assert issubclass(SimpleOrderChild.__pydantic_model__, SimpleOrder.__pydantic_model__)

    now = datetime.now()
    o = SimpleOrderChild(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date())
    o2 = SimpleOrder(timestamp=now, symbol="bar", quantity=200, settlement_date=now.date())

    m = MyCompositeStruct(order=o, order_list=[o, o2], order_dict={"foo": o, "bar": o2})
    m_pydantic = m.to_pydantic()
    assert m_pydantic.order == o.to_pydantic()
    assert m_pydantic.order_list == [o.to_pydantic(), o2.to_pydantic()]
    assert m_pydantic.order_dict == {"foo": o.to_pydantic(), "bar": o2.to_pydantic()}
    assert m_pydantic.csp() == m


def test_exclude_id():
    now = datetime.now()
    o = SimpleOrderChild(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date())
    # Since we exclude id from the set, the GatewayStruct automatically
    # consructs a new one on initialization
    o_from_pydantic = o.to_pydantic().csp(exclude=set(["id"]))
    assert o_from_pydantic.id != o.id


def test_exclude_id_timestamp_recursive():
    now = datetime.now()
    o = SimpleOrderChild(timestamp=now, symbol="foo", quantity=100, settlement_date=now.date())
    o2 = SimpleOrder(timestamp=now, symbol="bar", quantity=200, settlement_date=now.date())

    m = MyCompositeStruct(order=o, order_list=[o, o2])
    time.sleep(0.001)
    m_from_pydantic = m.to_pydantic().csp(exclude=set(["id", "timestamp"]))
    assert m_from_pydantic.id != m.id
    assert m_from_pydantic.order.id != o.id
    assert m_from_pydantic.order_list[0].id != o.id
    assert m_from_pydantic.order_list[1].id != o2.id

    assert m_from_pydantic.timestamp != m.timestamp
    assert m_from_pydantic.order.timestamp != o.timestamp
    assert m_from_pydantic.order_list[0].timestamp != o.timestamp
    assert m_from_pydantic.order_list[1].timestamp != o2.timestamp


def test_exclude_skips_base_csp_struct():
    my_csp_struct = MyCspStruct(id="bar")
    m = MyStruct(id="foo", my_csp_struct=my_csp_struct)

    m_from_pydantic = m.to_pydantic().csp(exclude=set(["id"]))
    assert m_from_pydantic.id != "foo"
    assert m_from_pydantic.my_csp_struct.id == "bar"


def test_union_list():
    # For Union[List[Model], Model] to work, we need to make sure that a list with a single invalid model
    # doesn't get coerced to an empty model, which happens due to a weird interplay between how unions are validated
    # and Models that have all default attributes
    OrderModel = SimpleOrder.__pydantic_model__
    o_r = OrderModel.model_validate({})
    assert isinstance(o_r, OrderModel)

    with pytest.raises(ValueError):
        OrderModel.model_validate([{}])

    class UnionModel(BaseModel):
        model: Union[List[OrderModel], OrderModel]

    model = UnionModel.model_validate({"model": {}})
    assert isinstance(model.model, OrderModel)

    model = UnionModel.model_validate({"model": [{}]})
    assert isinstance(model.model, list)

    with pytest.raises(ValidationError):
        UnionModel.model_validate({"model": [{"foo": "bar"}]})


def test_omit_structs_from_lookup():
    from csp_gateway.server.demo import ExampleData

    ExampleData.omit_from_lookup(True)
    d = ExampleData()
    assert ExampleData.lookup(d.id) is None

    ExampleData.omit_from_lookup(False)
    d = ExampleData()
    assert ExampleData.lookup(d.id) == d


def test_struct_with_validator():
    def validate_z(cls, v):
        return "yee" + v

    class MyValidatedStruct(Struct):
        z: str

        @classmethod
        def __get_validator_dict__(cls):
            return {"validate_z": field_validator("z", mode="after")(validate_z)}

    class MyValidatedGatewayStruct(GatewayStruct):
        my_valid_struct: MyValidatedStruct

    my_struct = MyValidatedGatewayStruct(my_valid_struct=MyValidatedStruct(z="Haw"))
    assert my_struct.my_valid_struct.z == "Haw"

    my_pydantic_struct = my_struct.to_pydantic()
    my_validated_struct = my_pydantic_struct.csp()
    assert my_validated_struct.my_valid_struct.z == "yeeHaw"


def test_int_to_str_coercion():
    class SmallStruct(GatewayStruct):
        z: str

    my_model = SmallStruct.__pydantic_model__(z=12345)
    assert my_model.z == "12345"
    assert my_model.csp().z == "12345"


def test_gateway_struct_timestamp_serialization():
    target = '{"id":"","timestamp":"2020-01-01T00:00:00"}'
    g = GatewayStruct(id="", timestamp=datetime(2020, 1, 1))
    assert g.to_pydantic().model_dump_json() == target
    g = GatewayStruct(id="", timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert g.to_pydantic().model_dump_json() == target
    g = GatewayStruct(id="", timestamp=datetime.fromtimestamp(datetime(2020, 1, 1).timestamp()))
    assert g.to_pydantic().model_dump_json() == target

    # With timezone
    g = GatewayStruct(id="", timestamp=datetime.fromisoformat("2020-01-01T00:00:00+05:00"))
    target = '{"id":"","timestamp":"2019-12-31T19:00:00"}'
    assert g.to_pydantic().model_dump_json() == target


def test_annotated():
    pyd_struct = StructA.__pydantic_model__(z=dict(x=12), z_annotated=13)
    assert pyd_struct.csp().z == pyd_struct.z
    # validation occurs
    assert pyd_struct.csp().z_annotated == MyPydanticModel(x=13)
    # Default
    assert not hasattr(pyd_struct.csp(), "z_annotated_field")

    pyd_struct = StructA.__pydantic_model__(z=dict(x=12), z_annotated=13, z_annotated_field=dict(x="BAD"))
    # wrap validator catches error
    assert not hasattr(pyd_struct.csp(), "z_annotated_field")

    pyd_struct = StructA.__pydantic_model__(z=dict(x=12), z_annotated=13, z_annotated_field=dict(x=15))
    # wrap validator catches error
    assert pyd_struct.csp().z_annotated_field == MyPydanticModel(x=15, y="VALIDATED")


def test_annotated_containers():
    # Test basic list validation
    pyd_struct = StructB.__pydantic_model__(
        list_field=[dict(x=1), dict(x=2)],
        dict_field={"a": dict(x=1)},
        list_annotated=12,  # Will be transformed to [MyPydanticModel(x=12)]
        dict_annotated=13,  # Will be transformed to {"key": MyPydanticModel(x=13)}
    )

    # Verify list transformations
    assert len(pyd_struct.csp().list_annotated) == 1
    assert pyd_struct.csp().list_annotated[0].x == 12

    # Verify dict transformations
    assert "key" in pyd_struct.csp().dict_annotated
    assert pyd_struct.csp().dict_annotated["key"].x == 13

    # Test wrapped validators with good data
    pyd_struct = StructB.__pydantic_model__(
        list_field=[dict(x=1)],
        dict_field={"a": dict(x=1)},
        list_annotated=[1],
        dict_annotated={"b": 2},
        list_annotated_wrapped=[dict(x=15)],
        dict_annotated_wrapped={"c": dict(x=16)},
    )

    # Verify wrapped validators modified the data
    assert pyd_struct.csp().list_annotated_wrapped[0].y == "VALIDATED_LIST"
    assert pyd_struct.csp().dict_annotated_wrapped["c"].y == "VALIDATED_DICT"

    # Test wrapped validators with bad data
    pyd_struct = StructB.__pydantic_model__(
        list_field=[dict(x=1)],
        dict_field={"a": dict(x=1)},
        list_annotated=[1],
        dict_annotated={"b": 2},
        list_annotated_wrapped=[dict(x="BAD")],  # Should be caught by validator
        dict_annotated_wrapped={"c": dict(x="BAD")},  # Should be caught by validator
    )

    # Verify invalid data was caught and fields were not set
    assert not hasattr(pyd_struct.csp(), "list_annotated_wrapped")
    assert not hasattr(pyd_struct.csp(), "dict_annotated_wrapped")


def test_annotated_nested():
    # Define our test struct with nested models
    class StructWithNested(GatewayStruct):
        # Regular nested model
        regular: OuterPydanticModel
        # Annotated with before validator
        converted: Annotated[OuterPydanticModel, BeforeValidator(before_validator, json_schema_input_type=OuterPydanticModel)]
        validated: Annotated[OuterPydanticModel, Field(default=None, description="test nested validation"), WrapValidator(wrap_validator)]

    # Test regular nested conversion
    pyd_struct = StructWithNested.__pydantic_model__(
        regular={"middle": {"inner": {"value": 42}, "name": "test"}},
        converted={"value": 13},  # Simple dict to be converted
    )

    # Verify regular nested structure
    assert pyd_struct.csp().regular.middle.inner.value == 42
    assert pyd_struct.csp().regular.middle.name == "test"

    # Verify before_validator conversion worked
    assert pyd_struct.csp().converted.middle.inner.value == 13
    assert pyd_struct.csp().converted.middle.name == "default"  # Uses default value
    assert not hasattr(pyd_struct.csp(), "validated")
    # Test wrap validator with invalid data
    pyd_struct = StructWithNested.__pydantic_model__(
        regular={"middle": 42},
        converted={"value": 13},
        validated={
            "middle": {
                "inner": {"value": "BAD"}  # This should fail validation
            }
        },
    )
    # Verify wrap validator caught the error and returned None
    assert not hasattr(pyd_struct.csp(), "validated")
    assert pyd_struct.regular.middle == MiddleNestedModel(inner=InnerNestedModel(value=42), name="converted_from_int")
    # Test wrap validator with valid data
    pyd_struct = StructWithNested.__pydantic_model__(
        regular={"middle": {"inner": {"value": 42}}}, converted={}, validated={"middle": {"inner": {"value": 15}}}
    )
    # Verify wrap validator processed valid data and modified description
    assert pyd_struct.csp().validated.middle.inner.value == 15
    # This works since BaseModel is not frozen, however, pydantic versions of GatewayStructs
    # are listed as frozen
    assert pyd_struct.csp().validated.middle.inner.description == "MIDDLE_VALIDATED"
    # Set from validator
    assert pyd_struct.csp().converted.middle.inner.value == 0


def test_annotated_nested_gateway_structs():
    # Define our test struct with nested GatewayStructs
    class StructWithNested(GatewayStruct):
        # Regular nested struct
        regular: OuterStruct
        # Annotated with before validator
        converted: Annotated[
            OuterStruct,
            BeforeValidator(before_validator_struct, json_schema_input_type=OuterStruct.__pydantic_model__),
        ]
        validated: Annotated[
            OuterStruct,
            Field(default=None, description="test nested validation"),
            WrapValidator(wrap_validator_struct),
        ]
        with_default: Annotated[
            InnerNestedStruct,
            Field(default=InnerNestedStruct(description="blank"), description="test nested validation"),
            WrapValidator(wrap_validator_struct),
        ]

    # Test regular nested conversion
    pyd_struct = StructWithNested.__pydantic_model__(
        regular={"middle": {"inner": {"value": 42}, "name": "test"}},
        converted={"value": 13},  # Simple dict to be converted,
        with_default={"value": 99},
    )

    # Verify regular nested structure
    assert pyd_struct.csp().regular.middle.inner.value == 42
    assert pyd_struct.csp().regular.middle.name == "test"
    assert isinstance(pyd_struct.csp().with_default, InnerNestedStruct)
    assert pyd_struct.csp().with_default.value == 99

    # Verify before_validator conversion worked
    assert pyd_struct.csp().converted.middle.inner.value == 13
    assert pyd_struct.csp().converted.middle.name == "default"  # Uses default value
    assert not hasattr(pyd_struct.csp(), "validated")
    # Test wrap validator with invalid data
    pyd_struct = StructWithNested.__pydantic_model__(
        regular={"middle": {"inner": {"value": 42}}},
        converted={"value": 13},
        validated={
            "middle": {
                "inner": {"value": "BAD"}  # This should fail validation
            }
        },
    )
    # Verify wrap validator caught the error and returned None
    assert not hasattr(pyd_struct.csp(), "validated")
    assert isinstance(pyd_struct.csp().with_default, InnerNestedStruct)
    assert pyd_struct.csp().with_default.description == "blank"
    # Test wrap validator with valid data
    pyd_struct = StructWithNested.__pydantic_model__(
        regular={"middle": {"inner": {"value": 42}}}, converted={"value": 13}, validated={"middle": {"inner": {"value": 15}}}
    )
    # Verify wrap validator processed valid data and modified description
    assert pyd_struct.csp().validated.middle.inner.value == 15
