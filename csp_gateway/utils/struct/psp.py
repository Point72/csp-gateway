import types
from collections.abc import Callable, Container, Iterable
from datetime import date, datetime
from enum import Enum as PyEnum
from itertools import accumulate
from logging import getLogger
from typing import Annotated, Any, NamedTuple, Optional, Union, get_args, get_origin

import numpy
import orjson
import pyarrow
from csp import Enum as CspEnum
from csp.impl.types.container_type_normalizer import ContainerTypeNormalizer
from csp.impl.types.typing_utils import CspTypingUtils
from numpy import ndarray
from pydantic import BaseModel
from typing_extensions import TypeAliasType

__all__ = (
    "ExcludedColumns",
    "PerspectiveUtilityMixin",
    "PspArrowEncoder",
    "PspField",
    "model_metadata",
    "psp_arrow_type",
    "psp_schema",
)

log = getLogger(__name__)


def _strip_annotated(annotation: Any) -> Any:
    """Drop ``Annotated`` wrappers, including inside an ``Optional``.

    ``GatewayStruct._relax_required_fields`` re-homes a field's constraints into ``Annotated`` so they
    survive being made nullable. Callers of ``model_metadata`` want the plain type -- perspective,
    duckdb and pyarrow all feed it straight into ``issubclass``.
    """
    while get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]
    args = get_args(annotation)
    if get_origin(annotation) in (Union, types.UnionType) and type(None) in args:
        inner = [_strip_annotated(arg) for arg in args if arg is not type(None)]
        if len(inner) == 1:
            return Optional[inner[0]]  # noqa: UP045 -- inner[0] is a runtime value
    return annotation


def model_metadata(cls, typed: bool = False) -> dict[str, Any]:
    """The field types of a pydantic model, in the shape csp's ``Struct.metadata`` returned.

    ``typed=True`` gives the declared annotation; ``typed=False`` normalizes it the way callers
    expect -- an optional collapses to its inner type, and a list reports as ``[element_type]``.
    """
    out: dict[str, Any] = {}
    for name, field in cls.model_fields.items():
        annotation = _strip_annotated(field.annotation)
        if typed:
            out[name] = annotation
            continue
        origin = get_origin(annotation)
        if origin is not None and type(None) in get_args(annotation):
            inner = [arg for arg in get_args(annotation) if arg is not type(None)]
            annotation = inner[0] if len(inner) == 1 else annotation
            origin = get_origin(annotation)
        if origin in (list, set, tuple):
            args = get_args(annotation)
            out[name] = [args[0]] if args else origin
        elif origin is not None:
            out[name] = origin
        else:
            out[name] = annotation
    return out


ExcludedColumns = TypeAliasType("ExcludedColumns", "set[str] | dict[str, bool | ExcludedColumns]")


def _is_excluded(field: str, excluded_columns: ExcludedColumns) -> bool | ExcludedColumns:
    if isinstance(excluded_columns, set):
        return field in excluded_columns

    return excluded_columns.get(field, False)


def _is_optional(t: type) -> bool:
    # Accept both typing.Optional[X]/typing.Union[X, None] and the PEP 604 ``X | None`` form.
    # The former have get_origin() is typing.Union; the latter is a types.UnionType.
    if get_origin(t) not in (Union, types.UnionType):
        return False
    args = list(get_args(t))
    return not (len(args) != 2 or type(None) not in args)


def _get_type_from_optional(t: type):
    args = list(get_args(t))
    args.remove(type(None))
    return args[0]


class PspField(NamedTuple):
    """How one field of a struct appears in Perspective, in place of the column its type would give.

    Returned by a struct type's ``psp_field_overrides``. The field becomes one Arrow column of
    ``arrow_type``, which Perspective flattens like any other: a struct type gives dotted columns, a
    list type is subject to the table's ``list_flatten``.

    ``convert`` gets the field's value as ``model_dump`` gives it, in python mode, so nested structs
    arrive as dicts, and only when that value is not None. It returns a value of ``arrow_type``, or
    None for a null cell. Without ``convert`` the dumped value is used as is.

    With ``raw``, ``convert`` gets the value as the attribute holds it instead: nested structs as
    struct instances, numpy fields as arrays. That skips a ``model_dump`` per record, which is most of
    what an override costs, and with it any pydantic serializer on the field. The value is the live
    object, so ``convert`` must not change it. The cell is still null wherever ``model_dump`` would
    leave the field out or None.
    """

    arrow_type: pyarrow.DataType
    convert: Callable[[Any], Any] | None = None
    raw: bool = False


class _Column(NamedTuple):
    """One field of a struct as Perspective sees it."""

    name: str
    #: The element type for a list field, otherwise the field type.
    py: type
    is_list: bool
    #: One of "scalar", "dict", "map", "enum", "text", "struct" or "override".
    kind: str
    #: Exclusions for the columns of a struct field.
    sub_excluded: ExcludedColumns | None
    #: The key and value types of a "map" field.
    map_types: tuple[type, type] | None = None
    #: The struct type's own encoding of an "override" field.
    override: PspField | None = None


def _scalar_arrow_type(py: Any) -> pyarrow.DataType | None:
    """The Arrow type of a plain scalar, or None if `py` is not one. Enums are not plain scalars."""
    if not isinstance(py, type) or issubclass(py, (PyEnum, CspEnum)):
        return None
    if issubclass(py, bool):
        return pyarrow.bool_()
    if issubclass(py, int):
        return pyarrow.int64()
    if issubclass(py, float):
        return pyarrow.float64()
    if issubclass(py, str):
        return pyarrow.string()
    if issubclass(py, datetime):
        return pyarrow.timestamp("us", tz="UTC")
    if issubclass(py, date):
        return pyarrow.date32()
    return None


def psp_arrow_type(annotation: Any) -> pyarrow.DataType | None:
    """The Arrow type the Perspective encoder gives a plain scalar or a list of them, or None for anything else.

    For building a `PspField` from Python types. ``Optional`` and ``Annotated`` wrappers are ignored;
    enums, dicts and structs are not plain scalars.
    """
    annotation = _strip_annotated(annotation)
    if _is_optional(annotation):
        annotation = _get_type_from_optional(annotation)
    if get_origin(annotation) is list:
        args = get_args(annotation)
        element = psp_arrow_type(args[0]) if args else None
        return None if element is None else pyarrow.list_(element)
    return _scalar_arrow_type(annotation)


def _is_text_union(annotation: Any) -> bool:
    """Whether `annotation` is a union of strings and enums, with or without None, which shows as one text column."""
    annotation = _strip_annotated(annotation)
    if get_origin(annotation) not in (Union, types.UnionType):
        return False
    members = [arg for arg in get_args(annotation) if arg is not type(None)]
    return len(members) > 1 and all(isinstance(arg, type) and issubclass(arg, (str, PyEnum, CspEnum)) for arg in members)


def _text(value: Any) -> str:
    """A text union's value as text: an enum by its name, a string as is."""
    return value.name if isinstance(value, (PyEnum, CspEnum)) else str(value)


def _map_types(annotation: Any) -> tuple[type, type] | None:
    """The key and value types of a dict annotation, if both are plain scalars."""
    if _is_optional(annotation):
        annotation = _get_type_from_optional(annotation)
    args = get_args(_strip_annotated(annotation))
    if len(args) == 2 and all(_scalar_arrow_type(arg) is not None for arg in args):
        return args
    return None


def _list_element_type(cls, name: str):
    """The element type of a list or ndarray field, read off the annotation, or `str` if there is none."""
    try:
        try:
            annotation = cls.__annotations__[name]
        except KeyError:
            annotation = None
            for base in cls.__mro__[1:]:
                anns = getattr(base, "__annotations__", {})
                if name in anns:
                    annotation = anns[name]
                    break
            if annotation is None:
                raise KeyError(name)
        annotation = _strip_annotated(annotation)
        if _is_optional(annotation):
            annotation = _get_type_from_optional(annotation)
        return get_args(annotation)[0]
    except (KeyError, IndexError):
        return str


def _columns(cls, excluded_columns: ExcludedColumns | None) -> list[_Column]:
    """The top level columns of a struct, in field order, after exclusions."""
    # Pydantic doesn't support fields that start with underscore
    schema = {k: v for k, v in model_metadata(cls, typed=False).items() if not k.startswith("_")}
    annotated = {k: v for k, v in model_metadata(cls, typed=True).items() if not k.startswith("_")}
    overrides_hook = getattr(cls, "psp_field_overrides", None)
    overrides = overrides_hook(excluded_columns) if overrides_hook is not None else {}
    out = []
    for name, value in schema.items():
        if name in overrides or _is_text_union(annotated[name]):
            # Partial exclusions of an overridden field are the struct type's to apply, in `psp_field_overrides`.
            if excluded_columns and _is_excluded(name, excluded_columns) is True:
                continue
            if name in overrides:
                out.append(_Column(name, object, False, "override", None, override=overrides[name]))
            else:
                out.append(_Column(name, str, False, "text", None))
            continue

        # Make sure its a type so `issubclass` calls don't fail
        if _is_optional(annotated[name]):
            value = ContainerTypeNormalizer.normalized_type_to_actual_python_type(_get_type_from_optional(annotated[name]))

        is_list = False
        if not isinstance(value, type):
            if not isinstance(value, list):
                log.warning(f"Type is not actually a type: {name} {value}")
                continue
            value, is_list = value[0], True

        if issubclass(value, (list, ndarray)):
            # will be unrolled into root type
            value, is_list = _list_element_type(cls, name), True
        if not isinstance(value, type):
            log.warning(f"Type is not actually a type: {name} {value}")
            continue

        excluded = excluded_columns and _is_excluded(name, excluded_columns)
        sub_excluded = None
        if excluded:
            if isinstance(excluded, bool) or not issubclass(value, BaseModel):
                continue
            sub_excluded = excluded

        map_types = None
        if issubclass(value, dict):
            # A dict of scalars is an Arrow map, which Perspective shows as JSON text. Any other dict is serialized here.
            map_types = None if is_list else _map_types(annotated[name])
            kind = "dict" if map_types is None else "map"
        elif issubclass(value, (PyEnum, CspEnum)):
            kind = "enum"
        elif issubclass(value, (str, int, float, bool, datetime, date)):
            kind = "scalar"
        elif issubclass(value, BaseModel):
            kind = "struct"
        else:
            log.warning(f"Type {value} on has no perspective conversion, ignoring in perspective tables: {cls.__name__}.{name}")
            continue
        out.append(_Column(name, value, is_list, kind, sub_excluded, map_types))
    return out


def _arrow_psp_schema(name: str, arrow_type: pyarrow.DataType, out: dict[str, type]) -> None:
    """The flattened perspective schema of one Arrow column, as `psp_schema` gives it for a field of that type."""
    if pyarrow.types.is_struct(arrow_type):
        for i in range(arrow_type.num_fields):
            field = arrow_type.field(i)
            _arrow_psp_schema(f"{name}.{field.name}", field.type, out)
    elif pyarrow.types.is_list(arrow_type) or pyarrow.types.is_large_list(arrow_type):
        _arrow_psp_schema(name, arrow_type.value_type, out)
    elif pyarrow.types.is_boolean(arrow_type):
        out[name] = bool
    elif pyarrow.types.is_integer(arrow_type):
        out[name] = int
    elif pyarrow.types.is_floating(arrow_type):
        out[name] = float
    elif pyarrow.types.is_timestamp(arrow_type):
        out[name] = datetime
    elif pyarrow.types.is_date(arrow_type):
        out[name] = date
    else:
        out[name] = str


def psp_schema(cls, excluded_columns: ExcludedColumns | None = None) -> dict[str, type]:
    """Returns the flattened perspective schema for a class.

    Structs become dotted column names, lists become their element type, enums, dicts, maps and unions of
    strings and enums become `str`, and fields the class overrides follow their `PspField.arrow_type`.

    Args:
        excluded_columns: Columns to exclude from the schema.
    """
    out: dict[str, type] = {}
    for column in _columns(cls, excluded_columns):
        if column.kind == "struct":
            for key, value in psp_schema(column.py, column.sub_excluded).items():
                out[f"{column.name}.{key}"] = value
        elif column.kind == "override":
            _arrow_psp_schema(column.name, column.override.arrow_type, out)
        elif column.kind in ("dict", "map", "enum", "text"):
            out[column.name] = str
        else:
            out[column.name] = column.py
    return out


def _json_str(value: Any) -> str:
    return orjson.dumps(value, default=str, option=orjson.OPT_NON_STR_KEYS).decode()


def _enum_name(enum_cls: type) -> Callable[[Any], str]:
    def convert(value):
        if isinstance(value, (PyEnum, CspEnum)):
            return value.name
        # csp enums subclass int, so a numpy object array of them can hand back the bare value.
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                return enum_cls(value).name
            except ValueError:
                log.warning(f"{value} is not a {enum_cls.__name__}, leaving it as is")
        return str(value)

    return convert


def _struct_fixer(fixers: dict[str, Callable[[Any], Any]]) -> Callable[[dict | None], dict | None]:
    def fix(row):
        if row is not None:
            for name, fn in fixers.items():
                value = row.get(name)
                if value is not None:
                    row[name] = fn(value)
        return row

    return fix


def _list_fixer(element: Callable[[Any], Any] | None) -> Callable[[Any], list]:
    def fix(value):
        if isinstance(value, ndarray):
            value = value.tolist()
        elif not isinstance(value, list):
            value = list(value)
        return [element(v) if v is not None else None for v in value] if element else value

    return fix


class _ArrowSpec(NamedTuple):
    #: The struct type the spec describes.
    cls: type
    columns: list[_Column]
    fields: list[pyarrow.Field]
    fixers: dict[str, Callable[[Any], Any]]
    #: The spec of each struct column, by column name.
    nested: dict[str, "_ArrowSpec"]
    #: The columns a JSON-only serializer applies to, which are read from a JSON-mode dump: see `_json_serialized`.
    json: frozenset[str] = frozenset()


def _arrow_spec(cls, excluded_columns: ExcludedColumns | None) -> _ArrowSpec:
    columns = _columns(cls, excluded_columns)
    spec = _ArrowSpec(cls, columns, [], {}, {}, _json_serialized(cls, columns))
    for column in spec.columns:
        fix = None
        if column.kind == "struct":
            sub = _arrow_spec(column.py, column.sub_excluded)
            spec.nested[column.name] = sub
            arrow_type = pyarrow.struct(sub.fields)
            fix = _struct_fixer(sub.fixers) if sub.fixers else None
        elif column.kind == "map":
            arrow_type = pyarrow.map_(*(_scalar_arrow_type(t) for t in column.map_types))
        elif column.kind == "dict":
            arrow_type, fix = pyarrow.string(), _json_str
        elif column.kind == "enum":
            arrow_type, fix = pyarrow.string(), _enum_name(column.py)
        elif column.kind == "text":
            arrow_type, fix = pyarrow.string(), _text
        elif column.kind == "override":
            # A raw override's `convert` takes the attribute, which a dumped row no longer has: see `_raw_filler`.
            arrow_type, fix = column.override.arrow_type, None if column.override.raw else column.override.convert
        else:
            arrow_type = _scalar_arrow_type(column.py)
        if column.is_list:
            arrow_type, fix = pyarrow.list_(arrow_type), _list_fixer(fix)
        spec.fields.append(pyarrow.field(column.name, arrow_type))
        if fix is not None:
            spec.fixers[column.name] = fix
    return spec


def _filler(spec: _ArrowSpec, own: Callable[[_ArrowSpec], Callable[[dict, Any], None] | None]) -> Callable[[dict, Any], None] | None:
    """For the `model_dump` path: applies `own` to a dumped row and the record it was dumped from, and to the structs in them.

    `own(spec)` is what to apply to the rows of one struct type, or None. None if neither `spec` nor a
    struct nested in it has anything to apply.
    """
    fill_own = own(spec)
    nested = {}
    for column in spec.columns:
        if column.kind == "struct":
            fill_nested = _filler(spec.nested[column.name], own)
            if fill_nested is not None:
                nested[column.name] = (fill_nested, column.is_list)
    if fill_own is None and not nested:
        return None

    def fill(row: dict, record: Any) -> None:
        if fill_own is not None:
            fill_own(row, record)
        for name, (fill_nested, is_list) in nested.items():
            dumped = row.get(name)
            if dumped is None:
                continue
            value = getattr(record, name)
            if not is_list:
                fill_nested(dumped, value)
                continue
            for dumped_element, element in zip(dumped, value):
                if dumped_element is not None:
                    fill_nested(dumped_element, element)

    return fill


def _raw_filler(spec: _ArrowSpec) -> Callable[[dict, Any], None] | None:
    """Sets the raw overrides of a dumped row from the record's attributes.

    A cell is filled only where the dumped row has a value, so fields `model_dump` leaves out or None
    stay null, as they are when reading attributes.
    """
    raw = {column.name: column.override.convert for column in spec.columns if column.kind == "override" and column.override.raw}
    if not raw:
        return None

    def fill(row: dict, record: Any) -> None:
        for name, convert in raw.items():
            if row.get(name) is not None:
                value = getattr(record, name)
                row[name] = value if value is None or convert is None else convert(value)

    return fill


def _from_json(arrow_type: pyarrow.DataType) -> Callable[[Any], Any]:
    """Turns a JSON-mode value into what a column of `arrow_type` is built from: JSON has dates and times as text."""
    if pyarrow.types.is_timestamp(arrow_type) or pyarrow.types.is_date(arrow_type):
        parse = datetime.fromisoformat if pyarrow.types.is_timestamp(arrow_type) else date.fromisoformat
        return lambda value: parse(value) if isinstance(value, str) else value
    if pyarrow.types.is_list(arrow_type):
        element = _from_json(arrow_type.value_type)
        return lambda value: [element(item) for item in value] if isinstance(value, list) else value
    if pyarrow.types.is_struct(arrow_type):
        children = {field.name: _from_json(field.type) for field in arrow_type}
        return lambda value: {k: children[k](v) if k in children else v for k, v in value.items()} if isinstance(value, dict) else value
    return lambda value: value


def _json_filler(spec: _ArrowSpec) -> Callable[[dict, Any], None] | None:
    """Sets the JSON-serialized columns of a dumped row from a JSON-mode dump of the record.

    Only the fields the row has, so that a serializer is not run on a field the record leaves unset.
    This is a second dump of every record, after the first: the slowest way a struct type is read.
    """
    converts = {field.name: _from_json(field.type) for field in spec.fields if field.name in spec.json}
    if not converts:
        return None

    def fill(row: dict, record: Any) -> None:
        names = converts.keys() & row.keys()
        if names:
            dumped = record.model_dump(mode="json", include=names, by_alias=False, warnings=False)
            for name in names & dumped.keys():
                row[name] = converts[name](dumped[name])

    return fill


# Reading attributes instead of `model_dump`. Attribute values equal what `model_dump` (python mode)
# returns unless a serializer runs on the way, so a struct type is read this way only when the only
# serializers it meets are ones the columns below reproduce: GatewayStruct's own (the timestamp's is
# JSON-only and gives the same time, and implicitly unset fields are nulled per record), csp's numpy
# arrays (`tolist()`, which a list column reproduces), enums (always written as names), dicts
# serialized to JSON text and overridden fields (which still go through `model_dump`), and raw
# overrides (whose struct type asks for the attribute). Anything else falls back to `model_dump`,
# which costs a dict per record. A struct type's other JSON-only serializers cost a second, JSON-mode
# dump per record on top of that: Perspective shows what they return, as the REST API does.


def _json_only(serializer: dict) -> bool:
    return serializer.get("when_used", "always") in ("json", "json-unless-none")


def _resolve(schema: dict, definitions: dict) -> dict:
    """Follow definition references and validator wrappers, which carry no serialization of their own."""
    while True:
        kind = schema.get("type", "")
        if kind == "definition-ref":
            schema = definitions[schema["schema_ref"]]
        elif kind.startswith("function-") and "serialization" not in schema and "schema" in schema:
            schema = schema["schema"]
        else:
            return schema


def _model_schema(cls) -> tuple[dict, dict, dict] | None:
    """`cls`'s pydantic core schema as its model, its fields by name and the definitions they share; None for another shape."""
    schema = cls.__pydantic_core_schema__
    definitions: dict = {}
    if schema.get("type") == "definitions":
        definitions = {d["ref"]: d for d in schema["definitions"]}
        schema = schema["schema"]
    model = _resolve(schema, definitions)
    if model.get("type") != "model":
        return None
    model_fields = _resolve(model["schema"], definitions)
    if model_fields.get("type") != "model-fields":
        return None
    return model, model_fields["fields"], definitions


def _json_serialized(cls, columns: list[_Column]) -> frozenset[str]:
    """The columns of `cls` a JSON-only serializer applies to: the field's own, or the model's, which applies to them all.

    Not GatewayStruct's serializer of the timestamp nor csp's of an enum, which write as text what
    the column has already, nor an overridden column, which its struct type says how to show.
    """
    from .base import GatewayStruct

    try:
        model, fields, definitions = _model_schema(cls) or ({}, {}, {})
        names = [column.name for column in columns if column.kind != "override" and column.name in fields]
        if _json_only(model.get("serialization") or {}):
            return frozenset(names)
        own = (GatewayStruct._serialize_timestamp, CspEnum._serialize)
        return frozenset(
            name
            for name in names
            if any(
                _json_only(serializer) and serializer.get("function") not in own for serializer in _serializers(fields[name]["schema"], definitions)
            )
        )
    except Exception:  # noqa: BLE001 -- best-effort read of pydantic's internal core schema, as `_reads_like_model_dump` is
        return frozenset()


def _runs_python_serializer(schema: dict, definitions: dict) -> bool:
    """Whether a python-mode serializer can run anywhere in a field's schema, short of a nested model."""
    return any(not _json_only(serializer) for serializer in _serializers(schema, definitions))


def _serializers(schema: dict, definitions: dict) -> Iterable[dict]:
    """The serializers anywhere in a field's schema, short of a nested model.

    Nested models are checked as their own struct type.
    """
    seen: set[str] = set()
    stack: list[Any] = [schema]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
            continue
        if not isinstance(node, dict):
            continue
        kind = node.get("type")
        if kind is not None:
            if kind == "model":
                # Its own serializer, and its fields, are checked when its struct type is.
                continue
            serializer = node.get("serialization")
            if serializer is not None:
                yield serializer
            if kind == "definition-ref":
                ref = node["schema_ref"]
                if ref not in seen:
                    seen.add(ref)
                    stack.append(definitions.get(ref))
                continue
        stack.extend(value for key, value in node.items() if key not in ("serialization", "metadata", "default") and isinstance(value, (dict, list)))


def _field_annotation(cls, name: str) -> Any:
    annotation = _strip_annotated(cls.model_fields[name].annotation)
    return _get_type_from_optional(annotation) if _is_optional(annotation) else annotation


def _is_numpy_field(cls, name: str) -> bool:
    return CspTypingUtils.is_numpy_array_type(_field_annotation(cls, name))


def _reads_like_model_dump(spec: _ArrowSpec) -> bool:
    """Whether reading `spec.cls`'s attributes gives what `model_dump` would, for these columns."""
    try:
        return _check_reads_like_model_dump(spec)
    except Exception:  # noqa: BLE001 -- best-effort read of pydantic's internal core schema; any failure means the safe fallback
        # A schema this cannot read (one not yet built, or an unfamiliar shape) is left to `model_dump`.
        return False


def _check_reads_like_model_dump(spec: _ArrowSpec) -> bool:
    from .base import GatewayStruct

    cls = spec.cls
    if spec.json or (issubclass(cls, GatewayStruct) and cls._implicitly_unset is not GatewayStruct._implicitly_unset):
        return False
    model_schema = _model_schema(cls)
    if model_schema is None:
        return False
    model, fields, definitions = model_schema
    serializer = model.get("serialization")
    if serializer is not None and not _json_only(serializer) and serializer.get("function") is not GatewayStruct._drop_implicitly_unset:
        return False
    for column in spec.columns:
        field = fields.get(column.name)
        if field is None or field.get("serialization_exclude") or "serialization_exclude_if" in field:
            return False
        # Dict and override columns are read through `model_dump`, or as the attribute where the override
        # is raw; enums and text unions are converted from the attribute.
        if column.kind in ("dict", "enum", "text", "override") or (column.is_list and _is_numpy_field(cls, column.name)):
            continue
        if _runs_python_serializer(field["schema"], definitions):
            return False
    return True


_Builder = Callable[[list[Any]], pyarrow.Array]


def _array_builder(arrow_type: pyarrow.DataType) -> _Builder:
    return lambda values: pyarrow.array(values, type=arrow_type)


def _enum_builder(enum_cls: type) -> _Builder:
    name = _enum_name(enum_cls)
    return lambda values: pyarrow.array([None if value is None else name(value) for value in values], type=pyarrow.string())


def _text_builder(values: list[Any]) -> pyarrow.Array:
    return pyarrow.array([None if value is None else _text(value) for value in values], type=pyarrow.string())


def _struct_builder(columns: "_AttributeColumns", arrow_type: pyarrow.StructType) -> _Builder:
    fields = [arrow_type.field(i) for i in range(arrow_type.num_fields)]

    def build(values: list[Any]) -> pyarrow.Array:
        nulls = [value is None for value in values]
        if not fields:
            return pyarrow.array([None if null else {} for null in nulls], type=arrow_type)
        mask = pyarrow.array(nulls) if any(nulls) else None
        return pyarrow.StructArray.from_arrays(columns.arrays(values), fields=fields, mask=mask)

    return build


def _list_builder(element: _Builder, arrow_type: pyarrow.ListType, numpy_values: bool) -> _Builder:
    value_type = arrow_type.value_type
    numeric = pyarrow.types.is_integer(value_type) or pyarrow.types.is_floating(value_type) or pyarrow.types.is_boolean(value_type)

    def build(values: list[Any]) -> pyarrow.Array:
        nulls = [value is None for value in values]
        if numpy_values and numeric and all(null or (isinstance(value, ndarray) and value.ndim == 1) for value, null in zip(values, nulls)):
            # Concatenated natively, without a Python object per element.
            arrays = [value for value in values if value is not None]
            flat = pyarrow.array(numpy.concatenate(arrays), type=value_type) if arrays else pyarrow.array([], type=value_type)
            lengths = [0 if value is None else len(value) for value in values]
        else:
            items: list[Any] = []
            lengths = []
            for value in values:
                if value is None:
                    lengths.append(0)
                    continue
                sequence = value.tolist() if isinstance(value, ndarray) else value if isinstance(value, list) else list(value)
                items.extend(sequence)
                lengths.append(len(sequence))
            flat = element(items)
        offsets = pyarrow.array([0, *accumulate(lengths)], type=pyarrow.int32())
        mask = pyarrow.array(nulls) if any(nulls) else None
        return pyarrow.ListArray.from_arrays(offsets, flat, type=arrow_type, mask=mask)

    return build


class _AttributeColumns:
    """Builds the Arrow columns of a struct type straight from its instances' attributes."""

    def __init__(self, spec: _ArrowSpec, builders: list[_Builder]):
        self._names = [column.name for column in spec.columns]
        self._builders = builders
        raw = [column for column in spec.columns if column.kind == "override" and column.override.raw]
        #: Raw overrides, whose `convert` takes the attribute itself.
        self._raw = {column.name: column.override.convert for column in raw}
        #: Dict columns serialized to JSON text, and the other fields the struct type overrides, read through
        #: `model_dump` so its serializers apply and an override's `convert` sees what the `model_dump` path gives it.
        self._dumped = {
            column.name: spec.fixers.get(column.name)
            for column in spec.columns
            if column.kind in ("dict", "override") and column.name not in self._raw
        }
        maybe_unset = getattr(spec.cls, "_maybe_unset_fields", None)
        self._maybe_unset = frozenset(maybe_unset()) & set(self._names) if maybe_unset is not None else frozenset()

    def unset(self, record: Any) -> frozenset[str]:
        """The columns `record` leaves unset, which `model_dump` would leave out of it."""
        return self._maybe_unset - record.__pydantic_fields_set__

    def arrays(self, records: list[Any], without: Container[str] = ()) -> list[pyarrow.Array]:
        """One array per column, less those named in `without`; a `None` record is a null row of every column.

        Nothing is made per record that the garbage collector tracks: such objects, alive until the
        batch is encoded, are promoted to its oldest generation and set off full collections, which
        hold the GIL while they sweep every live object.
        """
        out = []
        for name, build in zip(self._names, self._builders):
            if name in without:
                continue
            if name in self._dumped:
                fix = self._dumped[name]
                values = [
                    None if record is None else record.model_dump(include={name}, by_alias=False, warnings=False).get(name) for record in records
                ]
                if fix is not None:
                    values = [None if value is None else fix(value) for value in values]
            else:
                if name not in self._maybe_unset:
                    values = [None if record is None else getattr(record, name) for record in records]
                else:
                    # GatewayStruct's serializer drops fields that were never set and have no declared default:
                    # those `_implicitly_unset` reports, `_maybe_unset_fields()` less the fields set.
                    values = [None if record is None or name not in record.__pydantic_fields_set__ else getattr(record, name) for record in records]
                convert = self._raw.get(name)
                if convert is not None:
                    values = [None if value is None else convert(value) for value in values]
            out.append(build(values))
        return out


def _attribute_columns(spec: _ArrowSpec) -> _AttributeColumns | None:
    """The attribute reader for `spec`, or None where it could differ from `model_dump`."""
    if not _reads_like_model_dump(spec):
        return None
    builders = []
    for column, field in zip(spec.columns, spec.fields):
        arrow_type = field.type
        if column.kind in ("dict", "override"):
            # Fixed up in `_AttributeColumns.arrays`: dicts to JSON text, lists included, overrides by their `convert`.
            # A raw override's column is built the same way, from converted attributes.
            builders.append(_array_builder(arrow_type))
            continue
        element_type = arrow_type.value_type if column.is_list else arrow_type
        if column.kind == "struct":
            nested = _attribute_columns(spec.nested[column.name])
            if nested is None:
                return None
            element = _struct_builder(nested, element_type)
        elif column.kind == "enum":
            element = _enum_builder(column.py)
        elif column.kind == "text":
            element = _text_builder
        else:
            element = _array_builder(element_type)
        builders.append(_list_builder(element, arrow_type, _is_numpy_field(spec.cls, column.name)) if column.is_list else element)
    return _AttributeColumns(spec, builders)


class PspArrowEncoder:
    """Turns structs into an Arrow table that Perspective flattens itself.

    The Arrow schema keeps nested structs, lists and maps nested. Perspective explodes structs and
    lists into dotted columns and rows on ingest, in native code, and shows maps as JSON text, so the
    only work left here is the few values Arrow has no type for: enums become their names, and dicts
    that are not a map of scalars become JSON strings.

    Columns are built straight from the structs' attributes where that gives what `model_dump` would,
    which avoids a Python dict per record. A struct type with a pydantic serializer of its own, or
    holding one that has, goes through `model_dump` instead, which is several times slower; one whose
    serializer is JSON-only is dumped a second time in JSON mode, which is slower again.

    A struct can leave fields unset. `encode` gives those a null in every row by default. With
    `partial` it leaves out the columns the first item leaves unset instead, taking the first item
    to set every field the batch does: an indexed table keeps a row's value only for a column the
    update does not carry, and writes a null as a null.
    """

    def __init__(self, cls: type, excluded_columns: ExcludedColumns | None = None):
        spec = _arrow_spec(cls, excluded_columns)
        self.cls = cls
        #: The nested Arrow schema of the rows `encode` produces.
        self.schema = pyarrow.schema(spec.fields)
        self._fix = _struct_fixer(spec.fixers) if spec.fixers else None
        self._fill_json = _filler(spec, _json_filler)
        self._fill_raw = _filler(spec, _raw_filler)
        self._attributes = _attribute_columns(spec)
        self._warned_of_dropped = False

    def empty_ipc(self) -> bytes:
        """An Arrow IPC stream of the schema with no rows, which creates a Perspective table of these rows."""
        out = pyarrow.BufferOutputStream()
        with pyarrow.RecordBatchStreamWriter(out, self.schema):
            pass
        return out.getvalue().to_pybytes()

    def encode(self, items: Iterable[Any], partial: bool = False) -> pyarrow.Table:
        items = list(items)
        for item in items:
            prepare = getattr(item, "psp_prepare", None)
            if prepare is not None:
                prepare()
        if self._attributes is None:
            return self._encode_dumped(items, partial)
        unset = self._attributes.unset(items[0]) if partial and items else ()
        if unset and not self._warned_of_dropped:
            self._warn_of_dropped(unset, (item.__pydantic_fields_set__ for item in items))
        return pyarrow.Table.from_arrays(self._attributes.arrays(items, unset), schema=self._without(unset))

    def encode_ipc(self, items: Iterable[Any], partial: bool = False) -> bytes:
        """`encode` as an Arrow IPC stream, which Perspective takes as is, so one batch can update several tables."""
        table = self.encode(items, partial)
        out = pyarrow.BufferOutputStream()
        with pyarrow.RecordBatchStreamWriter(out, table.schema) as writer:
            writer.write_table(table)
        return out.getvalue().to_pybytes()

    def _warn_of_dropped(self, unset: frozenset[str] | set[str], fields_set: Iterable[Iterable[str]]) -> None:
        """Warn, once for this encoder, where a partial batch drops a field its first item leaves unset and a later one sets."""
        dropped = next((unset.intersection(fields) for fields in fields_set if not unset.isdisjoint(fields)), None)
        if dropped:
            self._warned_of_dropped = True
            log.warning(
                f"Perspective update of {self.cls.__name__} dropped {sorted(dropped)}: the first record of the batch left them unset, "
                "and the batch is sent with the fields its first record sets. Later drops are not logged."
            )

    def _without(self, unset: Container[str]) -> pyarrow.Schema:
        return pyarrow.schema([field for field in self.schema if field.name not in unset]) if unset else self.schema

    def _encode_dumped(self, items: list[Any], partial: bool = False) -> pyarrow.Table:
        """Encode through `model_dump`, for struct types whose attributes could serialize differently."""
        rows = [item.model_dump(by_alias=False, warnings=False) for item in items]
        if self._fill_json is not None:
            for row, item in zip(rows, items):
                self._fill_json(row, item)
        if self._fix is not None:
            for row in rows:
                self._fix(row)
        if self._fill_raw is not None:
            for row, item in zip(rows, items):
                self._fill_raw(row, item)
        unset = set(self.schema.names).difference(rows[0]) if partial and rows else ()
        if unset and not self._warned_of_dropped:
            self._warn_of_dropped(unset, rows)
        return pyarrow.Table.from_pylist(rows, schema=self._without(unset))


class PerspectiveUtilityMixin:
    def psp_prepare(self) -> None:
        """Hook run on each instance just before it is encoded for Perspective, to fill derived fields."""

    @classmethod
    def psp_schema(cls, excluded_columns: ExcludedColumns | None = None) -> dict[str, type]:
        """Return the perspective schema.

        Args:
            excluded_columns: Columns to exclude from the schema.
        """
        return psp_schema(cls, excluded_columns)

    @classmethod
    def psp_field_overrides(cls, excluded_columns: ExcludedColumns | None = None) -> dict[str, PspField]:
        """Fields of this struct type to show in Perspective differently from what their types give, by name.

        Consulted wherever the struct type is encoded, including as a field of another struct, and by
        `psp_schema`. A field the exclusions name outright is dropped as usual. Partial exclusions of an
        overridden field (``{"field": {"sub_column"}}``) are left to the override, which gets the
        struct type's ``excluded_columns`` here.

        An override is read through ``model_dump``, once per record, which costs far more than the
        column itself. Where the field's attribute is what ``convert`` should see, ``PspField(...,
        raw=True)`` reads that instead.

        Args:
            excluded_columns: The struct type's columns to exclude, as given to its encoder.
        """
        return {}

    @classmethod
    def psp_arrow_encoder(cls, excluded_columns: ExcludedColumns | None = None) -> PspArrowEncoder:
        """Return the encoder that turns instances into an Arrow table for Perspective."""
        return PspArrowEncoder(cls, excluded_columns)
