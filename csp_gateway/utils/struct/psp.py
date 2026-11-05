import types
from collections.abc import Callable, Iterable
from datetime import date, datetime
from enum import Enum as PyEnum
from logging import getLogger
from typing import Annotated, Any, NamedTuple, Optional, Union, get_args, get_origin

import orjson
import pyarrow
from csp import Enum as CspEnum
from csp.impl.types.container_type_normalizer import ContainerTypeNormalizer
from numpy import ndarray
from pydantic import BaseModel
from typing_extensions import TypeAliasType

__all__ = (
    "ExcludedColumns",
    "PerspectiveUtilityMixin",
    "PspArrowEncoder",
    "model_metadata",
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


class _Column(NamedTuple):
    """One field of a struct as Perspective sees it."""

    name: str
    #: The element type for a list field, otherwise the field type.
    py: type
    is_list: bool
    #: One of "scalar", "dict", "map", "enum" or "struct".
    kind: str
    #: Exclusions for the columns of a struct field.
    sub_excluded: ExcludedColumns | None
    #: The key and value types of a "map" field.
    map_types: tuple[type, type] | None = None


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
    out = []
    for name, value in schema.items():
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


def psp_schema(cls, excluded_columns: ExcludedColumns | None = None) -> dict[str, type]:
    """Returns the flattened perspective schema for a class.

    Structs become dotted column names, lists become their element type, and enums, dicts and maps become `str`.

    Args:
        excluded_columns: Columns to exclude from the schema.
    """
    out: dict[str, type] = {}
    for column in _columns(cls, excluded_columns):
        if column.kind == "struct":
            for key, value in psp_schema(column.py, column.sub_excluded).items():
                out[f"{column.name}.{key}"] = value
        elif column.kind in ("dict", "map", "enum"):
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
    fields: list[pyarrow.Field]
    fixers: dict[str, Callable[[Any], Any]]


def _arrow_spec(cls, excluded_columns: ExcludedColumns | None) -> _ArrowSpec:
    spec = _ArrowSpec([], {})
    for column in _columns(cls, excluded_columns):
        fix = None
        if column.kind == "struct":
            sub = _arrow_spec(column.py, column.sub_excluded)
            arrow_type = pyarrow.struct(sub.fields)
            fix = _struct_fixer(sub.fixers) if sub.fixers else None
        elif column.kind == "map":
            arrow_type = pyarrow.map_(*(_scalar_arrow_type(t) for t in column.map_types))
        elif column.kind == "dict":
            arrow_type, fix = pyarrow.string(), _json_str
        elif column.kind == "enum":
            arrow_type, fix = pyarrow.string(), _enum_name(column.py)
        else:
            arrow_type = _scalar_arrow_type(column.py)
        if column.is_list:
            arrow_type, fix = pyarrow.list_(arrow_type), _list_fixer(fix)
        spec.fields.append(pyarrow.field(column.name, arrow_type))
        if fix is not None:
            spec.fixers[column.name] = fix
    return spec


class PspArrowEncoder:
    """Turns structs into an Arrow table that Perspective flattens itself.

    The Arrow schema keeps nested structs, lists and maps nested. Perspective explodes structs and
    lists into dotted columns and rows on ingest, in native code, and shows maps as JSON text, so the
    only work left here is the few values Arrow has no type for: enums become their names, and dicts
    that are not a map of scalars become JSON strings.
    """

    def __init__(self, cls: type, excluded_columns: ExcludedColumns | None = None):
        spec = _arrow_spec(cls, excluded_columns)
        self.cls = cls
        #: The nested Arrow schema of the rows `encode` produces.
        self.schema = pyarrow.schema(spec.fields)
        self._fix = _struct_fixer(spec.fixers) if spec.fixers else None

    def empty_ipc(self) -> bytes:
        """An Arrow IPC stream of the schema with no rows, which creates a Perspective table of these rows."""
        out = pyarrow.BufferOutputStream()
        with pyarrow.RecordBatchStreamWriter(out, self.schema):
            pass
        return out.getvalue().to_pybytes()

    def encode(self, items: Iterable[Any]) -> pyarrow.Table:
        rows = []
        for item in items:
            prepare = getattr(item, "psp_prepare", None)
            if prepare is not None:
                prepare()
            rows.append(item.model_dump(by_alias=False, warnings=False))
        if self._fix is not None:
            for row in rows:
                self._fix(row)
        return pyarrow.Table.from_pylist(rows, schema=self.schema)


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
    def psp_arrow_encoder(cls, excluded_columns: ExcludedColumns | None = None) -> PspArrowEncoder:
        """Return the encoder that turns instances into an Arrow table for Perspective."""
        return PspArrowEncoder(cls, excluded_columns)
