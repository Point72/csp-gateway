import logging
from datetime import datetime
from enum import Enum as PyEnum
from typing import Literal, Optional, Union

try:
    from csp.impl.enum import Enum as CspEnum, EnumMeta as CspEnumMeta
except ImportError:
    # If csp is not available, we can still use the basic types
    CspEnum = PyEnum
    CspEnumMeta = PyEnum
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

FilterWhere = Literal["==", "!=", "<", "<=", ">", ">="]
FilterWhereLambdaMap = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
}


def _get_nested_attr(obj, attr: str):
    """``getattr`` that supports dotted paths into nested structs (e.g. ``"a.b.c"``).

    Each path segment is resolved with a plain ``getattr``, so a missing or unset segment raises
    ``AttributeError`` exactly like ``getattr`` would for a flat attribute -- callers that rely on that
    (such as :meth:`Filter.calculate`, which treats a missing attribute as "does not match") keep their
    existing behaviour.
    """
    for part in attr.split("."):
        obj = getattr(obj, part)
    return obj


class FilterCondition(BaseModel):
    # in priority order
    value: Optional[Union[float, int, str]] = Field(None)
    # have to handle separately otherwise
    # all ints would be datetimes..
    when: Optional[datetime] = Field(None)
    attr: str = ""
    where: FilterWhere = "=="


class Filter(BaseModel):
    attr: str = ""
    by: FilterCondition

    def calculate(self, obj) -> bool:
        """
        calculate the filter condition on the object

        returns `True` if SHOULD NOT BE FILTERED, else `False`
        """
        try:
            if self.by.value is not None:
                lhs = _get_nested_attr(obj, self.attr)
                # Convert enums attrs to strings during filtering
                if isinstance(lhs, (CspEnum, PyEnum, CspEnumMeta)):
                    lhs = lhs.name
                log.info(f"Filtering: {lhs} {self.by.where} {self.by.value}")
                return FilterWhereLambdaMap[self.by.where](lhs, self.by.value)
            if self.by.when is not None:
                log.info(f"Filtering: {_get_nested_attr(obj, self.attr)} {self.by.where} {self.by.when}")
                return FilterWhereLambdaMap[self.by.where](_get_nested_attr(obj, self.attr), self.by.when)
            if self.by.attr:
                log.info(f"Filtering: {_get_nested_attr(obj, self.attr)} {self.by.where} {_get_nested_attr(obj, self.by.attr)}")
                return FilterWhereLambdaMap[self.by.where](_get_nested_attr(obj, self.attr), _get_nested_attr(obj, self.by.attr))
        except (ValueError, AttributeError) as e:
            # TODO probably surface to webserver
            log.warning(f"Error during filtering {type(obj)} / {self}: {e}")

        # default case, if there was an issue assume its not included
        return False
