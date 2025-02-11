import logging
from typing import List

from pydantic import BaseModel

from .filter import Filter

log = logging.getLogger(__name__)


class Query(BaseModel):
    filters: List[Filter] = []

    def calculate(self, objs):
        """calculate and filter down objs by filters"""
        log.info(f"Querying {len(objs)} with query: {self}")
        return [o for o in objs if all(filter.calculate(o) for filter in self.filters)]
