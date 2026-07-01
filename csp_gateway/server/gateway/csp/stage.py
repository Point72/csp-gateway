"""Core staging support for csp-gateway channels.

A channel with staging enabled accumulates structs into named "staging areas"
before they are released into the main channel. This allows batch preparation
and atomic release of groups of structs.

See STAGE.md for the full API specification.
"""

import threading
from typing import Dict, List, Optional

from csp.impl.genericpushadapter import GenericPushAdapter

from csp_gateway.utils import GatewayStruct

__all__ = (
    "Stage",
    "Staging",
    "build_staging_node",
)


class Stage:
    """Annotation marker for declaring staging on a channel.

    Usage::

        class MyChannels(GatewayChannels):
            orders: Annotated[ts[OrderStruct], Stage()] = None

    This is equivalent to calling ``channels.set_stage("orders")`` in the
    module's ``connect`` method.
    """

    def __init__(self) -> None:
        pass


class Staging(GatewayStruct):
    """A staging group represented as a GatewayStruct.

    Each StagingArea gets a unique id and timestamp automatically from
    GatewayStruct. It holds a list of struct instances that have been staged
    but not yet released. The staging_id is simply ``self.id``.

    Note: ``items`` uses ``list`` (untyped) rather than ``List[GatewayStruct]``
    because CSP's C++ struct layer enforces strict type matching on typed lists,
    and not all channel structs inherit from GatewayStruct in the struct hierarchy.
    """

    items: list = []

    def add(self, struct) -> None:
        self.items.append(struct)

    def remove(self, struct) -> bool:
        """Remove a struct by id. Returns True if found and removed."""
        for i, item in enumerate(self.items):
            if item.id == struct.id:
                self.items.pop(i)
                return True
        return False

    def clear(self) -> list:
        """Remove all items and return them."""
        items = self.items[:]
        self.items = []
        return items

    def lookup(self) -> list:
        """Return a copy of the items list."""
        return self.items[:]


class _StageManager:
    """Manages multiple staging areas for a single channel.

    Thread-safe: all mutations are guarded by a lock.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._areas: Dict[str, Staging] = {}
        self._released: Dict[str, Staging] = {}

    @property
    def staging_ids(self) -> List[str]:
        with self._lock:
            return list(self._areas.keys())

    def stage_add(
        self,
        struct: Optional[GatewayStruct] = None,
        staging_ids: Optional[List[str]] = None,
    ) -> List[str]:
        """Add a struct to staging area(s).

        Returns the list of staging IDs affected.
        See STAGE.md for the full semantics.
        """
        with self._lock:
            if struct is None and staging_ids is not None and len(staging_ids) > 0:
                # None, [staging_id]: error
                raise ValueError("Cannot specify staging_ids without a struct to add")

            if struct is None:
                # None, None or None, []: create a new empty staging
                area = Staging()
                self._areas[area.id] = area
                return [area.id]

            if staging_ids is None:
                # struct, None: if staging exists, add to latest; else create new
                if self._areas:
                    latest_id = list(self._areas.keys())[-1]
                    self._areas[latest_id].add(struct)
                    return [latest_id]
                else:
                    area = Staging()
                    area.add(struct)
                    self._areas[area.id] = area
                    return [area.id]

            if len(staging_ids) == 0:
                # struct, []: add to all existing, or create new if none
                if self._areas:
                    affected = []
                    for sid, area in self._areas.items():
                        # Add only if not already present
                        if not any(item.id == struct.id for item in area.items):
                            area.add(struct)
                            affected.append(sid)
                    if not affected:
                        # Already in all, create a new one
                        area = Staging()
                        area.add(struct)
                        self._areas[area.id] = area
                        return [area.id]
                    return affected
                else:
                    area = Staging()
                    area.add(struct)
                    self._areas[area.id] = area
                    return [area.id]

            # struct, [staging_id, ...]: add to specified stagings
            affected = []
            for sid in staging_ids:
                if sid not in self._areas:
                    raise KeyError(f"Staging ID not found: {sid}")
                self._areas[sid].add(struct)
                affected.append(sid)
            return affected

    def stage_remove(
        self,
        struct: Optional[GatewayStruct] = None,
        staging_ids: Optional[List[str]] = None,
    ) -> List[str]:
        """Remove struct(s) from staging area(s).

        Returns the list of staging IDs affected.
        See STAGE.md for the full semantics.
        """
        with self._lock:
            if struct is None and staging_ids is not None and len(staging_ids) == 0:
                # None, []: clear all stagings
                affected = list(self._areas.keys())
                self._areas.clear()
                return affected

            if struct is None and staging_ids is None:
                # None, None: clear latest staging
                if not self._areas:
                    return []
                latest_id = list(self._areas.keys())[-1]
                del self._areas[latest_id]
                return [latest_id]

            if struct is None and staging_ids is not None and len(staging_ids) > 0:
                # None, [staging_id]: clear all structs from given staging
                affected = []
                for sid in staging_ids:
                    if sid in self._areas:
                        self._areas[sid].clear()
                        affected.append(sid)
                return affected

            if struct is not None and staging_ids is None:
                # struct, None: remove from latest staging containing it
                for sid in reversed(list(self._areas.keys())):
                    if self._areas[sid].remove(struct):
                        return [sid]
                return []

            if struct is not None and staging_ids is not None and len(staging_ids) == 0:
                # struct, []: remove from all stagings
                affected = []
                for sid, area in self._areas.items():
                    if area.remove(struct):
                        affected.append(sid)
                return affected

            # struct, [staging_id]: remove from specific staging
            affected = []
            for sid in staging_ids:
                if sid in self._areas:
                    if self._areas[sid].remove(struct):
                        affected.append(sid)
            return affected

    def stage_release(
        self,
        staging_ids: Optional[List[str]] = None,
    ) -> Dict[str, List[GatewayStruct]]:
        """Release staged structs.

        Returns a dict mapping staging_id -> list of released structs.
        Released stagings are moved to the released archive.
        """
        with self._lock:
            if staging_ids is None:
                # Release all
                released = {}
                for sid, area in list(self._areas.items()):
                    released[sid] = area.items[:]
                    self._released[sid] = area
                self._areas.clear()
                return released

            released = {}
            for sid in staging_ids:
                if sid in self._areas:
                    released[sid] = self._areas[sid].items[:]
                    self._released[sid] = self._areas[sid]
                    del self._areas[sid]
            return released

    def stage_list(
        self,
        staging_id: Optional[str] = None,
    ) -> List[str]:
        """List staging IDs, or verify a specific one exists."""
        with self._lock:
            if staging_id is None:
                return list(self._areas.keys())
            if staging_id in self._areas:
                return [staging_id]
            return []

    def stage_lookup(
        self,
        staging_id: Optional[str] = None,
    ) -> Dict[str, List[GatewayStruct]]:
        """Look up contents of staging area(s), including released stages.

        Returns dict mapping staging_id -> list of structs.
        """
        with self._lock:
            if staging_id is None:
                result = {sid: area.lookup() for sid, area in self._areas.items()}
                result.update({sid: area.lookup() for sid, area in self._released.items()})
                return result
            if staging_id in self._areas:
                return {staging_id: self._areas[staging_id].lookup()}
            if staging_id in self._released:
                return {staging_id: self._released[staging_id].lookup()}
            return {}


def build_staging_node(element_type: type) -> tuple:
    """Build a _StageManager instance and its associated push adapter for releases.

    Returns (stage, push_adapter) where:
    - stage: the _StageManager instance for managing staging areas
    - push_adapter: GenericPushAdapter[element_type] to push released items into the graph
    """
    stage = _StageManager()
    push_adapter = GenericPushAdapter(element_type, name=f"StagingRelease<{element_type.__name__}>")
    return stage, push_adapter
