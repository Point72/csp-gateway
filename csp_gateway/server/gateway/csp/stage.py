"""Core staging support for csp-gateway channels.

A channel with staging enabled accumulates structs into named "staging areas"
before they are released into the main channel. This allows batch preparation
and atomic release of groups of structs.

Staging mutations are also published as a ``ts[StagingEvent]`` delta stream, so modules can react to
what is being staged (see ``GatewayChannels.get_stage_events``).
"""

import threading
from collections.abc import Callable

import csp
from csp import Enum, ts
from csp.impl.genericpushadapter import GenericPushAdapter

from csp_gateway.utils import GatewayStruct

__all__ = (
    "Stage",
    "Staging",
    "StagingAction",
    "StagingEvent",
    "StagingRequest",
    "apply_stage_requests",
    "build_staging_node",
)


class StagingAction(Enum):
    """What happened to a staging area, one action per affected record."""

    CREATED = 0
    ADDED = 1
    REMOVED = 2
    RELEASED = 3


class StagingEvent(GatewayStruct):
    """One staging mutation, as ticked on a channel's staging event stream.

    ``CREATED`` and a whole-staging ``REMOVED`` carry no items; ``ADDED``/``REMOVED`` carry the single
    record involved, and ``RELEASED`` carries everything the staging released.

    ``items`` uses ``list`` (untyped) for the same reason ``Staging.items`` does.
    """

    channel: str = ""
    staging_id: str = ""
    action: StagingAction = StagingAction.CREATED
    items: list = []


class StagingRequest(GatewayStruct):
    """A request to mutate a staging area, tickable by a module.

    The same actions the REST API exposes: ``CREATED`` opens an empty staging, ``ADDED``/``REMOVED``
    stage or unstage each of ``items``, and ``RELEASED`` releases. A ``REMOVED`` with no ``items``
    clears rather than unstaging a particular record.

    Leaving ``staging_ids`` unset means "no ids" (the API's ``None``: latest, or a new staging); setting
    it to an empty list means "all" -- the same distinction the REST layer draws.
    """

    action: StagingAction = StagingAction.ADDED
    staging_ids: list = []
    items: list = []


@csp.node
def apply_stage_requests(requests: ts[StagingRequest], channels: object, field: str) -> None:
    """Apply ticked staging requests to ``field``'s staging areas."""
    if csp.ticked(requests):
        # Unset means None (latest / new); an explicit empty list means all.
        staging_ids = requests.staging_ids if hasattr(requests, "staging_ids") else None
        if requests.action == StagingAction.RELEASED:
            channels.stage_release(field, staging_ids=staging_ids)
        elif requests.action == StagingAction.CREATED:
            channels.stage_add(field, None, staging_ids=staging_ids)
        elif requests.action == StagingAction.ADDED:
            for item in requests.items:
                channels.stage_add(field, item, staging_ids=staging_ids)
        elif requests.action == StagingAction.REMOVED:
            if requests.items:
                for item in requests.items:
                    channels.stage_remove(field, item, staging_ids=staging_ids)
            else:
                channels.stage_remove(field, None, staging_ids=staging_ids)


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

    Thread-safe: all mutations are guarded by a lock. Mutations are reported to ``on_event`` as a list
    of ``(action, staging_id, items)`` deltas, derived by diffing the areas around each operation so
    the branchy add/remove semantics only have to be expressed once.
    """

    def __init__(self, on_event: Callable[[list], None] | None = None):
        # Reentrant so the public wrappers can snapshot/diff around the locked implementations.
        self._lock = threading.RLock()
        self._areas: dict[str, Staging] = {}
        self._on_event = on_event
        self._listeners: list[Callable[[list], None]] = []

    def add_listener(self, listener: Callable[[list], None]) -> None:
        """Also report deltas to ``listener``.

        Unlike ``on_event`` -- which feeds the graph's event adapter and so must be set while the graph is
        built -- listeners may be attached at any point, including after the graph is finalized.
        """
        self._listeners.append(listener)

    def _snapshot(self) -> dict[str, list]:
        """The current areas as ``staging_id -> items``. Call under the lock."""
        return {sid: area.items[:] for sid, area in self._areas.items()}

    def _diff(self, before: dict[str, list]) -> list:
        """Deltas between ``before`` and the current areas. Call under the lock.

        A staging that vanished is reported as a removal of each of its records followed by a removal of
        the staging itself. Releases do not go through here -- they are reported explicitly.
        """
        events = []
        after = self._snapshot()
        for sid, items in after.items():
            previous = before.get(sid)
            if previous is None:
                events.append((StagingAction.CREATED, sid, []))
                previous = []
            previous_ids = {item.id for item in previous}
            current_ids = {item.id for item in items}
            events.extend((StagingAction.ADDED, sid, [item]) for item in items if item.id not in previous_ids)
            events.extend((StagingAction.REMOVED, sid, [item]) for item in previous if item.id not in current_ids)
        for sid, items in before.items():
            if sid not in after:
                events.extend((StagingAction.REMOVED, sid, [item]) for item in items)
                events.append((StagingAction.REMOVED, sid, []))
        return events

    def _emit(self, events: list) -> None:
        if not events:
            return
        if self._on_event is not None:
            self._on_event(events)
        for listener in self._listeners:
            listener(events)

    @property
    def staging_ids(self) -> list[str]:
        with self._lock:
            return list(self._areas.keys())

    @staticmethod
    def _validate_identity(struct: object | None) -> None:
        if struct is None:
            return
        identity = getattr(struct, "id", None)
        if identity is None:
            raise ValueError("Staged items must have a non-null id")
        try:
            hash(identity)
        except TypeError:
            raise ValueError("Staged item id must be hashable") from None

    def stage_add(
        self,
        struct: GatewayStruct | None = None,
        staging_ids: list[str] | None = None,
    ) -> list[str]:
        """Add a struct to staging area(s), reporting what changed.

        Items must have a non-null, hashable id. Invalid items raise ValueError without changing staging.

        Returns the list of staging IDs affected.
        """
        with self._lock:
            self._validate_identity(struct)
            before = self._snapshot()
            affected = self._stage_add(struct, staging_ids)
            events = self._diff(before)
        self._emit(events)
        return affected

    def stage_remove(
        self,
        struct: GatewayStruct | None = None,
        staging_ids: list[str] | None = None,
    ) -> list[str]:
        """Remove struct(s) from staging area(s), reporting what changed.

        Items must have a non-null, hashable id. Invalid items raise ValueError without changing staging.

        Returns the list of staging IDs affected.
        """
        with self._lock:
            self._validate_identity(struct)
            before = self._snapshot()
            affected = self._stage_remove(struct, staging_ids)
            events = self._diff(before)
        self._emit(events)
        return affected

    def stage_release(
        self,
        staging_ids: list[str] | None = None,
    ) -> dict[str, list[GatewayStruct]]:
        """Release staged structs, reporting one RELEASED event per staging.

        Returns a dict mapping staging_id -> list of released structs.
        """
        with self._lock:
            released = self._stage_release(staging_ids)
        self._emit([(StagingAction.RELEASED, sid, items) for sid, items in released.items()])
        return released

    def _stage_add(
        self,
        struct: GatewayStruct | None = None,
        staging_ids: list[str] | None = None,
    ) -> list[str]:
        """Add a struct to staging area(s).

        Returns the list of staging IDs affected.
        See docs/wiki/Staging.md for the full semantics.
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
            for sid in staging_ids:
                if sid not in self._areas:
                    raise KeyError(f"Staging ID not found: {sid}")
            affected = []
            for sid in staging_ids:
                self._areas[sid].add(struct)
                affected.append(sid)
            return affected

    def _stage_remove(
        self,
        struct: GatewayStruct | None = None,
        staging_ids: list[str] | None = None,
    ) -> list[str]:
        """Remove struct(s) from staging area(s).

        Returns the list of staging IDs affected.
        See docs/wiki/Staging.md for the full semantics.
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
                if sid in self._areas and self._areas[sid].remove(struct):
                    affected.append(sid)
            return affected

    def _stage_release(
        self,
        staging_ids: list[str] | None = None,
    ) -> dict[str, list[GatewayStruct]]:
        """Release staged structs.

        Returns a dict mapping staging_id -> list of released structs. A released staging is dropped;
        its contents ride the RELEASED event and the channel itself.
        """
        with self._lock:
            if staging_ids is None:
                # Release all
                released = {}
                for sid, area in list(self._areas.items()):
                    released[sid] = area.items[:]
                self._areas.clear()
                return released

            released = {}
            for sid in staging_ids:
                if sid in self._areas:
                    released[sid] = self._areas[sid].items[:]
                    del self._areas[sid]
            return released

    def stage_list(
        self,
        staging_id: str | None = None,
    ) -> list[str]:
        """List staging IDs, or verify a specific one exists."""
        with self._lock:
            if staging_id is None:
                return list(self._areas.keys())
            if staging_id in self._areas:
                return [staging_id]
            return []

    def stage_lookup(
        self,
        staging_id: str | None = None,
    ) -> dict[str, list[GatewayStruct]]:
        """Look up contents of pending staging area(s).

        Returns dict mapping staging_id -> list of structs. Released stagings are gone; their contents
        were delivered on the channel and on the RELEASED event.
        """
        with self._lock:
            if staging_id is None:
                return {sid: area.lookup() for sid, area in self._areas.items()}
            if staging_id in self._areas:
                return {staging_id: self._areas[staging_id].lookup()}
            return {}


def build_staging_node(element_type: type, channel: str = "") -> tuple:
    """Build a _StageManager and the push adapters that carry its output into the graph.

    Returns (stage, push_adapter, event_adapter) where:
    - stage: the _StageManager instance for managing staging areas
    - push_adapter: GenericPushAdapter[element_type] to push released items into the graph
    - event_adapter: GenericPushAdapter[StagingEvent] carrying the staging delta stream
    """
    event_adapter = GenericPushAdapter(StagingEvent, name=f"StagingEvents<{element_type.__name__}>")

    def _on_event(events: list) -> None:
        for action, staging_id, items in events:
            event_adapter.push_tick(StagingEvent(channel=channel, staging_id=staging_id, action=action, items=items))

    stage = _StageManager(on_event=_on_event)
    push_adapter = GenericPushAdapter(element_type, name=f"StagingRelease<{element_type.__name__}>")
    return stage, push_adapter, event_adapter
