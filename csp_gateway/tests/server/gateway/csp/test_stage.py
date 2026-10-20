"""Tests for the staging functionality."""

from datetime import datetime, timedelta
from typing import Annotated

import csp
import pytest
from csp import ts
from pydantic import BaseModel

from csp_gateway import (
    Channels,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewayStruct,
    State,
)
from csp_gateway.server.gateway.csp.stage import Stage, Staging, StagingAction, StagingEvent, StagingRequest, _StageManager
from csp_gateway.testing import GatewayTestHarness
from csp_gateway.utils import NoProviderException

# --- Test structures ---


class OrderStruct(GatewayStruct):
    symbol: str = ""
    quantity: int = 0
    price: float = 0.0


class UnkeyedOrder(BaseModel):
    symbol: str = ""


class PlainOrder(BaseModel):
    id: object | None = None
    symbol: str = ""


class StagedChannels(GatewayChannels):
    orders: ts[OrderStruct] = None


class StagedWithStateChannels(GatewayChannels):
    orders: Annotated[ts[OrderStruct], State(keyby="id")] = None


class StagingModule(GatewayModule):
    """Module that enables staging on the orders channel."""

    def connect(self, channels: StagedChannels) -> None:
        channels.set_channel(StagedChannels.orders, csp.null_ts(OrderStruct))
        channels.set_stage(StagedChannels.orders)
        channels.add_send_channel(StagedChannels.orders)

    def shutdown(self) -> None:
        pass


class StagingWithStateModule(GatewayModule):
    """Module that enables staging + state on orders channel."""

    def connect(self, channels: StagedWithStateChannels) -> None:
        channels.set_channel(StagedWithStateChannels.orders, csp.null_ts(OrderStruct))
        channels.set_stage(StagedWithStateChannels.orders)
        channels.add_send_channel(StagedWithStateChannels.orders)

    def shutdown(self) -> None:
        pass


# --- Unit Tests for _StageManager class ---


class TestStagingArea:
    def test_is_gateway_struct(self):
        area = Staging()
        assert isinstance(area, GatewayStruct)
        assert area.id  # auto-generated
        assert area.timestamp

    def test_add_and_lookup(self):
        area = Staging()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        area.add(s)
        assert area.lookup() == [s]

    def test_remove(self):
        area = Staging()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        area.add(s)
        assert area.remove(s) is True
        assert area.lookup() == []

    def test_remove_not_found(self):
        area = Staging()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        assert area.remove(s) is False

    def test_clear(self):
        area = Staging()
        s1 = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        s2 = OrderStruct(symbol="GOOG", quantity=50, price=2800.0)
        area.add(s1)
        area.add(s2)
        cleared = area.clear()
        assert cleared == [s1, s2]
        assert area.lookup() == []


class TestStageManager:
    @pytest.mark.parametrize("method", ["stage_add", "stage_remove"])
    @pytest.mark.parametrize("struct", [UnkeyedOrder(), PlainOrder(), PlainOrder(id=[])])
    @pytest.mark.parametrize("populated", [False, True])
    def test_invalid_identity_is_rejected_without_mutation(self, method, struct, populated):
        stage = _StageManager()
        if populated:
            stage.stage_add(OrderStruct(symbol="AAPL"))
        before = stage.stage_lookup()
        events = []
        stage.add_listener(events.extend)

        with pytest.raises(ValueError, match="id"):
            getattr(stage, method)(struct)

        assert stage.stage_lookup() == before
        assert events == []

    def test_stage_add_none_none_creates_empty(self):
        stage = _StageManager()
        result = stage.stage_add(None, None)
        assert len(result) == 1
        assert stage.stage_list() == result

    def test_stage_add_none_empty_list_creates_empty(self):
        stage = _StageManager()
        result = stage.stage_add(None, [])
        assert len(result) == 1

    def test_stage_add_struct_none_creates_or_appends(self):
        stage = _StageManager()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        # No existing staging -> creates new
        result = stage.stage_add(s, None)
        assert len(result) == 1
        sid = result[0]
        contents = stage.stage_lookup(sid)
        assert contents[sid] == [s]

        # Existing staging -> appends to latest
        s2 = OrderStruct(symbol="GOOG", quantity=50, price=2800.0)
        result2 = stage.stage_add(s2, None)
        assert result2 == [sid]
        contents = stage.stage_lookup(sid)
        assert len(contents[sid]) == 2

    def test_stage_add_struct_empty_list_adds_to_all(self):
        stage = _StageManager()
        stage.stage_add(None, None)  # create first
        stage.stage_add(None, None)  # create second
        ids = stage.stage_list()
        assert len(ids) == 2

        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        result = stage.stage_add(s, [])
        assert set(result) == set(ids)

    def test_stage_add_struct_specific_ids(self):
        stage = _StageManager()
        ids = stage.stage_add(None, None)
        sid = ids[0]
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        result = stage.stage_add(s, [sid])
        assert result == [sid]
        contents = stage.stage_lookup(sid)
        assert contents[sid] == [s]

    def test_stage_add_none_with_ids_errors(self):
        stage = _StageManager()
        ids = stage.stage_add(None, None)
        with pytest.raises(ValueError):
            stage.stage_add(None, ids)

    def test_stage_add_nonexistent_id_errors(self):
        stage = _StageManager()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        with pytest.raises(KeyError):
            stage.stage_add(s, ["nonexistent"])

    @pytest.mark.parametrize("missing_first", [False, True])
    def test_stage_add_unknown_id_preserves_all_areas_and_events(self, missing_first):
        stage = _StageManager()
        existing = OrderStruct(symbol="AAPL")
        first_id = stage.stage_add(existing)[0]
        second_id = stage.stage_add()[0]
        before = stage.stage_lookup()
        events = []
        stage.add_listener(events.extend)
        staging_ids = [first_id, second_id, "missing"]
        if missing_first:
            staging_ids.reverse()

        with pytest.raises(KeyError):
            stage.stage_add(OrderStruct(symbol="MSFT"), staging_ids)

        assert stage.stage_lookup() == before
        assert events == []

    def test_stage_remove_none_none_clears_latest(self):
        stage = _StageManager()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        ids1 = stage.stage_add(s, None)
        ids2 = stage.stage_add(None, None)

        result = stage.stage_remove(None, None)
        assert result == ids2
        assert stage.stage_list() == ids1

    def test_stage_remove_none_empty_clears_all(self):
        stage = _StageManager()
        stage.stage_add(None, None)
        stage.stage_add(None, None)
        result = stage.stage_remove(None, [])
        assert len(result) == 2
        assert stage.stage_list() == []

    def test_stage_remove_none_specific_clears_that_staging(self):
        stage = _StageManager()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        ids = stage.stage_add(s, None)
        stage.stage_remove(None, ids)
        # Staging still exists but is empty
        contents = stage.stage_lookup(ids[0])
        assert contents[ids[0]] == []

    def test_stage_remove_struct_none_removes_from_latest(self):
        stage = _StageManager()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        ids = stage.stage_add(s, None)
        result = stage.stage_remove(s, None)
        assert result == ids
        contents = stage.stage_lookup(ids[0])
        assert contents[ids[0]] == []

    def test_stage_remove_struct_empty_removes_from_all(self):
        stage = _StageManager()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        stage.stage_add(s, None)
        stage.stage_add(None, None)
        # Add to second staging too
        all_ids = stage.stage_list()
        stage.stage_add(s, [all_ids[1]])

        result = stage.stage_remove(s, [])
        assert set(result) == set(all_ids)

    def test_stage_release_all(self):
        stage = _StageManager()
        s1 = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        s2 = OrderStruct(symbol="GOOG", quantity=50, price=2800.0)
        stage.stage_add(s1, None)
        stage.stage_add(None, None)
        ids = stage.stage_list()
        stage.stage_add(s2, [ids[1]])

        released = stage.stage_release(None)
        assert ids[0] in released
        assert ids[1] in released
        assert released[ids[0]] == [s1]
        assert released[ids[1]] == [s2]
        assert stage.stage_list() == []

    def test_stage_release_specific(self):
        stage = _StageManager()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        ids = stage.stage_add(s, None)
        stage.stage_add(None, None)

        released = stage.stage_release(ids)
        assert ids[0] in released
        assert released[ids[0]] == [s]
        # Second staging still exists
        remaining = stage.stage_list()
        assert len(remaining) == 1
        assert ids[0] not in remaining

    def test_stage_list(self):
        stage = _StageManager()
        assert stage.stage_list() == []
        ids1 = stage.stage_add(None, None)
        ids2 = stage.stage_add(None, None)
        assert stage.stage_list() == ids1 + ids2

    def test_stage_list_specific(self):
        stage = _StageManager()
        ids = stage.stage_add(None, None)
        assert stage.stage_list(ids[0]) == ids
        assert stage.stage_list("nonexistent") == []

    def test_stage_lookup_all(self):
        stage = _StageManager()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        ids = stage.stage_add(s, None)
        result = stage.stage_lookup()
        assert ids[0] in result
        assert result[ids[0]] == [s]

    def test_stage_lookup_specific(self):
        stage = _StageManager()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        ids = stage.stage_add(s, None)
        result = stage.stage_lookup(ids[0])
        assert result == {ids[0]: [s]}

    def test_stage_lookup_nonexistent(self):
        stage = _StageManager()
        result = stage.stage_lookup("nonexistent")
        assert result == {}


# --- Integration tests with Gateway ---


class TestStagingChannels:
    def _build_channels(self) -> StagedChannels:
        channels = StagedChannels()
        with channels._connection_context("StagingTest"):
            channels.set_stage(StagedChannels.orders)
        return channels

    def test_set_stage_basic(self):
        channels = self._build_channels()
        assert "orders" in channels.staged_channels()

    def test_stage_add_and_lookup(self):
        channels = self._build_channels()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        ids = channels.stage_add("orders", s)
        assert len(ids) == 1
        contents = channels.stage_lookup("orders", ids[0])
        assert contents[ids[0]] == [s]

    def test_stage_release_and_clear(self):
        channels = self._build_channels()
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        channels.stage_add("orders", s)
        removed = channels.stage_remove("orders", s, [])
        assert len(removed) == 1
        assert channels.stage_list("orders") == removed
        looked_up = channels.stage_lookup("orders", removed[0])
        assert looked_up[removed[0]] == []

    def test_stage_not_enabled_raises(self):
        channels = self._build_channels()
        with pytest.raises(NoProviderException):
            channels.stage_add("nonexistent", None)

    def test_stage_with_state_channels_model(self):
        channels = StagedWithStateChannels()
        with channels._connection_context("StagingStateTest"):
            channels.set_stage(StagedWithStateChannels.orders)
        assert "orders" in channels.staged_channels()


class TestStagingAnnotation:
    """Tests for Stage() annotation marker — symmetric with State()."""

    def test_annotation_declares_staging(self):
        """Stage() in Annotated auto-wires staging during finalization."""

        class AnnotatedChannels(GatewayChannels):
            orders: Annotated[ts[OrderStruct], Stage()] = None

        assert "orders" in AnnotatedChannels._declared_stages

    def test_annotation_wires_staging_via_harness(self):
        """Annotation-declared staging is wired during finalization like State."""

        class AnnotatedChannels(GatewayChannels):
            orders: Annotated[ts[OrderStruct], Stage()] = None

        class AnnotatedModule(GatewayModule):
            def connect(self, channels: AnnotatedChannels) -> None:
                channels.set_channel(AnnotatedChannels.orders, csp.null_ts(OrderStruct))

        class AnnotatedGateway(Gateway):
            channels_model: type[Channels] = AnnotatedChannels  # type: ignore[assignment]

        import socket

        from csp_gateway import GatewaySettings, MountRestRoutes

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            s.listen(1)
            port = s.getsockname()[1]

        module = AnnotatedModule()
        gateway = AnnotatedGateway(
            modules=[module, MountRestRoutes(force_mount_all=True)],
            channels=AnnotatedChannels(),
            settings=GatewaySettings(PORT=port),
        )
        gateway.start(rest=True, _in_test=True)
        try:
            assert "orders" in gateway.channels.staged_channels()
            # Can use staging API
            s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
            ids = gateway.channels.stage_add("orders", s)
            assert len(ids) == 1
        finally:
            gateway.stop()

    def test_set_stage_and_annotation_dont_conflict(self):
        """If a channel has both annotation and set_stage, only one stage is created."""

        class DualChannels(GatewayChannels):
            orders: Annotated[ts[OrderStruct], Stage()] = None

        class DualModule(GatewayModule):
            def connect(self, channels: DualChannels) -> None:
                channels.set_channel(DualChannels.orders, csp.null_ts(OrderStruct))
                channels.set_stage(DualChannels.orders)

        class DualGateway(Gateway):
            channels_model: type[Channels] = DualChannels  # type: ignore[assignment]

        import socket

        from csp_gateway import GatewaySettings, MountRestRoutes

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            s.listen(1)
            port = s.getsockname()[1]

        module = DualModule()
        gateway = DualGateway(
            modules=[module, MountRestRoutes(force_mount_all=True)],
            channels=DualChannels(),
            settings=GatewaySettings(PORT=port),
        )
        gateway.start(rest=True, _in_test=True)
        try:
            assert "orders" in gateway.channels.staged_channels()
            assert gateway.channels.staged_channels().count("orders") == 1
        finally:
            gateway.stop()


# --- Test with harness ---


class TestStagingHarness:
    def test_harness_with_staging(self):
        """Test that the harness works with a staging-enabled module."""

        class HarnessChannels(GatewayChannels):
            orders: ts[OrderStruct] = None

        class HarnessStagingModule(GatewayModule):
            def connect(self, channels: HarnessChannels) -> None:
                channels.set_stage(HarnessChannels.orders)

            def shutdown(self) -> None:
                pass

        class HarnessGateway(Gateway):
            channels_model: type[Channels] = HarnessChannels  # type: ignore[assignment]

        harness = GatewayTestHarness(
            test_channels=["orders"],
        )
        s = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
        harness.send("orders", s)
        harness.delay(timedelta(seconds=1))
        harness.assert_equal("orders", s)

        module = HarnessStagingModule()
        gateway = HarnessGateway(modules=[module, harness], channels=HarnessChannels())
        csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=5))

    def test_stage_release_pushes_to_channel(self):
        """Test that stage_release via the gateway pushes items into the csp channel.

        Note: GenericPushAdapter.push_tick only works in realtime mode.
        We use gateway.start(rest=True, _in_test=True) which runs csp on a thread.
        """

        class ReleaseChannels(GatewayChannels):
            orders: ts[OrderStruct] = None

        class ReleaseStagingModule(GatewayModule):
            def connect(self, channels: ReleaseChannels) -> None:
                channels.set_stage(ReleaseChannels.orders)
                channels.add_send_channel(ReleaseChannels.orders)

            def shutdown(self) -> None:
                pass

        class ReleaseGateway(Gateway):
            channels_model: type[Channels] = ReleaseChannels  # type: ignore[assignment]

        import socket

        from csp_gateway import GatewaySettings, MountRestRoutes

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            s.listen(1)
            port = s.getsockname()[1]

        module = ReleaseStagingModule()
        gateway = ReleaseGateway(
            modules=[module, MountRestRoutes(force_mount_all=True)],
            channels=ReleaseChannels(),
            settings=GatewaySettings(PORT=port),
        )

        gateway.start(rest=True, _in_test=True)
        try:
            # Stage items
            s1 = OrderStruct(symbol="AAPL", quantity=100, price=150.0)
            s2 = OrderStruct(symbol="GOOG", quantity=50, price=2800.0)
            ids = gateway.channels.stage_add("orders", s1)
            gateway.channels.stage_add("orders", s2, staging_ids=ids)

            # Verify staged content
            contents = gateway.channels.stage_lookup("orders", ids[0])
            assert len(contents[ids[0]]) == 2

            # Release - this calls push_tick internally
            released = gateway.channels.stage_release("orders", staging_ids=ids)
            assert ids[0] in released
            assert len(released[ids[0]]) == 2
            assert released[ids[0]][0].symbol == "AAPL"
            assert released[ids[0]][1].symbol == "GOOG"

            # After release, staging should be empty
            assert gateway.channels.stage_list("orders") == []
        finally:
            gateway.stop()


# --- Staging event stream ---


def _events():
    """A _StageManager plus the (action, staging_id, item_ids) deltas it reports."""
    captured = []

    def on_event(events):
        captured.extend((action, sid, [i.id for i in items]) for action, sid, items in events)

    return _StageManager(on_event=on_event), captured


class TestStagingEvents:
    def test_empty_staging_reports_created(self):
        stage, captured = _events()
        (sid,) = stage.stage_add()
        assert captured == [(StagingAction.CREATED, sid, [])]

    def test_first_add_reports_created_then_added(self):
        stage, captured = _events()
        s = OrderStruct(symbol="AAPL")
        (sid,) = stage.stage_add(s)
        assert captured == [(StagingAction.CREATED, sid, []), (StagingAction.ADDED, sid, [s.id])]

    def test_subsequent_add_reports_only_added(self):
        stage, captured = _events()
        (sid,) = stage.stage_add(OrderStruct(symbol="AAPL"))
        captured.clear()
        s2 = OrderStruct(symbol="GOOG")
        stage.stage_add(s2, staging_ids=[sid])
        assert captured == [(StagingAction.ADDED, sid, [s2.id])]

    def test_removing_a_record_reports_removed(self):
        stage, captured = _events()
        s = OrderStruct(symbol="AAPL")
        (sid,) = stage.stage_add(s)
        captured.clear()
        stage.stage_remove(s, staging_ids=[sid])
        assert captured == [(StagingAction.REMOVED, sid, [s.id])]

    def test_clearing_contents_reports_one_removal_per_record(self):
        stage, captured = _events()
        s1, s2 = OrderStruct(symbol="AAPL"), OrderStruct(symbol="GOOG")
        (sid,) = stage.stage_add(s1)
        stage.stage_add(s2, staging_ids=[sid])
        captured.clear()
        stage.stage_remove(staging_ids=[sid])
        assert captured == [(StagingAction.REMOVED, sid, [s1.id]), (StagingAction.REMOVED, sid, [s2.id])]

    def test_dropping_a_staging_reports_its_records_then_itself(self):
        stage, captured = _events()
        s = OrderStruct(symbol="AAPL")
        (sid,) = stage.stage_add(s)
        captured.clear()
        stage.stage_remove()  # drops the latest staging entirely
        assert captured == [(StagingAction.REMOVED, sid, [s.id]), (StagingAction.REMOVED, sid, [])]

    def test_release_reports_released_with_its_contents(self):
        stage, captured = _events()
        s1, s2 = OrderStruct(symbol="AAPL"), OrderStruct(symbol="GOOG")
        (sid,) = stage.stage_add(s1)
        stage.stage_add(s2, staging_ids=[sid])
        captured.clear()
        stage.stage_release([sid])
        assert captured == [(StagingAction.RELEASED, sid, [s1.id, s2.id])]

    def test_no_op_removal_reports_nothing(self):
        stage, captured = _events()
        stage.stage_add(OrderStruct(symbol="AAPL"))
        captured.clear()
        stage.stage_remove(OrderStruct(symbol="MSFT"), staging_ids=[])
        assert captured == []

    def test_events_are_optional(self):
        # The manager is usable without an observer (the REST-only path).
        stage = _StageManager()
        (sid,) = stage.stage_add(OrderStruct(symbol="AAPL"))
        assert stage.stage_list() == [sid]

    def test_released_stagings_are_not_retained(self):
        # A release is delivered on the channel and as an event; the area itself is dropped rather than
        # archived, so lookups do not grow without bound.
        stage, _captured = _events()
        (sid,) = stage.stage_add(OrderStruct(symbol="AAPL"))
        stage.stage_release([sid])
        assert stage.stage_list() == []
        assert stage.stage_lookup() == {}
        assert stage.stage_lookup(sid) == {}


@csp.node
def _collect_stage_events(events: ts[StagingEvent], out: list) -> None:
    if csp.ticked(events):
        out.append((events.action, events.staging_id, [i.symbol for i in events.items]))


@csp.node
def _mirror_staging(events: ts[StagingEvent], channels: object, field: str) -> None:
    """Build a derived staging from an upstream one, and follow its release."""
    if csp.ticked(events):
        if events.action == StagingAction.ADDED:
            for item in events.items:
                channels.stage_add(field, OrderStruct(symbol=f"HEDGE:{item.symbol}", quantity=-item.quantity))
        elif events.action == StagingAction.RELEASED:
            channels.stage_release(field)


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("", 0))
        sock.listen(1)
        return sock.getsockname()[1]


def _wait_for(predicate, timeout: float = 5.0) -> None:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out waiting for staging events")


class TestStagingEventChannel:
    """`get_stage_events` exposes the delta stream to modules as a normal timeseries."""

    def test_events_reach_a_module_through_the_graph(self):
        from csp_gateway import GatewaySettings

        collected = []

        class EventChannels(GatewayChannels):
            orders: ts[OrderStruct] = None

        class Producer(GatewayModule):
            def connect(self, channels: EventChannels) -> None:
                channels.set_channel("orders", csp.null_ts(OrderStruct))
                channels.set_stage("orders")

        class Observer(GatewayModule):
            def connect(self, channels: EventChannels) -> None:
                _collect_stage_events(channels.get_stage_events("orders"), collected)

        class EventGateway(Gateway):
            channels_model: type[Channels] = EventChannels  # type: ignore[assignment]

        gateway = EventGateway(
            modules=[Producer(), Observer()],
            channels=EventChannels(),
            settings=GatewaySettings(PORT=_free_port()),
        )
        gateway.start(rest=True, _in_test=True)
        try:
            order = OrderStruct(symbol="AAPL", quantity=10)
            (sid,) = gateway.channels.stage_add("orders", order)
            _wait_for(lambda: len(collected) >= 2)
            assert collected[0] == (StagingAction.CREATED, sid, [])
            assert collected[1] == (StagingAction.ADDED, sid, ["AAPL"])

            gateway.channels.stage_release("orders", staging_ids=[sid])
            _wait_for(lambda: any(e[0] == StagingAction.RELEASED for e in collected))
            assert (StagingAction.RELEASED, sid, ["AAPL"]) in collected
        finally:
            gateway.stop()

    def test_a_module_can_derive_and_cascade_a_staging(self):
        # The motivating case: react to an upstream staging, build your own, and release it when the
        # upstream one releases.
        from csp_gateway import GatewaySettings

        class CascadeChannels(GatewayChannels):
            orders: ts[OrderStruct] = None
            hedges: ts[OrderStruct] = None

        class Producer(GatewayModule):
            def connect(self, channels: CascadeChannels) -> None:
                channels.set_channel("orders", csp.null_ts(OrderStruct))
                channels.set_stage("orders")

        class Hedger(GatewayModule):
            def connect(self, channels: CascadeChannels) -> None:
                channels.set_channel("hedges", csp.null_ts(OrderStruct))
                channels.set_stage("hedges")
                _mirror_staging(channels.get_stage_events("orders"), channels, "hedges")

        class CascadeGateway(Gateway):
            channels_model: type[Channels] = CascadeChannels  # type: ignore[assignment]

        gateway = CascadeGateway(
            modules=[Producer(), Hedger()],
            channels=CascadeChannels(),
            settings=GatewaySettings(PORT=_free_port()),
        )
        gateway.start(rest=True, _in_test=True)
        try:
            (sid,) = gateway.channels.stage_add("orders", OrderStruct(symbol="AAPL", quantity=10))

            # The hedger staged its own derived order in response.
            _wait_for(lambda: gateway.channels.stage_list("hedges"))
            (hedge_sid,) = gateway.channels.stage_list("hedges")
            hedged = gateway.channels.stage_lookup("hedges", hedge_sid)[hedge_sid]
            assert [(h.symbol, h.quantity) for h in hedged] == [("HEDGE:AAPL", -10)]

            # Releasing upstream releases the derived staging too.
            gateway.channels.stage_release("orders", staging_ids=[sid])
            _wait_for(lambda: not gateway.channels.stage_list("hedges"))
            assert gateway.channels.stage_list("hedges") == []
        finally:
            gateway.stop()


class TestStagingRequests:
    """`set_stage_requests` drives staging from a timeseries instead of imperative calls."""

    def test_requests_stage_and_release_from_the_graph(self):
        from csp_gateway import GatewaySettings

        class RequestChannels(GatewayChannels):
            orders: ts[OrderStruct] = None

        class Requester(GatewayModule):
            def connect(self, channels: RequestChannels) -> None:
                channels.set_channel("orders", csp.null_ts(OrderStruct))
                channels.set_stage("orders")
                requests = csp.curve(
                    StagingRequest,
                    [
                        (timedelta(seconds=0.1), StagingRequest(action=StagingAction.ADDED, items=[OrderStruct(symbol="AAPL", quantity=5)])),
                        (timedelta(seconds=0.2), StagingRequest(action=StagingAction.ADDED, items=[OrderStruct(symbol="GOOG", quantity=7)])),
                    ],
                )
                channels.set_stage_requests("orders", requests)

        class RequestGateway(Gateway):
            channels_model: type[Channels] = RequestChannels  # type: ignore[assignment]

        gateway = RequestGateway(
            modules=[Requester()],
            channels=RequestChannels(),
            settings=GatewaySettings(PORT=_free_port()),
        )
        gateway.start(rest=True, _in_test=True)
        try:
            _wait_for(lambda: gateway.channels.stage_list("orders"))
            (sid,) = gateway.channels.stage_list("orders")
            _wait_for(lambda: len(gateway.channels.stage_lookup("orders", sid).get(sid, [])) == 2)
            staged = gateway.channels.stage_lookup("orders", sid)[sid]
            assert [s.symbol for s in staged] == ["AAPL", "GOOG"]
        finally:
            gateway.stop()

    def test_requests_require_staging_to_be_enabled(self):
        from csp_gateway import GatewaySettings

        class PlainChannels(GatewayChannels):
            orders: ts[OrderStruct] = None

        class BadModule(GatewayModule):
            def connect(self, channels: PlainChannels) -> None:
                channels.set_channel("orders", csp.null_ts(OrderStruct))
                with pytest.raises(NoProviderException, match="No staging enabled"):
                    channels.set_stage_requests("orders", csp.null_ts(StagingRequest))

        class PlainGateway(Gateway):
            channels_model: type[Channels] = PlainChannels  # type: ignore[assignment]

        gateway = PlainGateway(
            modules=[BadModule()],
            channels=PlainChannels(),
            settings=GatewaySettings(PORT=_free_port()),
        )
        gateway.start(rest=True, _in_test=True)
        gateway.stop()

    def test_get_stage_events_requires_staging_to_be_enabled(self):
        channels = GatewayChannels()
        with pytest.raises(NoProviderException, match="No staging enabled"):
            channels.get_stage_events("nope")
