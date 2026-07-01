"""Tests for the staging functionality."""

from datetime import datetime, timedelta
from typing import Annotated, Type

import csp
import pytest
from csp import ts

from csp_gateway import (
    Channels,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewayStruct,
    State,
)
from csp_gateway.server.gateway.csp.stage import Stage, Staging, _StageManager
from csp_gateway.testing import GatewayTestHarness
from csp_gateway.utils import NoProviderException

# --- Test structures ---


class OrderStruct(GatewayStruct):
    symbol: str = ""
    quantity: int = 0
    price: float = 0.0


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
            channels_model: Type[Channels] = AnnotatedChannels  # type: ignore[assignment]

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
            channels_model: Type[Channels] = DualChannels  # type: ignore[assignment]

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
            channels_model: Type[Channels] = HarnessChannels  # type: ignore[assignment]

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
            channels_model: Type[Channels] = ReleaseChannels  # type: ignore[assignment]

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
