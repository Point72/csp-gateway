"""Tests for Logfire integration module."""

import logging
from datetime import datetime, timedelta
from typing import Dict
from unittest.mock import MagicMock, patch

import csp
import pytest
from csp import ts

from csp_gateway import Gateway, GatewayChannels, GatewayModule, GatewayStruct

# Check for the Pydantic logfire observability package (not the basic logfire logger)
try:
    import logfire

    # Check if it's the Pydantic logfire by looking for configure
    if not hasattr(logfire, "configure"):
        logfire = None
except ImportError:
    logfire = None

# Import our logfire module using from...import to avoid naming conflicts
# with the logging.py file in the same package
from csp_gateway.server.modules.logging import logfire as logfire_mod


# Sample data structures for testing (prefixed with Sample_ to avoid pytest collection)
class SampleStruct(GatewayStruct):
    value: float
    name: str = "test"


class SampleGatewayChannels(GatewayChannels):
    test_channel: ts[SampleStruct] = None
    test_int: ts[int] = None
    test_basket: Dict[str, ts[float]] = None


class SampleDataModule(GatewayModule):
    """Module that produces test data for channels."""

    def connect(self, channels: SampleGatewayChannels) -> None:
        channels.set_channel(
            SampleGatewayChannels.test_channel,
            csp.const(SampleStruct(value=42.0, name="test_data")),
        )
        channels.set_channel(
            SampleGatewayChannels.test_int,
            csp.const(123),
        )

    def dynamic_keys(self):
        return {SampleGatewayChannels.test_basket: ["key1", "key2"]}


class SampleDictBasketModule(GatewayModule):
    """Module that produces dict basket data."""

    def dynamic_keys(self):
        return {SampleGatewayChannels.test_basket: ["key1", "key2"]}

    def connect(self, channels: SampleGatewayChannels) -> None:
        channels.set_channel(SampleGatewayChannels.test_basket, csp.const(1.0), "key1")
        channels.set_channel(SampleGatewayChannels.test_basket, csp.const(2.0), "key2")


class TestLogfireAvailability:
    """Tests for logfire availability checking functions."""

    def test_is_logfire_configured_initially_false(self):
        """Test is_logfire_configured returns False initially."""
        # Reset state
        logfire_mod._logfire_configured = False

        from csp_gateway.server.modules.logging.logfire import is_logfire_configured

        assert is_logfire_configured() is False


class TestConfigureLogfireEarly:
    """Tests for the configure_logfire_early function."""

    @pytest.fixture(autouse=True)
    def reset_logfire_state(self):
        """Reset logfire state before each test."""
        original_configured = logfire_mod._logfire_configured
        original_handler = logfire_mod._logfire_handler
        logfire_mod._logfire_configured = False
        logfire_mod._logfire_handler = None
        yield
        # Restore original state
        logfire_mod._logfire_configured = original_configured
        logfire_mod._logfire_handler = original_handler

    def test_configure_logfire_early_returns_false_if_already_configured(self):
        """Test that configure_logfire_early returns False if already configured."""
        logfire_mod._logfire_configured = True

        from csp_gateway.server.modules.logging.logfire import configure_logfire_early

        result = configure_logfire_early()
        assert result is False

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_configure_logfire_early_with_send_to_logfire_false(self):
        """Test configure_logfire_early with send_to_logfire=False."""
        from csp_gateway.server.modules.logging.logfire import configure_logfire_early

        result = configure_logfire_early(send_to_logfire=False)
        assert result is True

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_configure_logfire_early_sets_service_name(self):
        """Test configure_logfire_early respects service_name parameter."""
        from csp_gateway.server.modules.logging.logfire import configure_logfire_early

        result = configure_logfire_early(
            service_name="test-service",
            send_to_logfire=False,
        )
        assert result is True


class TestLogfireModule:
    """Tests for the Logfire GatewayModule."""

    @pytest.fixture(autouse=True)
    def reset_logfire_state(self):
        """Reset logfire state before each test."""
        original_configured = logfire_mod._logfire_configured
        original_handler = logfire_mod._logfire_handler
        logfire_mod._logfire_configured = False
        logfire_mod._logfire_handler = None
        yield
        # Restore and cleanup
        logfire_mod._logfire_configured = original_configured
        logfire_mod._logfire_handler = original_handler

        # Remove any test handlers from root logger
        root_logger = logging.getLogger()
        try:
            from logfire.integrations.logging import LogfireLoggingHandler

            for handler in root_logger.handlers[:]:
                if isinstance(handler, LogfireLoggingHandler):
                    root_logger.removeHandler(handler)
        except ImportError:
            # LogfireLoggingHandler not available, skip cleanup
            pass

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_module_instantiation_configures_early(self):
        """Test that instantiating Logfire module configures logfire."""
        from csp_gateway.server.modules.logging.logfire import (
            Logfire,
            is_logfire_configured,
        )

        # Logfire should not be configured yet
        assert is_logfire_configured() is False

        # Instantiate module (this triggers early configuration)
        module = Logfire(send_to_logfire=False)

        # Logfire should now be configured
        assert is_logfire_configured() is True
        assert module._configured_by_this_instance is True

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_module_with_custom_service_name(self):
        """Test Logfire module with custom service name."""
        from csp_gateway.server.modules.logging.logfire import Logfire

        module = Logfire(
            service_name="custom-service",
            send_to_logfire=False,
        )
        assert module.service_name == "custom-service"

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_module_capture_logging(self):
        """Test that Logfire module installs logging handler."""
        from logfire import LogfireLoggingHandler

        from csp_gateway.server.modules.logging.logfire import Logfire

        _ = Logfire(
            capture_logging=True,
            send_to_logfire=False,
        )

        root_logger = logging.getLogger()
        has_logfire_handler = any(isinstance(h, LogfireLoggingHandler) for h in root_logger.handlers)
        assert has_logfire_handler is True

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_module_no_capture_logging(self):
        """Test Logfire module without logging capture."""
        from csp_gateway.server.modules.logging.logfire import Logfire

        # First clean any existing handlers
        root_logger = logging.getLogger()
        from logfire import LogfireLoggingHandler

        for handler in root_logger.handlers[:]:
            if isinstance(handler, LogfireLoggingHandler):
                root_logger.removeHandler(handler)

        module = Logfire(
            capture_logging=False,
            send_to_logfire=False,
        )

        # Should not have added a handler since capture_logging=False
        # Note: connect() might still be called by the gateway
        assert module.capture_logging is False

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_module_connect_is_idempotent(self):
        """Test that calling connect multiple times is safe."""
        from csp_gateway.server.modules.logging.logfire import Logfire

        module = Logfire(send_to_logfire=False)

        # Create a simple channels mock
        channels = MagicMock()

        # Call connect multiple times - should not raise
        module.connect(channels)
        module.connect(channels)

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_module_rest_instruments_fastapi(self):
        """Test that rest() method instruments FastAPI."""
        from csp_gateway.server.modules.logging.logfire import Logfire

        module = Logfire(
            instrument_fastapi=True,
            send_to_logfire=False,
        )

        # Mock the app
        mock_app = MagicMock()
        mock_app.app = MagicMock()

        with patch("logfire.instrument_fastapi") as mock_instrument:
            module.rest(mock_app)
            mock_instrument.assert_called_once()

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_module_rest_skips_when_disabled(self):
        """Test that rest() skips instrumentation when disabled."""
        from csp_gateway.server.modules.logging.logfire import Logfire

        module = Logfire(
            instrument_fastapi=False,
            send_to_logfire=False,
        )

        mock_app = MagicMock()

        with patch("logfire.instrument_fastapi") as mock_instrument:
            module.rest(mock_app)
            mock_instrument.assert_not_called()


class TestPublishLogfireModule:
    """Tests for the PublishLogfire GatewayModule."""

    @pytest.fixture(autouse=True)
    def reset_logfire_state(self):
        """Reset logfire state before each test."""
        original_configured = logfire_mod._logfire_configured
        original_handler = logfire_mod._logfire_handler
        logfire_mod._logfire_configured = False
        logfire_mod._logfire_handler = None
        yield
        logfire_mod._logfire_configured = original_configured
        logfire_mod._logfire_handler = original_handler

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_channels_instantiation(self):
        """Test PublishLogfire can be instantiated."""
        from csp_gateway.server.modules.logging.logfire import PublishLogfire

        module = PublishLogfire()
        assert module.log_states is False
        assert module.log_level == logging.INFO
        assert module.use_spans is False

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_channels_with_selection(self):
        """Test PublishLogfire with channel selection."""
        from csp_gateway.server.modules.logging.logfire import PublishLogfire

        module = PublishLogfire(
            selection={"include": ["test_channel"]},
            log_level=logging.DEBUG,
        )
        assert module.selection.include == ["test_channel"]
        assert module.log_level == logging.DEBUG

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_channels_with_service_name(self):
        """Test PublishLogfire with custom service name."""
        from csp_gateway.server.modules.logging.logfire import PublishLogfire

        module = PublishLogfire(service_name="channel-logger")
        assert module.service_name == "channel-logger"

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_channels_use_spans(self):
        """Test PublishLogfire with span mode."""
        from csp_gateway.server.modules.logging.logfire import PublishLogfire

        module = PublishLogfire(use_spans=True)
        assert module.use_spans is True

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_channels_in_gateway(self):
        """Test PublishLogfire works in a Gateway."""

        from csp_gateway.server.modules.logging.logfire import (
            Logfire,
            PublishLogfire,
        )

        # Configure logfire first
        logfire_module = Logfire(send_to_logfire=False)

        # Create channels module
        channels_module = PublishLogfire(
            selection={"include": ["test_int"]},
        )

        gateway = Gateway(
            modules=[SampleDataModule(), logfire_module, channels_module],
            channels=SampleGatewayChannels(),
        )

        # Run the gateway briefly
        gateway.start(
            starttime=datetime(2020, 1, 1),
            endtime=timedelta(seconds=1),
        )

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_channels_with_dict_basket(self):
        """Test PublishLogfire with dict basket channels."""
        from csp_gateway.server.modules.logging.logfire import (
            Logfire,
            PublishLogfire,
        )

        logfire_module = Logfire(send_to_logfire=False)
        channels_module = PublishLogfire(
            selection={"include": ["test_basket"]},
        )

        gateway = Gateway(
            modules=[SampleDictBasketModule(), logfire_module, channels_module],
            channels=SampleGatewayChannels(),
        )

        gateway.start(
            starttime=datetime(2020, 1, 1),
            endtime=timedelta(seconds=1),
        )


class TestLogfireIntegration:
    """Integration tests for Logfire with Gateway."""

    @pytest.fixture(autouse=True)
    def reset_logfire_state(self):
        """Reset logfire state before each test."""
        original_configured = logfire_mod._logfire_configured
        original_handler = logfire_mod._logfire_handler
        logfire_mod._logfire_configured = False
        logfire_mod._logfire_handler = None
        yield
        logfire_mod._logfire_configured = original_configured
        logfire_mod._logfire_handler = original_handler

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_full_gateway_with_logfire(self):
        """Test a full Gateway with Logfire integration."""
        from csp_gateway.server.modules.logging.logfire import (
            Logfire,
            PublishLogfire,
        )

        logfire_module = Logfire(
            service_name="test-gateway",
            send_to_logfire=False,
            capture_logging=True,
            instrument_fastapi=False,  # No FastAPI in this test
        )

        channels_module = PublishLogfire(
            selection={"include": ["test_channel", "test_int"]},
            include_metadata=True,
        )

        gateway = Gateway(
            modules=[SampleDataModule(), logfire_module, channels_module],
            channels=SampleGatewayChannels(),
        )

        # Run the gateway
        gateway.start(
            starttime=datetime(2020, 1, 1),
            endtime=timedelta(seconds=2),
        )

    @pytest.mark.skipif(
        logfire is None,
        reason="logfire not installed",
    )
    def test_logfire_captures_gateway_logs(self, caplog):
        """Test that Logfire captures logs from the Gateway."""
        from csp_gateway.server.modules.logging.logfire import Logfire

        with caplog.at_level(logging.INFO):
            logfire_module = Logfire(
                send_to_logfire=False,
                capture_logging=True,
            )

            gateway = Gateway(
                modules=[SampleDataModule(), logfire_module],
                channels=SampleGatewayChannels(),
            )

            gateway.start(
                starttime=datetime(2020, 1, 1),
                endtime=timedelta(seconds=1),
            )

        # Check that some logs were captured
        assert len(caplog.records) > 0
