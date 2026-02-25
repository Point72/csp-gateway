"""Tests for standard library logging integration module."""

import logging
import os
import tempfile
from datetime import datetime, timedelta

import csp
import pytest

from csp_gateway import Gateway, LogChannels
from csp_gateway.server.modules.logging import stdlib as stdlib_mod
from csp_gateway.server.modules.logging.stdlib import (
    Logging,
    _build_logging_config,
    configure_stdlib_logging,
    is_stdlib_logging_configured,
)
from csp_gateway.testing.shared_helpful_classes import (
    MyDictBasketModule,
    MyExampleModule,
    MyGateway,
    MyGatewayChannels,
    MyGetModule,
    MyNoTickDictBasket,
    MySetModule,
    MySmallGatewayChannels,
    MyStruct,
)

# =============================================================================
# Tests for Logging module
# =============================================================================


class TestLoggingAvailability:
    """Tests for logging module availability checking functions."""

    @pytest.fixture(autouse=True)
    def reset_stdlib_state(self):
        """Reset stdlib logging state before each test."""
        original = stdlib_mod._stdlib_logging_configured
        stdlib_mod._stdlib_logging_configured = False
        yield
        stdlib_mod._stdlib_logging_configured = original

    def test_is_stdlib_logging_configured_initially_false(self):
        """Test is_stdlib_logging_configured returns False initially."""
        assert is_stdlib_logging_configured() is False


class TestConfigureStdlibLogging:
    """Tests for the configure_stdlib_logging function."""

    @pytest.fixture(autouse=True)
    def reset_stdlib_state(self):
        """Reset stdlib logging state before each test."""
        original = stdlib_mod._stdlib_logging_configured
        stdlib_mod._stdlib_logging_configured = False
        yield
        stdlib_mod._stdlib_logging_configured = original

    def test_configure_stdlib_logging_returns_true_on_first_call(self):
        """Test that configure_stdlib_logging returns True on first call."""
        result = configure_stdlib_logging()
        assert result is True

    def test_configure_stdlib_logging_returns_false_if_already_configured(self):
        """Test that configure_stdlib_logging returns False if already configured."""
        stdlib_mod._stdlib_logging_configured = True
        result = configure_stdlib_logging()
        assert result is False

    def test_configure_stdlib_logging_sets_flag(self):
        """Test that configure_stdlib_logging sets the configured flag."""
        assert is_stdlib_logging_configured() is False
        configure_stdlib_logging()
        assert is_stdlib_logging_configured() is True

    def test_configure_stdlib_logging_with_custom_levels(self):
        """Test configure_stdlib_logging with custom log levels."""
        result = configure_stdlib_logging(
            console_level="WARNING",
            file_level="ERROR",
            root_level="INFO",
        )
        assert result is True

    def test_configure_stdlib_logging_with_file(self):
        """Test configure_stdlib_logging with file output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.log")
            result = configure_stdlib_logging(log_file=log_file)
            assert result is True

            # Log something and verify file was created
            test_logger = logging.getLogger("test_stdlib_logging")
            test_logger.info("Test message")

            # File should exist
            assert os.path.exists(log_file)


class TestBuildLoggingConfig:
    """Tests for the _build_logging_config function."""

    def test_build_logging_config_defaults(self):
        """Test _build_logging_config with default values."""
        config = _build_logging_config()

        assert config["version"] == 1
        assert config["disable_existing_loggers"] is False
        assert "simple" in config["formatters"]
        assert "whenAndWhere" in config["formatters"]
        assert "console" in config["handlers"]
        assert config["root"]["handlers"] == ["console"]
        assert config["root"]["level"] == logging.DEBUG

    def test_build_logging_config_with_file(self):
        """Test _build_logging_config with file handler."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.log")
            config = _build_logging_config(log_file=log_file)

            assert "file" in config["handlers"]
            assert config["handlers"]["file"]["filename"] == log_file
            assert "file" in config["root"]["handlers"]

    def test_build_logging_config_with_logger_levels(self):
        """Test _build_logging_config with custom logger levels."""
        config = _build_logging_config(logger_levels={"uvicorn.error": logging.CRITICAL, "myapp": "DEBUG"})

        assert "uvicorn.error" in config["loggers"]
        assert config["loggers"]["uvicorn.error"]["level"] == logging.CRITICAL
        assert "myapp" in config["loggers"]
        assert config["loggers"]["myapp"]["level"] == logging.DEBUG

    def test_build_logging_config_no_colors(self):
        """Test _build_logging_config with colors disabled."""
        config = _build_logging_config(use_colors=False, console_formatter="colorlog")

        # Should fall back to simple when colors disabled
        assert config["handlers"]["console"]["formatter"] == "simple"


class TestLoggingModule:
    """Tests for the Logging GatewayModule."""

    @pytest.fixture(autouse=True)
    def reset_stdlib_state(self):
        """Reset stdlib logging state before each test."""
        original = stdlib_mod._stdlib_logging_configured
        stdlib_mod._stdlib_logging_configured = False
        yield
        stdlib_mod._stdlib_logging_configured = original

    def test_logging_module_instantiation_configures_early(self):
        """Test that instantiating Logging module configures logging."""
        assert is_stdlib_logging_configured() is False

        # Instantiate module (this triggers early configuration)
        module = Logging()

        assert is_stdlib_logging_configured() is True
        assert module._configured_by_this_instance is True

    def test_logging_module_with_custom_console_level(self):
        """Test Logging module with custom console level."""
        module = Logging(console_level=logging.WARNING)
        assert module.console_level == logging.WARNING

    def test_logging_module_with_string_levels(self):
        """Test Logging module with string log levels."""
        module = Logging(
            console_level="WARNING",
            file_level="ERROR",
            root_level="INFO",
        )
        assert module.console_level == logging.WARNING
        assert module.file_level == logging.ERROR
        assert module.root_level == logging.INFO

    def test_logging_module_with_file(self):
        """Test Logging module with file output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.log")
            module = Logging(log_file=log_file, use_hydra_output_dir=False)

            assert module._resolved_log_file == log_file
            assert is_stdlib_logging_configured() is True

    def test_logging_module_with_logger_levels(self):
        """Test Logging module with custom logger levels."""
        module = Logging(logger_levels={"uvicorn.error": logging.CRITICAL, "myapp": "DEBUG"})
        assert module.logger_levels["uvicorn.error"] == logging.CRITICAL

    def test_logging_module_connect_is_noop(self):
        """Test that calling connect is a no-op."""
        module = Logging()

        # Should not raise
        module.connect(None)

    def test_logging_module_invalid_level_raises(self):
        """Test that invalid log level raises ValueError."""
        with pytest.raises(ValueError, match="Invalid log level"):
            Logging(console_level="INVALID_LEVEL")

    def test_logging_second_instance_skips_config(self):
        """Test that a second instance does not reconfigure logging."""
        module1 = Logging()
        assert module1._configured_by_this_instance is True

        module2 = Logging()
        assert module2._configured_by_this_instance is False


# =============================================================================
# Tests for LogChannels module (existing tests)
# =============================================================================


@pytest.mark.parametrize("which_channels", [[MySmallGatewayChannels.example], {}])
def test_LogChannels(which_channels, caplog):
    logger = LogChannels(selection=which_channels)
    gateway = Gateway(
        modules=[MyExampleModule(), logger],
        channels=MySmallGatewayChannels(),
    )
    with caplog.at_level(logging.INFO):
        gateway.start(starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=1))
    expected = (
        "csp_gateway.server.modules.logging.stdlib",
        logging.INFO,
        "2020-01-01 00:00:01 example:1",
    )
    assert expected in caplog.record_tuples


def test_LogChannels_dict_basket(caplog):
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = Gateway(
        modules=[
            MyDictBasketModule(my_data=csp.const(2.0)),
            logger,
        ],
        channels=MySmallGatewayChannels(),
    )
    with caplog.at_level(logging.INFO, logger="gateway_modules_test_logger"):
        gateway.start(starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=1))
    expected = (
        "gateway_modules_test_logger",
        20,
        "2020-01-01 00:00:00 my_str_basket[my_key]:2.0",
    )
    assert expected in caplog.record_tuples


def test_LogChannels_no_tick_dict_basket(caplog):
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = Gateway(
        modules=[
            MyNoTickDictBasket(my_data=csp.const(2.0)),
            logger,
        ],
        channels=MySmallGatewayChannels(),
    )
    with caplog.at_level(logging.INFO, logger="gateway_modules_test_logger"):
        gateway.start(starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=1))
    for logger, _level, _message in caplog.record_tuples:
        assert logger != "gateway_modules_test_logger"


def test_LogChannels_state(caplog):
    logger = LogChannels(
        log_name="gateway_modules_test_logger",
        log_states=True,
    )
    gateway = MyGateway(modules=[MyExampleModule(), logger], channels=MySmallGatewayChannels())
    with caplog.at_level(logging.INFO):
        csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=3))
    # why do we have use 'caplog.text' here? The record_tuples uses some interpolation
    # and for recording state that makes the actual captured log_calls different from
    # the ones in caplog.record_tuples
    assert "2020-01-01 00:00:02 s_example:[2]" in caplog.text


def test_LogChannels_no_state(caplog):
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = MyGateway(modules=[MyExampleModule(), logger], channels=MySmallGatewayChannels())
    with caplog.at_level(logging.INFO):
        csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=3))
    assert "s_example" not in caplog.text


@pytest.mark.parametrize("by_key", [True, False])
def test_get_set_LogChannels_doesnt_break(by_key, caplog):
    setter = MySetModule(
        my_data=csp.const(MyStruct(foo=1.0)),
        my_data2=csp.const(MyStruct(foo=2.0)),
        my_list_data=csp.const([MyStruct(foo=1.0), MyStruct(foo=2.0)]),
        by_key=by_key,
    )
    getter = MyGetModule()
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = MyGateway(modules=[getter, setter, logger], channels=MyGatewayChannels())
    with caplog.at_level(logging.INFO, logger="gateway_modules_test_logger"):
        out = csp.run(gateway.graph, starttime=datetime(2020, 1, 1), endtime=timedelta(1))
    assert len(out["my_channel"]) == 1
    assert len(out["my_list_channel"]) == 1
    assert len(out["my_list_channel"][0][1]) == 2
    assert len(out["my_array_channel"]) == 1
    assert len(out["my_array_channel"][0][1]) == 2
    assert len(out["my_enum_basket[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket[MyEnum.TWO]"]) == 1
    assert len(out["my_str_basket[my_key]"]) == 1
    assert len(out["my_str_basket[my_key2]"]) == 1
    assert len(out["my_enum_basket_list[MyEnum.ONE]"]) == 1
    assert len(out["my_enum_basket_list[MyEnum.TWO]"]) == 1
    assert len(out["my_enum_basket_ONE"]) == 1
    assert len(out["my_enum_basket_TWO"]) == 1
    assert len(out["my_str_basket_my_key"]) == 1
    assert len(out["my_str_basket_my_key2"]) == 1


def test_LogChannels_nothing_set(caplog):
    logger = LogChannels(log_name="gateway_modules_test_logger")
    gateway = Gateway(
        modules=[
            logger,
        ],
        channels=MySmallGatewayChannels(),
    )
    with caplog.at_level(logging.INFO, logger="gateway_modules_test_logger"):
        gateway.start(starttime=datetime(2020, 1, 1), endtime=timedelta(seconds=1))
    for logger, _level, _message in caplog.record_tuples:
        assert logger != "gateway_modules_test_logger"
