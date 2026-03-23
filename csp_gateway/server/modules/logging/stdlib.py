"""Standard library logging integration for csp-gateway.

This module provides two main classes:

1. `Logging` - Configures Python's standard logging module at instantiation
   time (similar to how Logfire works). Sets up formatters, handlers, and log levels.

2. `LogChannels` - Logs CSP channel data to Python's standard logging.
"""

from __future__ import annotations

import logging
import logging.config
import os
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

import csp
from pydantic import Field, PrivateAttr, field_validator

from csp_gateway.server import ChannelSelection, ChannelsType, GatewayModule

if TYPE_CHECKING:
    pass

__all__ = (
    "Logging",
    "LogChannels",
    "configure_stdlib_logging",
    "is_stdlib_logging_configured",
    # Backwards compatibility alias
    "StdlibLogging",
)

log = logging.getLogger(__name__)

# Global flag to track if stdlib logging has been configured by this module
_stdlib_logging_configured = False


def is_stdlib_logging_configured() -> bool:
    """Check if stdlib logging has been configured by this module.

    Returns:
        bool: True if Logging.configure() has been called, False otherwise.
    """
    return _stdlib_logging_configured


def configure_stdlib_logging(
    console_level: Union[str, int] = logging.INFO,
    file_level: Union[str, int] = logging.DEBUG,
    root_level: Union[str, int] = logging.DEBUG,
    console_formatter: str = "colorlog",
    file_formatter: str = "whenAndWhere",
    log_file: Optional[str] = None,
    use_colors: bool = True,
    logger_levels: Optional[Dict[str, Union[str, int]]] = None,
) -> bool:
    """Configure stdlib logging early in application startup.

    This function can be called as early as possible in the application lifecycle
    to configure Python's standard logging before hydra runs.

    Args:
        console_level: Log level for console output. Defaults to INFO.
        file_level: Log level for file output. Defaults to DEBUG.
        root_level: Root logger level. Defaults to DEBUG.
        console_formatter: Formatter for console output ('simple', 'colorlog', 'whenAndWhere').
        file_formatter: Formatter for file output ('simple', 'colorlog', 'whenAndWhere').
        log_file: Path to log file. If None, file logging is disabled.
        use_colors: Whether to use colorlog for console output.
        logger_levels: Dict mapping logger names to their levels.

    Returns:
        bool: True if logging was configured, False if already configured.

    Example:
        from csp_gateway.server.modules.logging.stdlib import configure_stdlib_logging
        configure_stdlib_logging(console_level="INFO", log_file="/tmp/app.log")
    """
    global _stdlib_logging_configured

    if _stdlib_logging_configured:
        log.debug("Stdlib logging already configured, skipping")
        return False

    # Convert string levels to int
    if isinstance(console_level, str):
        console_level = logging.getLevelName(console_level.upper())
    if isinstance(file_level, str):
        file_level = logging.getLevelName(file_level.upper())
    if isinstance(root_level, str):
        root_level = logging.getLevelName(root_level.upper())

    # Create the logging configuration
    config = _build_logging_config(
        console_level=console_level,
        file_level=file_level,
        root_level=root_level,
        console_formatter=console_formatter,
        file_formatter=file_formatter,
        log_file=log_file,
        use_colors=use_colors,
        logger_levels=logger_levels,
    )

    logging.config.dictConfig(config)
    _stdlib_logging_configured = True
    log.info("Stdlib logging configured")
    return True


def _build_logging_config(
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
    root_level: int = logging.DEBUG,
    console_formatter: str = "colorlog",
    file_formatter: str = "whenAndWhere",
    log_file: Optional[str] = None,
    use_colors: bool = True,
    logger_levels: Optional[Dict[str, Union[str, int]]] = None,
) -> Dict[str, Any]:
    """Build a logging configuration dictionary.

    Returns:
        Dict compatible with logging.config.dictConfig()
    """
    # Default formatters matching custom.yaml
    formatters: Dict[str, Any] = {
        "simple": {"format": "[%(asctime)s][%(threadName)s][%(name)s][%(levelname)s]: %(message)s"},
        "whenAndWhere": {"format": "[%(asctime)s][%(threadName)s][%(name)s][%(filename)s:%(lineno)s][%(levelname)s]: %(message)s"},
    }

    # Add colorlog formatter if requested and available
    if use_colors:
        try:
            import colorlog  # noqa: F401

            formatters["colorlog"] = {
                "()": "colorlog.ColoredFormatter",
                "format": "[%(cyan)s%(asctime)s%(reset)s][%(threadName)s][%(blue)s%(name)s%(reset)s][%(log_color)s%(levelname)s%(reset)s]: %(message)s",
                "log_colors": {
                    "DEBUG": "purple",
                    "INFO": "green",
                    "WARNING": "yellow",
                    "ERROR": "red",
                    "CRITICAL": "red",
                },
            }
        except ImportError:
            # Fall back to simple formatter if colorlog not available
            if console_formatter == "colorlog":
                console_formatter = "simple"
    else:
        # Use simple if colors disabled
        if console_formatter == "colorlog":
            console_formatter = "simple"

    # Build handlers
    handlers: Dict[str, Any] = {
        "console": {
            "level": console_level,
            "class": "logging.StreamHandler",
            "formatter": console_formatter,
            "stream": "ext://sys.stdout",
        }
    }
    root_handlers = ["console"]

    # Add file handler if log_file specified
    if log_file:
        # Ensure directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        handlers["file"] = {
            "level": file_level,
            "class": "logging.FileHandler",
            "formatter": file_formatter,
            "filename": log_file,
        }
        root_handlers.append("file")

    # Build loggers config
    loggers: Dict[str, Any] = {}
    if logger_levels:
        for logger_name, level in logger_levels.items():
            if isinstance(level, str):
                level = logging.getLevelName(level.upper())
            loggers[logger_name] = {"level": level}

    config: Dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters,
        "handlers": handlers,
        "root": {
            "handlers": root_handlers,
            "level": root_level,
        },
        "loggers": loggers,
    }

    return config


class Logging(GatewayModule):
    """Gateway module for Python standard library logging configuration.

    This module configures Python's standard logging at instantiation time,
    similar to how the Logfire module works. It provides:
    - Console and file handler configuration
    - Colored output via colorlog (optional)
    - Per-logger level configuration
    - Early configuration before CSP graph is built

    **Early Configuration**: Unlike most GatewayModules, Logging configures
    itself during __init__ (when the module is instantiated by hydra/ccflow),
    not during connect(). This ensures logging is configured as early as possible.

    The defaults match the previous custom.yaml hydra logging configuration.

    Attributes:
        console_level: Log level for console output. Defaults to INFO.
        file_level: Log level for file output. Defaults to DEBUG.
        root_level: Root logger level. Defaults to DEBUG.
        console_formatter: Formatter for console ('simple', 'colorlog', 'whenAndWhere').
        file_formatter: Formatter for file output.
        log_file: Path to log file. If None, uses hydra output dir or disables.
        use_hydra_output_dir: If True and log_file is None, log to hydra output dir.
        use_colors: Whether to use colorlog for console output.
        logger_levels: Dict mapping logger names to their levels.

    Example YAML configuration::

        modules:
          logging:
            _target_: csp_gateway.server.modules.logging.Logging
            console_level: INFO
            file_level: DEBUG
            use_colors: true
            logger_levels:
              uvicorn.error: CRITICAL
    """

    console_level: int = Field(
        default=logging.INFO,
        description="Log level for console output.",
    )
    file_level: int = Field(
        default=logging.DEBUG,
        description="Log level for file output.",
    )
    root_level: int = Field(
        default=logging.DEBUG,
        description="Root logger level.",
    )
    console_formatter: str = Field(
        default="colorlog",
        description="Formatter for console output ('simple', 'colorlog', 'whenAndWhere').",
    )
    file_formatter: str = Field(
        default="whenAndWhere",
        description="Formatter for file output.",
    )
    log_file: Optional[str] = Field(
        default=None,
        description="Path to log file. If None and use_hydra_output_dir is True, logs to hydra output.",
    )
    use_hydra_output_dir: bool = Field(
        default=True,
        description="If True and log_file is None, log to hydra output directory.",
    )
    use_colors: bool = Field(
        default=True,
        description="Whether to use colorlog for console output.",
    )
    logger_levels: Dict[str, Union[str, int]] = Field(
        default_factory=lambda: {"uvicorn.error": logging.CRITICAL},
        description="Dict mapping logger names to their levels.",
    )

    # No channel requirements - this module only configures logging
    requires: Optional[ChannelSelection] = Field(default=[])

    # Private attribute to track if this instance configured logging
    _configured_by_this_instance: bool = PrivateAttr(default=False)
    _resolved_log_file: Optional[str] = PrivateAttr(default=None)

    @field_validator("console_level", "file_level", "root_level", mode="before")
    @classmethod
    def _convert_log_level(cls, v: Union[str, int]) -> int:
        if isinstance(v, str):
            level = logging.getLevelName(v.upper())
            if isinstance(level, int):
                return level
            raise ValueError(f"Invalid log level: {v}")
        return v

    def __init__(self, **data: Any) -> None:
        """Initialize StdlibLogging module and configure logging early.

        This runs during hydra/ccflow configuration loading, which is
        before the CSP graph is built. This allows capturing logs from
        the entire application lifecycle.
        """
        super().__init__(**data)
        self._configure_logging_early()

    def _get_hydra_output_dir(self) -> Optional[str]:
        """Try to get the hydra output directory."""
        try:
            from hydra.core.hydra_config import HydraConfig

            if HydraConfig.initialized():
                return HydraConfig.get().runtime.output_dir
        except (ImportError, Exception):
            pass
        return None

    def _configure_logging_early(self) -> None:
        """Configure logging at instantiation time for early log capture."""
        global _stdlib_logging_configured

        if _stdlib_logging_configured:
            log.debug("Stdlib logging already configured, skipping")
            return

        # Determine log file path
        log_file = self.log_file
        if log_file is None and self.use_hydra_output_dir:
            hydra_dir = self._get_hydra_output_dir()
            if hydra_dir:
                log_file = os.path.join(hydra_dir, "csp-gateway.log")

        self._resolved_log_file = log_file

        # Build and apply logging config
        config = _build_logging_config(
            console_level=self.console_level,
            file_level=self.file_level,
            root_level=self.root_level,
            console_formatter=self.console_formatter,
            file_formatter=self.file_formatter,
            log_file=log_file,
            use_colors=self.use_colors,
            logger_levels=self.logger_levels,
        )

        logging.config.dictConfig(config)
        _stdlib_logging_configured = True
        self._configured_by_this_instance = True

        log.info("Stdlib logging configured early during module instantiation")

    def connect(self, channels: ChannelsType) -> None:
        """No-op during graph building.

        Logging is configured at instantiation time, not during connect().
        """
        pass


class LogChannels(GatewayModule):
    selection: ChannelSelection = Field(default_factory=ChannelSelection)
    log_states: bool = False
    log_level: int = logging.INFO
    log_name: str = str(__name__)
    requires: Optional[ChannelSelection] = []

    @field_validator("log_level", mode="before")
    @classmethod
    def _convert_log_level(cls, v: Union[str, int]) -> int:
        if isinstance(v, str):
            level = logging.getLevelName(v.upper())
            if isinstance(level, int):
                return level
            raise ValueError(f"Invalid log level: {v}")
        return v

    def connect(self, channels: ChannelsType):
        logger_to_use = logging.getLogger(self.log_name)

        for field in self.selection.select_from(channels, state_channels=self.log_states):
            data = channels.get_channel(field)
            # list baskets not supported yet
            if isinstance(data, dict):
                for k, v in data.items():
                    csp.log(self.log_level, f"{field}[{k}]", v, logger=logger_to_use)
            else:
                edge = channels.get_channel(field)
                csp.log(self.log_level, field, edge, logger=logger_to_use)


# Backwards compatibility alias
StdlibLogging = Logging
