"""Logfire integration for csp-gateway.

This module provides two main integrations:

1. `Logfire` - Early integration that captures all Python logging (including hydra)
   and optionally instruments FastAPI. Configures logfire at instantiation time.

2. `PublishLogfire` - Logs channel data to Logfire during CSP graph execution.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

import csp
from csp import ts
from pydantic import Field, PrivateAttr, field_validator, model_validator

from csp_gateway.server import ChannelSelection, ChannelsType, GatewayModule

try:
    import logfire
    from logfire import LogfireLoggingHandler

except ImportError:
    # Hold and raise in model validator
    logfire = None
    LogfireLoggingHandler = None

if TYPE_CHECKING:
    from csp_gateway.server import GatewayWebApp

__all__ = (
    "Logfire",
    "PublishLogfire",
    "configure_logfire_early",
    "is_logfire_configured",
)

log = logging.getLogger(__name__)

# Global flag to track if logfire has been configured
_logfire_configured = False
_logfire_handler: Optional[Any] = None


def is_logfire_configured() -> bool:
    """Check if logfire has been configured.

    Returns:
        bool: True if logfire.configure() has been called, False otherwise.
    """
    return _logfire_configured


def configure_logfire_early(
    token: Optional[str] = None,
    service_name: Optional[str] = "csp-gateway",
    send_to_logfire: Optional[bool] = None,
    console: Optional[Union[bool, Dict[str, Any]]] = None,
    **configure_kwargs: Any,
) -> bool:
    """Configure Logfire early in application startup, before hydra runs.

    This function should be called as early as possible in the application lifecycle
    to capture all logs including hydra configuration logs. It can be called from:
    - A custom entry point before hydra.main()
    - A hydra plugin or callback
    - As part of the ccflow configuration loading

    Args:
        token: Logfire API token. If None, will use LOGFIRE_TOKEN env var.
        service_name: Service name for Logfire traces.
        send_to_logfire: Whether to send logs to Logfire. Defaults to True if token is set.
        console: Console output configuration. Can be False to disable, True for defaults,
            or a dict with console options.
        **configure_kwargs: Additional kwargs passed to logfire.configure()

    Returns:
        bool: True if logfire was configured, False if already configured or logfire not available.

    Example:
        # In your entry point, before hydra.main():
        from csp_gateway.server.modules.logging.logfire import configure_logfire_early
        configure_logfire_early(token="your-token")

        # Then run your hydra application
        from csp_gateway.server.cli import main
        main()
    """
    global _logfire_configured, _logfire_handler

    if _logfire_configured:
        log.debug("Logfire already configured, skipping early configuration")
        return False

    if logfire is None:
        log.warning("logfire package not installed, skipping early configuration")
        return False

    # Build configure kwargs
    kwargs: Dict[str, Any] = {}
    if token is not None:
        kwargs["token"] = token
    if service_name is not None:
        kwargs["service_name"] = service_name
    if send_to_logfire is not None:
        kwargs["send_to_logfire"] = send_to_logfire
    if console is not None:
        if console is False:
            kwargs["console"] = False
        elif console is True:
            pass  # Use defaults
        else:
            kwargs["console"] = logfire.ConsoleOptions(**console)

    kwargs.update(configure_kwargs)

    try:
        logfire.configure(**kwargs)
        _logfire_configured = True

        # Install the LogfireLoggingHandler to capture all Python logging
        _logfire_handler = LogfireLoggingHandler()
        root_logger = logging.getLogger()

        # Only add handler if not already present
        if not any(isinstance(h, LogfireLoggingHandler) for h in root_logger.handlers):
            root_logger.addHandler(_logfire_handler)
            log.info("Logfire configured and logging handler installed")

        return True

    except Exception as e:
        log.warning(f"Failed to configure logfire early: {e}")
        return False


class Logfire(GatewayModule):
    """Gateway module for Logfire integration.

    This module provides:
    - Logfire configuration at instantiation time (early, before CSP graph)
    - Standard library logging integration via LogfireLoggingHandler
    - FastAPI instrumentation for web endpoints
    - Pydantic instrumentation for model validation tracking

    **Early Configuration**: Unlike most GatewayModules, Logfire configures itself
    during __init__ (when the module is instantiated by hydra/ccflow), not during
    connect(). This ensures logging is captured as early as possible, including
    hydra configuration logs.

    Attributes:
        token: Logfire API token. If None, uses LOGFIRE_TOKEN env var.
        service_name: Service name for Logfire traces. Defaults to "csp-gateway".
        instrument_fastapi: Whether to instrument FastAPI endpoints.
        instrument_pydantic: Whether to instrument Pydantic models.
        capture_logging: Whether to capture Python standard library logging.
        log_level: Minimum log level to capture (logging.DEBUG, INFO, etc).
        send_to_logfire: Whether to send data to Logfire backend.
            Set to False for local development without a token.
        console: Console output configuration.
            - None: Use Logfire defaults
            - False: Disable console output
            - Dict: Custom console options (colors, verbose, etc.)

    Example YAML configuration::

        modules:
          logfire:
            _target_: csp_gateway.server.modules.logging.Logfire
            token: ${oc.env:LOGFIRE_TOKEN,null}
            service_name: my-gateway
            instrument_fastapi: true
            capture_logging: true
    """

    token: Optional[str] = Field(
        default=None,
        description="Logfire API token. If None, uses LOGFIRE_TOKEN env var.",
    )
    project_name: Optional[str] = Field(
        default=None,
        description="Logfire project name (required when using a project-scoped write token).",
    )
    service_name: str = Field(
        default="csp-gateway",
        description="Service name for Logfire traces.",
    )
    instrument_fastapi: bool = Field(
        default=True,
        description="Whether to instrument FastAPI endpoints.",
    )
    instrument_pydantic: bool = Field(
        default=False,
        description="Whether to instrument Pydantic models for validation tracking.",
    )
    capture_logging: bool = Field(
        default=True,
        description="Whether to capture Python standard library logging.",
    )
    log_level: int = Field(
        default=logging.INFO,
        description="Minimum log level to capture.",
    )
    send_to_logfire: Optional[bool] = Field(
        default=None,
        description="Whether to send data to Logfire. Defaults to True if token is available.",
    )
    console: Optional[Union[bool, Dict[str, Any]]] = Field(
        default=None,
        description="Console output configuration.",
    )
    base_url: Optional[str] = Field(
        default=None,
        description="Base URL for Logfire API (for enterprise/self-hosted instances).",
    )

    # No channel requirements - this module only configures instrumentation
    requires: Optional[ChannelSelection] = Field(default=[])

    # Private attribute to track if this instance configured logfire
    _configured_by_this_instance: bool = PrivateAttr(default=False)

    @model_validator(mode="before")
    def check_import(cls, values):
        if logfire is None:
            raise ImportError("logfire is required for Logfire module. Install it with: pip install logfire")
        return values

    @field_validator("log_level", mode="before")
    @classmethod
    def _convert_log_level(cls, v: Union[str, int]) -> int:
        if isinstance(v, str):
            level = logging.getLevelName(v.upper())
            if isinstance(level, int):
                return level
            raise ValueError(f"Invalid log level: {v}")
        return v

    def __init__(self, **data: Any) -> None:
        """Initialize Logfire module and configure logfire early.

        This runs during hydra/ccflow configuration loading, which is
        before the CSP graph is built. This allows capturing logs from
        the entire application lifecycle including hydra configuration.
        """
        super().__init__(**data)
        self._configure_logfire_early()

    def _configure_logfire_early(self) -> None:
        """Configure logfire at instantiation time for early log capture."""
        global _logfire_configured, _logfire_handler

        if _logfire_configured:
            log.debug("Logfire already configured, skipping")
            return

        kwargs: Dict[str, Any] = {"service_name": self.service_name}

        # Use project_name if specified
        if self.project_name is not None:
            kwargs["project_name"] = self.project_name

        # Use token from field or environment
        token = self.token or os.environ.get("LOGFIRE_TOKEN")
        if token is not None:
            kwargs["token"] = token

        if self.send_to_logfire is not None:
            kwargs["send_to_logfire"] = self.send_to_logfire

        if self.console is not None:
            if self.console is False:
                kwargs["console"] = False
            elif isinstance(self.console, dict):
                kwargs["console"] = logfire.ConsoleOptions(**self.console)

        # Use base_url for enterprise/self-hosted instances
        if self.base_url is not None:
            kwargs["advanced"] = logfire.AdvancedOptions(base_url=self.base_url)

        logfire.configure(**kwargs)
        _logfire_configured = True
        self._configured_by_this_instance = True

        # Install logging handler if requested
        if self.capture_logging:
            root_logger = logging.getLogger()
            if not any(isinstance(h, LogfireLoggingHandler) for h in root_logger.handlers):
                _logfire_handler = LogfireLoggingHandler(level=self.log_level)
                root_logger.addHandler(_logfire_handler)

        log.info("Logfire configured early during module instantiation")

    def connect(self, channels: ChannelsType) -> None:
        """Configure logfire when the CSP graph is being built.

        This is called during graph construction. If logfire was already configured
        via configure_logfire_early(), this will be a no-op for configuration but
        will still set up any additional instrumentations.
        """
        global _logfire_configured, _logfire_handler

        # Configure logfire if not already done
        if not _logfire_configured:
            kwargs: Dict[str, Any] = {"service_name": self.service_name}
            if self.project_name is not None:
                kwargs["project_name"] = self.project_name
            if self.token is not None:
                kwargs["token"] = self.token
            if self.send_to_logfire is not None:
                kwargs["send_to_logfire"] = self.send_to_logfire
            if self.console is not None:
                if self.console is False:
                    kwargs["console"] = False
                elif isinstance(self.console, dict):
                    kwargs["console"] = logfire.ConsoleOptions(**self.console)

            try:
                logfire.configure(**kwargs)
                _logfire_configured = True
                log.info("Logfire configured via LogfireIntegration")
            except Exception as e:
                log.warning(f"Failed to configure logfire: {e}")
                return

        # Install logging handler if requested and not already installed
        if self.capture_logging:
            root_logger = logging.getLogger()
            if not any(isinstance(h, LogfireLoggingHandler) for h in root_logger.handlers):
                _logfire_handler = LogfireLoggingHandler(level=self.log_level)
                root_logger.addHandler(_logfire_handler)
                log.info("Logfire logging handler installed")

        # Instrument Pydantic if requested
        if self.instrument_pydantic:
            try:
                logfire.instrument_pydantic()
                log.debug("Pydantic instrumentation enabled")
            except Exception as e:
                log.warning(f"Failed to instrument Pydantic: {e}")

    def rest(self, app: "GatewayWebApp") -> None:
        """Instrument the FastAPI application with Logfire.

        This is called after the web application is built.
        """
        if not self.instrument_fastapi:
            return

        try:
            import logfire
        except ImportError:
            return

        try:
            # Get the underlying FastAPI app from the GatewayWebApp
            fastapi_app = getattr(app, "app", app)
            logfire.instrument_fastapi(fastapi_app)
            log.info("FastAPI instrumentation enabled")
        except Exception as e:
            log.warning(f"Failed to instrument FastAPI: {e}")


class PublishLogfire(GatewayModule):
    """Gateway module for logging channel data to Logfire.

    This module logs CSP channel data (ticks) to Logfire as spans/logs,
    similar to LogChannels but with rich Logfire integration including:
    - Structured logging with channel data as attributes
    - Span context for tracing data flow
    - Integration with Logfire's dashboard and query capabilities

    Attributes:
        selection: Channel selection for which channels to log.
        log_states: Whether to also log state channels (s_* channels).
        log_level: Log level for channel data (DEBUG, INFO, WARNING, ERROR).
        service_name: Optional service name override for these logs.
        include_metadata: Whether to include channel metadata (timestamps, etc).
        batch_logs: Whether to batch multiple ticks in a single log entry.
    """

    selection: ChannelSelection = Field(
        default_factory=ChannelSelection,
        description="Channel selection for which channels to log.",
    )
    log_states: bool = Field(
        default=False,
        description="Whether to also log state channels.",
    )
    log_level: int = Field(
        default=logging.INFO,
        description="Log level for channel data.",
    )
    service_name: Optional[str] = Field(
        default=None,
        description="Optional service name override for channel logs.",
    )
    include_metadata: bool = Field(
        default=True,
        description="Whether to include channel metadata (timestamps, etc).",
    )
    use_spans: bool = Field(
        default=False,
        description="Whether to wrap channel data in Logfire spans for tracing.",
    )

    # No channels required - we select from what's available
    requires: Optional[ChannelSelection] = Field(default=[])

    @model_validator(mode="before")
    def check_import(cls, values):
        if logfire is None:
            raise ImportError("logfire is required for Logfire module. Install it with: pip install logfire")
        return values

    @field_validator("log_level", mode="before")
    @classmethod
    def _convert_log_level(cls, v: Union[str, int]) -> int:
        if isinstance(v, str):
            level = logging.getLevelName(v.upper())
            if isinstance(level, int):
                return level
            raise ValueError(f"Invalid log level: {v}")
        return v

    def connect(self, channels: ChannelsType) -> None:
        """Connect to channels and set up logging nodes."""
        # Get logfire instance (service_name is set at configure time, not per-instance)
        logfire_instance = logfire.DEFAULT_LOGFIRE_INSTANCE

        # Select channels to log
        selected_fields = self.selection.select_from(channels, state_channels=self.log_states)

        for field in selected_fields:
            data = channels.get_channel(field)

            # Handle dict baskets (keyed channels)
            if isinstance(data, dict):
                for key, edge in data.items():
                    self._log_channel_to_logfire(
                        logfire_instance,
                        f"{field}[{key}]",
                        edge,
                        include_metadata=self.include_metadata,
                        use_spans=self.use_spans,
                        log_level=self.log_level,
                    )
            else:
                # Regular channel
                edge = channels.get_channel(field)
                self._log_channel_to_logfire(
                    logfire_instance,
                    field,
                    edge,
                    include_metadata=self.include_metadata,
                    use_spans=self.use_spans,
                    log_level=self.log_level,
                )

    @staticmethod
    @csp.node
    def _log_channel_to_logfire(
        logfire_instance: object,
        channel_name: str,
        data: ts[object],
        include_metadata: bool,
        use_spans: bool,
        log_level: int,
    ):
        """CSP node that logs channel data to Logfire.

        This node receives ticks from a channel and logs them to Logfire
        with appropriate formatting and metadata.
        """
        with csp.start():
            # Log that we're starting to monitor this channel
            logfire.info(f"PublishLogfire monitoring started for {channel_name}")

        with csp.stop():
            logfire.info(f"PublishLogfire monitoring stopped for {channel_name}")

        if csp.ticked(data):
            value = data

            # Build attributes dict
            attributes: Dict[str, Any] = {
                "channel": channel_name,
            }

            if include_metadata:
                attributes["csp_timestamp"] = str(csp.now())

            # Convert value to loggable format
            if hasattr(value, "to_dict"):
                # GatewayStruct or similar
                attributes["data"] = value.to_dict()
            elif hasattr(value, "model_dump"):
                # Pydantic model
                attributes["data"] = value.model_dump()
            elif isinstance(value, (dict, list, str, int, float, bool, type(None))):
                attributes["data"] = value
            else:
                # Fallback to string representation
                attributes["data"] = str(value)

            # Log to logfire
            if use_spans:
                with logfire.span(f"channel:{channel_name}", **attributes):
                    pass  # Span captures the data
            else:
                # Map Python log levels to logfire methods
                if log_level <= logging.DEBUG:
                    logfire.debug(f"Channel tick: {channel_name}", **attributes)
                elif log_level <= logging.INFO:
                    logfire.info(f"Channel tick: {channel_name}", **attributes)
                elif log_level <= logging.WARNING:
                    logfire.warn(f"Channel tick: {channel_name}", **attributes)
                else:
                    logfire.error(f"Channel tick: {channel_name}", **attributes)
