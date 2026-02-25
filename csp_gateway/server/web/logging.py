"""Logging utilities for secure log handling.

This module provides utilities for creating access log configurations
that redact sensitive information like tokens and passwords.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Pattern

__all__ = (
    "SecretRedactingFormatter",
    "get_secure_log_config",
    "SENSITIVE_PATTERNS",
)

# Patterns to redact from logs (query params and headers)
SENSITIVE_PATTERNS: List[Pattern] = [
    # Query parameters
    re.compile(r"(\?|&)(token|api_key|apikey|api-key|password|secret|access_token|refresh_token|id_token)=([^&\s]+)", re.IGNORECASE),
    # Authorization headers in logs
    re.compile(r"(Authorization:\s*(?:Bearer|Basic|Token)\s+)([^\s,]+)", re.IGNORECASE),
    # Cookie values with session info
    re.compile(r"(oauth_session|session_id|auth_token|csp_gateway_session)=([^;\s]+)", re.IGNORECASE),
]

REDACTION_TEXT = "[REDACTED]"


class SecretRedactingFormatter(logging.Formatter):
    """A logging formatter that redacts sensitive information.

    This formatter replaces sensitive patterns like tokens, passwords,
    and API keys in log messages with [REDACTED].

    Example:
        >>> formatter = SecretRedactingFormatter("%(message)s")
        >>> record = logging.LogRecord(
        ...     name="test", level=logging.INFO, pathname="", lineno=0,
        ...     msg="GET /api?token=secret123&name=test", args=(), exc_info=None
        ... )
        >>> formatter.format(record)
        'GET /api?token=[REDACTED]&name=test'
    """

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: str = "%",
        additional_patterns: Optional[List[Pattern]] = None,
    ):
        """Initialize the formatter with optional additional patterns.

        Args:
            fmt: The format string.
            datefmt: The date format string.
            style: The format style ('%', '{', or '$').
            additional_patterns: Additional regex patterns to redact.
        """
        super().__init__(fmt, datefmt, style)
        self._patterns = list(SENSITIVE_PATTERNS)
        if additional_patterns:
            self._patterns.extend(additional_patterns)

    def format(self, record: logging.LogRecord) -> str:
        """Format the record, redacting sensitive information."""
        message = super().format(record)
        return self._redact(message)

    def _redact(self, message: str) -> str:
        """Apply redaction patterns to the message."""
        for pattern in self._patterns:
            # Use a function to preserve the pattern prefix
            message = pattern.sub(self._redact_match, message)
        return message

    def _redact_match(self, match: re.Match) -> str:
        """Replace the sensitive part of a match while preserving context."""
        groups = match.groups()
        if len(groups) >= 2:
            # Pattern has prefix group(s) + sensitive value
            return "".join(groups[:-1]) + REDACTION_TEXT
        return REDACTION_TEXT


def get_secure_log_config(
    log_level: str = "info",
    access_log: bool = True,
    additional_patterns: Optional[List[Pattern]] = None,
) -> Dict[str, Any]:
    """Get a uvicorn log configuration with secret redaction.

    This returns a log config dict suitable for passing to uvicorn's
    `log_config` parameter. Access logs will have sensitive information
    like tokens and API keys redacted.

    Args:
        log_level: The log level (debug, info, warning, error, critical).
        access_log: Whether to enable access logs.
        additional_patterns: Additional regex patterns to redact.

    Returns:
        A logging configuration dict for uvicorn.

    Example:
        >>> from csp_gateway.server.web.logging import get_secure_log_config
        >>> config = get_secure_log_config(log_level="info")
        >>> # Pass to gateway or uvicorn:
        >>> # gateway.start(rest=True, log_config=config)
    """
    # Build the formatter with redaction
    patterns = list(SENSITIVE_PATTERNS)
    if additional_patterns:
        patterns.extend(additional_patterns)

    # Standard uvicorn log config with our custom formatter
    config: Dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": SecretRedactingFormatter,
                "fmt": "%(levelprefix)s %(message)s",
            },
            "access": {
                "()": SecretRedactingFormatter,
                # Standard uvicorn access log format with redaction
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
            },
            "access": {
                "formatter": "access",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": log_level.upper(), "propagate": False},
            "uvicorn.error": {"level": log_level.upper()},
            "uvicorn.access": {
                "handlers": ["access"],
                "level": log_level.upper() if access_log else "ERROR",
                "propagate": False,
            },
        },
    }

    return config
