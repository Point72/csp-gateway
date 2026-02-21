"""Tests for the secure logging utilities."""

import logging
import re

import pytest

from csp_gateway.server.web.logging import (
    REDACTION_TEXT,
    SENSITIVE_PATTERNS,
    SecretRedactingFormatter,
    get_secure_log_config,
)


class TestSecretRedactingFormatter:
    """Tests for SecretRedactingFormatter."""

    @pytest.fixture
    def formatter(self):
        """Create a basic formatter for testing."""
        return SecretRedactingFormatter("%(message)s")

    def test_redacts_token_query_param(self, formatter):
        """Test that token query parameters are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="GET /api?token=supersecret123",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "supersecret123" not in result
        assert REDACTION_TEXT in result
        # The parameter name is preserved but value is redacted
        assert "?token" in result

    def test_redacts_api_key_query_param(self, formatter):
        """Test that api_key query parameters are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="GET /api?api_key=myapikey123&name=test",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "myapikey123" not in result
        assert "name=test" in result  # Non-sensitive params preserved

    def test_redacts_password_query_param(self, formatter):
        """Test that password query parameters are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="POST /login?username=alice&password=hunter2",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "hunter2" not in result
        assert "username=alice" in result  # Username is preserved

    def test_redacts_access_token_query_param(self, formatter):
        """Test that access_token query parameters are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="GET /api?access_token=jwt.token.here",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "jwt.token.here" not in result

    def test_redacts_bearer_authorization_header(self, formatter):
        """Test that Bearer tokens in headers are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Request headers: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "Authorization: Bearer" in result

    def test_redacts_basic_authorization_header(self, formatter):
        """Test that Basic auth headers are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "dXNlcm5hbWU6cGFzc3dvcmQ=" not in result

    def test_redacts_session_cookies(self, formatter):
        """Test that session cookies are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Cookie: oauth_session=abc123def456; other=value",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "abc123def456" not in result
        assert "other=value" in result  # Non-sensitive cookie preserved

    def test_preserves_non_sensitive_content(self, formatter):
        """Test that non-sensitive content is preserved."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="GET /api/users/123 - 200 OK",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert result == "GET /api/users/123 - 200 OK"

    def test_multiple_sensitive_params(self, formatter):
        """Test redaction of multiple sensitive parameters."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="GET /api?token=secret1&api_key=secret2&name=test",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "secret1" not in result
        assert "secret2" not in result
        assert "name=test" in result

    def test_case_insensitive_redaction(self, formatter):
        """Test that redaction is case-insensitive."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="GET /api?TOKEN=secret&API_KEY=key123",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "secret" not in result
        assert "key123" not in result

    def test_additional_patterns(self):
        """Test adding custom redaction patterns."""
        custom_pattern = re.compile(r"(ssn=)(\d{3}-\d{2}-\d{4})")
        formatter = SecretRedactingFormatter(
            "%(message)s",
            additional_patterns=[custom_pattern],
        )
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="User data: ssn=123-45-6789",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "123-45-6789" not in result
        assert "ssn=" in result


class TestGetSecureLogConfig:
    """Tests for get_secure_log_config function."""

    def test_returns_valid_config_structure(self):
        """Test that the config has the required structure."""
        config = get_secure_log_config()
        assert "version" in config
        assert config["version"] == 1
        assert "formatters" in config
        assert "handlers" in config
        assert "loggers" in config

    def test_includes_access_formatter(self):
        """Test that the access formatter is included."""
        config = get_secure_log_config()
        assert "access" in config["formatters"]
        assert config["formatters"]["access"]["()"] == SecretRedactingFormatter

    def test_includes_default_formatter(self):
        """Test that the default formatter is included."""
        config = get_secure_log_config()
        assert "default" in config["formatters"]
        assert config["formatters"]["default"]["()"] == SecretRedactingFormatter

    def test_log_level_setting(self):
        """Test that log level is properly set."""
        config = get_secure_log_config(log_level="debug")
        assert config["loggers"]["uvicorn"]["level"] == "DEBUG"
        assert config["loggers"]["uvicorn.access"]["level"] == "DEBUG"

    def test_access_log_disabled(self):
        """Test that access logs can be disabled."""
        config = get_secure_log_config(access_log=False)
        # When disabled, access log level should be ERROR
        assert config["loggers"]["uvicorn.access"]["level"] == "ERROR"


class TestSensitivePatterns:
    """Tests for the default SENSITIVE_PATTERNS."""

    def test_patterns_are_compiled_regexes(self):
        """Test that patterns are compiled regex objects."""
        for pattern in SENSITIVE_PATTERNS:
            assert hasattr(pattern, "search")
            assert hasattr(pattern, "sub")

    def test_token_pattern_matches(self):
        """Test that token pattern matches expected strings."""
        token_pattern = SENSITIVE_PATTERNS[0]  # Query param pattern
        assert token_pattern.search("?token=abc123")
        assert token_pattern.search("&api_key=xyz")
        assert token_pattern.search("?password=secret")
        assert not token_pattern.search("?name=john")

    def test_auth_header_pattern_matches(self):
        """Test that auth header pattern matches."""
        auth_pattern = SENSITIVE_PATTERNS[1]
        assert auth_pattern.search("Authorization: Bearer abcdef")
        assert auth_pattern.search("Authorization: Basic base64str")
        assert not auth_pattern.search("Content-Type: application/json")
