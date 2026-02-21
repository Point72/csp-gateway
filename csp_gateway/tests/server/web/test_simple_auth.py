"""Tests for MountSimpleAuthMiddleware."""

import base64
from unittest.mock import MagicMock, patch

import pytest
from ccflow import PyObjectPath
from fastapi.testclient import TestClient
from pydantic import ValidationError

from csp_gateway import (
    Gateway,
    GatewaySettings,
    MountRestRoutes,
)
from csp_gateway.server.demo import (
    ExampleGatewayChannels,
    ExampleModule,
)
from csp_gateway.server.middleware.simple import (
    MountSimpleAuthMiddleware,
    _get_unix_user_info,
    _validate_host_unix,
    _validate_host_windows,
)


def mock_validator_valid(username: str, password: str, settings, module) -> dict:
    """A mock validator that accepts specific credentials."""
    valid_users = {
        ("alice", "alicepass"): {"user": "alice", "role": "admin"},
        ("bob", "bobpass"): {"user": "bob", "role": "viewer"},
    }
    return valid_users.get((username, password))


def mock_validator_invalid(username: str, password: str, settings, module) -> dict:
    """A mock validator that always returns None (invalid credentials)."""
    return None


def mock_validator_raises(username: str, password: str, settings, module) -> dict:
    """A mock validator that raises an exception."""
    raise ValueError("External validation service error")


class TestMountSimpleAuthMiddlewareValidation:
    """Test MountSimpleAuthMiddleware validation."""

    def test_requires_auth_method(self):
        """Test that at least one auth method must be configured."""
        with pytest.raises(ValidationError):
            MountSimpleAuthMiddleware()

    def test_external_validator_alone_valid(self):
        """Test that external_validator alone is valid."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_simple_auth:mock_validator_valid")
        middleware = MountSimpleAuthMiddleware(external_validator=validator_path)
        assert middleware.external_validator is not None
        assert middleware.use_host_auth is False

    def test_use_host_auth_alone_valid(self):
        """Test that use_host_auth alone is valid."""
        middleware = MountSimpleAuthMiddleware(use_host_auth=True)
        assert middleware.use_host_auth is True
        assert middleware.external_validator is None

    def test_both_auth_methods_valid(self):
        """Test that both auth methods can be configured."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_simple_auth:mock_validator_valid")
        middleware = MountSimpleAuthMiddleware(
            external_validator=validator_path,
            use_host_auth=True,
        )
        assert middleware.external_validator is not None
        assert middleware.use_host_auth is True


class TestSimpleAuthWithExternalValidator:
    """Test MountSimpleAuthMiddleware with external validation."""

    @pytest.fixture(scope="class")
    def simple_auth_gateway(self, free_port):
        """Create a gateway with simple auth external validation."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_simple_auth:mock_validator_valid")
        gateway = Gateway(
            modules=[
                ExampleModule(),
                MountRestRoutes(force_mount_all=True),
                MountSimpleAuthMiddleware(external_validator=validator_path),
            ],
            channels=ExampleGatewayChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        return gateway

    @pytest.fixture(scope="class")
    def simple_auth_webserver(self, simple_auth_gateway):
        simple_auth_gateway.start(rest=True, _in_test=True)
        yield simple_auth_gateway
        simple_auth_gateway.stop()

    @pytest.fixture(scope="class")
    def simple_auth_rest_client(self, simple_auth_webserver) -> TestClient:
        return TestClient(simple_auth_webserver.web_app.get_fastapi())

    def test_basic_auth_valid_credentials(self, simple_auth_rest_client: TestClient):
        """Test that valid Basic Auth credentials are accepted."""
        credentials = base64.b64encode(b"alice:alicepass").decode("utf-8")
        response = simple_auth_rest_client.get(
            "/api/v1/last",
            headers={"Authorization": f"Basic {credentials}"},
        )
        assert response.status_code == 200, "Valid Basic Auth credentials should be accepted"

    def test_basic_auth_second_user(self, simple_auth_rest_client: TestClient):
        """Test that a second valid user is accepted."""
        credentials = base64.b64encode(b"bob:bobpass").decode("utf-8")
        response = simple_auth_rest_client.get(
            "/api/v1/last",
            headers={"Authorization": f"Basic {credentials}"},
        )
        assert response.status_code == 200, "Second valid user should be accepted"

    def test_basic_auth_invalid_credentials(self, simple_auth_rest_client: TestClient):
        """Test that invalid Basic Auth credentials are rejected."""
        credentials = base64.b64encode(b"alice:wrongpass").decode("utf-8")
        response = simple_auth_rest_client.get(
            "/api/v1/last",
            headers={"Authorization": f"Basic {credentials}"},
        )
        assert response.status_code == 401, "Invalid credentials should be rejected"

    def test_no_auth_rejected(self, simple_auth_rest_client: TestClient):
        """Test that requests without auth are rejected."""
        response = simple_auth_rest_client.get("/api/v1/last")
        assert response.status_code == 401, "Request without auth should be rejected"

    def test_whoami_returns_identity(self, simple_auth_rest_client: TestClient):
        """Test that whoami returns the user identity."""
        credentials = base64.b64encode(b"alice:alicepass").decode("utf-8")
        response = simple_auth_rest_client.get(
            "/api/v1/auth/whoami",
            headers={"Authorization": f"Basic {credentials}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["user"] == "alice"
        assert data["role"] == "admin"


class TestSimpleAuthFormLogin:
    """Test form-based login flow."""

    @pytest.fixture(scope="class")
    def form_login_gateway(self, free_port):
        """Create a gateway for form login testing."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_simple_auth:mock_validator_valid")
        gateway = Gateway(
            modules=[
                ExampleModule(),
                MountRestRoutes(force_mount_all=True),
                MountSimpleAuthMiddleware(external_validator=validator_path),
            ],
            channels=ExampleGatewayChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        return gateway

    @pytest.fixture(scope="class")
    def form_login_webserver(self, form_login_gateway):
        form_login_gateway.start(rest=True, _in_test=True)
        yield form_login_gateway
        form_login_gateway.stop()

    @pytest.fixture(scope="class")
    def form_login_rest_client(self, form_login_webserver) -> TestClient:
        return TestClient(form_login_webserver.web_app.get_fastapi())

    def test_login_page_accessible(self, form_login_rest_client: TestClient):
        """Test that login page is accessible without auth."""
        response = form_login_rest_client.get("/login")
        assert response.status_code == 200
        assert "login" in response.text.lower() or "username" in response.text.lower()

    def test_form_login_valid_credentials(self, form_login_rest_client: TestClient):
        """Test form login with valid credentials."""
        response = form_login_rest_client.post(
            "/login",
            data={"username": "alice", "password": "alicepass"},
            follow_redirects=False,
        )
        assert response.status_code == 303, "Form login should redirect"
        assert response.headers.get("location") == "/"

    def test_form_login_invalid_credentials(self, form_login_rest_client: TestClient):
        """Test form login with invalid credentials."""
        response = form_login_rest_client.post(
            "/login",
            data={"username": "alice", "password": "wrongpass"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "error" in response.headers.get("location", "")

    def test_form_login_missing_credentials(self, form_login_rest_client: TestClient):
        """Test form login with missing credentials."""
        response = form_login_rest_client.post(
            "/login",
            data={"username": "alice"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "error" in response.headers.get("location", "")


class TestHostAuthUnix:
    """Test Unix/PAM host authentication helpers."""

    def test_validate_host_unix_with_pamela(self):
        """Test that _validate_host_unix tries pamela first."""
        mock_pamela = MagicMock()
        mock_pamela.authenticate = MagicMock()
        mock_pamela.PAMError = Exception

        with patch.dict("sys.modules", {"pamela": mock_pamela}):
            # Import triggers pamela usage
            _ = _validate_host_unix("testuser", "testpass")
            # pamela.authenticate was called
            mock_pamela.authenticate.assert_called_once_with("testuser", "testpass")

    def test_validate_host_unix_pamela_auth_failure(self):
        """Test that _validate_host_unix returns None on PAM error."""
        mock_pamela = MagicMock()
        pamela_error = type("PAMError", (Exception,), {})
        mock_pamela.PAMError = pamela_error
        mock_pamela.authenticate = MagicMock(side_effect=pamela_error("Auth failed"))

        with patch.dict("sys.modules", {"pamela": mock_pamela}):
            result = _validate_host_unix("testuser", "wrongpass")
            assert result is None

    def test_get_unix_user_info_returns_dict(self):
        """Test that _get_unix_user_info returns user info."""
        mock_pwd = MagicMock()
        mock_pwd.getpwnam = MagicMock(
            return_value=MagicMock(
                pw_uid=1001,
                pw_gid=1001,
                pw_dir="/home/testuser",
                pw_shell="/bin/bash",
                pw_gecos="Test User",
            )
        )

        with patch.dict("sys.modules", {"pwd": mock_pwd}):
            result = _get_unix_user_info("testuser")
            assert result["user"] == "testuser"
            assert result["uid"] == 1001


class TestHostAuthWindows:
    """Test Windows host authentication helpers."""

    def test_validate_host_windows_success(self):
        """Test successful Windows authentication."""
        mock_win32security = MagicMock()
        mock_win32security.LOGON32_LOGON_NETWORK = 3
        mock_win32security.LOGON32_PROVIDER_DEFAULT = 0
        mock_handle = MagicMock()
        mock_win32security.LogonUser = MagicMock(return_value=mock_handle)
        mock_win32security.error = Exception

        mock_win32net = MagicMock()
        mock_win32net.NetUserGetInfo = MagicMock(
            return_value={
                "full_name": "Test User",
                "home_dir": "C:\\Users\\testuser",
                "comment": "",
            }
        )

        with patch.dict(
            "sys.modules",
            {
                "win32security": mock_win32security,
                "win32net": mock_win32net,
            },
        ):
            result = _validate_host_windows("testuser", "testpass")
            assert result is not None
            assert result["user"] == "testuser"
            mock_win32security.LogonUser.assert_called_once()

    def test_validate_host_windows_auth_failure(self):
        """Test Windows authentication failure."""
        mock_win32security = MagicMock()
        mock_win32security.LOGON32_LOGON_NETWORK = 3
        mock_win32security.LOGON32_PROVIDER_DEFAULT = 0
        win32_error = type("error", (Exception,), {})
        mock_win32security.error = win32_error
        mock_win32security.LogonUser = MagicMock(side_effect=win32_error("Auth failed"))

        with patch.dict("sys.modules", {"win32security": mock_win32security}):
            result = _validate_host_windows("testuser", "wrongpass")
            assert result is None


class TestIdentityAwareMiddlewareMixin:
    """Test IdentityAwareMiddlewareMixin implementation in SimpleAuth."""

    @pytest.fixture
    def middleware_with_identity(self):
        """Create middleware with pre-populated identity store."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_simple_auth:mock_validator_valid")
        middleware = MountSimpleAuthMiddleware(external_validator=validator_path)
        # Pre-populate identity store
        middleware._identity_store["test-session-uuid"] = {"user": "alice", "role": "admin"}
        return middleware

    @pytest.mark.asyncio
    async def test_get_identity(self, middleware_with_identity):
        """Test get_identity returns stored identity."""
        identity = await middleware_with_identity.get_identity("test-session-uuid")
        assert identity is not None
        assert identity["user"] == "alice"

    @pytest.mark.asyncio
    async def test_get_identity_not_found(self, middleware_with_identity):
        """Test get_identity returns None for unknown session."""
        identity = await middleware_with_identity.get_identity("unknown-uuid")
        assert identity is None

    @pytest.mark.asyncio
    async def test_get_identity_from_credentials_cookie(self, middleware_with_identity):
        """Test get_identity_from_credentials extracts from cookie."""
        identity = await middleware_with_identity.get_identity_from_credentials(
            cookies={"session": "test-session-uuid"},
        )
        assert identity is not None
        assert identity["user"] == "alice"

    @pytest.mark.asyncio
    async def test_get_identity_from_credentials_basic_auth(self, middleware_with_identity):
        """Test get_identity_from_credentials extracts from Basic Auth header."""
        credentials = base64.b64encode(b"alice:alicepass").decode("utf-8")
        identity = await middleware_with_identity.get_identity_from_credentials(
            headers={"Authorization": f"Basic {credentials}"},
        )
        assert identity is not None
        assert identity["user"] == "alice"
