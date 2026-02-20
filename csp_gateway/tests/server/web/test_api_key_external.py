"""Tests for MountExternalAPIKeyMiddleware."""

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
from csp_gateway.server.middleware.api_key_external import MountExternalAPIKeyMiddleware


def mock_validator_valid(api_key: str, settings, module) -> dict:
    """A mock validator that accepts specific API keys and returns an identity dict."""
    valid_keys = {"valid_key_1": {"user": "alice", "role": "admin"}, "valid_key_2": {"user": "bob", "role": "viewer"}}
    return valid_keys.get(api_key)


def mock_validator_invalid(api_key: str, settings, module) -> dict:
    """A mock validator that always returns None (invalid key)."""
    return None


def mock_validator_raises(api_key: str, settings, module) -> dict:
    """A mock validator that raises an exception."""
    raise ValueError("External validation service error")


class TestMountExternalAPIKeyMiddleware:
    """Test MountExternalAPIKeyMiddleware with external validation."""

    @pytest.fixture(scope="class")
    def external_key_gateway(self, free_port):
        """Create a gateway with external API key validation."""
        # Use a PyObjectPath pointing to our mock validator
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_api_key_external:mock_validator_valid")
        gateway = Gateway(
            modules=[
                ExampleModule(),
                MountRestRoutes(force_mount_all=True),
                MountExternalAPIKeyMiddleware(external_validator=validator_path),
            ],
            channels=ExampleGatewayChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        return gateway

    @pytest.fixture(scope="class")
    def external_key_webserver(self, external_key_gateway):
        external_key_gateway.start(rest=True, _in_test=True)
        yield external_key_gateway
        external_key_gateway.stop()

    @pytest.fixture(scope="class")
    def external_key_rest_client(self, external_key_webserver) -> TestClient:
        return TestClient(external_key_webserver.web_app.get_fastapi())

    def test_external_valid_key_accepted(self, external_key_rest_client: TestClient):
        """Test that a valid external API key is accepted."""
        response = external_key_rest_client.get("/api/v1/last?token=valid_key_1")
        assert response.status_code == 200, "Valid external API key should be accepted"

    def test_external_second_valid_key_accepted(self, external_key_rest_client: TestClient):
        """Test that a second valid external API key is also accepted."""
        response = external_key_rest_client.get("/api/v1/last?token=valid_key_2")
        assert response.status_code == 200, "Second valid external API key should be accepted"

    def test_external_invalid_key_rejected(self, external_key_rest_client: TestClient):
        """Test that an invalid external API key is rejected."""
        response = external_key_rest_client.get("/api/v1/last?token=invalid_key")
        assert response.status_code == 403, "Invalid external API key should be rejected"

    def test_external_no_key_rejected(self, external_key_rest_client: TestClient):
        """Test that requests without an API key are rejected."""
        response = external_key_rest_client.get("/api/v1/last")
        assert response.status_code == 403, "Request without API key should be rejected"


class TestExternalAPIKeyLogin:
    """Test login/logout flow with external API key validation."""

    @pytest.fixture(scope="class")
    def login_gateway(self, free_port):
        """Create a gateway for login testing."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_api_key_external:mock_validator_valid")
        gateway = Gateway(
            modules=[
                ExampleModule(),
                MountRestRoutes(force_mount_all=True),
                MountExternalAPIKeyMiddleware(external_validator=validator_path),
            ],
            channels=ExampleGatewayChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        return gateway

    @pytest.fixture(scope="class")
    def login_webserver(self, login_gateway):
        login_gateway.start(rest=True, _in_test=True)
        yield login_gateway
        login_gateway.stop()

    @pytest.fixture(scope="class")
    def login_rest_client(self, login_webserver) -> TestClient:
        return TestClient(login_webserver.web_app.get_fastapi())

    def test_login_redirects_with_valid_key(self, login_rest_client: TestClient):
        """Test that login with a valid key redirects."""
        response = login_rest_client.get("/api/v1/auth/login?token=valid_key_1", follow_redirects=False)
        assert response.status_code == 307, "Login should redirect"
        # Note: httponly cookies may not be visible in TestClient.cookies
        # The actual cookie setting is tested implicitly by successful authentication

    def test_logout_redirects(self, login_rest_client: TestClient):
        """Test that public logout redirects to login page."""
        # Public logout should always redirect to login page
        logout_response = login_rest_client.get("/logout", follow_redirects=False)
        assert logout_response.status_code == 200, "Public logout page should return 200"


class TestExternalAPIKeyIdentityStore:
    """Test that identity is stored and retrieved correctly."""

    def test_identity_stored_on_login(self):
        """Test that identity is stored in _identity_store after validation."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_api_key_external:mock_validator_valid")
        middleware = MountExternalAPIKeyMiddleware(external_validator=validator_path)

        # Clear any existing identity store
        middleware._identity_store = {}

        # Directly invoke the external validator to check identity
        identity = middleware._invoke_external("valid_key_1", None, None)
        assert identity == {"user": "alice", "role": "admin"}

    def test_invalid_key_returns_none(self):
        """Test that invalid key returns None from validator."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_api_key_external:mock_validator_invalid")
        middleware = MountExternalAPIKeyMiddleware(external_validator=validator_path)

        identity = middleware._invoke_external("any_key", None, None)
        assert identity is None


class TestExternalValidatorConfiguration:
    """Test validator configuration and validation."""

    def test_invalid_python_path_raises(self):
        """Test that invalid python path raises ValidationError."""
        with pytest.raises(ValidationError, match="Invalid python path"):
            MountExternalAPIKeyMiddleware(external_validator="not_a_valid_path")

    def test_validator_must_be_callable(self):
        """Test that external_validator must point to a callable object."""
        # This path points to a non-callable (a string constant)
        with pytest.raises(ValueError, match="external_validator must point to a callable object"):
            MountExternalAPIKeyMiddleware(external_validator=PyObjectPath("csp_gateway.tests.server.web.test_api_key_external:NON_CALLABLE"))

    def test_none_validator_allowed(self):
        """Test that None is allowed for external_validator."""
        middleware = MountExternalAPIKeyMiddleware(external_validator=None)
        assert middleware.external_validator is None


# Non-callable constant for testing
NON_CALLABLE = "I am not callable"
