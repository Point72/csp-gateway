"""Tests for AuthFilterMiddleware."""

from datetime import timedelta

import csp
import pytest
from ccflow import PyObjectPath
from csp import ts
from fastapi.testclient import TestClient

from csp_gateway import (
    ChannelSelection,
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewaySettings,
    GatewayStruct,
    MountRestRoutes,
)
from csp_gateway.server.middleware.api_key_external import MountExternalAPIKeyMiddleware
from csp_gateway.server.middleware.auth_filter import AuthFilterMiddleware


# Test struct with a "user" field for filtering
class UserData(GatewayStruct):
    user: str
    data: str


class UserDataChannels(GatewayChannels):
    user_data: ts[UserData] = None


class UserDataModule(GatewayModule):
    """Module that produces data for multiple users."""

    @csp.node
    def produce_data(self, trigger: ts[bool]) -> ts[UserData]:
        with csp.state():
            s_count = 0
            s_users = ["alice", "bob", "charlie"]
        if csp.ticked(trigger):
            user = s_users[s_count % len(s_users)]
            s_count += 1
            return UserData(user=user, data=f"data_{s_count}")

    def connect(self, channels: UserDataChannels):
        data = self.produce_data(csp.timer(interval=timedelta(seconds=0.1), value=True))
        channels.set_channel("user_data", data)


def mock_validator(api_key: str, settings, module) -> dict:
    """Mock validator that returns identity with user field."""
    users = {
        "alice_key": {"user": "alice", "role": "admin"},
        "bob_key": {"user": "bob", "role": "viewer"},
        "charlie_key": {"user": "charlie", "role": "viewer"},
    }
    return users.get(api_key)


class TestAuthFilterMiddleware:
    """Test AuthFilterMiddleware basic functionality."""

    def test_filter_struct_matching_user(self):
        """Test that filter_struct correctly filters structs."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        # Struct with matching user should pass
        assert middleware.filter_struct({"user": "alice", "data": "test"}, {"user": "alice"}) is True

        # Struct with non-matching user should be filtered
        assert middleware.filter_struct({"user": "bob", "data": "test"}, {"user": "alice"}) is False

    def test_filter_struct_no_filter_fields(self):
        """Test that all structs pass when no filter_fields configured."""
        middleware = AuthFilterMiddleware(filter_fields=[])

        assert middleware.filter_struct({"user": "bob", "data": "test"}, {"user": "alice"}) is True

    def test_filter_struct_no_identity(self):
        """Test that all structs pass when no identity provided."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        assert middleware.filter_struct({"user": "bob", "data": "test"}, None) is True

    def test_filter_struct_missing_identity_field(self):
        """Test struct passes when identity doesn't have the filter field."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        # Identity doesn't have "user" field, so no filtering
        assert middleware.filter_struct({"user": "bob", "data": "test"}, {"role": "admin"}) is True

    def test_filter_struct_missing_struct_field(self):
        """Test struct passes when struct doesn't have the filter field."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        # Struct doesn't have "user" field, so no filtering
        assert middleware.filter_struct({"data": "test"}, {"user": "alice"}) is True

    def test_filter_response_data_list(self):
        """Test filtering a list of structs."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        data = [
            {"user": "alice", "data": "visible"},
            {"user": "bob", "data": "hidden"},
            {"user": "alice", "data": "also_visible"},
        ]

        filtered = middleware.filter_response_data(data, {"user": "alice"})

        assert len(filtered) == 2
        assert all(item["user"] == "alice" for item in filtered)

    def test_filter_response_data_single_dict_matching(self):
        """Test filtering a single dict that matches."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        data = {"user": "alice", "data": "visible"}

        filtered = middleware.filter_response_data(data, {"user": "alice"})

        assert filtered == data

    def test_filter_response_data_single_dict_not_matching(self):
        """Test filtering a single dict that doesn't match."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        data = {"user": "bob", "data": "hidden"}

        filtered = middleware.filter_response_data(data, {"user": "alice"})

        assert filtered is None


class TestAuthFilterMiddlewareIntegration:
    """Integration tests for AuthFilterMiddleware with gateway."""

    @pytest.fixture(scope="class")
    def filter_gateway(self, free_port):
        """Create a gateway with auth filtering enabled."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_auth_filter:mock_validator")
        gateway = Gateway(
            modules=[
                UserDataModule(),
                MountRestRoutes(force_mount_all=True),
                MountExternalAPIKeyMiddleware(external_validator=validator_path),
                AuthFilterMiddleware(filter_fields=["user"]),
            ],
            channels=UserDataChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        return gateway

    @pytest.fixture(scope="class")
    def filter_webserver(self, filter_gateway):
        filter_gateway.start(rest=True, _in_test=True)
        yield filter_gateway
        filter_gateway.stop()

    @pytest.fixture(scope="class")
    def filter_client(self, filter_webserver) -> TestClient:
        return TestClient(filter_webserver.web_app.get_fastapi())

    def test_auth_required(self, filter_client: TestClient):
        """Test that authentication is required."""
        response = filter_client.get("/api/v1/last")
        assert response.status_code == 403

    def test_auth_accepts_valid_key(self, filter_client: TestClient):
        """Test that valid API keys are accepted."""
        response = filter_client.get("/api/v1/last?token=alice_key")
        assert response.status_code == 200


class TestAuthFilterMiddlewareNoAuth:
    """Test AuthFilterMiddleware when no auth middleware is present."""

    @pytest.fixture(scope="class")
    def no_auth_gateway(self, free_port):
        """Create a gateway without auth middleware."""
        gateway = Gateway(
            modules=[
                UserDataModule(),
                MountRestRoutes(force_mount_all=True),
                AuthFilterMiddleware(filter_fields=["user"]),
            ],
            channels=UserDataChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        return gateway

    @pytest.fixture(scope="class")
    def no_auth_webserver(self, no_auth_gateway):
        no_auth_gateway.start(rest=True, _in_test=True)
        yield no_auth_gateway
        no_auth_gateway.stop()

    @pytest.fixture(scope="class")
    def no_auth_client(self, no_auth_webserver) -> TestClient:
        return TestClient(no_auth_webserver.web_app.get_fastapi())

    def test_no_filtering_without_auth(self, no_auth_client: TestClient):
        """Test that filtering is bypassed when no auth middleware exists."""
        # Without auth middleware, all requests should succeed without filtering
        response = no_auth_client.get("/api/v1/last")
        # Should succeed since there's no auth requirement
        assert response.status_code == 200


class TestAuthFilterMultipleFields:
    """Test AuthFilterMiddleware with multiple filter fields."""

    def test_multiple_filter_fields_all_match(self):
        """Test filtering with multiple fields - all must match."""
        middleware = AuthFilterMiddleware(filter_fields=["user", "tenant"])

        # Both fields match
        assert middleware.filter_struct({"user": "alice", "tenant": "acme", "data": "test"}, {"user": "alice", "tenant": "acme"}) is True

    def test_multiple_filter_fields_one_mismatch(self):
        """Test filtering with multiple fields - one mismatch filters out."""
        middleware = AuthFilterMiddleware(filter_fields=["user", "tenant"])

        # User matches but tenant doesn't
        assert middleware.filter_struct({"user": "alice", "tenant": "other", "data": "test"}, {"user": "alice", "tenant": "acme"}) is False

    def test_multiple_filter_fields_partial_struct(self):
        """Test filtering when struct only has some filter fields."""
        middleware = AuthFilterMiddleware(filter_fields=["user", "tenant"])

        # Struct only has user, not tenant - only user is checked
        assert middleware.filter_struct({"user": "alice", "data": "test"}, {"user": "alice", "tenant": "acme"}) is True


class TestWebSocketFiltering:
    """Test WebSocket data filtering."""

    @pytest.mark.asyncio
    async def test_filter_websocket_data_filters_correctly(self):
        """Test that filter_websocket_data filters WebSocket messages."""
        # Create middleware with mock auth
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        # Mock the auth middleware with proper async interface
        class MockAuthMiddleware:
            _identity_store = {"test-uuid": {"user": "alice"}}

            async def get_identity(self, session_uuid: str):
                return self._identity_store.get(session_uuid)

            async def get_identity_from_credentials(self, cookies, headers, query_params):
                token = cookies.get("token")
                if token:
                    return await self.get_identity(token)
                return None

        middleware._auth_middlewares = [MockAuthMiddleware()]

        # Create a mock websocket with cookies
        class MockWebSocket:
            cookies = {"token": "test-uuid"}
            headers = {}
            query_params = {}

        ws = MockWebSocket()

        # Test filtering
        message = '{"channel": "test", "data": [{"user": "alice", "data": "visible"}, {"user": "bob", "data": "hidden"}]}'
        filtered = await middleware.filter_websocket_data(message, ws)

        import json

        parsed = json.loads(filtered)
        assert len(parsed["data"]) == 1
        assert parsed["data"][0]["user"] == "alice"

    @pytest.mark.asyncio
    async def test_filter_websocket_data_all_filtered(self):
        """Test that None is returned when all data is filtered out."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        class MockAuthMiddleware:
            _identity_store = {"test-uuid": {"user": "alice"}}

            async def get_identity(self, session_uuid: str):
                return self._identity_store.get(session_uuid)

            async def get_identity_from_credentials(self, cookies, headers, query_params):
                token = cookies.get("token")
                if token:
                    return await self.get_identity(token)
                return None

        middleware._auth_middlewares = [MockAuthMiddleware()]

        class MockWebSocket:
            cookies = {"token": "test-uuid"}
            headers = {}
            query_params = {}

        ws = MockWebSocket()

        # All data is for bob, should be filtered out
        message = '{"channel": "test", "data": [{"user": "bob", "data": "hidden"}]}'
        filtered = await middleware.filter_websocket_data(message, ws)

        assert filtered is None

    @pytest.mark.asyncio
    async def test_filter_websocket_data_no_identity(self):
        """Test that data passes through when no identity found."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        class MockAuthMiddleware:
            _identity_store = {}

            async def get_identity(self, session_uuid: str):
                return self._identity_store.get(session_uuid)

            async def get_identity_from_credentials(self, cookies, headers, query_params):
                token = cookies.get("token")
                if token:
                    return await self.get_identity(token)
                return None

        middleware._auth_middlewares = [MockAuthMiddleware()]

        class MockWebSocket:
            cookies = {"token": "unknown-uuid"}
            headers = {}
            query_params = {}

        ws = MockWebSocket()

        message = '{"channel": "test", "data": [{"user": "bob", "data": "visible"}]}'
        filtered = await middleware.filter_websocket_data(message, ws)

        # Should pass through unchanged
        assert filtered == message


class TestIdentityCacheUnit:
    """Unit tests for identity cache functionality."""

    def test_cache_single_item(self):
        """Test caching a single item by identity."""
        middleware = AuthFilterMiddleware(
            filter_fields=["user"],
            identity_cache_channels=ChannelSelection(include=["test_channel"]),
        )
        # Initialize cache
        middleware._identity_cache["test_channel"] = {}
        middleware._cached_channels.add("test_channel")

        # Cache an item
        middleware._cache_single_item(
            {"user": "alice", "data": "test1"},
            "test_channel",
            "user",
        )

        assert "alice" in middleware._identity_cache["test_channel"]
        assert middleware._identity_cache["test_channel"]["alice"]["data"] == "test1"

    def test_cache_updates_on_new_value(self):
        """Test that cache updates when new value for same identity arrives."""
        middleware = AuthFilterMiddleware(
            filter_fields=["user"],
            identity_cache_channels=ChannelSelection(include=["test_channel"]),
        )
        middleware._identity_cache["test_channel"] = {}
        middleware._cached_channels.add("test_channel")

        # Cache first item
        middleware._cache_single_item(
            {"user": "alice", "data": "old"},
            "test_channel",
            "user",
        )

        # Cache second item for same user
        middleware._cache_single_item(
            {"user": "alice", "data": "new"},
            "test_channel",
            "user",
        )

        # Should have the new value
        assert middleware._identity_cache["test_channel"]["alice"]["data"] == "new"

    def test_cache_multiple_users(self):
        """Test caching values for multiple users."""
        middleware = AuthFilterMiddleware(
            filter_fields=["user"],
            identity_cache_channels=ChannelSelection(include=["test_channel"]),
        )
        middleware._identity_cache["test_channel"] = {}
        middleware._cached_channels.add("test_channel")

        middleware._cache_single_item(
            {"user": "alice", "data": "alice_data"},
            "test_channel",
            "user",
        )
        middleware._cache_single_item(
            {"user": "bob", "data": "bob_data"},
            "test_channel",
            "user",
        )

        assert middleware._identity_cache["test_channel"]["alice"]["data"] == "alice_data"
        assert middleware._identity_cache["test_channel"]["bob"]["data"] == "bob_data"

    def test_get_cached_last(self):
        """Test retrieving cached values."""
        middleware = AuthFilterMiddleware(
            filter_fields=["user"],
            identity_cache_channels=ChannelSelection(include=["test_channel"]),
        )
        middleware._identity_cache["test_channel"] = {
            "alice": {"user": "alice", "data": "cached"},
        }

        result = middleware.get_cached_last("test_channel", "alice")
        assert result is not None
        assert result["data"] == "cached"

        # Unknown user
        result = middleware.get_cached_last("test_channel", "unknown")
        assert result is None

        # Unknown channel
        result = middleware.get_cached_last("unknown_channel", "alice")
        assert result is None


class TestIdentityCacheIntegration:
    """Integration tests for identity cache with gateway."""

    @pytest.fixture(scope="class")
    def cached_gateway(self, free_port):
        """Create a gateway with identity cache enabled."""
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_auth_filter:mock_validator")
        gateway = Gateway(
            modules=[
                UserDataModule(),
                MountRestRoutes(force_mount_all=True),
                MountExternalAPIKeyMiddleware(external_validator=validator_path),
                AuthFilterMiddleware(
                    filter_fields=["user"],
                    identity_cache_channels=ChannelSelection(include=["user_data"]),
                ),
            ],
            channels=UserDataChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        return gateway

    @pytest.fixture(scope="class")
    def cached_webserver(self, cached_gateway):
        cached_gateway.start(rest=True, _in_test=True)
        yield cached_gateway
        cached_gateway.stop()

    @pytest.fixture(scope="class")
    def cached_client(self, cached_webserver) -> TestClient:
        return TestClient(cached_webserver.web_app.get_fastapi())

    def test_auth_required_with_cache(self, cached_client: TestClient):
        """Test that authentication is still required with cache enabled."""
        response = cached_client.get("/api/v1/last/user_data")
        assert response.status_code == 403

    def test_cached_last_returns_user_data(self, cached_client: TestClient):
        """Test that /last returns only data for the authenticated user."""
        import time

        # Wait for some data to be generated
        time.sleep(0.5)

        # Get data as alice
        response = cached_client.get("/api/v1/last/user_data?token=alice_key")
        assert response.status_code == 200

        data = response.json()
        # All returned data should be for alice (or empty if no alice data yet)
        for item in data:
            assert item.get("user") == "alice"


class TestSendValidation:
    """Test send validation functionality."""

    def test_validate_send_data_single_item_match(self):
        """Test that valid send data passes validation."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        # Matching identity should pass
        assert (
            middleware._validate_send_data(
                {"user": "alice", "data": "test"},
                "user",
                "alice",
            )
            is True
        )

    def test_validate_send_data_single_item_mismatch(self):
        """Test that mismatched send data fails validation."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        # Mismatching identity should fail
        assert (
            middleware._validate_send_data(
                {"user": "bob", "data": "test"},
                "user",
                "alice",
            )
            is False
        )

    def test_validate_send_data_list_all_match(self):
        """Test that list data with all matching items passes."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        data = [
            {"user": "alice", "data": "test1"},
            {"user": "alice", "data": "test2"},
        ]
        assert middleware._validate_send_data(data, "user", "alice") is True

    def test_validate_send_data_list_one_mismatch(self):
        """Test that list data with one mismatch fails."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        data = [
            {"user": "alice", "data": "test1"},
            {"user": "bob", "data": "test2"},  # Mismatch
        ]
        assert middleware._validate_send_data(data, "user", "alice") is False

    def test_validate_send_data_missing_field(self):
        """Test that missing identity field passes (struct may not have field)."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])

        # Missing field should pass (allows structs without identity field)
        assert (
            middleware._validate_send_data(
                {"data": "test"},
                "user",
                "alice",
            )
            is True
        )


class TestSendValidationIntegration:
    """Integration tests for send validation.

    Note: These tests require proper cookie handling between requests.
    The unit tests in TestSendValidation verify the core validation logic,
    which is the key functionality. Integration testing requires session
    persistence via cookies.
    """

    @pytest.fixture(scope="class")
    def free_port(self):
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    @pytest.fixture(scope="class")
    def send_validated_gateway(self, free_port):
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_auth_filter:mock_validator")
        gateway = Gateway(
            modules=[
                UserDataModule(),
                MountRestRoutes(force_mount_all=True),
                MountExternalAPIKeyMiddleware(external_validator=validator_path),
                AuthFilterMiddleware(
                    filter_fields=["user"],
                    send_validation_channels=ChannelSelection(include=["user_data"]),
                ),
            ],
            channels=UserDataChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        return gateway

    @pytest.fixture(scope="class")
    def send_validated_server(self, send_validated_gateway):
        send_validated_gateway.start(rest=True, _in_test=True)
        yield send_validated_gateway
        send_validated_gateway.stop()

    @pytest.fixture(scope="class")
    def send_validated_client(self, send_validated_server) -> TestClient:
        return TestClient(send_validated_server.web_app.get_fastapi())

    def test_send_validation_channels_populated(self, send_validated_server):
        """Test that send validation channels are populated correctly."""
        # Find the auth filter middleware
        auth_filter = None
        for module in send_validated_server.modules:
            if isinstance(module, AuthFilterMiddleware):
                auth_filter = module
                break

        assert auth_filter is not None
        assert "user_data" in auth_filter._send_validated_channels

    @pytest.mark.skip(reason="Requires cookie session persistence between requests")
    def test_send_valid_data_accepted(self, send_validated_client: TestClient):
        """Test that send with matching identity is accepted."""
        response = send_validated_client.post(
            "/api/v1/send/user_data?token=alice_key",
            json={"user": "alice", "data": "test_data"},
        )
        # Should be accepted (200 or whatever the actual send handler returns)
        assert response.status_code != 403

    @pytest.mark.skip(reason="Requires cookie session persistence between requests")
    def test_send_mismatched_data_rejected(self, send_validated_client: TestClient):
        """Test that send with mismatched identity is rejected."""
        response = send_validated_client.post(
            "/api/v1/send/user_data?token=alice_key",
            json={"user": "bob", "data": "test_data"},  # Alice trying to send as Bob
        )
        assert response.status_code == 403
        assert "does not match" in response.json().get("detail", "")

    @pytest.mark.skip(reason="Requires cookie session persistence between requests")
    def test_send_list_with_mismatch_rejected(self, send_validated_client: TestClient):
        """Test that send list with any mismatch is rejected."""
        response = send_validated_client.post(
            "/api/v1/send/user_data?token=alice_key",
            json=[
                {"user": "alice", "data": "test1"},
                {"user": "bob", "data": "test2"},  # Mismatch
            ],
        )
        assert response.status_code == 403


class TestNextFilteringUnit:
    """Unit tests for next filtering functionality."""

    def test_next_filter_channels_populated(self):
        """Test that next filter channels are populated correctly."""
        middleware = AuthFilterMiddleware(
            filter_fields=["user"],
            next_filter_channels=ChannelSelection(include=["user_data"]),
        )
        channels = UserDataChannels()
        middleware.connect(channels)
        assert "user_data" in middleware._next_filtered_channels

    def test_next_filter_timeout_default(self):
        """Test that next filter timeout has correct default."""
        middleware = AuthFilterMiddleware(filter_fields=["user"])
        assert middleware.next_filter_timeout == 30.0

    def test_next_filter_timeout_custom(self):
        """Test that custom next filter timeout is set."""
        middleware = AuthFilterMiddleware(
            filter_fields=["user"],
            next_filter_timeout=60.0,
        )
        assert middleware.next_filter_timeout == 60.0


class TestNextFilteringIntegration:
    """Integration tests for next filtering."""

    @pytest.fixture(scope="class")
    def free_port(self):
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    @pytest.fixture(scope="class")
    def next_filtered_gateway(self, free_port):
        validator_path = PyObjectPath("csp_gateway.tests.server.web.test_auth_filter:mock_validator")
        gateway = Gateway(
            modules=[
                UserDataModule(),
                MountRestRoutes(force_mount_all=True),
                MountExternalAPIKeyMiddleware(external_validator=validator_path),
                AuthFilterMiddleware(
                    filter_fields=["user"],
                    next_filter_channels=ChannelSelection(include=["user_data"]),
                    next_filter_timeout=5.0,  # Short timeout for tests
                ),
            ],
            channels=UserDataChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        return gateway

    @pytest.fixture(scope="class")
    def next_filtered_server(self, next_filtered_gateway):
        next_filtered_gateway.start(rest=True, _in_test=True)
        yield next_filtered_gateway
        next_filtered_gateway.stop()

    def test_next_filter_channels_populated_in_gateway(self, next_filtered_server):
        """Test that next filter channels are populated correctly in gateway."""
        # Find the auth filter middleware
        auth_filter = None
        for module in next_filtered_server.modules:
            if isinstance(module, AuthFilterMiddleware):
                auth_filter = module
                break

        assert auth_filter is not None
        assert "user_data" in auth_filter._next_filtered_channels
        assert auth_filter.next_filter_timeout == 5.0
