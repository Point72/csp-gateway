"""Authentication-based response filtering middleware.

This middleware filters REST and WebSocket responses based on the authenticated
user's identity. When a struct has an attribute matching an identity field
(e.g., "user"), only records where that attribute matches the authenticated
user's value are returned.

This middleware works with any authentication middleware that implements
the IdentityAwareMiddlewareMixin interface, including:
- MountExternalAPIKeyMiddleware
- MountOAuth2Middleware
- MountSimpleAuthMiddleware

Multiple auth middlewares are supported - the filter will check each one
in order when looking up user identity. This allows for different auth
methods for different scopes.

Example:
    If a user authenticates with identity {"user": "testuser"}, and the response
    contains structs like:
    [
        {"user": "testuser", "data": "visible"},
        {"user": "otheruser", "data": "hidden"}
    ]
    Only the first record will be returned.

Features:
    - Response filtering: Automatically filters REST and WebSocket responses
    - identity_cache_channels: Per-identity cache so `/last` returns user's data
    - send_validation_channels: Reject `/send` requests with wrong identity
    - next_filter_channels: Loop `/next` until matching record arrives
    - Multi-auth support: Works with multiple auth middlewares for different scopes
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

import csp
from csp import ts
from fastapi import Request
from pydantic import Field, PrivateAttr
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from starlette.websockets import WebSocket

from csp_gateway.server import ChannelSelection, GatewayChannels, GatewayModule

from ..web import GatewayWebApp
from .base import IdentityAwareMiddlewareMixin

__all__ = ("AuthFilterMiddleware",)

log = logging.getLogger(__name__)


class AuthFilterMiddleware(GatewayModule):
    """Middleware that filters responses based on authenticated user identity.

    This middleware works with authentication middlewares that store user identity
    (like MountExternalAPIKeyMiddleware, MountOAuth2Middleware, or MountSimpleAuthMiddleware)
    and filters response data so users only see records matching their identity.

    Attributes:
        filter_fields: List of struct attribute names to filter on. If a struct
            has any of these attributes, it will be filtered to only return
            records where the attribute value matches the authenticated user's
            corresponding identity field.
        cookie_name: Name of the cookie containing the session UUID. Should match
            the api_key_name of the auth middleware.
        auth_middleware_class: Optional class type of the auth middleware to look
            for. If not specified, searches for any middleware with _identity_store.
        identity_cache_channels: Optional ChannelSelection specifying which channels
            should maintain a per-identity cache for /last endpoints. When enabled,
            /last will return the most recent record matching the user's identity,
            not just the global last record.
        send_validation_channels: Optional ChannelSelection specifying which channels
            should validate /send requests. When enabled, rejects sends where the
            struct's identity field doesn't match the authenticated user.
        next_filter_channels: Optional ChannelSelection specifying which channels
            should filter /next requests. When enabled, loops until a record matching
            the user's identity arrives (with timeout).
        next_filter_timeout: Timeout in seconds for /next filtering. Default 30s.
    """

    filter_fields: List[str] = Field(
        default_factory=list,
        description="List of struct attribute names to filter on (e.g., ['user'])",
    )
    cookie_name: str = Field(
        default="token",
        description="Cookie name for session UUID (should match auth middleware's api_key_name)",
    )
    auth_middleware_class: Optional[str] = Field(
        default=None,
        description="Fully qualified class name of auth middleware (optional)",
    )
    identity_cache_channels: Optional[ChannelSelection] = Field(
        default=None,
        description="Channels to maintain per-identity cache for /last endpoints. "
        "When set, /last returns the most recent record matching user's identity.",
    )
    send_validation_channels: Optional[ChannelSelection] = Field(
        default=None,
        description="Channels to validate /send requests. When set, rejects sends "
        "where the struct's identity field doesn't match the authenticated user.",
    )
    next_filter_channels: Optional[ChannelSelection] = Field(
        default=None,
        description="Channels to filter /next requests. When set, loops until a record matching the user's identity arrives.",
    )
    next_filter_timeout: float = Field(
        default=30.0,
        description="Timeout in seconds for /next filtering.",
    )

    # List of auth middlewares implementing IdentityAwareMiddlewareMixin
    _auth_middlewares: List[IdentityAwareMiddlewareMixin] = PrivateAttr(default_factory=list)
    _app: Any = PrivateAttr(default=None)
    _channels: Any = PrivateAttr(default=None)
    # Per-identity cache: {channel_name: {identity_value: last_record}}
    _identity_cache: Dict[str, Dict[Any, Any]] = PrivateAttr(default_factory=dict)
    # Track which channels are cached
    _cached_channels: set = PrivateAttr(default_factory=set)
    # Track which channels have send validation enabled
    _send_validated_channels: set = PrivateAttr(default_factory=set)
    # Track which channels have next filtering enabled
    _next_filtered_channels: set = PrivateAttr(default_factory=set)

    def connect(self, channels: GatewayChannels) -> None:
        """Subscribe to channels for per-identity caching and filtering if configured."""
        self._channels = channels

        # Populate send validated channels
        if self.send_validation_channels and self.filter_fields:
            for field in self.send_validation_channels.select_from(channels):
                maybe_edge = channels.get_channel(field)
                if maybe_edge is None:
                    continue
                if isinstance(maybe_edge, dict):
                    for key in maybe_edge.keys():
                        self._send_validated_channels.add(f"{field}/{key}")
                else:
                    self._send_validated_channels.add(field)

        # Populate next filtered channels
        if self.next_filter_channels and self.filter_fields:
            for field in self.next_filter_channels.select_from(channels):
                maybe_edge = channels.get_channel(field)
                if maybe_edge is None:
                    continue
                if isinstance(maybe_edge, dict):
                    for key in maybe_edge.keys():
                        self._next_filtered_channels.add(f"{field}/{key}")
                else:
                    self._next_filtered_channels.add(field)

        # Set up identity caching
        if not self.identity_cache_channels or not self.filter_fields:
            return

        # Get the first filter field to use as the identity key
        identity_field = self.filter_fields[0]

        for field in self.identity_cache_channels.select_from(channels):
            maybe_edge = channels.get_channel(field)
            if maybe_edge is None:
                continue

            # Handle dict baskets
            if isinstance(maybe_edge, dict):
                for key, edge in maybe_edge.items():
                    cache_key = f"{field}/{key}"
                    self._identity_cache[cache_key] = {}
                    self._cached_channels.add(cache_key)
                    self._cache_identity_values(edge, cache_key, identity_field)
            else:
                self._identity_cache[field] = {}
                self._cached_channels.add(field)
                self._cache_identity_values(maybe_edge, field, identity_field)

    @csp.node
    def _cache_identity_values(
        self,
        data: ts[object],
        channel_name: str,
        identity_field: str,
    ):
        """CSP node that caches the latest value per identity."""
        if csp.ticked(data):
            value = data

            # Handle list types - cache each item separately
            if isinstance(value, list):
                for item in value:
                    self._cache_single_item(item, channel_name, identity_field)
            else:
                self._cache_single_item(value, channel_name, identity_field)

    def _cache_single_item(self, item: Any, channel_name: str, identity_field: str) -> None:
        """Cache a single item by its identity field value."""
        # Try to extract identity value from the item
        identity_value = None

        if hasattr(item, identity_field):
            identity_value = getattr(item, identity_field)
        elif isinstance(item, dict) and identity_field in item:
            identity_value = item[identity_field]

        if identity_value is not None:
            self._identity_cache[channel_name][identity_value] = item

    def get_cached_last(self, channel_name: str, identity_value: Any) -> Optional[Any]:
        """Get the cached last value for a channel and identity."""
        if channel_name not in self._identity_cache:
            return None
        return self._identity_cache[channel_name].get(identity_value)

    def _handle_cached_last(self, request: Request, identity: Dict[str, Any]) -> Optional[Response]:
        """Handle /last requests for cached channels by serving from cache.

        Returns a Response if this is a cached channel request, None otherwise.
        """
        path = request.url.path

        # Check if this is a /last request
        # Pattern: /api/v1/last/{channel} or /api/v1/last/{channel}/{key}
        if "/last/" not in path:
            return None

        # Extract channel name from path
        # e.g., /api/v1/last/user_data -> user_data
        # e.g., /api/v1/last/user_data/some_key -> user_data/some_key
        parts = path.split("/last/", 1)
        if len(parts) != 2:
            return None

        channel_path = parts[1].rstrip("/")

        # Check if this channel is in our cache
        if channel_path not in self._cached_channels:
            return None

        # Get the identity field value
        if not self.filter_fields:
            return None

        identity_field = self.filter_fields[0]
        identity_value = identity.get(identity_field)
        if identity_value is None:
            return None

        # Get cached value
        cached = self.get_cached_last(channel_path, identity_value)

        if cached is None:
            # No cached value for this identity - return empty list
            return Response(
                content="[]",
                media_type="application/json",
            )

        # Serialize the cached value
        if hasattr(cached, "type_adapter"):
            # It's a GatewayStruct
            json_bytes = b"[" + cached.type_adapter().dump_json(cached) + b"]"
            return Response(
                content=json_bytes,
                media_type="application/json",
            )
        else:
            # Fallback to json.dumps
            return Response(
                content=json.dumps([cached]),
                media_type="application/json",
            )

    async def _validate_send_request(self, request: Request, identity: Dict[str, Any]) -> Optional[Response]:
        """Validate /send requests to ensure identity field matches authenticated user.

        Returns a 403 Response if validation fails, None otherwise.
        """
        path = request.url.path

        # Check if this is a /send request
        if "/send/" not in path or request.method != "POST":
            return None

        # Extract channel name from path
        parts = path.split("/send/", 1)
        if len(parts) != 2:
            return None

        channel_path = parts[1].rstrip("/")

        # Check if this channel has send validation enabled
        if channel_path not in self._send_validated_channels:
            return None

        # Get the identity field and value
        if not self.filter_fields:
            return None

        identity_field = self.filter_fields[0]
        identity_value = identity.get(identity_field)

        if identity_value is None:
            # No identity value to validate against
            return None

        # Read and parse the request body
        try:
            body = await request.body()
            data = json.loads(body.decode())

            # Validate the data
            if not self._validate_send_data(data, identity_field, identity_value):
                return Response(
                    content=json.dumps({"error": "Forbidden", "detail": f"Send data {identity_field} does not match authenticated user"}),
                    status_code=403,
                    media_type="application/json",
                )
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Can't parse body, let route handler deal with it
            pass

        return None

    def _validate_send_data(self, data: Any, identity_field: str, expected_value: Any) -> bool:
        """Validate that send data has matching identity field.

        Returns True if valid, False otherwise.
        """
        if isinstance(data, list):
            # All items in list must match
            return all(self._validate_single_send_item(item, identity_field, expected_value) for item in data)
        else:
            return self._validate_single_send_item(data, identity_field, expected_value)

    def _validate_single_send_item(self, item: Any, identity_field: str, expected_value: Any) -> bool:
        """Validate a single send item."""
        if isinstance(item, dict):
            # If field is present, it must match
            if identity_field in item:
                return item[identity_field] == expected_value
            # Field not present - allow (struct may not have this field)
            return True
        elif hasattr(item, identity_field):
            return getattr(item, identity_field) == expected_value
        # Field not present
        return True

    async def _handle_filtered_next(
        self,
        request: Request,
        identity: Dict[str, Any],
        call_next: Any,
    ) -> Optional[Response]:
        """Handle /next requests by looping until matching record arrives.

        Returns a Response if this is a filtered next request, None otherwise.
        """
        path = request.url.path

        # Check if this is a /next request
        if "/next/" not in path:
            return None

        # Extract channel name from path
        parts = path.split("/next/", 1)
        if len(parts) != 2:
            return None

        channel_path = parts[1].rstrip("/")

        # Check if this channel has next filtering enabled
        if channel_path not in self._next_filtered_channels:
            return None

        # Get the identity field and value
        if not self.filter_fields:
            return None

        identity_field = self.filter_fields[0]
        identity_value = identity.get(identity_field)

        if identity_value is None:
            return None

        # Loop until we get a matching record or timeout
        start_time = time.time()

        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed >= self.next_filter_timeout:
                return Response(
                    content=json.dumps({"error": "Timeout", "detail": f"No matching record found within {self.next_filter_timeout}s"}),
                    status_code=408,
                    media_type="application/json",
                )

            # Call the actual next handler
            response = await call_next(request)

            # Check if we got data
            if response.status_code != 200:
                return response

            # Parse the response
            body = b""
            async for chunk in response.body_iterator:
                body += chunk

            try:
                data = json.loads(body.decode())

                # Filter the data
                filtered = self.filter_response_data(data, identity)

                if filtered is not None and (not isinstance(filtered, list) or len(filtered) > 0):
                    # Found matching data
                    return Response(
                        content=json.dumps(filtered),
                        status_code=200,
                        headers=dict(response.headers),
                        media_type="application/json",
                    )

                # No match, wait a bit and try again
                await asyncio.sleep(0.1)

            except (json.JSONDecodeError, UnicodeDecodeError):
                # Can't parse, return original
                return Response(
                    content=body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                )

    def _find_auth_middlewares(self, app: GatewayWebApp) -> List[IdentityAwareMiddlewareMixin]:
        """Find all authentication middlewares that implement IdentityAwareMiddlewareMixin.

        Returns a list of auth middlewares, allowing for multiple auth methods
        for different scopes. Middlewares are checked in order when looking up identity.

        Args:
            app: The gateway web application

        Returns:
            List of auth middlewares implementing IdentityAwareMiddlewareMixin
        """
        auth_middlewares = []
        for module in app.gateway.modules:
            # Check if module implements IdentityAwareMiddlewareMixin
            if isinstance(module, IdentityAwareMiddlewareMixin):
                # If auth_middleware_class is specified, filter by class name
                if self.auth_middleware_class:
                    module_class_name = f"{module.__class__.__module__}.{module.__class__.__name__}"
                    if module_class_name == self.auth_middleware_class:
                        auth_middlewares.append(module)
                else:
                    auth_middlewares.append(module)
        return auth_middlewares

    async def get_identity_from_request(self, request: Request) -> Optional[Dict[str, Any]]:
        """Extract user identity from request using auth middlewares.

        Checks all registered auth middlewares in order, returning the first
        valid identity found. Each middleware handles its own credential extraction
        and validation.

        Args:
            request: FastAPI request object

        Returns:
            Identity dict if found, None otherwise.
        """
        if not self._auth_middlewares:
            return None

        # Convert request data to dicts for middleware
        cookies = dict(request.cookies)
        headers = dict(request.headers)
        query_params = dict(request.query_params)

        # Try each auth middleware
        for auth_middleware in self._auth_middlewares:
            identity = await auth_middleware.get_identity_from_credentials(
                cookies=cookies,
                headers=headers,
                query_params=query_params,
            )
            if identity:
                return identity

        return None

    async def get_identity_from_websocket(self, websocket: WebSocket) -> Optional[Dict[str, Any]]:
        """Extract user identity from WebSocket using auth middlewares.

        Checks all registered auth middlewares in order, returning the first
        valid identity found.

        Args:
            websocket: Starlette WebSocket object

        Returns:
            Identity dict if found, None otherwise.
        """
        if not self._auth_middlewares:
            return None

        # Convert websocket data to dicts for middleware
        cookies = dict(websocket.cookies)
        headers = dict(websocket.headers)
        query_params = dict(websocket.query_params) if hasattr(websocket, "query_params") else {}

        # Try each auth middleware
        for auth_middleware in self._auth_middlewares:
            identity = await auth_middleware.get_identity_from_credentials(
                cookies=cookies,
                headers=headers,
                query_params=query_params,
            )
            if identity:
                return identity

        return None

    def filter_struct(self, data: Dict[str, Any], identity: Dict[str, Any]) -> bool:
        """Check if a struct record should be included based on identity.

        Returns True if the record should be included, False otherwise.
        """
        if not identity or not self.filter_fields:
            return True

        for field in self.filter_fields:
            # Check if struct has this field
            if field in data:
                # Check if identity has this field
                if field in identity:
                    # Filter: only include if values match
                    if data[field] != identity[field]:
                        return False
        return True

    def filter_response_data(self, data: Any, identity: Optional[Dict[str, Any]]) -> Any:
        """Filter response data based on user identity.

        Args:
            data: The response data (can be list, dict, or other)
            identity: The authenticated user's identity dict

        Returns:
            Filtered data with only records matching identity
        """
        if not identity or not self.filter_fields:
            return data

        if isinstance(data, list):
            return [item for item in data if not isinstance(item, dict) or self.filter_struct(item, identity)]
        elif isinstance(data, dict):
            if self.filter_struct(data, identity):
                return data
            return None
        return data

    def rest(self, app: GatewayWebApp) -> None:
        """Install the auth filtering middleware."""
        self._app = app
        self._auth_middlewares = self._find_auth_middlewares(app)

        if not self._auth_middlewares:
            log.warning("AuthFilterMiddleware: No auth middleware implementing IdentityAwareMiddlewareMixin found. Filtering will not be applied.")
            return

        # Log found auth middlewares
        middleware_names = [m.__class__.__name__ for m in self._auth_middlewares]
        log.info(f"AuthFilterMiddleware: Found {len(self._auth_middlewares)} auth middleware(s): {middleware_names}")

        # Store reference on app for WebSocket module access
        app.app.state.auth_filter_middleware = self

        # Install response filtering middleware
        middleware = self

        class FilterResponseMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
                # Get identity for this request
                identity = await middleware.get_identity_from_request(request)

                # Store identity on request state for downstream use
                request.state.identity = identity

                # Handle send validation for configured channels
                if identity and middleware._send_validated_channels:
                    validation_result = await middleware._validate_send_request(request, identity)
                    if validation_result is not None:
                        return validation_result

                # Check if this is a /last request for a cached channel
                if identity and middleware._cached_channels:
                    cached_response = middleware._handle_cached_last(request, identity)
                    if cached_response is not None:
                        return cached_response

                # Handle next filtering for configured channels
                if identity and middleware._next_filtered_channels:
                    next_result = await middleware._handle_filtered_next(request, identity, call_next)
                    if next_result is not None:
                        return next_result

                # Call the actual route handler
                response = await call_next(request)

                # Only filter JSON responses
                if identity and middleware.filter_fields and response.headers.get("content-type", "").startswith("application/json"):
                    # Read response body
                    body = b""
                    async for chunk in response.body_iterator:
                        body += chunk

                    try:
                        # Parse JSON
                        data = json.loads(body.decode())

                        # Filter the data
                        filtered_data = middleware.filter_response_data(data, identity)

                        # Create new response with filtered data
                        filtered_body = json.dumps(filtered_data).encode()
                        return Response(
                            content=filtered_body,
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            media_type="application/json",
                        )
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # If we can't parse JSON, return original response body
                        return Response(
                            content=body,
                            status_code=response.status_code,
                            headers=dict(response.headers),
                        )

                return response

        app.app.add_middleware(FilterResponseMiddleware)

    async def filter_websocket_data(self, data: str, websocket: WebSocket) -> Optional[str]:
        """Filter WebSocket response data based on authenticated user.

        Args:
            data: JSON string of websocket message
            websocket: The WebSocket connection

        Returns:
            Filtered JSON string, or None if all data filtered out
        """
        identity = await self.get_identity_from_websocket(websocket)
        if not identity or not self.filter_fields:
            return data

        try:
            message = json.loads(data)
            if "data" in message:
                # Filter the data portion
                filtered = self.filter_response_data(message["data"], identity)
                if filtered is None or (isinstance(filtered, list) and len(filtered) == 0):
                    return None
                message["data"] = filtered
                return json.dumps(message)
            return data
        except json.JSONDecodeError:
            return data
