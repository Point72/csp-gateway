"""CSP integration for streaming data from the Gateway client over websockets.

This module provides the adapter infrastructure for streaming data from a GatewayServer
via websockets in CSP graphs. The main entry point is the `stream_csp` method on
`GatewayClient`.

Example:
    >>> import csp
    >>> from csp_gateway.client import GatewayClient
    >>>
    >>> @csp.graph
    >>> def my_graph():
    ...     client = GatewayClient(host="localhost", port=8000)
    ...
    ...     # Subscribe to channels dynamically
    ...     subscribe = csp.curve(str, [(timedelta(seconds=0), "channel1"), (timedelta(seconds=1), "channel2")])
    ...     unsubscribe = csp.curve(str, [(timedelta(seconds=5), "channel1")])
    ...
    ...     # Returns a DynamicBasket where each key is a channel name
    ...     basket = client.stream_csp(subscribe=subscribe, unsubscribe=unsubscribe)
    ...
    ...     # Access data for specific channels
    ...     csp.print("basket", basket)
    ...
    ...     # Bidirectional: send data back to the server
    ...     outgoing = csp.const({"action": "send", "channel": "my_channel", "data": {"value": 42}})
    ...     basket = client.stream_csp(subscribe=subscribe, data=outgoing)
"""

import logging
import threading
import time
from queue import Empty, Queue
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

import csp
from csp import ts
from csp.impl.adaptermanager import AdapterManagerImpl
from csp.impl.pushadapter import PushInputAdapter
from csp.impl.wiring import py_push_adapter_def

if TYPE_CHECKING:
    from .client import GatewayClientConfig

__all__ = ("GatewayStreamAdapterManager", "ConnectionError")

log = logging.getLogger(__name__)


def _build_ws_route(config: "GatewayClientConfig") -> str:
    """Build the websocket route URL from a config."""
    from .client import _host

    host = _host(config)
    # Replace http with ws
    if host.startswith("https://"):
        ws_host = "wss://" + host[8:]
    else:
        ws_host = "ws://" + host[7:]
    return f"{ws_host}{config.api_route}/stream"


class GatewayStreamAdapterManager:
    """Graph-time representation of the Gateway streaming adapter manager.

    This manager handles the websocket connection to the gateway server and
    distributes incoming data to the appropriate adapters.
    """

    def __init__(self, config: "GatewayClientConfig", connection_timeout: float = -1):
        """Initialize the adapter manager.

        Args:
            config: The GatewayClientConfig specifying the server connection details.
            connection_timeout: How long to wait for the server to be available (in seconds).
                - 0: Expect server to be immediately available at startup
                - -1: Wait indefinitely for the server (default)
                - positive number: Wait up to this many seconds before raising an error
        """
        self._config = config
        self._connection_timeout = connection_timeout
        self._impl: Optional["_GatewayStreamAdapterManagerImpl"] = None

    def subscribe(self, push_mode: csp.PushMode = csp.PushMode.NON_COLLAPSING) -> ts[Dict[str, Any]]:
        """Subscribe to stream data from the gateway.

        Args:
            push_mode: How to handle buffered ticks. Defaults to NON_COLLAPSING.

        Returns:
            A time series of dictionaries containing the streamed data.
        """
        return _GatewayStreamAdapter(self, push_mode=push_mode)

    def add_channel(self, channel: str):
        """Add a channel to subscribe to.

        This can be called after the manager is created to dynamically add channels.
        """
        if self._impl is not None:
            self._impl.add_channel(channel)

    def remove_channel(self, channel: str):
        """Remove a channel subscription.

        This can be called to unsubscribe from a channel.
        """
        if self._impl is not None:
            self._impl.remove_channel(channel)

    def send_data(self, data: Dict[str, Any]):
        """Send data through the websocket.

        This can be called to send data back to the server through the websocket connection.

        Args:
            data: A dictionary mapping channel names to data to send. For example:
                - {"my_channel": {"value": 42}} - sends single dict to channel
                - {"my_channel": [{"value": 1}, {"value": 2}]} - sends list to channel
                - {"ch1": {"v": 1}, "ch2": [{"v": 2}]} - sends to multiple channels
        """
        if self._impl is not None:
            self._impl.send_data(data)

    def _create(self, engine, memo):
        """Create the runtime implementation of this adapter manager."""
        self._impl = _GatewayStreamAdapterManagerImpl(engine, self._config, self, self._connection_timeout)
        return self._impl


class ConnectionError(Exception):
    """Raised when the websocket connection fails or is lost."""

    pass


class _GatewayStreamAdapterManagerImpl(AdapterManagerImpl):
    """Runtime implementation of the Gateway streaming adapter manager."""

    def __init__(
        self,
        engine,
        config: "GatewayClientConfig",
        graph_manager: GatewayStreamAdapterManager,
        connection_timeout: float = -1,
    ):
        super().__init__(engine)
        self._config = config
        self._graph_manager = graph_manager
        self._connection_timeout = connection_timeout
        self._adapters: List[PushInputAdapter] = []
        self._subscribed_channels: Set[str] = set()
        self._pending_subscribes: Queue = Queue()
        self._pending_unsubscribes: Queue = Queue()
        self._pending_data: Queue = Queue()
        self._running = False
        self._connected = threading.Event()
        self._connection_error: Optional[Exception] = None
        self._disconnected = False
        self._thread: Optional[threading.Thread] = None
        self._loop = None
        self._ws = None

    def start(self, starttime, endtime):
        """Start the websocket streaming connection."""
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the websocket streaming connection."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def _check_connection(self):
        """Check if the connection is still valid, raise if disconnected unexpectedly."""
        if self._disconnected and self._running:
            raise ConnectionError(f"WebSocket connection to {_build_ws_route(self._config)} was lost unexpectedly")
        if self._connection_error is not None:
            raise self._connection_error

    def register_input_adapter(self, adapter: PushInputAdapter):
        """Register an input adapter to receive data."""
        self._adapters.append(adapter)

    def add_channel(self, channel: str):
        """Add a channel to subscribe to.

        This is thread-safe and can be called from the CSP engine thread.
        Requests are buffered until the connection is established.
        """
        self._check_connection()
        if channel not in self._subscribed_channels:
            self._subscribed_channels.add(channel)
            self._pending_subscribes.put(channel)

    def remove_channel(self, channel: str):
        """Remove a channel subscription.

        This is thread-safe and can be called from the CSP engine thread.
        Requests are buffered until the connection is established.
        """
        self._check_connection()
        if channel in self._subscribed_channels:
            self._subscribed_channels.remove(channel)
            self._pending_unsubscribes.put(channel)

    def send_data(self, data: Dict[str, Any]):
        """Queue data to be sent through the websocket.

        This is thread-safe and can be called from the CSP engine thread.
        Requests are buffered until the connection is established.

        The data should be a dictionary where keys are channel names and values
        are the data to send to that channel. The adapter will automatically
        wrap each key-value pair into the proper websocket message format.

        Args:
            data: A dictionary mapping channel names to data. For example:
                - {"my_channel": {"value": 42}} - sends single dict to channel
                - {"my_channel": [{"value": 1}, {"value": 2}]} - sends list to channel
                - {"ch1": {"v": 1}, "ch2": [{"v": 2}]} - sends to multiple channels
        """
        self._check_connection()
        # Transform simplified format to websocket message format
        for channel, channel_data in data.items():
            msg = {"action": "send", "channel": channel, "data": channel_data}
            self._pending_data.put(msg)

    def process_next_sim_timeslice(self, now):
        """Not used for realtime adapters."""
        return None

    def _run(self):
        """Main streaming thread."""
        import asyncio

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            self._loop.run_until_complete(self._connect_and_stream())
        except Exception as e:
            self._connection_error = e
            log.exception(f"Error in websocket streaming: {e}")
        finally:
            self._disconnected = True
            self._loop.close()

    async def _connect_and_stream(self):
        """Async method to connect and stream data with retry logic."""
        import asyncio

        try:
            from aiohttp import ClientConnectorError, ClientSession
        except ImportError:
            raise ImportError("aiohttp is required for websocket streaming. Install with: pip install aiohttp")

        route = _build_ws_route(self._config)
        start_time = time.time()
        retry_delay = 0.5  # Start with 500ms delay
        max_retry_delay = 5.0  # Cap at 5 seconds
        last_error: Optional[Exception] = None

        while self._running:
            try:
                async with ClientSession() as session:
                    async with session.ws_connect(route) as ws:
                        self._ws = ws
                        self._connected.set()
                        log.info(f"Connected to websocket at {route}")

                        # Create tasks for receiving and sending
                        receive_task = asyncio.create_task(self._receive_messages(ws))
                        send_task = asyncio.create_task(self._send_subscriptions(ws))

                        try:
                            await asyncio.gather(receive_task, send_task)
                        except Exception:
                            receive_task.cancel()
                            send_task.cancel()
                        finally:
                            # If we get here while still running, connection was lost
                            if self._running:
                                self._connected.clear()
                                self._disconnected = True
                                raise ConnectionError(f"WebSocket connection to {route} was lost unexpectedly")
                        return  # Normal exit

            except ClientConnectorError as e:
                last_error = e
                elapsed = time.time() - start_time

                # Check timeout
                if self._connection_timeout == 0:
                    # Immediate connection required
                    raise ConnectionError(
                        f"Failed to connect to websocket at {route}: {e}. Server must be available at startup (connection_timeout=0)."
                    ) from e
                elif self._connection_timeout > 0 and elapsed >= self._connection_timeout:
                    # Timeout exceeded
                    raise ConnectionError(
                        f"Failed to connect to websocket at {route} after {elapsed:.1f}s (timeout={self._connection_timeout}s): {e}"
                    ) from e

                # Wait and retry with exponential backoff
                log.debug(
                    f"Connection to {route} failed, retrying in {retry_delay:.1f}s... (elapsed: {elapsed:.1f}s, timeout: {self._connection_timeout}s)"
                )
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)

            except Exception as e:
                # For other exceptions, don't retry
                raise ConnectionError(f"Error connecting to websocket at {route}: {e}") from e

        # If we exit the loop because _running is False, that's a clean shutdown
        if last_error is not None:
            log.debug(f"Stopped trying to connect: {last_error}")

    async def _receive_messages(self, ws):
        """Receive messages from the websocket."""
        from json import loads

        try:
            async for msg in ws:
                if not self._running:
                    break

                if msg.type == 1:  # aiohttp.WSMsgType.TEXT
                    try:
                        data = loads(msg.data)
                        # Push data to all registered adapters
                        for adapter in self._adapters:
                            adapter.push_tick(data)
                    except Exception as e:
                        log.debug(f"Error parsing websocket message: {e}")
                elif msg.type == 8:  # aiohttp.WSMsgType.ERROR
                    log.error(f"WebSocket error received: {ws.exception()}")
                    break
                elif msg.type == 258:  # aiohttp.WSMsgType.CLOSED
                    log.warning("WebSocket connection closed by server")
                    break
        except Exception as e:
            log.error(f"Error receiving websocket messages: {e}")
            raise

    async def _send_subscriptions(self, ws):
        """Send subscription/unsubscription requests and outgoing data from the pending queues."""
        import asyncio

        while self._running:
            try:
                # Check for pending subscribe requests
                try:
                    channel = self._pending_subscribes.get_nowait()
                    await ws.send_json({"action": "subscribe", "channel": channel})
                    log.debug(f"Subscribed to channel: {channel}")
                except Empty:
                    pass

                # Check for pending unsubscribe requests
                try:
                    channel = self._pending_unsubscribes.get_nowait()
                    await ws.send_json({"action": "unsubscribe", "channel": channel})
                    log.debug(f"Unsubscribed from channel: {channel}")
                except Empty:
                    pass

                # Check for pending outgoing data
                try:
                    data = self._pending_data.get_nowait()
                    await ws.send_json(data)
                    log.debug(f"Sent data through websocket: {data}")
                except Empty:
                    pass

                await asyncio.sleep(0.01)
            except Exception as e:
                log.debug(f"Error sending data: {e}")


class _GatewayStreamAdapterImpl(PushInputAdapter):
    """Runtime implementation of the Gateway stream adapter."""

    def __init__(self, manager_impl: _GatewayStreamAdapterManagerImpl):
        manager_impl.register_input_adapter(self)
        self._manager_impl = manager_impl
        super().__init__()


_GatewayStreamAdapter = py_push_adapter_def(
    "_GatewayStreamAdapter",
    _GatewayStreamAdapterImpl,
    ts[Dict[str, Any]],
    GatewayStreamAdapterManager,
)


@csp.node
def _manage_subscriptions_node(
    manager: GatewayStreamAdapterManager,
    subscribe_channel: ts[str],
    unsubscribe_channel: ts[str],
    incoming_data: ts[Dict[str, Any]],
    outgoing_data: ts[object],
) -> csp.DynamicBasket[str, object]:
    """Internal node to manage dynamic channel subscriptions and route data to the appropriate basket key.

    Args:
        manager: The adapter manager (graph-time object with reference to impl).
        subscribe_channel: Time series of channel names to subscribe to.
        unsubscribe_channel: Time series of channel names to unsubscribe from.
        incoming_data: Time series of data received from the adapter.
        outgoing_data: Optional time series of data to send through the websocket.

    Returns:
        A DynamicBasket where each key is a channel name and values are the data for that channel.
    """
    with csp.state():
        s_active_channels: Set[str] = set()

    if csp.ticked(subscribe_channel):
        channel = subscribe_channel
        if channel not in s_active_channels:
            manager.add_channel(channel)
            s_active_channels.add(channel)
            # Output an empty dict to create the dynamic key - it will be populated when data arrives
            log.debug(f"Added subscription for channel: {channel}")

    if csp.ticked(unsubscribe_channel):
        channel = unsubscribe_channel
        if channel in s_active_channels:
            manager.remove_channel(channel)
            s_active_channels.remove(channel)
            csp.remove_dynamic_key(channel)
            log.debug(f"Removed dynamic key for channel: {channel}")

    if csp.ticked(outgoing_data):
        manager.send_data(outgoing_data)
        log.debug(f"Queued outgoing data: {outgoing_data}")

    if csp.ticked(incoming_data):
        # Route incoming data to the appropriate channel key
        # The data should contain a 'channel' field indicating which channel it belongs to
        data = incoming_data
        channel = data.get("channel") if isinstance(data, dict) else None
        if channel and channel in s_active_channels:
            csp.output({channel: data})
        elif channel:
            log.debug(f"Received data for unknown channel: {channel}")
        else:
            # If no channel specified, output to all active channels
            for ch in s_active_channels:
                csp.output({ch: data})


def _create_stream_csp_graph(config: "GatewayClientConfig", connection_timeout: float = -1):
    """Factory function to create the stream_csp graph for a given config.

    This is used internally by GatewayClient.stream_csp() to create the
    graph function with the client's config bound to it.

    Args:
        config: The GatewayClientConfig specifying the server connection details.
        connection_timeout: How long to wait for the server to be available (in seconds).
            - 0: Expect server to be immediately available at startup
            - -1: Wait indefinitely for the server (default)
            - positive number: Wait up to this many seconds before raising an error
    """

    @csp.graph
    def stream_csp(
        subscribe: ts[str],
        unsubscribe: ts[str] = None,
        data: ts[Dict[str, Any]] = None,
        push_mode: csp.PushMode = csp.PushMode.NON_COLLAPSING,
    ) -> csp.DynamicBasket[str, object]:
        """Stream data bidirectionally with a GatewayServer via websockets using CSP.

        This function creates a CSP DynamicBasket that streams data from the specified
        channels on a GatewayServer. Channels can be dynamically added or removed by
        ticking on the `subscribe` and `unsubscribe` inputs. Each channel becomes a
        key in the returned DynamicBasket, with values being the data received for
        that channel.

        Args:
            subscribe: A time series of channel names to subscribe to. Each time this
                ticks, a new channel is added and a new dynamic output key is created.
            unsubscribe: Optional time series of channel names to unsubscribe from.
                Each time this ticks, the channel is removed and csp.remove_dynamic_key
                is called.
            data: Optional time series of dictionaries to send through the websocket.
                Each tick will send the data to the server. The dictionary should map
                channel names to the data to send. For example:
                - {"my_channel": {"value": 42}} - sends single dict to channel
                - {"my_channel": [{"value": 1}, {"value": 2}]} - sends list to channel
                - {"ch1": {"v": 1}, "ch2": [{"v": 2}]} - sends to multiple channels
            push_mode: How to handle buffered ticks. Options are:
                - LAST_VALUE: Only tick the latest value since the last cycle
                - BURST: Tick all buffered values as a list
                - NON_COLLAPSING: Tick all events without collapsing (default)

        Returns:
            A DynamicBasket[str, object] where each key is a channel name and values
            are the data (GatewayStruct or dict) received for that channel.
        """
        # Create the adapter manager with the bound config and connection timeout
        manager = GatewayStreamAdapterManager(config, connection_timeout=connection_timeout)

        # Get the stream output from the adapter
        incoming_data = manager.subscribe(push_mode=push_mode)

        # Create null time series for optional inputs if not provided
        unsubscribe_ts = unsubscribe if unsubscribe is not None else csp.null_ts(str)
        data_ts = data if data is not None else csp.null_ts(object)

        # Use the subscription management node to handle dynamic channels
        return _manage_subscriptions_node(manager, subscribe, unsubscribe_ts, incoming_data, data_ts)

    return stream_csp
