import asyncio
from datetime import timedelta
from logging import getLogger
from typing import Any, Dict, List, Optional, Set, Tuple, TypeVar, get_args, get_origin
from uuid import uuid4

import csp
import janus
from csp import ts
from csp.impl.genericpushadapter import GenericPushAdapter
from pydantic import Field, PrivateAttr, TypeAdapter
from starlette.websockets import WebSocket, WebSocketDisconnect
from uvicorn.protocols.utils import ClientDisconnected

from csp_gateway.server import ChannelSelection, GatewayChannels, GatewayModule

# separate to avoid circular
from csp_gateway.server.web import (
    GatewayWebApp,
    get_default_responses,
    prepare_response,
)
from csp_gateway.utils import is_gateway_struct_like

log = getLogger(__name__)

T = TypeVar("T")
U = TypeVar("U")


class MountWebSocketRoutes(GatewayModule):
    requires: Optional[ChannelSelection] = []
    selection: ChannelSelection = Field(default_factory=ChannelSelection)

    readonly: bool = False
    prefix: str = "/stream"
    debug: bool = False
    ping_time_s: int = 1

    _channels: Any = PrivateAttr(None)
    _supported_channels: Dict[Tuple[str, Any], Any] = PrivateAttr(default_factory=dict)
    _dict_basket_keys_and_type_adapter: Dict[str, Tuple[Any, List[Any]]] = PrivateAttr(
        default_factory=dict
    )  # Maps dict basket channels to the type adapter for their keys and keys themselves
    _connect_events: Dict[Tuple[str, Any], GenericPushAdapter] = PrivateAttr(default_factory=dict)
    _disconnect_events: Dict[Tuple[str, Any], GenericPushAdapter] = PrivateAttr(default_factory=dict)
    _subscriptions: Dict[str, Set[Tuple[str, Any]]] = PrivateAttr(default_factory=dict)
    _queue: Optional[janus.Queue] = PrivateAttr(None)
    _task: Optional[asyncio.Task] = PrivateAttr(None)

    def connect(self, channels: GatewayChannels) -> None:
        self._channels = channels

        for field in self.selection.select_from(channels):
            maybe_edge = channels.get_channel(field)

            # Process both regular channels and dict baskets
            edges_and_keys = []
            if isinstance(maybe_edge, dict):
                # For dict baskets, collect each key and edge
                type_adapter = None
                keys_for_channel = []
                for key, edge in maybe_edge.items():
                    if type_adapter is None:
                        type_adapter = TypeAdapter(key.__class__)
                    edges_and_keys.append((key, edge))
                    keys_for_channel.append(key)
                self._dict_basket_keys_and_type_adapter[field] = (type_adapter, keys_for_channel)
            else:
                # Regular channel
                edges_and_keys = [(None, maybe_edge)]

            is_list_model, ts_type = None, None
            for key, edge in edges_and_keys:
                # Only assign is_list_model and
                # ts_type once
                if is_list_model is None:
                    # extract timeseries
                    ts_type = edge.tstype.typ

                    # check if its a list model
                    if get_origin(ts_type) is list:
                        is_list_model = True
                        ts_type = get_args(ts_type)[0]
                    else:
                        is_list_model = False

                channel_and_key = (field, key)
                name = field if key is None else f"{field}_{key}"

                # add to tracking
                self._supported_channels[channel_and_key] = (is_list_model, ts_type)

                # add generic push for connects
                self._connect_events[channel_and_key] = GenericPushAdapter(Tuple[str, WebSocket], name=f"connect_{name}")

                # add generic push for disconnects
                self._disconnect_events[channel_and_key] = GenericPushAdapter(Tuple[str, WebSocket], name=f"disconnect_{name}")

                # run csp node
                self.handle_websocket_connection(
                    edge,
                    connect=self._connect_events[channel_and_key].out(),
                    disconnect=self._disconnect_events[channel_and_key].out(),
                    channel_and_key=channel_and_key,
                    is_list_model=is_list_model,
                )

        heartbeat_key = ("heartbeat", None)
        self._supported_channels[heartbeat_key] = (False, None)
        self._connect_events[heartbeat_key] = GenericPushAdapter(Tuple[str, WebSocket], name="connect_heartbeat")
        self._disconnect_events[heartbeat_key] = GenericPushAdapter(Tuple[str, WebSocket], name="disconnect_heartbeat")
        self.handle_heartbeat_connection(
            connect=self._connect_events[heartbeat_key].out(),
            disconnect=self._disconnect_events[heartbeat_key].out(),
        )

    def start_app(self):
        """Start the app, needs to be called with event loop from main thread running."""
        if self._queue is None:
            self._queue = janus.Queue()
            self._task = asyncio.create_task(self.process_queue())

    async def process_queue(self):
        while True:
            try:
                uuid, websocket, message = await asyncio.wait_for(self._queue.async_q.get(), timeout=3.0)
                if uuid in self._subscriptions:
                    try:
                        if self.debug:
                            await websocket.send_text(message)
                        else:
                            await self.try_send_text(websocket, message)
                    except (ClientDisconnected, WebSocketDisconnect, asyncio.CancelledError) as e:
                        log.debug(f"Writing to client with {uuid = } disconnected with error {e = }")
                        self.disconnect_websocket(websocket, uuid)
            except TimeoutError:
                log.debug("No data to submit via websockets, retrying...")
            except Exception:
                log.exception("Something bad happened during queue processing")

    @csp.node
    def handle_heartbeat_connection(self, connect: ts["T"], disconnect: ts["T"]):
        with csp.alarms():
            a_send_ping: ts[bool] = csp.alarm(bool)
        with csp.state():
            s_connections: Dict[str, WebSocket] = {}

        with csp.start():
            csp.schedule_alarm(a_send_ping, timedelta(seconds=self.ping_time_s), True)

        if csp.ticked(connect):
            s_connections[connect[0]] = connect[1]

        if csp.ticked(disconnect):
            s_connections.pop(disconnect[0], None)

        if csp.ticked(a_send_ping):
            csp.schedule_alarm(a_send_ping, timedelta(seconds=self.ping_time_s), True)
            response = '{"channel": "heartbeat", "data": "PING"}'
            for uuid, websocket in s_connections.items():
                self._queue.sync_q.put((uuid, websocket, response))

    @csp.node
    def handle_websocket_connection(
        self,
        data: ts["T"],
        connect: ts["U"],
        disconnect: ts["U"],
        channel_and_key: Tuple[str, Any],  # channel name to possible dict basket key
        is_list_model: bool = False,
    ):
        with csp.state():
            s_connections: Dict[str, WebSocket] = {}
        with csp.start():
            # make the input passive unless we have active subscriptions
            csp.make_passive(data)

        if csp.ticked(connect):
            if len(s_connections) == 0:
                # make the data input active if this is the first connection
                csp.make_active(data)
            # add
            s_connections[connect[0]] = connect[1]

        if csp.ticked(disconnect):
            s_connections.pop(disconnect[0], None)

            if len(s_connections) == 0:
                # make the data input passive if that was the last connection
                csp.make_passive(data)

        if csp.ticked(data):
            channel, maybe_db_key = channel_and_key
            if maybe_db_key is None:
                key_json_fragment = ""
            else:
                key_json_fragment = f'"key": "{maybe_db_key.name if hasattr(maybe_db_key, "name") else maybe_db_key}",'
            # convert to pydantic, then convert to json, then send to all clients
            response = (
                f'{{"channel":"{channel}",'
                f"{key_json_fragment}"
                f'"data":{prepare_response(data, is_list_model=is_list_model, is_dict_basket=False, wrap_in_response=False)}}}'
            )
            for uuid, websocket in s_connections.items():
                self._queue.sync_q.put((uuid, websocket, response))

    async def try_send_text(self, websocket: WebSocket, resp: str):
        try:
            await websocket.send_text(resp)
        except (RuntimeError, AssertionError):
            log.exception(f"Error during websocket data send to CSP for {resp = }")

    def _handle_subscription(self, action: str, channel_and_key: Any, uuid: str, websocket: WebSocket):
        """Helper method to handle subscribe/unsubscribe for a specific channel+key"""
        if action == "subscribe" and channel_and_key not in self._subscriptions[uuid]:
            # add to subscriptions list

            self._subscriptions[uuid].add(channel_and_key)

            # push tick to csp
            self._connect_events[channel_and_key].push_tick((uuid, websocket))

        elif action == "unsubscribe" and channel_and_key in self._subscriptions[uuid]:
            # remove from subscriptions list
            self._subscriptions[uuid].discard(channel_and_key)

            # push tick to csp
            self._disconnect_events[channel_and_key].push_tick((uuid, websocket))

    def handle_message(self, message: dict, uuid: str, websocket: WebSocket):
        action = message.get("action", None)

        # validate
        if not action or action not in ("subscribe", "unsubscribe", "send"):
            # ignore
            log.info(f"unsupported action: {action}")
            return
        # get channel
        channel = message.get("channel", None)

        if not channel:
            # ignore
            log.info("no channel specified")
            return

        dict_basket_key_type_adapter, dict_basket_keys = self._dict_basket_keys_and_type_adapter.get(channel, (None, []))

        if dict_basket_keys and "key" not in message:
            if action in ("subscribe", "unsubscribe"):
                # Apply the action to all keys in the dict basket
                for key in dict_basket_keys:
                    self._handle_subscription(action, (channel, key), uuid, websocket)
                return
            elif action == "send":
                # For sending to a dict basket, we require a key
                log.info(f"sending data to dict basket {channel} requires a key")
                return

        raw_key = message.get("key", None)
        if raw_key and not dict_basket_key_type_adapter:
            log.info(f"Provided key {raw_key} for non-dict-basket channel {channel}, ignoring")
            return

        if dict_basket_key_type_adapter:
            key = dict_basket_key_type_adapter.validate_python(raw_key)
        else:
            key = raw_key

        # Create channel key tuple
        channel_and_key = (channel, key)

        if channel_and_key not in self._supported_channels:
            # ignore
            if key is None:
                log.info(f"unsupported channel: {channel}")
            else:
                log.info(f"unsupported channel: {channel} (dict-basket) with key: {key}")
            return

        if action == "send" and not self.readonly:
            # get the channel type from before
            is_list, channel_type = self._supported_channels.get(channel_and_key)

            # do some error checking
            if not isinstance(channel_type, type):
                log.info(f"unsupported type: {channel_type}")
                return

            if "data" not in message:
                log.info(f"unsupported data: {message}")
                return

            if is_gateway_struct_like(channel_type):
                # parse out the object and send
                msg_data = message.get("data")

                if not msg_data:
                    log.error("Error - received no data in websocket message")
                    return

                if not isinstance(msg_data, list):
                    msg_data = [msg_data]

                # do conversion in its own little try/except to avoid ambiguity
                try:
                    type_adapter = channel_type.type_adapter()
                    datum = [type_adapter.validate_python(obj) for obj in msg_data]
                except Exception:
                    log.error("Error during websocket data conversion", exc_info=True)
                    return

                try:
                    if is_list:
                        self._channels.send(channel, datum, key)
                    else:
                        for obj in datum:
                            self._channels.send(channel, obj, key)
                except Exception:
                    log.error("Error during websocket data send to CSP", exc_info=True)
                    return

            else:
                log.info(f"unsupported data: {message}")
        self._handle_subscription(action, channel_and_key, uuid, websocket)

    def disconnect_websocket(self, websocket: WebSocket, uuid: str):
        for subscription in self._subscriptions.get(uuid, set()):
            self._disconnect_events[subscription].push_tick((uuid, websocket))

        # remove from dict
        self._subscriptions.pop(uuid, None)

    async def websocket_handler(self, websocket: WebSocket):
        self.start_app()
        try:
            # connect to websocket
            await websocket.accept()
            uuid = str(uuid4())
            self._subscriptions[uuid] = set()
            log.debug(f"Client with {uuid = } connected")
            while True:
                try:
                    # get subscription message from client
                    message = await websocket.receive_json()
                    self.handle_message(message, uuid, websocket)

                except (ValueError, KeyError):
                    log.info(f"Malformed websocket message or error during data parsing: {message}", exc_info=True)
                    # ignore malformed
                    continue

        except (ClientDisconnected, WebSocketDisconnect, asyncio.CancelledError) as e:
            # push disconnect tick
            log.debug(f"Reading from client with {uuid = } disconnected with error {e = }")
        except Exception:
            log.exception("Error during websocket connection")

        finally:
            self.disconnect_websocket(websocket, uuid)

    def rest(self, app: GatewayWebApp) -> None:
        api_router = app.get_router("api")

        # add websocket handler
        api_router.add_api_websocket_route(path=self.prefix, endpoint=self.websocket_handler, name="streaming")

        # add dummy route for openapi
        @api_router.get(
            f"{self.prefix}",
            responses=get_default_responses(),
            response_model=List[str],
            tags=["Streaming"],
        )
        async def stream() -> List[str]:
            """
            This endpoint returns all of the available mounted websocket streams.

            The websocket stream is available on the same route.
            Data is bidirectional, any channel available as a `send` or `last` route is also available under the websocket connection.

            To subscribe to channels, send a JSON message of the form:
            ```
            {
                "action": "subscribe",
                "channel": "<channel name>",
                "key": "<optional dict basket key>"
            }
            ```

            For dict basket channels, omitting the "key" will subscribe to all available keys in that basket.

            To unsubscribe to channels, send a JSON message of the form:
            ```
            {
                "action": "unsubscribe",
                "channel": "<channel name>",
                "key": "<optional dict basket key>"
            }
            ```

            For dict basket channels, omitting the "key" will unsubscribe from all keys in that basket.

            Data will be sent across the websocket for all subscribed channels. It has the form:

            ```
            {
                "channel": "<channel name>",
                "key": "<only included for dict basket channels>",
                "data": <the same data that would be transmitted over e.g. the `last` endpoint>
            }
            ```
            """
            # Return a list of available channels
            res = []
            for channel, key in self._supported_channels:
                if key is None:
                    res.append(channel)
                else:
                    key_str = key.name if hasattr(key, "name") else key
                    res.append(f"{channel}/{key_str}")
            return res
