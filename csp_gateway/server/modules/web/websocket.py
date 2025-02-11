import asyncio
from datetime import timedelta
from logging import getLogger
from typing import Any, Dict, List, Optional, Set, Tuple, TypeVar, get_args, get_origin
from uuid import uuid4

import csp
import janus
from csp import ts
from csp.impl.genericpushadapter import GenericPushAdapter
from pydantic import Field, PrivateAttr
from starlette.websockets import WebSocket, WebSocketDisconnect
from uvicorn.protocols.utils import ClientDisconnected

from csp_gateway.server import ChannelSelection, GatewayChannels, GatewayModule

# separate to avoid circular
from csp_gateway.server.web import (
    GatewayWebApp,
    get_default_responses,
    prepare_response,
)
from csp_gateway.utils import GatewayStruct

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
    _supported_channels: Dict[str, Any] = PrivateAttr(default_factory=dict)
    _connect_events: Dict[str, GenericPushAdapter] = PrivateAttr(default_factory=dict)
    _disconnect_events: Dict[str, GenericPushAdapter] = PrivateAttr(default_factory=dict)
    _subscriptions: Dict[str, Set[str]] = PrivateAttr(default_factory=dict)
    _queue: Optional[janus.Queue] = PrivateAttr(None)
    _task: Optional[asyncio.Task] = PrivateAttr(None)

    def connect(self, channels: GatewayChannels) -> None:
        self._channels = channels

        for field in self.selection.select_from(channels):
            edge = channels.get_channel(field)

            if isinstance(edge, dict):
                # TODO dict baskets
                continue

            # extract timeseries
            ts_type = channels.get_channel(field).tstype.typ

            # check if its a list model
            if get_origin(ts_type) is list:
                is_list_model = True
                ts_type = get_args(ts_type)[0]
            else:
                is_list_model = False

            # add to tracking
            self._supported_channels[field] = (is_list_model, ts_type)

            # add generic push for connects
            self._connect_events[field] = GenericPushAdapter(Tuple[str, WebSocket], name=f"connect_{field}")

            # add generic push for disconnects
            self._disconnect_events[field] = GenericPushAdapter(Tuple[str, WebSocket], name=f"disconnect_{field}")

            # run csp node
            self.handle_websocket_connection(
                edge,
                connect=self._connect_events[field].out(),
                disconnect=self._disconnect_events[field].out(),
                channel=field,
                is_list_model=is_list_model,
            )

        self._supported_channels["heartbeat"] = (False, None)
        self._connect_events["heartbeat"] = GenericPushAdapter(Tuple[str, WebSocket], name="connect_heartbeat")
        self._disconnect_events["heartbeat"] = GenericPushAdapter(Tuple[str, WebSocket], name="disconnect_heartbeat")
        self.handle_heartbeat_connection(
            connect=self._connect_events["heartbeat"].out(),
            disconnect=self._disconnect_events["heartbeat"].out(),
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
        channel: str,
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
            # convert to pydantic, then convert to json, then send to all clients
            response = (
                f'{{"channel":"{channel}",'
                f'"data":{prepare_response(data, is_list_model=is_list_model, is_dict_basket=False, wrap_in_response=False)}}}'
            )
            for uuid, websocket in s_connections.items():
                self._queue.sync_q.put((uuid, websocket, response))

    async def try_send_text(self, websocket: WebSocket, resp: str):
        try:
            await websocket.send_text(resp)
        except (RuntimeError, AssertionError):
            log.exception(f"Error during websocket data send to CSP for {resp = }")

    def handle_message(self, message: dict, uuid: str, websocket: WebSocket):
        action = message.get("action", None)

        # validate
        if not action or action not in ("subscribe", "unsubscribe", "send"):
            # ignore
            log.info(f"unsupported action: {action}")
            return

        # get channel
        channel = message.get("channel", None)

        if not channel or channel not in self._supported_channels:
            # ignore
            log.info(f"unsupported channel: {channel}")
            return

        if action == "send" and not self.readonly:
            # get the channel type from before
            is_list, channel_type = self._supported_channels.get(channel)

            # do some error checking
            if not isinstance(channel_type, type):
                log.info(f"unsupported type: {channel_type}")
                return

            if "data" not in message:
                log.info(f"unsupported data: {message}")
                return

            if issubclass(channel_type, GatewayStruct):
                # parse out the object and send
                msg_data = message.get("data")

                if not msg_data:
                    log.error("Error - received no data in websocket message")
                    return

                if not isinstance(msg_data, list):
                    msg_data = [msg_data]

                # do conversion in its own little try/except to avoid ambiguity
                try:
                    type_adapter = channel_type.get_type_adapter()
                    datum = [type_adapter.validate_python(obj) for obj in msg_data]
                except Exception:
                    log.error("Error during websocket data conversion", exc_info=True)
                    return

                try:
                    if is_list:
                        self._channels.send(channel, datum)
                    else:
                        for obj in datum:
                            self._channels.send(channel, obj)
                except Exception:
                    log.error("Error during websocket data send to CSP", exc_info=True)
                    return

            else:
                log.info(f"unsupported data: {message}")

        # at this point, push the subscription if not already subscribed
        if action == "subscribe" and channel not in self._subscriptions[uuid]:
            # add to subscriptions list
            self._subscriptions[uuid].add(channel)

            # push tick to csp
            self._connect_events[channel].push_tick((uuid, websocket))

        if action == "unsubscribe" and channel in self._subscriptions[uuid]:
            # remove from subscriptions list
            self._subscriptions[uuid].remove(channel)

            # push tick to csp
            self._disconnect_events[channel].push_tick((uuid, websocket))

    def disconnect_websocket(self, websocket: WebSocket, uuid: str):
        for subscription in self._subscriptions.get(uuid, ()):
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
                "channel": "<channel name>"
            }
            ```

            To unsubscribe to channels, send a JSON message of the form:
            ```
            {
                "action": "unsubscribe",
                "channel": "<channel name>"
            }
            ```

            Data will be sent across the websocket for all subscribed channels. It has the form:


            ```
            {
                "channel": "<channel name>",
                "data": <the same data that would be transmitted over e.g. the `last` endpoint>
            }
            ```
            """
            return list(self._supported_channels)
