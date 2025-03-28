import logging
from abc import abstractmethod
from asyncio import (
    AbstractEventLoop,
    Future,
    Queue,
    get_event_loop,
    new_event_loop,
    run_coroutine_threadsafe,
    set_event_loop,
    wrap_future,
)
from json import JSONDecodeError
from threading import Thread
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Literal, Optional, Tuple, Union, cast

from aiohttp import ClientSession, WSMsgType
from aiostream.stream import merge
from ccflow import BaseModel
from httpx import AsyncClient, Response, get as GET, post as POST
from jsonref import replace_refs
from nest_asyncio import apply as applyAsyncioNexting
from orjson import loads
from packaging import version
from pydantic import Field, PrivateAttr, field_validator, model_validator

if TYPE_CHECKING:
    from pandas import DataFrame as PandasDataFrame
    from polars import DataFrame as PolarsDataFrame

from ..utils import (
    Query,
    ServerRouteNotFoundException,
    ServerRouteNotMountedException,
    ServerUnknownException,
    ServerUnprocessableException,
)

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10.0
_PANDAS_TYPE_MAPPING = {
    "string": "string",
    "integer": "int64",
    "number": "float64",
    "boolean": "bool",
    "object": "object",
}

_POLARS_TYPE_MAPPING = {
    "string": "String",
    "integer": "Int64",
    "number": "Float64",
    "boolean": "Boolean",
    "object": "Object",
}


def _openapi_to_dataframe_dtypes(schema, path, df_type_mapping):
    res = {}
    for column, properties in schema["properties"].items():
        if "properties" in properties:
            res.update(_openapi_to_dataframe_dtypes(properties, path + column + ".", df_type_mapping))
            continue
        if "anyOf" in properties:
            # This schema value can be one of many types
            new_multi_type = list(filter(lambda d: d.get("type") != "null", properties["anyOf"]))
            if len(new_multi_type) > 1:
                # Multiple non-null types, keep the type as object
                openapi_type = "object"
            else:
                properties = new_multi_type[0]
                # Only 1 non-null type, use that as the type
                if "properties" in properties:
                    res.update(_openapi_to_dataframe_dtypes(properties, path + column + ".", df_type_mapping))
                    continue
                openapi_type = new_multi_type[0].get("type")
        else:
            openapi_type = properties.get("type")
        dataframe_type = df_type_mapping.get(openapi_type, df_type_mapping.get("object"))
        res[path + column] = dataframe_type
    return res


def _normalize_field(field: str) -> str:
    if "/" in field:
        return field.split("/")[0] + "/"
    return field


def _get_schema(spec: Dict[str, Any], path: str) -> Optional[Dict[str, Any]]:
    if (paths := spec.get("paths")) is None:
        return None

    if (path_data := paths.get(path)) is None:
        # could be a lookup for an id, or a key
        base_path = path.rpartition("/")[0]
        if (possible_path := paths.get(base_path + "/{id}")) is not None:
            path_data = possible_path
        elif (possible_path := paths.get(base_path + "/{key}")) is not None:
            path_data = possible_path
        else:
            return None

    response_type = "get" if "get" in path_data else "post"
    try:
        return path_data[response_type]["responses"]["200"]["content"]["application/json"]["schema"]
    except KeyError:
        return None


def _raiseIfNotMounted(foo: Callable) -> Callable:
    group = foo.__name__

    def _wrapped_foo(self: Any, field: str = "", *args: Any, **kwargs: Any) -> Any:
        if not self._initialized:
            self._initialize()
        check_field = _normalize_field(field)

        if check_field and check_field not in self._mounted_apis[group]:
            raise ServerRouteNotMountedException("Route not mounted in group {}: {}".format(group, field))
        return foo(self, field, *args, **kwargs)

    return _wrapped_foo


class GatewayClientConfig(BaseModel):
    model_config = dict(extra="forbid")  # To raise error on misspelling/misspecification

    protocol: Literal["http", "https"] = "http"
    host: str = "localhost"
    port: Optional[int] = 8000
    api_route: str = "/api/v1"
    authenticate: bool = False
    api_key: str = ""
    return_raw_json: bool = Field(
        True, description="Determines whether REST request responses should be returned as raw json data, or as a ResponseWrapper object."
    )


class ResponseWrapper(BaseModel):
    json_data: Any
    openapi_schema: Optional[Dict[str, Any]] = None

    @field_validator("openapi_schema", mode="after")
    def validate_openapi_schema(cls, v):
        if v is not None:
            # we have a list of items, so we get the properties for those
            if (schema := v.get("items")) is not None:
                return schema
        return v

    def is_empty(self):
        return bool(self.json_data)

    def as_json(self):
        return self.json_data

    def as_pandas_df(self) -> "PandasDataFrame":
        try:
            import pandas as pd
        except ImportError:
            log.exception("Must have pandas installed to use `as_pandas_df`")
            raise
        if self.openapi_schema is None:
            log.warning(f"No matching schema found for {self.json_data}")
            return pd.json_normalize(self.json_data or {})
        if "properties" not in self.openapi_schema:
            # we have a list of non-dicts, return a single column dataframe
            typ = _PANDAS_TYPE_MAPPING.get(self.openapi_schema.get("type"), "object")
            return pd.DataFrame(self.json_data or {}).astype(typ)
        pandas_dtypes = _openapi_to_dataframe_dtypes(self.openapi_schema, "", _PANDAS_TYPE_MAPPING)
        if self.json_data:
            res = pd.json_normalize(self.json_data)
            # we do this to not change the order of columns
            columns = {col: True for col in res.columns}
            for col in pandas_dtypes.keys():
                if col not in columns:
                    columns[col] = True
            # We might have some columns missing data,
            # such as attributes on the structs that are dicts.
            res = res.reindex(columns=columns.keys(), fill_value=None)
            return res.astype(dict(pandas_dtypes.items()))
        # No data
        else:
            return pd.DataFrame({k: pd.Series(dtype=v) for k, v in pandas_dtypes.items()})

    def as_polars_df(self) -> "PolarsDataFrame":
        try:
            import polars as pl
        except ImportError:
            log.exception("Must have polars installed to use `as_polars_df`")
            raise

        if version.parse(pl.__version__) < version.parse("1.0.0"):
            raise ValueError("Polars version must be 1.0.0 or higher to use json_normalize")

        if self.openapi_schema is None:
            log.warning(f"No matching schema found for {self.json_data}")
            return pl.json_normalize(self.json_data or {})
        if "properties" not in self.openapi_schema:
            typ = getattr(pl, _POLARS_TYPE_MAPPING.get(self.openapi_schema.get("type"), "Object"))
            return pl.DataFrame(self.json_data or []).cast(typ)

        polars_dtypes = _openapi_to_dataframe_dtypes(self.openapi_schema, "", {k: getattr(pl, v) for k, v in _POLARS_TYPE_MAPPING.items()})
        return pl.json_normalize(self.json_data, schema=polars_dtypes)


ResponseType = Union[ResponseWrapper, Dict[str, Any]]


def _get_or_new_event_loop() -> AbstractEventLoop:
    try:
        return get_event_loop()
    except RuntimeError:
        log.debug("Attempted to get event loop without one running, creating a new one...")
        # We need a new event loop if this is running on another thread
        set_event_loop(new_event_loop())
        return get_event_loop()


class BaseGatewayClient(BaseModel):
    # server configuration
    config: GatewayClientConfig = Field(default_factory=GatewayClientConfig)

    # openapi configureation
    _initialized: bool = PrivateAttr(default=False)
    _openapi_spec: Dict[Any, Any] = PrivateAttr(default=None)
    _mounted_apis: Dict[str, set] = PrivateAttr(
        default={
            "controls": set(),
            "last": set(),
            "lookup": set(),
            "next": set(),
            "send": set(),
            "state": set(),
        }
    )

    # stream configuration
    _initialized_streaming: Future = PrivateAttr(default=None)
    _request_queue: Queue = PrivateAttr(default=None)
    _event_loop_setup: bool = PrivateAttr(default=False)
    _event_loop: Optional[AbstractEventLoop] = PrivateAttr(default=None)
    _event_loop_thread: Optional[Thread] = PrivateAttr(default=None)

    def __init__(self, config: GatewayClientConfig = None) -> None:
        # Exists for compatibility with positional argument instantiation
        super().__init__(config=config or GatewayClientConfig())

    @model_validator(mode="after")
    def validate_client(self):
        if self._event_loop is None:
            self._event_loop = _get_or_new_event_loop()

        if self._initialized_streaming is None:
            self._initialized_streaming = Future(loop=self._event_loop)

        if self._request_queue is None:
            self._request_queue = Queue()

        return self

    def _initializeStreaming(self) -> None:
        if not self._initialized_streaming.done():
            # handle streaming / event loop
            if self._event_loop.is_running():
                # loop is already setup, assume in main thread and use as-is
                self._event_loop_setup = True
            else:
                # setup a new event loop in thread
                self._event_loop_thread = Thread(target=self._event_loop.run_forever, daemon=True)
                self._event_loop_thread.start()

            self._initialized_streaming.set_result(True)

    def _initialize(self) -> None:
        if not self._initialized:
            # grab openapi spec
            self._openapi_spec: Dict[Any, Any] = replace_refs(
                cast(
                    Dict[Any, Any],
                    GET(
                        "{}://{}{}/{}".format(
                            "http" if self.config.port == 80 else "https" if self.config.port == 443 else self.config.protocol,
                            self.config.host,
                            ":{}".format(self.config.port) if self.config.port else "",
                            "openapi.json",
                        )
                    ).json(),
                )
            )

            # collect mounted routes
            for path in self._openapi_spec["paths"]:
                path = path.replace(self.config.api_route, "")
                for group, subroute in (
                    ("controls", "/controls/"),
                    ("last", "/last/"),
                    ("lookup", "/lookup/"),
                    ("next", "/next/"),
                    ("send", "/send/"),
                    ("state", "/state/"),
                ):
                    if "{channel}" in path:
                        # TODO later
                        continue

                    if path.startswith(subroute):
                        key = path.replace(subroute, "")

                        if "{key}" in key:
                            # dict basket
                            key = key.replace("{key}", "")

                        if "/{id}" in key:
                            # lookup route
                            key = key.replace("/{id}", "")

                        self._mounted_apis[group].add(key)

        # mark self as initialized
        self._initialized = True

    def _buildpath(self, route: str) -> str:
        return f"{self.config.api_route}/{route}"

    def _buildroute(self, route: str) -> str:
        base_url = f"{self.config.protocol}://{self.config.host}"
        if self.config.port:
            base_url += f":{self.config.port}"
        base_url += self._buildpath(route)
        if self.config.authenticate:
            return base_url, {"token": self.config.api_key}
        return base_url, {}

    def _api_path_and_route(self, route: str) -> str:
        return self.config.api_route + "/" + route

    def _buildroutews(self, route: str) -> str:
        protocol = "wss" if "https" in self.config.protocol else "ws"
        port = f":{self.config.port}" if self.config.port else ""
        auth = f"?token={self.config.api_key}" if self.config.authenticate else ""

        return f"{protocol}://{self.config.host}{port}{self.config.api_route}/{route}{auth}"

    def _handle_response(self, resp: Response, route: str) -> ResponseType:
        try:
            resp_json = cast(Dict[str, Any], resp.json())
        except JSONDecodeError as e:
            resp_json = dict(detail=str(e))
        if resp.status_code == 200:
            if self.config.return_raw_json:
                return resp_json
            path = self._buildpath(route=route)
            schema = _get_schema(spec=self._openapi_spec, path=path)
            return ResponseWrapper(json_data=resp_json, openapi_schema=schema)
        elif resp.status_code == 404:
            raise ServerRouteNotFoundException(resp_json.get("detail"))
        elif resp.status_code == 422:
            raise ServerUnprocessableException(resp_json.get("detail"))
        raise ServerUnknownException(f"{resp.status_code}: {resp_json.get('detail')}")

    def _get(
        self,
        route: str,
        params: Dict[str, Any] = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> ResponseType:
        params = params or {}
        resolved_route, extra_params = self._buildroute(route)
        return self._handle_response(GET(resolved_route, params={**params, **extra_params}, timeout=timeout), route=route)

    async def _getasync(
        self,
        route: str,
        params: Dict[str, Any] = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> ResponseType:
        params = params or {}
        resolved_route, extra_params = self._buildroute(route)
        async with AsyncClient() as client:
            return self._handle_response(await client.get(resolved_route, params={**params, **extra_params}, timeout=timeout), route=route)

    def _post(
        self,
        route: str,
        params: Dict[str, Any] = None,
        data: Dict[str, Any] = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> ResponseType:
        params = params or {}
        resolved_route, extra_params = self._buildroute(route)
        return self._handle_response(POST(resolved_route, params={**params, **extra_params}, json=data, timeout=timeout), route=route)

    async def _postasync(
        self,
        route: str,
        params: Dict[str, Any] = None,
        data: Dict[str, Any] = None,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> ResponseType:
        params = params or {}
        resolved_route, extra_params = self._buildroute(route)
        async with AsyncClient() as client:
            return self._handle_response(
                await client.post(resolved_route, params={**params, **extra_params}, json=data, timeout=timeout), route=route
            )

    def _stream(
        self,
        channels: Optional[List[Union[str, Tuple[str, str]]]] = None,
        callback: Callable = None,
    ):
        if callback:
            async_generator = self._streamAsync(channels=channels)
            iterator = async_generator.__aiter__()

            async def wait_for_aio_fut(aio_fut):
                return await aio_fut

            try:
                if self._event_loop.is_running():
                    applyAsyncioNexting(self._event_loop)
                while True:
                    callback(self._event_loop.run_until_complete(iterator.__anext__()))
            except StopAsyncIteration:
                return

    async def _streamAsync(self, channels: Optional[List[Union[str, Tuple[str, str]]]] = None):
        if not self._initialized_streaming.done():
            self._initializeStreaming()

        channels = channels or []

        for channel in channels:
            if isinstance(channel, (list, tuple)) and len(channel) == 2:
                true_channel, key = channel
                await self._subscribe(true_channel, key)
            else:
                await self._subscribe(channel)

        async for data in self._connectAsync():
            yield data

    async def _subscribe(self, channel: str, key: Optional[str] = None):
        if not self._initialized_streaming:
            await self._initialized_streaming

        subscription = dict(action="subscribe", channel=channel)
        if key is not None:
            subscription["key"] = key

        if self._event_loop_setup:
            return await self._request_queue.put(subscription)

        return wrap_future(
            run_coroutine_threadsafe(
                self._request_queue.put(subscription),
                loop=self._event_loop,
            ),
            loop=self._event_loop,
        )

    async def _unsubscribe(self, channel: str, key: Optional[str] = None):
        if not self._initialized_streaming:
            await self._initialized_streaming

        subscription_removal = dict(action="unsubscribe", channel=channel)
        if key is not None:
            subscription_removal["key"] = key

        if self._event_loop_setup:
            return await self._request_queue.put(subscription_removal)

        return wrap_future(
            run_coroutine_threadsafe(
                self._request_queue.put(subscription_removal),
                loop=self._event_loop,
            ),
            loop=self._event_loop,
        )

    async def _publish(self, channel: str, data: Union[Dict[str, Any], List[Any]], key: Optional[str] = None):
        if not self._initialized_streaming:
            await self._initialized_streaming
        send_msg = dict(action="send", channel=channel, data=data)
        if key is not None:
            send_msg["key"] = key
        if self._event_loop_setup:
            return await self._request_queue.put(send_msg)

        return wrap_future(
            run_coroutine_threadsafe(
                self._request_queue.put(send_msg),
                loop=self._event_loop,
            ),
            loop=self._event_loop,
        )

    async def _websocketData(self, ws):
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                yield ("out", loads(msg.data))
            elif msg.type == WSMsgType.CLOSED:
                break
            elif msg.type == WSMsgType.ERROR:
                break

    async def _clientRequests(self):
        # infinite generator to deal with client requests
        if self._event_loop_setup:
            while True:
                yield ("in", await self._request_queue.get())
        else:
            while True:
                yield (
                    "in",
                    await wrap_future(
                        run_coroutine_threadsafe(self._request_queue.get(), loop=self._event_loop),
                        loop=self._event_loop,
                    ),
                )

    async def _connectAsync(self):
        session = ClientSession()

        route = self._buildroutews("stream")

        async with session.ws_connect(route) as ws:
            # merge async generators
            merged = merge(self._websocketData(ws), self._clientRequests())

            async with merged.stream() as streamer:
                async for direction, data in streamer:
                    if direction == "in":
                        # send to server
                        await ws.send_json(data)
                    elif direction == "out":
                        # yield out to client
                        yield data
                    else:
                        # ignore
                        ...

    @abstractmethod
    def controls(self, field: str = "", data: Any = None, timeout: float = _DEFAULT_TIMEOUT) -> ResponseType: ...

    @abstractmethod
    def last(self, field: str = "", timeout: float = _DEFAULT_TIMEOUT) -> ResponseType: ...

    @abstractmethod
    def lookup(self, field: str, id: str, timeout: float = _DEFAULT_TIMEOUT) -> ResponseType: ...

    @abstractmethod
    def next(self, field: str = "", timeout: float = None) -> ResponseType: ...

    @abstractmethod
    def send(self, field: str = "", data: Any = None, timeout: float = _DEFAULT_TIMEOUT) -> ResponseType: ...

    @abstractmethod
    def state(self, field: str = "", timeout: float = _DEFAULT_TIMEOUT, query: Optional[Query] = None) -> ResponseType: ...

    @abstractmethod
    def stream(self, channels: Optional[List[Union[str, Tuple[str, str]]]] = None): ...

    # NOTE: sync version
    # def stream(self, channels: List[str] = None, callback: Callable = None):

    @abstractmethod
    def subscribe(self, field: str = "", key: Optional[str] = None): ...

    @abstractmethod
    def publish(self, field: str, data: Any, key: Optional[str] = None): ...

    @abstractmethod
    def unsubscribe(self, field: str = "", key: Optional[str] = None): ...


class SyncGatewayClientMixin:
    @_raiseIfNotMounted
    def controls(
        self, field: str = "", data: Any = None, timeout: float = _DEFAULT_TIMEOUT, return_raw_json_override: Optional[bool] = None
    ) -> ResponseType:
        if return_raw_json_override is not None:
            old_return_raw_json = self.config.return_raw_json
            self.config.return_raw_json = return_raw_json_override
        if field in ("shutdown",):
            res = self._post("{}/{}".format("controls", field), data=data, timeout=timeout)
        else:
            res = self._get("{}/{}".format("controls", field), timeout=timeout)
        if return_raw_json_override is not None:
            self.config.return_raw_json = old_return_raw_json
        return res

    @_raiseIfNotMounted
    def last(self, field: str = "", timeout: float = _DEFAULT_TIMEOUT, return_raw_json_override: Optional[bool] = None) -> ResponseType:
        if return_raw_json_override is not None:
            old_return_raw_json = self.config.return_raw_json
            self.config.return_raw_json = return_raw_json_override
        res = self._get("{}/{}".format("last", field), timeout=timeout)
        if return_raw_json_override is not None:
            self.config.return_raw_json = old_return_raw_json
        return res

    @_raiseIfNotMounted
    def lookup(self, field: str, id: str, timeout: float = _DEFAULT_TIMEOUT, return_raw_json_override: Optional[bool] = None) -> ResponseType:
        if return_raw_json_override is not None:
            old_return_raw_json = self.config.return_raw_json
            self.config.return_raw_json = return_raw_json_override
        res = self._get("{}/{}/{}".format("lookup", field, id), timeout=timeout)
        if return_raw_json_override is not None:
            self.config.return_raw_json = old_return_raw_json
        return res

    @_raiseIfNotMounted
    def next(self, field: str = "", timeout: float = None, return_raw_json_override: Optional[bool] = None) -> ResponseType:
        if return_raw_json_override is not None:
            old_return_raw_json = self.config.return_raw_json
            self.config.return_raw_json = return_raw_json_override
        res = self._get("{}/{}".format("next", field), timeout=timeout)
        if return_raw_json_override is not None:
            self.config.return_raw_json = old_return_raw_json
        return res

    @_raiseIfNotMounted
    def send(
        self, field: str = "", data: Any = None, timeout: float = _DEFAULT_TIMEOUT, return_raw_json_override: Optional[bool] = None
    ) -> ResponseType:
        if return_raw_json_override is not None:
            old_return_raw_json = self.config.return_raw_json
            self.config.return_raw_json = return_raw_json_override
        res = self._post("{}/{}".format("send", field), data=data, timeout=timeout)
        if return_raw_json_override is not None:
            self.config.return_raw_json = old_return_raw_json
        return res

    @_raiseIfNotMounted
    def state(
        self, field: str = "", timeout: float = _DEFAULT_TIMEOUT, query: Optional[Query] = None, return_raw_json_override: Optional[bool] = None
    ) -> ResponseType:
        if return_raw_json_override is not None:
            old_return_raw_json = self.config.return_raw_json
            self.config.return_raw_json = return_raw_json_override
        params = None if query is None else {"query": query.model_dump_json()}
        res = self._get("{}/{}".format("state", field), timeout=timeout, params=params)
        if return_raw_json_override is not None:
            self.config.return_raw_json = old_return_raw_json
        return res

    def stream(self, channels: Optional[List[Union[str, Tuple[str, str]]]] = None, callback: Callable = None):
        """Stream data from specified channels with optional key filtering for dict baskets.

        Establishes a synchronous streaming connection to receive real-time updates from the specified channels.
        For dict basket channels, you can subscribe to specific keys by providing tuples of (channel, key).

        Args:
            channels: A list of channel names to subscribe to. For dict basket channels,
                    each entry can be either a string (channel name) or a tuple of
                    (channel_name, key) to subscribe only to a specific key in a dict basket.
            callback: A function that will be called with each received message.
        """
        self._stream(channels=channels, callback=callback)

    def publish(self, field: str, data: Union[Dict[str, Any], List[Any]], key: Optional[str] = None):
        """Publish data to a channel or specific key within a dict basket channel.

        This synchronous method sends data to a specific channel. For dict basket channels,
        a key can be specified to send data to that specific key.

        Args:
            field: The channel name to publish to.
            data: The data to publish.
            key: For dict basket channels, the specific key to publish to. If None, publishes to the entire channel.
        """
        self._event_loop.run_until_complete(self._publish(channel=field, data=data, key=key))

    def subscribe(self, field: str = "", key: Optional[str] = None):
        """Subscribe to a channel or specific key within a dict basket channel.

        This synchronous method subscribes to data updates from a specific channel. For dict basket channels,
        a key can be specified to subscribe only to updates for that specific key.

        Args:
            field: The channel name to subscribe to.
            key: For dict basket channels, the specific key to subscribe to. If None, subscribes to the entire channel.
        """
        self._event_loop.run_until_complete(self._subscribe(channel=field, key=key))

    def unsubscribe(self, field: str = "", key: Optional[str] = None):
        """Unsubscribe from a channel or specific key within a dict basket channel.

        This synchronous method unsubscribes from data updates from a specific channel. For dict basket channels,
        a key can be specified to unsubscribe only from updates for that specific key.

        Args:
            field: The channel name to unsubscribe from.
            key: For dict basket channels, the specific key to unsubscribe from. If None, unsubscribes from the entire channel.
        """
        self._event_loop.run_until_complete(self._unsubscribe(channel=field, key=key))


class SyncGatewayClient(SyncGatewayClientMixin, BaseGatewayClient):
    """
    A synchronous (blocking) Gateway client.

    This client will expose synchronous methods to connect to the server's REST endpoints:

        - controls
        - last
        - lookup
        - next
        - send
        - state

    These methods will depend on the configuration of the corresponding GatewayServer.

    Additionally, if the server is configured with WebSocket support, the following syncronous methods will be available:

        - stream
        - publish
        - subscribe
        - unsubscribe
    """

    ...


class AsyncGatewayClientMixin:
    @_raiseIfNotMounted
    async def controls(self, field: str = "", data: Any = None, timeout: float = _DEFAULT_TIMEOUT) -> ResponseType:
        if field in ("shutdown",):
            return await self._postasync("{}/{}".format("controls", field), data=data, timeout=timeout)
        return await self._getasync("{}/{}".format("controls", field), timeout=timeout)

    @_raiseIfNotMounted
    async def last(self, field: str = "", timeout: float = _DEFAULT_TIMEOUT) -> ResponseType:
        return await self._getasync("{}/{}".format("last", field), timeout=timeout)

    @_raiseIfNotMounted
    async def lookup(self, field: str, id: str, timeout: float = _DEFAULT_TIMEOUT) -> ResponseType:
        return await self._getasync("{}/{}/{}".format("lookup", field, id), timeout=timeout)

    @_raiseIfNotMounted
    async def next(self, field: str = "", timeout: float = None) -> ResponseType:
        return await self._getasync("{}/{}".format("next", field), timeout=timeout)

    @_raiseIfNotMounted
    async def send(self, field: str = "", data: Any = None, timeout: float = _DEFAULT_TIMEOUT) -> ResponseType:
        return await self._postasync("{}/{}".format("send", field), data=data, timeout=timeout)

    @_raiseIfNotMounted
    async def state(self, field: str = "", timeout: float = _DEFAULT_TIMEOUT, query: Optional[Query] = None) -> ResponseType:
        params = None if query is None else {"query": query.model_dump_json()}
        return await self._getasync("{}/{}".format("state", field), timeout=timeout, params=params)

    async def stream(self, channels: List[Union[str, Tuple[str, str]]] = None):
        """Stream data from specified channels with optional key filtering for dict baskets.

        Establishes an asynchronous streaming connection to receive real-time updates from the specified channels.
        For dict basket channels, you can subscribe to specific keys by providing tuples of (channel, key).

        Args:
            channels: A list of channel names to subscribe to. For dict basket channels,
                    each entry can be either a string (channel name) or a tuple of
                    (channel_name, key) to subscribe only to a specific key in a dict basket.

        Yields:
            Data messages received from the subscribed channels.
        """
        async for data in self._streamAsync(channels=channels):
            yield data

    async def publish(self, field: str, data: Union[Dict[str, Any], List[Any]], key: Optional[str] = None):
        """Publish data to a channel or specific key within a dict basket channel.

        This asynchronous method sends data to a specific channel. For dict basket channels,
        a key can be specified to send data to that specific key.

        Args:
            field: The channel name to publish to.
            data: The data to publish.
            key: For dict basket channels, the specific key to publish to. If None, publishes to the entire channel.
        """
        await self._publish(channel=field, data=data, key=key)

    async def subscribe(self, field: str, key: Optional[str] = None):
        """Subscribe to a channel or specific key within a dict basket channel.

        This asynchronous method subscribes to data updates from a specific channel. For dict basket channels,
        a key can be specified to subscribe only to updates for that specific key.

        Args:
            field: The channel name to subscribe to.
            key: For dict basket channels, the specific key to subscribe to. If None, subscribes to the entire channel.
        """
        await self._subscribe(channel=field, key=key)

    async def unsubscribe(self, field: str, key: Optional[str] = None):
        """Unsubscribe from a channel or specific key within a dict basket channel.

        This asynchronous method unsubscribes from data updates from a specific channel. For dict basket channels,
        a key can be specified to unsubscribe only from updates for that specific key.

        Args:
            field: The channel name to unsubscribe from.
            key: For dict basket channels, the specific key to unsubscribe from. If None, unsubscribes from the entire channel.
        """
        await self._unsubscribe(channel=field, key=key)


class AsyncGatewayClient(AsyncGatewayClientMixin, BaseGatewayClient):
    """
    An asynchronous Gateway client.

    This client will expose async methods:
    - controls
    - last
    - lookup
    - next
    - send
    - state

    These methods will depend on the configuration of the corresponding GatewayServer.

    Additionally, if the server is configured with WebSocket support, the following asyncronous methods will be available:

        - stream
        - publish
        - subscribe
        - unsubscribe
    """

    ...


GatewayClient = SyncGatewayClient
