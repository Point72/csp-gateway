import logging
import multiprocessing.pool
import os
import signal
from datetime import datetime, timedelta
from socket import gethostname
from time import sleep
from typing import Any, Callable, List, Optional, Type, Union, get_args, get_origin

import csp
from csp import ts
from pydantic import Field, PrivateAttr, create_model, model_validator

from csp_gateway.server.gateway import State
from csp_gateway.server.settings import Settings

from .csp import Channels, ChannelsFactory, ChannelsType, Module

__all__ = (
    "Gateway",
    "GatewayChannels",
    "GatewayModule",
)


MAX_END_TIME = datetime(2261, 12, 31, 23, 59, 50, 999999)
log = logging.getLogger(__name__)


class GatewayChannels(Channels):
    @classmethod
    def fields(cls) -> List[str]:
        return list(cls.model_fields.keys())


class GatewayModule(Module[GatewayChannels]):
    model_config = {
        "ignored_types": (
            csp.impl.wiring.GraphDefMeta,
            csp.impl.wiring.NodeDefMeta,
        ),
    }

    def __hash__(self):
        # So that csp doesn't complain about inability to memoize
        return id(self)

    def shutdown(self):
        """Perform cleanup when the module is shutting down"""
        return


class Gateway(ChannelsFactory[GatewayChannels]):
    """The Gateway defines a combination of channels and a collection of modules that get and send data to the channels.

    Furthermore, it builds the underling csp event processing graph, as well as the web application (for the REST, web sockets and graphical interfaces).
    It also contains settings to define the behavior of the web application and how the csp graph should be run.
    """

    # For pydantic 2
    model_config = {"ignored_types": (csp.impl.wiring.GraphDefMeta, csp.impl.wiring.NodeDefMeta), "arbitrary_types_allowed": True}

    modules: List[GatewayModule] = Field([], description="The list of modules that will operate on the channels.")

    # Substructures
    settings: Settings = Field(default_factory=Settings, description="Generic settings for the gateway")
    web_app: Any = Field(None, description="The gateway will populate this field with the web application handle once started.")
    channels_model: Type[GatewayChannels] = Field(
        default=GatewayChannels,
        description="The type of the channels. Users of a `Gateway` are expected to pass `channels`, and `channels_model` will"
        "be automatically inferred from the type. Developers can subclass `Gateway` and set the default value of"
        "`channels_model` to be the specific type of channels that users must provide.",
    )

    # Running attributes
    output: Any = Field(None, description="(Running attribute). The gateway will save the output of the csp.graph run once complete to this field")
    graph_built: bool = Field(
        False,
        description="(Running attribute). The gateway will set this field to True when the application has detected the csp graph build is complete",
    )
    graph_build_failed: bool = Field(
        False, description="(Running attribute). The gateway will set this field to True if the csp graph build has failed"
    )
    running: bool = Field(False, description="(Running attribute). The gateway will set this field to True once the csp graph is running")
    _in_test: bool = PrivateAttr()
    _module_shutdown_timeout: int = PrivateAttr()
    _dynamic_channels_instantiated: bool = PrivateAttr(False)

    def __init__(
        self,
        modules: List[Module[GatewayChannels]] = None,
        channels: ChannelsType = None,
        *args: str,
        **kwargs: str,
    ):
        log.info(f"Initializing Gateway - pid[{os.getpid()}]")
        channels = channels or GatewayChannels()
        # Note that the channels object passed into the init function here is not necessarily the channels object
        # that is used to build the graph. Things like dynamic channels can be added.
        super().__init__(modules=modules, channels=channels, *args, **kwargs)
        self.graph_built = False
        self.graph_build_failed = False
        self._in_test = False
        self._module_shutdown_timeout = 60

    def _instantiate_dynamic_channel(self, modules: List[Module[GatewayChannels]], channels: ChannelsType) -> GatewayChannels:
        if self._dynamic_channels_instantiated:
            return channels

        if modules is None:
            modules = []

        dynamic_channels = {}
        for m in modules:
            module_dynamic_channels = m.dynamic_channels() if hasattr(m, "dynamic_channels") else None
            if module_dynamic_channels:
                channels_with_state = m.dynamic_state_channels() if hasattr(m, "dynamic_state_channels") else None
                for n, t in module_dynamic_channels.items():
                    existing_type = dynamic_channels.get(n, None)
                    if existing_type is not None:
                        if t is not existing_type:
                            raise ValueError(f"Conflicting types for dynamic channel {n}.")

                    dynamic_channels[n] = t
                    if channels_with_state and n in channels_with_state:
                        if get_origin(t) is list:
                            t = get_args(t)[0]

                        dynamic_channels[f"s_{n}"] = State[t]

        if dynamic_channels:
            dynamic_channel_kwargs = {n: (ts[t], None) for n, t in dynamic_channels.items()}
            base_class = type(channels)
            new_channel_name = f"{base_class.__name__}WithDynamicChannels"
            channels_type = create_model(new_channel_name, __base__=base_class, **dynamic_channel_kwargs)
            channels = channels_type(**{f: getattr(channels, f) for f in channels.model_dump(exclude_defaults=True)})

        self._dynamic_channels_instantiated = True
        return channels

    @model_validator(mode="before")
    @classmethod
    def _model_validate(cls, values):
        """Root validator to append "user_modules" to list of modules."""
        values["modules"] = values.get("modules") or []
        values["modules"].extend(values.pop("user_modules", []))
        return values

    def __getattribute__(self, attr: str) -> Any:
        if attr in ("channels", "state"):
            if not self.running:
                raise Exception("Can only access `{}` when engine is running".format(attr))
        return object.__getattribute__(self, attr)

    @csp.graph
    def graph(self, user_graph: Callable[[GatewayChannels], Any] = None):  # type: ignore[no-untyped-def]
        """Generates the csp graph corresponding to the gateway application.

        This is the graph that will be called by the `start` method

        This function can be passed to a csp.run call directly, which is especially useful if you want to control the graph running
        yourself, perhaps to save the output values from csp.add_graph_output, or to customize the arguments passed
        to csp.run further (for profiling, etc).

        Args:
            user_graph: A function that will be called with the channels to augment the existing application graph.
        """
        self._start_csp_detector()
        try:
            self.channels = self.build(channels=self._instantiate_dynamic_channel(self.modules, object.__getattribute__(self, "channels")))

            self.graph_built = True

            if user_graph:
                user_graph_result = user_graph(object.__getattribute__(self, "channels"))
                if user_graph_result is None:
                    # add a placeholder to ensure exit does not use os._exit
                    user_graph_result = csp.const(True)
                csp.add_graph_output("user_graph", user_graph_result)

        except Exception:
            self.graph_build_failed = True
            raise

        log.info("Launching CSP")
        csp.log(logging.INFO, "CSP Running", csp.const(True), logger=log)

    @csp.node
    def _start_csp_detector(self):
        with csp.start():
            self.running = True
        with csp.stop():
            self.running = False

    def start(
        self,
        user_graph: Optional[Any] = None,
        realtime: bool = True,
        block: bool = True,
        show: bool = False,
        rest: bool = False,
        ui: bool = False,
        _in_test: bool = False,
        starttime: Optional[datetime] = None,
        endtime: Optional[Union[datetime, timedelta]] = None,
        build_timeout: int = 30,
        module_shutdown_timeout: int = 60,
        **uvicorn_kwargs: Any,
    ) -> None:
        """Starts the application corresponding to the Gateway.

        Depending on the provided settings, this will start the web application as well as run the csp graph.
        To return the csp graph independent of the web application, look at the `graph` method.

        Args:
            user_graph: A function that will be called with the channels to augment the existing application graph.
            realtime: Whether to run the csp graph in realtime mode
            block: Whether the csp graph should be run in the foreground or on a background thread. Selecting `rest=True`
                will force this setting to False.
            show: Whether to write the csp graph to file (tmp.png) and return without running.
            rest: Whether to launch the web application as part of the Gateway (i.e. for the REST endpoints). If `True`, will
                force `block=False`.
            ui: Whether to equip the web application with the pieces necessary to run the Perspective-based UI.
            starttime: Start time of the csp graph run.
            endtime: End time of the csp graph run.
            build_timeout: Timeout that the web application uses to wait for the csp graph to start running successfully in the background.
                If the csp graph is not running by the timeout, the web application will shut down.
            module_shutdown_timeout: Timeout that the shutdown method uses to wait for all the modules to shutdown
            uvicorn_kwargs: Additional kwargs to pass to the [uvicorn server config](https://www.uvicorn.org/settings/). Also see `GatewayWebApp`.
        """
        # to avoid hard shutdown, starting webserver, etc
        self._in_test = _in_test
        self._module_shutdown_timeout = module_shutdown_timeout

        try:
            if show:
                # Show graph and return without running
                os.makedirs("outputs", exist_ok=True)
                csp.show_graph(self.graph, user_graph, graph_filename="outputs/gateway.png")
                return

            if rest:
                # Run csp blocking on thread, run app in foreground
                block = False

            if block:
                # If blocking, run csp in foreground
                self.output = csp.run(
                    self.graph,
                    user_graph,
                    realtime=realtime,
                    starttime=starttime,
                    endtime=endtime or MAX_END_TIME,
                )
            else:
                # If not blocking, run csp on thread
                self.output = csp.run_on_thread(
                    self.graph,
                    user_graph,
                    realtime=realtime,
                    starttime=starttime,
                    endtime=endtime or MAX_END_TIME,
                )

            if rest:
                # these are temporary until a pydantic model is in place
                if isinstance(build_timeout, timedelta):
                    build_timeout = build_timeout.total_seconds()
                if isinstance(build_timeout, str):
                    build_timeout = int(build_timeout)

                # if graph shuts down or breaks, we need to shut down the web app
                # as well otherwise it "looks" like its running but its now
                self.web_app = self._build_web(ui=ui, timeout=build_timeout, _in_test=_in_test)
                log.info("Launching web server on:")
                url = f"http://{gethostname()}:{self.settings.PORT}"

                if ui:
                    if self.settings.AUTHENTICATE:
                        log.info(f"\tUI: {url}?token={self.settings.API_KEY}")
                    else:
                        log.info(f"\tUI: {url}")

                log.info(f"\tDocs: {url}/docs")
                log.info(f"\tDocs: {url}/redoc")

                # Run the web app
                # NOTE: this will block, except in test mode
                self.web_app.run(**uvicorn_kwargs)

            if _in_test:
                # return here, dont bother waiting
                return

            if rest:
                # send shutdown to csp if alive
                return self._shutdown()
            elif block:
                # wait for csp thread to be done
                return self._shutdown(wait=True)
            return self.output

        except KeyboardInterrupt:
            log.critical("Shutting down...(Keyboard Interrupt)")
            self._shutdown(user_initiated=True)
        except Exception:
            log.exception("Shutting down...")
            self._shutdown(user_initiated=False)
            # If we're here, we hit some form of error,
            # so re-raise it back to the caller
            raise

    def _get_web_app_class(self) -> Any:
        # FIXME ugly
        from csp_gateway.server import GatewayWebApp

        return GatewayWebApp

    def _build_web(self, ui: bool, timeout: int, _in_test: bool = False) -> Any:
        log.info(f"Building server with: {self.settings}")

        web_app_class = self._get_web_app_class()
        web_app = web_app_class(
            self,
            csp_thread=self.output,
            ui=ui,
            settings=self.settings,
            logger=log,
            _in_test=_in_test,
        )

        # Wait until graph is built by csp thread
        elapsed = 0

        while not self.running and not self.graph_build_failed:
            # FIXME ugly
            sleep(0.5)
            elapsed += 0.5

            if elapsed >= timeout:
                log.critical("Timeout during startup of graph, shutting down")
                raise RuntimeError("Graph start timeout")

            if not self.output.is_alive():
                log.critical("Graph start failure")
                raise RuntimeError("Graph start failure")

        if self.graph_build_failed:
            log.critical("Startup of graph failed, shutting down")
            raise RuntimeError("Graph build failure")

        # Revisit each module and connect to rest, if necessary
        for module in self.modules:
            if not module.disable:
                module.rest(web_app)

        web_app._finalize()

        return web_app

    def stop(self, **kwargs) -> Any:
        log.warning("Shutting down gateway...")

        if isinstance(self.output, csp.impl.wiring.threaded_runtime.ThreadRunner):
            # stop csp
            kwargs["user_initiated"] = True
            return self._shutdown(**kwargs)
        else:
            raise Exception("Gateway can only be stopped if started with `block=False`")

    def _shutdown(self, user_initiated: bool = True, wait: bool = False):
        # Now run through shutdown routine
        log.warning("Initiating shutdown...")

        if not isinstance(self.output, csp.impl.wiring.threaded_runtime.ThreadRunner):
            # nothing more to do
            return self.output

        if not wait:
            if self.output.is_alive():
                # First, try to stop the CSP thread if its alive
                try:
                    self.output.stop_engine()
                except Exception:
                    # If there was an error stopping it, we have an unclean shutdown
                    log.exception("CSP `stop_engine` exception")
                    raise

        # Now join the csp thread, allowing it to raise
        try:
            ret = self.output.join(suppress=False)
        except Exception:
            log.exception("CSP exception detected:")
            raise

        # Invoke shutdown for each of the modules in parallel
        # NOTE: Modules should shutdown independently of each other
        log.warning("Shutting down modules...")
        pool = multiprocessing.pool.ThreadPool()
        result = pool.map_async(lambda mod: mod.shutdown(), self.modules)
        # Wait for modules to shutdown safely, all modules should shutdown within this time
        try:
            result.get(timeout=self._module_shutdown_timeout)
        except multiprocessing.TimeoutError:
            log.warning(f"Shutting down modules took more than {self._module_shutdown_timeout}, forcefully shutting down...")

        # NOTE: Avoid having long running jobs in shutdown since python does not allow
        # forcefull termination of running threads. Therefore the threads will keep runnning
        # until they complete or the parent process dies
        pool.terminate()

        # Now run through shutdown routine
        log.warning("Shutting down webserver...")

        if ret is not None:
            # return value to caller
            log.warning("Returning value to user")
            return ret

        # No output from graph
        log.warning("No graph outputs detected, initiating hard shutdown")

        # else exit
        if not self._in_test:
            if user_initiated:
                log.warning("Shutting down webserver - CLEAN")

                # try clean
                os._exit(0)

                # should not get here
                sleep(5)

            else:
                log.warning("Shutting down webserver - UNCLEAN")

                # try exit
                os._exit(1)

                sleep(5)

            # NOTE: should be unreachable
            log.warning("Shutting down webserver - SIGTERM")

            # force sigkill to self
            os.kill(os.getpid(), signal.SIGKILL)

    def __hash__(self):
        # So that csp doesn't complain about inability to memoize
        return id(self)
