import asyncio
import os
import signal
import typing
from contextlib import asynccontextmanager
from logging import Logger, getLogger
from os import path
from typing import Any, Callable, Dict, List, Optional, Set

from csp.impl.types.tstype import isTsType
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware
from uvicorn.config import Config
from uvicorn.server import Server

from csp_gateway.server.settings import Settings
from csp_gateway.utils import (
    get_args,
    get_dict_basket_key_type,
    get_dict_basket_value_type,
    get_origin,
    is_dict_basket,
)

from .routes import (
    add_controls_available_channels,
    add_controls_routes,
    add_last_available_channels,
    add_last_routes,
    add_lookup_available_channels,
    add_lookup_routes,
    add_next_available_channels,
    add_next_routes,
    add_send_available_channels,
    add_send_routes,
    add_stage_available_channels,
    add_stage_routes,
    add_state_available_channels,
    add_state_routes,
)
from .static import CacheControlledStaticFiles

if typing.TYPE_CHECKING:
    from .spaday_ui import GatewayUI

# from uvicorn.supervisors import Multiprocess


if typing.TYPE_CHECKING:
    from csp_gateway.server.gateway import Gateway


__all__ = ("GatewayWebApp",)

build_files_dir = path.abspath(path.join(path.dirname(__file__), "..", "build"))
static_files_dir = build_files_dir
images_files_dir = path.join(build_files_dir, "img")


class GatewayWebApp(object):
    # Public
    app: FastAPI
    gateway: "Gateway"
    csp_thread: Any

    # Private
    _uvicorn_server: Server
    _controls: Dict[Callable[[Any, Optional[Any]], Any], Any]

    def __init__(
        self,
        gateway: "Gateway",
        csp_thread: Any,
        settings: Settings,
        ui: bool = True,
        logger: Logger = None,
        _in_test: bool = False,
    ):
        # Instantiate a new FastAPI instance
        root_path = self._normalize_root_path(settings.ROOT_PATH)
        self.app = FastAPI(
            title=settings.TITLE,
            description=settings.DESCRIPTION,
            version=settings.VERSION,
            contact={"name": settings.AUTHOR, "email": settings.EMAIL},
            root_path=root_path,
            lifespan=self._lifespan,
        )
        self.templates = Jinja2Templates(
            directory=os.path.join(os.path.dirname(__file__), "templates"),
        )

        # Attach gateway
        self.gateway = gateway
        self.app.gateway = gateway

        # add csp thread for monitoring
        self.csp_thread = csp_thread

        # setup controls
        self._controls = {}

        # local files (logos / custom js / css) served by url, keyed by url path
        self._custom_asset_routes: Dict[str, str] = {}

        # raw UI customization config (root-relative URLs); populated in add_static_files
        self._ui_config_raw: Dict[str, Any] = {}

        # update ui in settings
        self.settings = settings.model_copy(update={"ROOT_PATH": root_path})
        if ui:
            self.settings.UI = True

        # spaday UI provider (only when the 'spaday' frontend is selected AND the UI is enabled).
        # Modules populate this via their `ui()` hook and it is mounted at finalization. Imported
        # here (not at module load) so the optional `spaday` dependency is only required when the
        # spaday frontend is actually served.
        self.ui: Optional["GatewayUI"] = None
        if self.settings.UI and self.settings.UI_PROVIDER == "spaday":
            from .spaday_ui import GatewayUI

            self.ui = GatewayUI(self, self.settings)

        # for logging
        self.logger = logger or getLogger(__name__)

        # for certain test overrides
        self._in_test = _in_test

        # Construct routers
        # These correspond to the various channel
        # types in `Channels`
        self._routers = {
            "api": APIRouter(),  # top level
            # HTML Routes
            "app": APIRouter(),
            "public": APIRouter(),
            # API Routes
            "auth": APIRouter(),
            "controls": APIRouter(),
            "last": APIRouter(),
            "lookup": APIRouter(),
            "next": APIRouter(),
            "send": APIRouter(),
            "stage": APIRouter(),
            "state": APIRouter(),
        }

        # middlewares
        self._middlewares = []

    def get_fastapi(self) -> FastAPI:
        return self.app

    @asynccontextmanager
    async def _lifespan(self, app: FastAPI):
        # install periodic monitoring
        async def monitor_thread(thread=self.csp_thread):
            while True:
                if not thread.is_alive():
                    self.logger.critical("Detected csp thread dead/done")
                    self._uvicorn_server.should_exit = True
                    return
                await asyncio.sleep(1)

        loop = asyncio.get_running_loop()
        fut = loop.create_task(monitor_thread())

        yield

        if fut.done():
            # either no-op or raises
            fut.result()

        if not self._uvicorn_server.started:
            # error during startup, blow up
            self.logger.critical("Error during webserver startup")
            self.gateway._shutdown(user_initiated=False)
            raise RuntimeError("Error during webserver startup")
        self._uvicorn_server.should_exit = True

    def check_control(self, key, value=None):
        return key in self._controls and self._controls[key](value)

    def get_routers(self) -> Dict[str, APIRouter]:
        return self._routers

    def get_router(self, kind: str = "api"):
        return self.get_routers()[kind]

    def add_middleware(self, middleware) -> None:
        self._middlewares.append(middleware)

    def add_cors(self) -> None:
        """Add CORS middleware to FastAPI app"""
        if self.settings.BACKEND_CORS_ORIGINS:
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=[str(origin) for origin in self.settings.BACKEND_CORS_ORIGINS],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

    def add_docs(self) -> None:
        """Add OpenAPI routes to FastAPI app"""
        app_router: APIRouter = self.get_router("app")

        # Mount openapi
        @app_router.get("/openapi.json", include_in_schema=False)
        def getOpenapi(request: Request) -> Dict[str, Any]:
            root_path = request.scope.get("root_path", "")
            return get_openapi(
                title=self.settings.TITLE,
                version=self.settings.VERSION,
                routes=self.app.routes,
                servers=[{"url": root_path}] if root_path else None,
            )

        @app_router.get("/docs/", include_in_schema=False, response_class=HTMLResponse)
        def getDocs(request: Request):
            root_path = request.scope.get("root_path", "")
            return get_swagger_ui_html(openapi_url=f"{root_path}/openapi.json", title=self.settings.TITLE)

        @app_router.get("/redoc/", include_in_schema=False, response_class=HTMLResponse)
        def getRedoc(request: Request):
            root_path = request.scope.get("root_path", "")
            return get_redoc_html(openapi_url=f"{root_path}/openapi.json", title=self.settings.TITLE)

    @staticmethod
    def _is_asset_url(value: str) -> bool:
        """Whether an asset reference is already a servable URL (vs a local file path)."""
        return value.startswith(("http://", "https://", "data:"))

    @staticmethod
    def _normalize_root_path(value: Optional[str]) -> str:
        """Normalize a configured ROOT_PATH to '' or a leading-slash, no-trailing-slash path.

        '' / '/' -> '', 'watchtower' -> '/watchtower', '/watchtower/' -> '/watchtower'.
        """
        if not value:
            return ""
        value = value.strip().rstrip("/")
        if not value:
            return ""
        if not value.startswith("/"):
            value = "/" + value
        return value

    @staticmethod
    def _join_root_path(root_path: str, url: Optional[str]) -> Optional[str]:
        """Prefix a root-relative URL with the proxy root_path, leaving absolute URLs alone."""
        if not url or not root_path:
            return url
        if url.startswith(("http://", "https://", "data:")):
            return url
        if url.startswith("/"):
            return f"{root_path.rstrip('/')}{url}"
        return url

    @staticmethod
    def root_path_url(request: Optional[Request], url: str) -> str:
        """Prefix a root-relative URL with the current request's proxy root_path.

        Use for redirect targets and template links so auth and navigation flows
        work when the app is served under a sub-path behind a reverse proxy.
        """
        root_path = request.scope.get("root_path", "") if request is not None else ""
        return GatewayWebApp._join_root_path(root_path, url) or url

    def _prefixed_ui_config(self, root_path: str) -> Dict[str, Any]:
        """Return the UI config with all local asset URLs prefixed for the current root_path."""
        raw = self._ui_config_raw
        return {
            **raw,
            "basePath": root_path or "",
            "headerLogo": self._join_root_path(root_path, raw["headerLogo"]),
            "footerLogo": self._join_root_path(root_path, raw["footerLogo"]),
            "customCss": [self._join_root_path(root_path, css) for css in raw["customCss"]],
            "customJs": [self._join_root_path(root_path, js) for js in raw["customJs"]],
        }

    def _resolve_asset(self, value: Optional[str], kind: str) -> Optional[str]:
        """Resolve an asset reference to a URL, serving local files automatically."""
        if not value:
            return None
        # http(s) URLs and data URIs are used as-is. Anything that exists on disk
        # is served automatically; everything else is treated as a URL path
        # (e.g. an already-mounted "/static/..." or "/img/..." asset).
        if self._is_asset_url(value) or not path.isfile(value):
            return value
        abspath = path.abspath(value)
        url = f"/custom-assets/{kind}-{len(self._custom_asset_routes)}-{path.basename(abspath)}"
        self._custom_asset_routes[url] = abspath
        return url

    def _resolve_ui_assets(self):
        """Resolve all configured UI assets into URLs, mounting/serving local files."""
        header_logo = self._resolve_asset(self.settings.HEADER_LOGO, "logo")
        footer_logo = self._resolve_asset(self.settings.FOOTER_LOGO, "logo")
        custom_css = [self._resolve_asset(css, "css") for css in self.settings.CUSTOM_CSS]
        custom_js = [self._resolve_asset(js, "js") for js in self.settings.CUSTOM_JS]

        # Auto-discover any *.js / *.css in the configured custom static directory
        if self.settings.CUSTOM_STATIC_DIR:
            custom_dir = path.abspath(self.settings.CUSTOM_STATIC_DIR)
            if path.isdir(custom_dir):
                self.app.mount(
                    "/custom",
                    CacheControlledStaticFiles(directory=custom_dir, check_dir=False),
                    name="custom",
                )
                for fname in sorted(os.listdir(custom_dir)):
                    if fname.endswith(".css"):
                        custom_css.append(f"/custom/{fname}")
                    elif fname.endswith(".js"):
                        custom_js.append(f"/custom/{fname}")
            else:
                self.logger.warning("CUSTOM_STATIC_DIR %s is not a directory", custom_dir)

        # Raw config with root-relative URLs; prefixed per-request via _prefixed_ui_config.
        self._ui_config_raw = {
            "title": self.settings.TITLE,
            "description": "",
            "headerLogo": header_logo,
            "footerLogo": footer_logo,
            "customCss": custom_css,
            "customJs": custom_js,
        }
        return self._ui_config_raw

    def add_static_files(self) -> None:
        """Add static file handlers to FastAPI app"""
        app_router: APIRouter = self.get_router("app")
        public_router: APIRouter = self.get_router("public")

        # Mount static files
        self.app.mount(
            "/static",
            CacheControlledStaticFiles(directory=static_files_dir, check_dir=False, html=True),
            name="frontend",
        )

        # Mount images
        self.app.mount(
            "/img",
            CacheControlledStaticFiles(directory=images_files_dir, check_dir=False, html=True),
            name="img",
        )

        # Resolve UI customization assets (logos, custom js/css), serving local files
        self._resolve_ui_assets()

        # Serve any local files referenced by the UI customization settings
        if self._custom_asset_routes:

            @app_router.get("/custom-assets/{name:path}", include_in_schema=False, response_class=FileResponse)
            async def serve_custom_asset(name: str):
                target = self._custom_asset_routes.get(f"/custom-assets/{name}")
                if target is None:
                    raise HTTPException(status_code=404, detail="Not found")
                return FileResponse(target)

        # Expose the UI customization config (title, logos, custom assets) for the frontend.
        # Public (no auth) so the UI shell can render before authentication.
        @public_router.get("/ui-config", include_in_schema=False)
        async def get_ui_config(request: Request) -> Dict[str, Any]:
            return self._prefixed_ui_config(request.scope.get("root_path", ""))

        # Mount top level routes
        @self.app.get("/favicon.ico", include_in_schema=False, response_class=FileResponse)
        async def readFavicon():
            return FileResponse(path.join(build_files_dir, "favicon.png"))

        # Add UI if present, otherwise redirect to docs
        if self.settings.UI:
            if self.ui is not None:
                # spaday provider: mount the spaday page (page, tree, and /js assets) at the root.
                self.ui.mount()
            else:

                @app_router.get("/", include_in_schema=False, response_class=HTMLResponse)
                async def serve_react_app(request: Request):
                    root_path = request.scope.get("root_path", "")
                    ui_config = self._prefixed_ui_config(root_path)
                    return self.templates.TemplateResponse(
                        request,
                        "index.html.j2",
                        {
                            "title": ui_config["title"],
                            "description": ui_config["description"],
                            "base_path": root_path,
                            "ui_config": ui_config,
                            "custom_css": ui_config["customCss"],
                            "custom_js": ui_config["customJs"],
                        },
                    )

        else:

            @self.app.get("/", include_in_schema=False, response_class=RedirectResponse)
            async def serve_react_app(request: Request):
                root_path = request.scope.get("root_path", "")
                return RedirectResponse(f"{root_path}/redoc")

    def add_api(self) -> None:
        """Add API handlers to FastAPI app"""
        api_router = self.get_router("api")
        api_router.include_router(
            self.get_router("auth"),
            prefix="/auth",
            tags=["Auth"],
            dependencies=self._middlewares,
        )
        api_router.include_router(
            self.get_router("controls"),
            prefix="/controls",
            tags=["Controls"],
            dependencies=self._middlewares,
        )
        api_router.include_router(
            self.get_router("last"),
            prefix="/last",
            tags=["Last"],
            dependencies=self._middlewares,
        )
        api_router.include_router(
            self.get_router("lookup"),
            prefix="/lookup",
            tags=["Lookup"],
            dependencies=self._middlewares,
        )
        api_router.include_router(
            self.get_router("next"),
            prefix="/next",
            tags=["Next"],
            dependencies=self._middlewares,
        )
        api_router.include_router(
            self.get_router("send"),
            prefix="/send",
            tags=["Requests"],
            dependencies=self._middlewares,
        )
        api_router.include_router(
            self.get_router("stage"),
            prefix="/stage",
            tags=["Stage"],
            dependencies=self._middlewares,
        )
        api_router.include_router(
            self.get_router("state"),
            prefix="/state",
            tags=["State"],
            dependencies=self._middlewares,
        )

        self.app.include_router(
            api_router,
            prefix=self.settings.API_STR,
            dependencies=self._middlewares,
        )

    def _get_field_type(self, field: str) -> Any:
        return self.gateway.channels_model.get_outer_type(field)

    def _is_dict_basket_field(self, field: str) -> Any:
        field_type = self._get_field_type(field)
        if is_dict_basket(field_type):
            return (
                get_dict_basket_key_type(field_type),
                get_dict_basket_value_type(field_type),
            )
        return None

    def _get_field_pydantic_type(self, field: str) -> BaseModel:
        field_type = self._get_field_type(field)
        if is_dict_basket(field_type):
            typ = get_dict_basket_value_type(field_type)
        elif isTsType(field_type):  # Check if it's an edge
            typ = field_type.typ
        else:
            return None
        if get_origin(typ) is list:
            return List[get_args(typ)[0]]
        return typ

    def add_last_api(self, field: str) -> None:
        api_router = self.get_router("last")
        dict_basket = self._is_dict_basket_field(field=field)

        if dict_basket:
            dict_basket_key_type, model = dict_basket
            subroute_key = dict_basket_key_type
        else:
            model = self._get_field_pydantic_type(field)
            subroute_key = None

        add_last_routes(api_router=api_router, field=field, model=model, subroute_key=subroute_key)

    def add_last_available_channels(self, fields: Optional[Set[str]] = None) -> None:
        api_router = self.get_router("last")
        add_last_available_channels(api_router=api_router, fields=fields)

    def add_next_api(self, field: str) -> None:
        api_router = self.get_router("next")

        if dict_basket := self._is_dict_basket_field(field=field):
            dict_basket_key_type, model = dict_basket
            subroute_key = dict_basket_key_type
        else:
            model = self._get_field_pydantic_type(field)
            subroute_key = None

        add_next_routes(api_router=api_router, field=field, model=model, subroute_key=subroute_key)

    def add_next_available_channels(self, fields: Optional[Set[str]] = None) -> None:
        api_router = self.get_router("next")
        add_next_available_channels(api_router=api_router, fields=fields)

    def add_lookup_api(self, field: str) -> None:
        api_router = self.get_router("lookup")
        dict_basket = self._is_dict_basket_field(field=field)

        if dict_basket:
            _, model = dict_basket
        else:
            model = self._get_field_pydantic_type(field)

        add_lookup_routes(api_router=api_router, field=field, model=model)

    def add_lookup_available_channels(self, fields: Optional[Set[str]] = None) -> None:
        api_router = self.get_router("lookup")
        add_lookup_available_channels(api_router=api_router, fields=fields)

    def add_send_api(self, field: str) -> None:
        api_router = self.get_router("send")
        dict_basket = self._is_dict_basket_field(field=field)

        if dict_basket:
            dict_basket_key_type, model = dict_basket
            subroute_key = dict_basket_key_type
        else:
            model = self._get_field_pydantic_type(field)
            subroute_key = None

        add_send_routes(api_router=api_router, field=field, model=model, subroute_key=subroute_key)

    def add_send_available_channels(self, fields: Optional[Set[str]] = None) -> None:
        api_router = self.get_router("send")
        add_send_available_channels(api_router=api_router, fields=fields)

    def add_state_api(self, field: str) -> None:
        """Mount REST routes for the given state ``field``.

        ``field`` must be a known state name on the gateway's channels — either
        declared via ``Annotated[..., State(...)]`` or registered dynamically
        via ``set_state`` during a module's ``connect``.
        """
        api_router = self.get_router("state")

        spec = self.gateway.channels._states.get(field) or self.gateway.channels_model._declared_states.get(field)
        if spec is None:
            raise ValueError("Unknown state '{}' on {}".format(field, self.gateway.channels_model.__name__))

        if spec.source_field is not None:
            dict_basket = self._is_dict_basket_field(field=spec.source_field)
            if dict_basket:
                dict_basket_key_type, model = dict_basket
                # If the annotation pinned an indexer, expose as a non-keyed route on that one key.
                subroute_key = None if spec.indexer is not None else dict_basket_key_type
            else:
                model = self._get_field_pydantic_type(spec.source_field)
                subroute_key = None
        else:
            # set_state-registered: source is a raw edge with a known type.
            state_edge = self.gateway.channels._state_edges.get((field, spec.indexer))
            model = None
            subroute_key = None
            if state_edge is not None:
                inner = state_edge.tstype.typ
                # Unwrap _StateManager[T] -> T for the response model
                model = getattr(inner, "_typ", inner)

        add_state_routes(
            api_router=api_router,
            field=field,
            model=model,
            subroute_key=subroute_key,
            keyby=tuple(spec.keyby) if spec.keyby else (),
            indexer=spec.indexer,
        )

    def add_state_available_channels(self, fields: Optional[Set[str]] = None) -> None:
        api_router = self.get_router("state")
        add_state_available_channels(api_router=api_router, fields=fields)

    def add_stage_api(self, field: str) -> None:
        """Mount REST routes for staging on a channel."""
        api_router = self.get_router("stage")
        model = self._get_field_pydantic_type(field)
        add_stage_routes(api_router=api_router, field=field, model=model)

    def add_stage_available_channels(self, fields: Optional[Set[str]] = None) -> None:
        api_router = self.get_router("stage")
        add_stage_available_channels(api_router=api_router, fields=fields)

    def add_controls_api(self, field: str) -> None:
        api_router = self.get_router("controls")
        add_controls_routes(api_router, field=field)

    def add_controls_available_channels(self, fields: Optional[Set[str]] = None) -> None:
        api_router = self.get_router("controls")
        add_controls_available_channels(api_router=api_router, fields=fields)

    def _finalize(self) -> None:
        # Mount API routes
        self.add_api()

        # Add cors
        self.add_cors()

        # Add docs
        self.add_docs()

        # Mount static routes
        self.add_static_files()

        # fix up last few routes
        # omit middlewares for publics
        self.app.include_router(self.get_router("public"))
        self.app.include_router(
            self.get_router("app"),
            dependencies=self._middlewares,
        )

    def run(
        self,
        # Existing options
        host: str = "",  # NOTE: from settings
        port: int = 0,  # NOTE: from settings
        log_config: typing.Optional[typing.Union[typing.Dict[str, typing.Any], str]] = None,
        log_level: typing.Optional[typing.Union[str, int]] = "error",
        # New Options
        timeout_notify: int = 0,  # NOTE: NEW
    ) -> None:
        config = Config(
            # Existing options
            app=self.app,
            host=self.settings.BIND,
            port=self.settings.PORT,
            uds=None,
            fd=None,
            loop="auto",
            http="auto",
            ws="auto",
            lifespan="auto",
            interface="auto",
            reload=False,
            log_config=log_config,
            log_level=log_level,
            # New options
            timeout_notify=timeout_notify,
        )
        self._uvicorn_server = Server(config=config)

        if self._in_test:
            self.logger.info("TEST MODE: Webserver not started")
            return

        # deal with fallout from https://github.com/encode/uvicorn/pull/1600
        def _handle_uvicorn_exit(sig, frame):
            # All we need to do here is raise an exception to ensure
            # uvicorn propagates it forward
            raise InterruptedError()

        def _handle_sigusr1_exit(sig, frame):
            # Uvicorn won't have any specific handling for other signals,
            # so we force shutdown the gateway here
            self.gateway._shutdown(user_initiated=True)

        signal.signal(signal.SIGTERM, _handle_uvicorn_exit)
        signal.signal(signal.SIGUSR1, _handle_sigusr1_exit)

        try:
            self._uvicorn_server.run()
        except KeyboardInterrupt:
            self.gateway._shutdown(user_initiated=True)
        except InterruptedError:
            self.gateway._shutdown(user_initiated=True)
        except Exception:
            self.gateway._shutdown(user_initiated=False)
