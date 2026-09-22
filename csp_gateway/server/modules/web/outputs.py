import os
import os.path
from typing import TYPE_CHECKING

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from hydra.core.hydra_config import HydraConfig
from pydantic import Field

try:
    # conditional on libmagic being installed on the machine
    from magic import Magic
except ImportError:
    Magic = None

from pydantic import BaseModel

from csp_gateway.server import GatewayChannels, GatewayModule

# Imported from the leaf module, not the `csp_gateway.server` package: that package re-exports
# `.modules` before `.web`, so it is only partially initialized while this module is imported.
from csp_gateway.server.web import GatewayWebApp

if TYPE_CHECKING:
    from csp_gateway.server.web.spaday_ui import GatewayUI


class _ChunkRequest(BaseModel):
    """A chunk read as the viewer's tree posts it: `paths` from a selection, `path` once one is open."""

    paths: list[str] = []
    path: str | None = None
    start: int | None = None
    end: int | None = None


class MountOutputsFolder(GatewayModule):
    """The output/log folder, browsable as a page and readable in chunks.

    Under the default UI provider this serves the same HTML directory listing it always has. Under
    the spaday provider it also contributes an in-page log viewer: a file tree beside a reader that
    pulls the file a chunk at a time, so opening a large log never ships the whole thing.
    """

    dir: str | None = None

    chunk_bytes: int = Field(
        default=64 * 1024,
        description="Bytes served per chunk request. The viewer opens on the last chunk of a file and walks backwards from there.",
    )

    max_entries: int = Field(
        default=2000,
        description="Maximum paths returned by the tree listing. The tree renders every path it is given, so a large run directory is capped rather than sent whole.",
    )

    def _resolve(self, relative: str) -> str:
        """The absolute path for a request-supplied relative path, or a 404 if it is not under `dir`.

        ``realpath`` rather than ``abspath``: the latter does not resolve symlinks, so a link under
        the output directory could otherwise point anywhere. ``commonpath`` rather than
        ``startswith``: the latter also accepts a sibling whose name merely begins with the output
        directory's (``/tmp/outputs-elsewhere`` for ``/tmp/outputs``).
        """
        root = os.path.realpath(self.dir)
        target = os.path.realpath(os.path.join(root, relative)) if relative else root
        try:
            contained = os.path.commonpath([root, target]) == root
        except ValueError:
            # Different drives on Windows have no common path.
            contained = False
        if not contained or not os.path.exists(target):
            raise HTTPException(status_code=404, detail=f"Not found: {relative}")
        return target

    def _read_chunk(self, path: str, start: int | None, end: int | None) -> dict:
        """One byte range of one output file, defaulting to the last `chunk_bytes` of it.

        Only the requested range is read, so the size of the file does not bound the response. A range
        can split a multi-byte character at either edge; those decode to the replacement character
        rather than failing the request.
        """
        target = self._resolve(path)
        if not os.path.isfile(target):
            raise HTTPException(status_code=404, detail=f"Not a file: {path}")

        size = os.path.getsize(target)
        if start is None and end is None:
            start, end = max(0, size - self.chunk_bytes), size
        elif start is None:
            # "The chunk before this point": bounded like any other, not everything preceding it.
            end = min(end, size)
            start = max(0, end - self.chunk_bytes)
        else:
            start = max(0, start)
            end = size if end is None else min(end, size)

        with open(target, "rb") as fp:
            fp.seek(start)
            raw = fp.read(max(0, end - start))
        return {
            "path": path,
            "size": size,
            "start": start,
            "end": start + len(raw),
            "text": raw.decode("utf-8", "replace"),
        }

    def connect(self, channels: GatewayChannels) -> None:
        if self.dir is None:
            if HydraConfig.initialized():
                self.dir = os.path.abspath(os.path.join(HydraConfig.get().runtime.output_dir, "..", "..", ".."))
            else:
                self.dir = os.path.abspath(os.path.join(os.getcwd(), "outputs"))

    def rest(self, app: GatewayWebApp) -> None:
        app_router = app.get_router("app")
        mime = Magic(mime=True) if Magic else None

        # Registered before the catch-all below, which would otherwise swallow them as file names.
        @app_router.get("/outputs/_tree", tags=["Utility"])
        def outputs_tree(limit: int | None = None) -> dict:
            """The files under the output folder, as relative paths for the log viewer's tree."""
            root = os.path.abspath(self.dir)
            cap = self.max_entries if limit is None else limit
            paths: list[str] = []
            truncated = False
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames.sort()
                for name in sorted(filenames):
                    if len(paths) >= cap:
                        truncated = True
                        break
                    paths.append(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/"))
                if truncated:
                    break
            return {"paths": paths, "truncated": truncated}

        @app_router.get("/outputs/_chunk", tags=["Utility"])
        def outputs_chunk(path: str, start: int | None = None, end: int | None = None) -> dict:
            """One byte range of one output file, defaulting to the last `chunk_bytes` of it."""
            return self._read_chunk(path, start, end)

        @app_router.post("/outputs/_chunk", tags=["Utility"])
        def outputs_chunk_post(body: _ChunkRequest) -> dict:
            """The same read, shaped for the viewer's tree.

            ``spaday-tree`` emits its selection as ``{"paths": [...]}``, so the browser can hand that
            event straight to this route without composing a URL from it.
            """
            path = body.path or (body.paths[0] if body.paths else None)
            # Expanding a directory in the tree emits a selection like any other, and clearing the
            # selection emits none at all. Neither is an error, so both answer with an empty window
            # rather than the 404 the GET route owes a caller that asked for a file by name.
            if not path or os.path.isdir(self._resolve(path)):
                return {"path": "", "size": 0, "start": 0, "end": 0, "text": ""}
            return self._read_chunk(path, body.start, body.end)

        # TODO subselect
        @app_router.get("/outputs/{full_path:path}", response_class=HTMLResponse, tags=["Utility"])
        def browse_logs(full_path: str, request: Request):
            """
            This endpoint is a small webpage for browsing the [hydra](https://github.com/facebookresearch/hydra)
            output logs and configuration settings of the running application.
            """
            file_or_dir = self._resolve(full_path)
            if os.path.isdir(file_or_dir):
                files = os.listdir(file_or_dir)
                # Build file URLs using path only, then append query string if present
                base_path = str(request.url.path).rstrip("/")
                query_suffix = f"?{request.url.query}" if request.url.query else ""
                files_paths = sorted([f"{base_path}/{f}{query_suffix}".replace("outputs//", "outputs/") for f in files])
                # The UI browses these through `_tree` and reads them through `_chunk`; a caller
                # asking for the directory itself gets the same listing as data.
                return JSONResponse({"files": files_paths})

            def iterfile():
                with open(file_or_dir, "rb") as fp:
                    yield from fp

            if file_or_dir.endswith((".log", ".txt")):
                # NOTE: so viewable in browser, magic is guessing wrong type
                media_type = "text/plain; charset=utf-8"
            elif mime:
                media_type = mime.from_file(file_or_dir)
            else:
                media_type = None

            return StreamingResponse(iterfile(), media_type=media_type)

    def ui(self, app: "GatewayUI") -> None:
        """Contribute the in-page log viewer: a file tree beside a chunked reader.

        Only the spaday provider calls this, so the HTML browser `rest()` mounts stays the default
        provider's log page and this replaces the drawer link that used to navigate away from it.
        """
        from spaday import element
        from spaday.actions import CallEndpoint, Sequence, SetField, concat, event_value, field, obj
        from spaday_trees import Tree
        from spaday_webawesome import WaButton

        from csp_gateway.server.web.spaday_ui import Region

        tree_url = app.url("/outputs/_tree")
        chunk_url = app.url("/outputs/_chunk")

        # `CallEndpoint` writes {"status", "ok", "body"} to its result field, so every read below goes
        # through `.body`. `logs` is the open file's window; `logs_older` receives the chunk before it,
        # which the Older gesture folds onto the front of the window rather than replacing it.
        app.seed_store(
            logs={"ok": True, "body": {"path": "", "text": "", "start": 0, "end": 0, "size": 0}},
            logs_tree={"ok": True, "body": {"paths": [], "truncated": False}},
            logs_older={"ok": True, "body": {"text": "", "start": 0}},
        )

        load_tree = CallEndpoint("GET", tree_url, result="logs_tree")
        open_selected = CallEndpoint("POST", chunk_url, event_value(), result="logs")
        # Growing the window backwards: fetch the range ending where it currently starts, then prepend.
        # At `start` 0 the whole file is loaded and the fetch returns nothing to add.
        load_older = Sequence(
            CallEndpoint("POST", chunk_url, obj({"path": field("logs.body.path"), "end": field("logs.body.start")}), result="logs_older"),
            SetField("logs.body.text", concat(field("logs_older.body.text"), field("logs.body.text"))),
            SetField("logs.body.start", field("logs_older.body.start")),
        )
        load_newer = CallEndpoint("POST", chunk_url, obj({"path": field("logs.body.path"), "start": field("logs.body.start")}), result="logs")

        def panel():
            tree = (
                Tree(id="gateway-log-tree")
                .compute("paths", field("logs_tree.body.paths"))
                .on("selection-change", open_selected)
                # The tree virtualizes its rows against its measured height, so it needs to be a flex
                # child of a column that has one. That is also why the listing is fetched when the tab
                # opens (see the `tab_button` action below) rather than on page load: a closed tab is
                # not laid out, and the tree measures zero.
                .style(flex="1", min_height="0")
            )
            toolbar = (
                element("div")
                .style(display="flex", gap="0.5rem", align_items="center", padding="0.5rem")
                .child(element("strong").bind("textContent", "logs.body.path"))
                # The HTML log page has always shown the serving process's pid beside its heading;
                # keep it here so the tab identifies the process whose logs these are.
                .child(element("span").style(color="var(--spa-muted)").text(f"pid[{os.getpid()}]"))
                .child(element("span").style(flex="1"))
                .child(WaButton(appearance="outlined", size="s").text("Older").on("click", load_older))
                .child(WaButton(appearance="outlined", size="s").text("Newer").on("click", load_newer))
                .child(WaButton(appearance="outlined", size="s").text("Reload").on("click", load_tree))
            )
            reader = (
                element("pre")
                .bind("textContent", "logs.body.text")
                .style(
                    margin="0",
                    padding="0.5rem",
                    height="100%",
                    overflow="auto",
                    white_space="pre-wrap",
                    font_family="ui-monospace, monospace",
                )
            )
            return (
                element("div")
                .style(display="flex", flex_direction="column", height="100%")
                .child(toolbar)
                .child(
                    element("div")
                    .style(display="flex", flex="1", min_height="0")
                    .child(
                        element("div")
                        .style(
                            width="20rem",
                            display="flex",
                            flex_direction="column",
                            min_height="0",
                            overflow="hidden",
                            border_right="1px solid var(--spa-border)",
                        )
                        .child(tree)
                    )
                    .child(element("div").style(flex="1", min_width="0").child(reader))
                )
            )

        app.add_tab("logs", "Logs", panel)
        app.add(Region.DRAWER_RIGHT, app.tab_button("Logs", "logs", action=load_tree))
