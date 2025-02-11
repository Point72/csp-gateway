import os
import os.path

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse

try:
    # conditional on libmagic being installed on the machine
    from magic import Magic
except ImportError:
    Magic = None

from csp_gateway.server import GatewayChannels, GatewayModule

# separate to avoid circular
from csp_gateway.server.web import GatewayWebApp


class MountOutputsFolder(GatewayModule):
    def connect(self, channels: GatewayChannels) -> None:
        # NO-OP
        ...

    def rest(self, app: GatewayWebApp) -> None:
        app_router = app.get_router("app")
        mime = Magic(mime=True) if Magic else None

        # TODO subselect
        @app_router.get("/outputs/{full_path:path}", response_class=HTMLResponse, tags=["Utility"])
        def browse_logs(full_path: str, request: Request):
            """
            This endpoint is a small webpage for browsing the [hydra](https://github.com/facebookresearch/hydra)
            output logs and configuration settings of the running application.
            """
            outputs_dir = os.path.join(os.getcwd(), "outputs")
            file_or_dir = outputs_dir
            if full_path:
                file_or_dir = os.path.join(file_or_dir, full_path)
            if os.path.abspath(file_or_dir).startswith(outputs_dir) and os.path.exists(file_or_dir):
                if os.path.isdir(file_or_dir):
                    files = os.listdir(file_or_dir)
                    files_paths = sorted([f"{request.url._url}/{f}".replace("outputs//", "outputs/") for f in files])
                    return app.templates.TemplateResponse(
                        "files.html.j2", {"request": request, "files": files_paths, "pid": os.getpid()}, media_type="text/html"
                    )

                def iterfile():  #
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
            raise HTTPException(status_code=404, detail="Not found: {}".format(request.url._url))
