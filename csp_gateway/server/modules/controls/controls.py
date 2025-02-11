import csp
import getpass
import psutil
import socket
import threading
import resource
from csp import ts
from datetime import datetime
from fastapi import FastAPI

from csp_gateway.server import GatewayChannels, GatewayModule

# separate to avoid circular
from csp_gateway.server.web import GatewayWebApp
from csp_gateway.utils import Controls

_HOSTNAME = socket.gethostname()
_USER = getpass.getuser()


class MountControls(GatewayModule):
    app: GatewayWebApp = None
    fastapi: FastAPI = None

    def connect(self, channels: GatewayChannels) -> None:
        self.subscribe(channels.get_channel("controls"))
        channels.add_send_channel("controls")

    def rest(self, app: GatewayWebApp) -> None:
        self.app = app
        self.fastapi = app.get_fastapi()

    @csp.node
    def manage_controls(self, data: ts[Controls]):
        if csp.ticked(data):
            # TODO better check if "seen"
            if data.name == "heartbeat":
                # don't have to do anything
                data.status = "ok"

            elif data.name == "stats" and not data.data:
                stats = {}

                # Machine information
                stats["cpu"] = psutil.cpu_percent()
                stats["memory"] = psutil.virtual_memory().percent
                stats["memory-total"] = round(
                    psutil.virtual_memory().available * 100 / psutil.virtual_memory().total,
                    2,
                )

                # Process and thread information
                current_process = psutil.Process()
                stats["pid"] = current_process.pid
                stats["active_threads"] = threading.active_count()

                # Get max threads from ulimit
                _, hard_limit = resource.getrlimit(resource.RLIMIT_NPROC)
                stats["max_threads"] = hard_limit if hard_limit != resource.RLIM_INFINITY else "unlimited"

                # Time information
                stats["now"] = datetime.utcnow()
                stats["csp-now"] = csp.now()

                stats["host"] = _HOSTNAME
                stats["user"] = _USER

                data.data = stats
                data.status = "ok"  # we mark as ok at the end only after we have all the data

    @csp.graph
    def subscribe(self, data: ts[Controls]):
        self.manage_controls(data)
