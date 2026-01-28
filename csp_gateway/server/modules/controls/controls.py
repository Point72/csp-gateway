import getpass
import resource
import socket
import threading
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    # Hold and raise in model validator
    psutil = None

import csp
from csp import ts

from csp_gateway.server import GatewayChannels, GatewayModule

# separate to avoid circular
from csp_gateway.server.web import GatewayWebApp
from csp_gateway.utils import Controls

_HOSTNAME = socket.gethostname()
_USER = getpass.getuser()


class MountControls(GatewayModule):
    mount_heartbeat: bool = True
    mount_stats: bool = True
    mount_shutdown: bool = True

    def connect(self, channels: GatewayChannels) -> None:
        self.subscribe(channels.get_channel("controls"))
        channels.add_send_channel("controls")

    def rest(self, app: GatewayWebApp) -> None:
        available = []
        if self.mount_heartbeat:
            app.add_controls_api(field="heartbeat")
            available.append("heartbeat")
        if self.mount_stats:
            app.add_controls_api(field="stats")
            available.append("stats")
        if self.mount_shutdown:
            app.add_controls_api(field="shutdown")
            available.append("shutdown")

        app.add_controls_available_channels(fields=set(available))

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
                stats["cpu"] = psutil.cpu_percent() if psutil else None
                stats["memory"] = psutil.virtual_memory().percent if psutil else None
                stats["memory-total"] = round(
                    psutil.virtual_memory().available * 100 / psutil.virtual_memory().total if psutil else 0,
                    2,
                )

                # Process and thread information
                current_process = psutil.Process() if psutil else None
                stats["pid"] = current_process.pid if current_process else None
                stats["active_threads"] = threading.active_count()

                # Get max threads from ulimit
                _, hard_limit = resource.getrlimit(resource.RLIMIT_NPROC)
                stats["max_threads"] = hard_limit if hard_limit != resource.RLIM_INFINITY else "unlimited"

                # Time information
                stats["now"] = datetime.now(timezone.utc)
                stats["csp-now"] = csp.now()

                stats["host"] = _HOSTNAME
                stats["user"] = _USER

                data.data = stats
                data.status = "ok"  # we mark as ok at the end only after we have all the data

    @csp.graph
    def subscribe(self, data: ts[Controls]):
        self.manage_controls(data)
