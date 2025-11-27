import logging
from typing import Optional

import csp
import logfire
from pydantic import Field

from csp_gateway.server import ChannelSelection, ChannelsType, GatewayModule


class Logfire(GatewayModule):
    hydra: bool = True
    fastapi: bool = True
    token: Optional[str] = None

    def connect(self, channels: ChannelsType):
        logfire.configure(token=self.token)

        # Install logfire handler into default logging
        # and instrument fastapi

    def web(self, app):
        if self.fastapi:
            logfire.instrument_fastapi(app)

class LogfireChannels(GatewayModule):
    token: Optional[str] = None
    selection: ChannelSelection = Field(default_factory=ChannelSelection)
    log_states: bool = False
    log_level: int = logging.INFO
    log_name: str = str(__name__)
    requires: Optional[ChannelSelection] = []

    def connect(self, channels: ChannelsType):
        logfire.configure(token=self.token)
        # logger_to_use = logging.getLogger(self.log_name)

        # for field in self.selection.select_from(channels, state_channels=self.log_states):
        #     data = channels.get_channel(field)
        #     # list baskets not supported yet
        #     if isinstance(data, dict):
        #         for k, v in data.items():
        #             csp.log(self.log_level, f"{field}[{k}]", v, logger=logger_to_use)
        #     else:
        #         edge = channels.get_channel(field)
        #         csp.log(self.log_level, field, edge, logger=logger_to_use)
