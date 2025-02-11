import logging
from typing import Optional

import csp
from pydantic import Field

from csp_gateway.server import ChannelSelection, ChannelsType, GatewayModule


class LogChannels(GatewayModule):
    selection: ChannelSelection = Field(default_factory=ChannelSelection)
    log_states: bool = False
    log_level: int = logging.INFO
    log_name: str = str(__name__)
    requires: Optional[ChannelSelection] = []

    def connect(self, channels: ChannelsType):
        logger_to_use = logging.getLogger(self.log_name)

        for field in self.selection.select_from(channels, state_channels=self.log_states):
            data = channels.get_channel(field)
            # list baskets not supported yet
            if isinstance(data, dict):
                for k, v in data.items():
                    csp.log(self.log_level, f"{field}[{k}]", v, logger=logger_to_use)
            else:
                edge = channels.get_channel(field)
                csp.log(self.log_level, field, edge, logger=logger_to_use)
