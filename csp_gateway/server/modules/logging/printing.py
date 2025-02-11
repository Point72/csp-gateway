from typing import Optional

import csp
from pydantic import Field

from csp_gateway.server import ChannelSelection, ChannelsType, GatewayModule


class PrintChannels(GatewayModule):
    """
    Gateway Module for printing channels, which could be useful for debugging.
    There exists a designated logging node class `LogChannels` which is preferred
    and can specify a logger to use by name.
    """

    selection: ChannelSelection = Field(default_factory=ChannelSelection)
    requires: Optional[ChannelSelection] = []

    def connect(self, channels: ChannelsType):
        for field in self.selection.select_from(channels):
            csp.print(f"{field}", channels.get_channel(field))
