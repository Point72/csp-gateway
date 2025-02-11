from typing import Optional

import csp
from csp.impl.types.tstype import isTsType
from pydantic import Field

from csp_gateway.server import ChannelSelection, ChannelsType, GatewayModule
from csp_gateway.utils import is_dict_basket

__all__ = ("AddChannelsToGraphOutput",)


class AddChannelsToGraphOutput(GatewayModule):
    selection: ChannelSelection = Field(default_factory=ChannelSelection)
    requires: Optional[ChannelSelection] = []

    def connect(self, channels: ChannelsType):
        for field in self.selection.select_from(channels):
            outer_type = channels.get_outer_type(field)
            # list baskets not supported yet
            if is_dict_basket(outer_type):
                edge = channels.get_channel(field)
                for k, v in edge.items():
                    csp.add_graph_output(f"{field}[{k}]", v)
            elif isTsType(outer_type):
                edge = channels.get_channel(field)
                csp.add_graph_output(f"{field}", edge)
