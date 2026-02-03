import logging
from typing import Optional, Union

import csp
from pydantic import Field, field_validator

from csp_gateway.server import ChannelSelection, ChannelsType, GatewayModule

__all__ = ("LogChannels",)


class LogChannels(GatewayModule):
    selection: ChannelSelection = Field(default_factory=ChannelSelection)
    log_states: bool = False
    log_level: int = logging.INFO
    log_name: str = str(__name__)
    requires: Optional[ChannelSelection] = []

    @field_validator("log_level", mode="before")
    @classmethod
    def _convert_log_level(cls, v: Union[str, int]) -> int:
        if isinstance(v, str):
            level = logging.getLevelName(v.upper())
            if isinstance(level, int):
                return level
            raise ValueError(f"Invalid log level: {v}")
        return v

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
