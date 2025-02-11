from typing import Dict, Optional, Tuple

from pydantic import Field, field_validator

from csp_gateway.server import ChannelSelection, ChannelsType, GatewayModule
from csp_gateway.server.shared.engine_replay import EngineReplay
from csp_gateway.utils import ReadWriteMode


class Mirror(GatewayModule):
    """
    Designed to mirror the ticks of a gateway instance from a given source.
    Wires in the state channels to allow state queries.
    """

    requires: ChannelSelection = []
    selection: ChannelSelection = Field(default_factory=ChannelSelection)
    encode_selection: Optional[ChannelSelection] = Field(
        default=None,
        description=("Optional selection that can be specified to override the selection to specify channels only for encoding."),
    )
    decode_selection: Optional[ChannelSelection] = Field(
        default=None,
        description=("Optional selection that can be specified to override the selection to specify channels only for decoding."),
    )
    mirror_source: EngineReplay
    state_channels: Dict[str, Tuple[str, ...]] = Field(
        default_factory=dict,
        description="Set which channels should be state channels and what their keyby value is",
    )

    @field_validator("state_channels", mode="before")
    def validate_state_channels_for_replay(cls, v):
        return {state: (tuple(keyby) if isinstance(keyby, (list, tuple)) else (keyby,)) for state, keyby in v.items()}

    @field_validator("mirror_source", mode="after")
    def set_same_channels(cls, v, info):
        v.requires = info.data.get("requires", ChannelSelection(include=[]))
        v.selection = info.data.get("selection", ChannelSelection())
        v.read_write_mode = ReadWriteMode.READ
        v.encode_selection = info.data.get("encode_selection")
        v.decode_selection = info.data.get("decode_selection")
        return v

    def connect(self, channels: ChannelsType):
        for channel, keyby in self.state_channels.items():
            channels.set_state(channel, keyby)
        # the requirements should be the same so
        # the channels context manager missing these updates
        # shouldn't matter
        self.mirror_source.connect(channels)
