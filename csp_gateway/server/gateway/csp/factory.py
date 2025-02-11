from datetime import datetime
from typing import Generic, List, Optional, Type

from ccflow import BaseModel
from csp.impl.enum import Enum
from csp.impl.genericpushadapter import GenericPushAdapter
from pydantic import Field

from csp_gateway.utils import get_dict_basket_key_type

from .channels import ChannelsType
from .module import Module


class ChannelsFactory(BaseModel, Generic[ChannelsType]):
    model_config = dict(arbitrary_types_allowed=True)  # (for FeedbackOutputDef)

    modules: List[Module[ChannelsType]] = Field(
        default_factory=list, description="The list of modules that will operate on the channels to build the csp graph."
    )
    channels: ChannelsType = Field(
        default=None,
        description="An instance of the Channels to be provided by the user for the Gateway. One can think of this as the internal message bus topics for the Gateway, "
        "even though there is no message bus, just named edges in a csp graph.",
    )
    channels_model: Type[ChannelsType] = Field(  # type: ignore[misc]
        default=ChannelsType,
        description="The type of the channels. Users of a `Gateway` are expected to pass `channels`, and `channels_model` will"
        "be automatically inferred from the type. Developers can subclass `Gateway` and set the default value of"
        "`channels_model` to be the specific type of channels that users must provide.",
    )
    block_set_channels_until: Optional[datetime] = Field(
        default=None,
        description="""
        This determines the csp time at which modules can start sending data to channels.
        This can be overriden on a per module basis, to allow some modules to send data to channels.
        """,
    )

    def build(self, channels: ChannelsType) -> ChannelsType:
        # First update the channels model type so we use the correct type,
        # important because we'll actually want to subclass the base GatewayChannels
        self.channels_model = channels.__class__

        # Collect dynamic keys from the channels
        if dynamic_keys := channels.dynamic_keys():
            for field, keys in dynamic_keys.items():
                channels._dynamic_keys[field].update((k, None) for k in keys)

        enabled_modules = [node for node in self.modules if not node.disable]
        # Collect dynamic keys for each node
        for node in enabled_modules:
            if dynamic_keys := node.dynamic_keys():
                for field, keys in dynamic_keys.items():
                    channels._dynamic_keys[field].update((k, None) for k in keys)

        if self.block_set_channels_until is not None:
            channels._block_set_channels_until = self.block_set_channels_until

        # Wire in each edge Provider.
        # The implementation of set_channel will handle multiplexing streams
        for node in enabled_modules:
            with channels._connection_context(node):
                node.connect(channels)

                # Connect to web app if it exists
                if self.web_app:  # type: ignore[attr-defined]
                    node.rest(self.web_app)  # type: ignore[attr-defined]

        # Now wire in the signals
        # first pass is for any baskets
        for (field, _indexer), push_adapter in channels._send_channels.items():
            if isinstance(push_adapter, tuple):
                # dict basket, plug in now that we should know all the
                # possible keys
                key_type = get_dict_basket_key_type(channels.get_outer_type(field))
                if isinstance(key_type, type) and issubclass(key_type, Enum):
                    for enumfield in key_type:
                        channels.add_send_channel(field, enumfield)

                    # add for whole basket ticks
                    channels._add_send_channel_dict_basket(field, key_type)
                else:
                    for key in channels._dynamic_keys.get(field, []):
                        channels.add_send_channel(field, key)

                    # add for whole basket ticks
                    channels._add_send_channel_dict_basket(field, channels._dynamic_keys.get(field, []))

        # second pass to finish connecting in wires
        for (field, indexer), push_adapter in channels._send_channels.items():
            with channels._connection_context(f"Send[{field}]{f'<{indexer}>' if indexer else ''}"):
                # Add it as an edge on the StreamGroup
                if isinstance(push_adapter, GenericPushAdapter):
                    channels.set_channel(field, push_adapter.out(), indexer=indexer)
                else:
                    # basket, first item of tuple is generic channel,
                    # second item is output
                    channels.set_channel(field, push_adapter[1], indexer=indexer)

        # Do any post work thats necessary
        channels._finalize()
        return channels
