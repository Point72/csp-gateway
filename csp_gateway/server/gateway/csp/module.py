import abc
import typing
from datetime import datetime
from typing import Any, Dict, Generic, List, Optional, Set, Type, Union

from ccflow import BaseModel
from pydantic import Field, TypeAdapter, model_validator

from csp_gateway.server.shared import ChannelSelection
from csp_gateway.utils import GatewayStruct

from .channels import ChannelsType

if typing.TYPE_CHECKING:
    from csp_gateway.server import GatewayWebApp


class Module(BaseModel, Generic[ChannelsType], abc.ABC):
    model_config = {"arbitrary_types_allowed": True}

    requires: Optional[ChannelSelection] = None
    disable: bool = False
    block_set_channels_until: Optional[datetime] = Field(
        default=None,
        description="""
        This determines the csp time at which this module can start sending data to channels.
        This value overrides any gateway-level blocks imposed.
        """,
    )

    @abc.abstractmethod
    def connect(self, Channels: ChannelsType) -> None: ...

    def rest(self, app: "GatewayWebApp") -> None: ...

    @abc.abstractmethod
    def shutdown(self) -> None: ...

    def dynamic_keys(self) -> Optional[Dict[str, List[Any]]]: ...

    def dynamic_channels(self) -> Optional[Dict[str, Union[Type[GatewayStruct], Type[List[GatewayStruct]]]]]:
        """
        Channels that this module dynamically adds to the gateway channels when this module is included into the gateway.

        Returns:
            Dictionary keyed by channel name and type of the timeseries of the channel as values.
        """
        ...

    def dynamic_state_channels(self) -> Optional[Set[str]]:
        """
        The set of dynamic channels that have state.
        """
        ...

    # @abc.abstractmethod
    # def subscribe(self):
    #     ...

    def __eq__(self, other):
        # Override equality because occasionally, Modules will contain fields with non-standard equality methods
        # i.e. numpy arrays or csp edges.
        # Without overriding, these types will prevent the modules from being compared with each other
        # which is needed for the dependency resolutions
        return id(self) == id(other)

    # See https://docs.pydantic.dev/latest/concepts/validators/#validation-of-default-values
    @model_validator(mode="before")
    def validate_requires(cls, v):
        requires = v.get("requires", cls.model_fields["requires"].default)
        v["requires"] = TypeAdapter(ChannelSelection).validate_python(requires)
        return v
