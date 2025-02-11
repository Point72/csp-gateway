from typing import List, Optional, Set, Union

from ccflow import BaseModel
from csp.impl.types.tstype import isTsType
from pydantic import Field, model_validator

from csp_gateway.server.gateway.csp import Channels, ChannelsType
from csp_gateway.utils import is_dict_basket

__all__ = ("ChannelSelection",)


class ChannelSelection(BaseModel):
    """
    A class to represent channel selection options for filtering channels based on inclusion and exclusion criteria.

    Attributes:
        `include` (Optional[List[str]]): A list of channel names to include in the selection.
            The order here matters
            Defaults to None (include everything).
        `exclude` (Set[str]): A list of channel names to exclude from the selection.
            This overrides anything in `include`
            Defaults to an empty set.

    Methods:
        select_from(channels, static_fields=False, state_channels=False): Returns a list of selected channel names
            based on the inclusion and exclusion criteria, and optional static_fields and
            state_channels flags. The order of channels is based on the order of the channels
            in `include`. State channels always follow their corresponding channels.
            If `include` is None, the order is based on the order of the fields in the channels object.
        validate(v): Validates and coerces the input value to a ChannelSelection instance.
    """

    include: Optional[List[str]] = None
    exclude: Set[str] = Field(default_factory=set)

    @model_validator(mode="before")
    def validate_requires(cls, v):
        if v is None:
            return {}
        if isinstance(v, list):
            return dict(include=list(v))
        return v

    def select_from(
        self,
        channels: Union[Channels, ChannelsType],
        *,
        static_fields: bool = False,  # Select only static fields
        state_channels: bool = False,  # Select only state channels
        all_fields: bool = False,  # Select all fields in include and not in exclude
    ) -> List[str]:
        """
        Select fields from the given channels based on the specified criteria.

        Args:
            channels (Union[Channels, ChannelsType]): The channels to select fields from.
            static_fields (bool, optional): If True, select only static fields. Defaults to False.
            state_channels (bool, optional): If True, select only state channels. Defaults to False.
            all_fields (bool, optional): If True, select all fields in include and not in exclude. Defaults to False.

        Returns:
            List[str]: A list of selected field names.
        """
        names = {}

        if all_fields:
            fields = channels.model_fields if self.include is None else self.include
            return list(dict.fromkeys([field for field in fields if field not in self.exclude]))

        for idx, field in enumerate(channels.model_fields):
            # avoid duplicates
            if field in names:
                continue

            # TODO not this `s_` business...
            # Return state channels or regular channels
            if state_field := field.startswith("s_"):
                if not state_channels:
                    continue
                field = field[2:]
            else:
                if state_channels:
                    continue

            # Check whether static
            outer_type = channels.get_outer_type(field)
            if is_dict_basket(outer_type) or isTsType(outer_type):
                if static_fields:
                    continue
            else:
                if not static_fields:
                    continue

            # Check whether included
            if self.include is not None:
                try:
                    idx = self.include.index(field)
                except ValueError:
                    continue

            # Check whether excluded
            if field in self.exclude:
                continue

            if state_field:
                field = f"s_{field}"

            names[field] = idx

        return [k for k, _ in sorted(names.items(), key=lambda x: x[1])]
