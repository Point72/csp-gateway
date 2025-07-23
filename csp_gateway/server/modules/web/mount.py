import logging

from pydantic import Field, model_validator

from csp_gateway.server import ChannelSelection, GatewayChannels, GatewayModule

# separate to avoid circular
from csp_gateway.server.web import GatewayWebApp

log = logging.getLogger(__name__)


class MountRestRoutes(GatewayModule):
    force_mount_all: bool = Field(
        False,
        description="For debugging, will mount all rest routes for every channel, including state and send routes, even if not added by any modules",
    )

    mount_last: ChannelSelection = Field(default_factory=ChannelSelection, description="Channels to mount for last operations. Defaults to all")
    mount_next: ChannelSelection = Field(default_factory=ChannelSelection, description="Channels to mount for next operations. Defaults to all")
    mount_send: ChannelSelection = Field(default_factory=ChannelSelection, description="Channels to mount for send operations. Defaults to all")
    mount_state: ChannelSelection = Field(default_factory=ChannelSelection, description="Channels to mount for state operations. Defaults to all")
    mount_lookup: ChannelSelection = Field(default_factory=ChannelSelection, description="Channels to mount for lookup operations. Defaults to all")

    @model_validator(mode="before")
    @classmethod
    def _deprecate_mount_all(cls, values):
        if (mount_all := values.pop("mount_all", None)) is not None:
            log.warning("mount_all is deprecated, please use force_mount_all instead")
            if "force_mount_all" not in values:
                values["force_mount_all"] = mount_all
        return values

    def connect(self, channels: GatewayChannels) -> None:
        # NO-OP
        ...

    def rest(self, app: GatewayWebApp) -> None:
        self._mount_last(app)
        self._mount_next(app)
        self._mount_send(app)
        self._mount_state(app)
        self._mount_lookup(app)

    def _mount_last(self, app: GatewayWebApp) -> None:
        selection = ChannelSelection() if self.force_mount_all else self.mount_last
        channels_set = set(selection.select_from(app.gateway.channels_model))

        # Bind every wire
        for name in channels_set:
            # Install on router
            app.add_last_api(name)

        app.add_last_available_channels(channels_set)

    def _mount_next(self, app: GatewayWebApp) -> None:
        selection = ChannelSelection() if self.force_mount_all else self.mount_next
        channels_set = set(selection.select_from(app.gateway.channels_model))

        # Bind every wire
        for name in channels_set:
            # Install on router
            app.add_next_api(name)

        app.add_next_available_channels(channels_set)

    def _mount_send(self, app: GatewayWebApp) -> None:
        selection = ChannelSelection() if self.force_mount_all else self.mount_send
        channels_set = set(selection.select_from(app.gateway.channels_model))
        seen_channels = set()

        # Bind every wire
        if self.force_mount_all:
            for channel in channels_set:
                app.add_send_api(channel)
            seen_channels = channels_set

        else:
            for channel, _ in app.gateway.channels._send_channels.keys():
                if channel in seen_channels or channel not in channels_set:
                    continue
                seen_channels.add(channel)
                # Install on router
                app.add_send_api(channel)

            missing_channels = channels_set - seen_channels
            if missing_channels:
                log.info(f"Requested channels missing send routes are: {list(missing_channels)}")

        app.add_send_available_channels(seen_channels)

    def _mount_state(self, app: GatewayWebApp) -> None:
        selection = ChannelSelection() if self.force_mount_all else self.mount_state
        channels_set = set(selection.select_from(app.gateway.channels_model, state_channels=True))
        seen_channels = set()

        # Bind every wire
        if self.force_mount_all:
            for state_channel in channels_set:
                app.add_state_api(state_channel)
            seen_channels = channels_set

        else:
            for state_channel, _ in app.gateway.channels._state_requests.keys():
                if state_channel in seen_channels or state_channel not in channels_set:
                    continue
                seen_channels.add(state_channel)
                # Install on router
                app.add_state_api(state_channel)

            missing_channels = channels_set - seen_channels
            if missing_channels:
                log.info(f"Requested channels missing state routes: {list(channel[2:] for channel in missing_channels)}")

        app.add_state_available_channels(seen_channels)

    def _mount_lookup(self, app: GatewayWebApp) -> None:
        selection = ChannelSelection() if self.force_mount_all else self.mount_lookup
        channels_set = set(selection.select_from(app.gateway.channels_model))

        # Bind every wire
        for name in selection.select_from(app.gateway.channels_model):
            # Install on router
            app.add_lookup_api(name)

        app.add_lookup_available_channels(channels_set)
