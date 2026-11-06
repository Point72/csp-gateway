import json
from typing import TypeVar

import csp
from csp import ts
from pydantic import model_validator

from csp_gateway.server import GatewayChannels, GatewayModule

try:
    from csp_adapter_symphony import SymphonyAdapter, SymphonyMessage
except ImportError:
    # Hold and raise in model validator
    SymphonyAdapter = None
    SymphonyMessage = None

T = TypeVar("T")


class PublishSymphony(GatewayModule):
    """
    Takes a set of channels (selections) and turns them into symphony messages.

    Args
    -----
    cert_path: str
        path to the crt.pem file (absolute)
    key_path: str
        path to the key.pem file (absolute)
    room_name: str
        name of the chat room with your bot
    user: str
        display name of your bot (from above)
    selections: List[str]
        list of channels to push to your symphony room

    Configuration
    -------------
    To be included in your watchtower config.

    ```yaml
    symphony_alerts:
        _target_: csp_gateway.PublishSymphony
        cert_path: /my/path/to/crt.pem
        key_path: /my/path/to/key.pem
        room_name: "My Symphony Room"
        user: "My Symphony Bot"
    ```

    """

    cert_path: str
    key_path: str
    room_name: str
    user: str

    selections: list[str] = []

    def get_cert_and_key(self) -> tuple[str, str]:
        with open(self.cert_path) as f:
            cert = f.read()
        with open(self.key_path) as f:
            key = f.read()
        return cert, key

    @model_validator(mode="before")
    def check_import(cls, values):
        if SymphonyAdapter is None:
            raise ImportError("csp_adapter_symphony is required for PublishSymphony. Install it with: pip install csp-adapter-symphony")
        return values

    def connect(self, channels: GatewayChannels):
        cert, key = self.get_cert_and_key()
        symphony_manager = SymphonyAdapter(cert, key)

        @csp.node
        def subscribe_channel(self, channel: ts["T"]) -> csp.Outputs(messages=ts[list[SymphonyMessage]]):
            if csp.ticked(channel):
                msgs = []
                # TODO: Not sure how to manage a dict basket here
                if isinstance(channel, list):
                    msgs.extend(
                        [
                            SymphonyMessage(
                                user=self.user,
                                room=self.room_name,
                                msg=json.dumps(c.to_dict(), default=str),
                            )
                            for c in channel
                        ]
                    )
                else:
                    msgs.append(
                        SymphonyMessage(
                            user=self.user,
                            room=self.room_name,
                            msg=json.dumps(channel.to_dict(), default=str),
                        )
                    )
                csp.output(messages=msgs)

        for channel in self.selections:
            sub = subscribe_channel(channels.get_channel(channel))
            symphony_manager.publish(csp.unroll(sub.messages))
