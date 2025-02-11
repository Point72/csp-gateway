import json
from typing import List, Tuple, TypeVar

import csp
from csp import ts
from csp_adapter_symphony import SymphonyAdapter, SymphonyMessage

from csp_gateway.server import GatewayChannels, GatewayModule

T = TypeVar("T")


class PublishSymphony(GatewayModule):
    """
    Takes a set of channels (selections) and turns them into symphony messages.

    To get setup with symphony:
    1. Email 'Tech - Symphony Admin' to create a new symphony account for your bot and for them to generate a pfx keyc.
        You should include the following in your email:
            * Bot Display Name (AAAA Alerts)
            * Distribution Email Address (e.g. trading-AAAA@cubistsystematic.com)
    2. Create a key.pem and crt.pem file locally (these will be used to authenticate your bot on your machine of choice):
    ( replace pfx_file with your filename)

    ```bash
        PFX="mypfxfile.pfx"
        openssl pkcs12 -in $PFX -out key.pem -nocerts -nodes
        openssl pkcs12 -in $PFX -out crt.pem -clcerts -nokeys
    ```

    3. On your target machine move your newly created key.pem and crt.pem files to an accessible directory.

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

    selections: List[str] = []

    def get_cert_and_key(self) -> Tuple[str, str]:
        with open(self.cert_path, "r") as f:
            cert = f.read()
        with open(self.key_path, "r") as f:
            key = f.read()
        return cert, key

    def connect(self, channels: GatewayChannels):
        cert, key = self.get_cert_and_key()
        symphony_manager = SymphonyAdapter(cert, key)
        for channel in self.selections:
            sub = self.subscribe_channel(channels.get_channel(channel))
            symphony_manager.publish(csp.unroll(sub.messages))

    @csp.node
    def subscribe_channel(self, channel: ts["T"]) -> csp.Outputs(messages=ts[List[SymphonyMessage]]):
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
