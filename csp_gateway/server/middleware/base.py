from csp_gateway.server import GatewayChannels, GatewayModule

__all__ = ("AuthenticationMiddleware",)


class AuthenticationMiddleware(GatewayModule):
    def connect(self, channels: GatewayChannels) -> None:
        # NO-OP
        ...
