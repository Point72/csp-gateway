class GatewayException(Exception): ...


class NoProviderException(GatewayException): ...


class ServerException(GatewayException): ...


class ServerRouteNotMountedException(ServerException): ...


class ServerRouteNotFoundException(ServerException): ...


class ServerUnprocessableException(ServerException): ...


class ServerUnknownException(ServerException): ...


class _Controls(GatewayException):
    def __init__(self, control: str):
        super().__init__("Control: {}".format(control))
