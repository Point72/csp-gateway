import logging

from pydantic import Field, PrivateAttr, model_validator

from csp_gateway.server import ChannelSelection, GatewayModule

try:
    import opsgenie_sdk
except ImportError:
    opsgenie_sdk = None

log = logging.getLogger("csp_gateway.server.modules.logging.opsgenie")

TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")


def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL):
        self._log(TRACE_LEVEL, message, args, **kwargs)


logging.Logger.trace = trace


class _OpsGeniePublisher(GatewayModule):
    """Shared OpsGenie configuration and API client."""

    ops_api_key: str = Field(description="The API key for OpsGenie.")
    requires: ChannelSelection | None = Field(default=[], description="List of required channels.")
    ops_tags: dict[str, str] | None = Field(default=None, description="Tags to be included with OpsGenie alerts.")
    ops_async_delay_sec: float | None = Field(default=5.0, description="Delay in seconds for asynchronous operations.")
    ops_sync_delay_sec: float | None = Field(default=5.0, description="Delay in seconds for synchronous operations.")

    _api_client: "opsgenie_sdk.api_client.ApiClient" = PrivateAttr()

    @model_validator(mode="before")
    def check_import(cls, values):
        if opsgenie_sdk is None:
            raise ImportError(f"opsgenie_sdk is required for {cls.__name__}. Install it with: pip install opsgenie-sdk")
        return values

    def _connect_client(self) -> None:
        config = opsgenie_sdk.configuration.Configuration()
        config.api_key["Authorization"] = self.ops_api_key
        self._api_client = opsgenie_sdk.api_client.ApiClient(configuration=config)
