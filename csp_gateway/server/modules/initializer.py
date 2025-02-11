from datetime import timedelta
from typing import Any, Dict

import csp

from csp_gateway.server import ChannelsType, GatewayModule
from csp_gateway.server.gateway.csp.channels import _CSP_ENGINE_CYCLE_TIMESTAMP_FIELD
from csp_gateway.server.shared.engine_replay import JSONConverter

__all__ = ("Initialize",)


class Initialize(GatewayModule):
    """A generic initializer, uses pydantic to parse objects into the correct type for pushing into a Gateway at startup."""

    channel: str
    value: Any = None
    # This is effectively a python dict/list representing the structure we want to push into the graph
    # (This structure can be defined in a yaml file using hydra).
    # It should have the structure of the channel (note the caveat where `unroll` is set to True)
    # If the channel takes a csp.ts[GatewayStruct], then "value" should have the full structure of the
    # GatewayStruct. Refer to the tests for examples.
    seconds_offset: int = 0
    # How many seconds we want to delay before ticking the "value" into the graph.
    unroll: bool = False
    # This allows us to send multiple values, that get unrolled.
    # Setting this to True, the "value" must be a list of values to push into the graph.
    # For example, if a channel is type csp.ts[List[MyGatewayStruct]], then
    # "value" will be a list of GatewayStruct, if "unroll" = False. If "unroll" = True,
    # "value" should be a list of lists of GatewayStruct (where each entry in the outer list is one tick)

    @csp.node
    def tick_engine_cycle(self) -> csp.ts[Dict[str, object]]:
        with csp.alarms():
            a_send = csp.alarm(object)

        with csp.start():
            if not self.unroll:
                goal_dict = {self.channel: self.value}
                csp.schedule_alarm(a_send, timedelta(seconds=self.seconds_offset), goal_dict)
            else:
                for val in self.value:
                    goal_dict = {
                        self.channel: val,
                    }
                    csp.schedule_alarm(a_send, timedelta(seconds=self.seconds_offset), goal_dict)

        if csp.ticked(a_send):
            goal_dict = a_send
            goal_dict[_CSP_ENGINE_CYCLE_TIMESTAMP_FIELD] = csp.now()
            return goal_dict

    def connect(self, channels: ChannelsType):
        if self.value is not None:
            json_channel_converter = JSONConverter(
                channels=channels,
                decode_channels=[self.channel],
                encode_channels=[],
                log_lagging_engine_cycles=False,
            )
            # The "decode" function decodes the dictionary representing the
            # channel tick and ticks it into the graph
            json_channel_converter.decode(self.tick_engine_cycle())
