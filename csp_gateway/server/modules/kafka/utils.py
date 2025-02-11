import abc
from typing import Any, List, Union, get_args, get_origin

import csp
from ccflow import BaseModel
from csp import ts

from csp_gateway.utils import GatewayStruct

__all__ = ("KafkaChannelProcessor",)


class KafkaChannelProcessor(BaseModel, abc.ABC):
    """
    Process channel inputs before sending to Kafka, or before propagating into the graph.
    """

    @abc.abstractmethod
    def process(self, obj: Union[List[GatewayStruct], GatewayStruct], topic: str, key: str) -> Any:
        raise NotImplementedError()

    def apply_process(self, typ: Any, obj: ts[object], topic: str, key: str) -> ts[object]:
        """Applies a function to a ticking edge.

        Args:
            typ: The class of the processed object, according to csp.
            obj: The ticking edge that ticks values of the object
            topic: The Kafka topic
            key: The Kafka key

        Returns:
            A ticking edge with the processed output, of type specified by `typ`
        """

        actual_type = typ
        # csp doesnt like typing.List, so we replace it if we see it
        if get_origin(typ) is list:
            arg = get_args(typ)[0]
            actual_type = [arg]

        res = csp.apply(obj, lambda x, topic=topic, key=key: self.process(x, topic, key), object)
        flag = csp.apply(res, lambda x: x is not None, bool)

        filtered_res = csp.filter(flag, res)
        # safer than static_cast since csp does type checking at runtime for us
        return csp.dynamic_cast(filtered_res, actual_type)
