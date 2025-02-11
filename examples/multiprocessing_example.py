"""This example demonstrates a module that takes data from an input channel and applies some expensive calculation to it
in a subprocess, and puts the results back onto an output channel. This may help throughput if the operation is a lot
more expensive than the cost of pickling/unpickling the data and all the IPC stuff from multiprocessing.

TODO: Extend this for simulation mode - possibly by enforcing that each input must have an output.
"""

import csp
import logging
import numpy as np
from csp import ts
from ccflow import Frequency
from datetime import datetime, timedelta
from multiprocessing import Process, Queue
from pydantic import Field

from csp_gateway import Gateway, GatewayChannels, GatewayModule, GatewayStruct


class MyInputStruct(GatewayStruct):
    x: int


class MyComputedStruct(GatewayStruct):
    x: int


class MyGatewayChannel(GatewayChannels):
    input_data: ts[MyInputStruct] = None
    computed_data: ts[MyComputedStruct] = None


def _some_really_expensive_operation(x: MyInputStruct):
    # "Expensive" operation.
    return MyComputedStruct(x=x.x + 1)


def _run_worker(input_queue, output_queue):
    while True:
        x: MyInputStruct = input_queue.get(block=True)
        output = _some_really_expensive_operation(x)
        output_queue.put_nowait(output)


class MyInputModule(GatewayModule):
    """Module for generating random inputs."""

    def connect(self, channels: MyGatewayChannel):
        trigger = csp.timer(timedelta(seconds=1))
        input_data = self._generate_random_inputs(trigger)
        channels.set_channel("input_data", input_data)

    @staticmethod
    @csp.node
    def _generate_random_inputs(trigger: ts[bool]) -> csp.Outputs(ts[MyInputStruct]):
        if csp.ticked(trigger):
            return MyInputStruct(x=int(np.random.uniform(-100, 100)))


class MyMultiProcessingModule(GatewayModule):
    """Module for applying some very expensive function in a sub-process."""

    drain_queue_interval: Frequency = Field(Frequency("1s"))

    def connect(self, channels: MyGatewayChannel):
        input_data = channels.get_channel("input_data")
        # Use queues for communication between this module and the worker process.
        input_queue = Queue()  # Us -> worker
        output_queue = Queue()  # Worker -> us

        # Start worker.
        p = Process(target=_run_worker, args=(input_queue, output_queue))
        p.start()

        # Queue inputs + drain queue
        drain_queue = csp.timer(self.drain_queue_interval.timedelta)
        computed_data = csp.unroll(self._process_monitor(input_data, drain_queue, input_queue, output_queue, p))
        channels.set_channel("computed_data", computed_data)

        # Log so we can see outputs whilst running.
        csp.log(logging.INFO, "input_data", input_data)
        csp.log(logging.INFO, "computed_data", computed_data)

    @staticmethod
    @csp.node
    def _process_monitor(x: ts[MyInputStruct], drain_queue: ts[bool], input_queue: object, output_queue: object, process: object) -> csp.Outputs(
        ts[[MyComputedStruct]]
    ):
        with csp.stop():
            process.join(0)
            if process.is_alive():
                process.terminate()

        if csp.ticked(x):
            input_queue.put_nowait(x)

        if csp.ticked(drain_queue):
            output = []
            while not output_queue.empty():
                output.append(output_queue.get_nowait())

            if output:
                return output


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    input_module = MyInputModule()
    multi_processing_module = MyMultiProcessingModule()
    gateway = Gateway(
        modules=[
            input_module,
            multi_processing_module,
        ],
        channels=MyGatewayChannel(),
        channels_model=MyGatewayChannel,
    )

    out = csp.run(
        gateway.graph,
        starttime=datetime.utcnow(),
        endtime=timedelta(seconds=10),
        realtime=True,
    )
