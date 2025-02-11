"""This example uses Panel (https://panel.holoviz.org/) to visualize data inside a gateway. You will need to install
Panel and plotly for this example to work (they are not part of csp-gateways requirements). This example runs the Panel
server inside the gateway process. Another way you can do it is to subscribe to the data from the client. There are
advantages/disadvantages to each approach."""

import csp
import logging
import numpy as np
import pandas as pd
import panel as pn
import plotly.graph_objects as go
from csp import ts
from ccflow import BaseModel
from datetime import timedelta
from pydantic import Field, PrivateAttr
from queue import Queue
from threading import Thread
from typing import Any, Dict, Optional

from csp_gateway import Gateway, GatewayChannels, GatewayModule, GatewayStruct


class ExampleData(GatewayStruct):
    x: float
    y: float
    z: float


class ExampleGatewayChannel(GatewayChannels):
    data: ts[ExampleData] = None


class ExampleDataModule(GatewayModule):
    """Example data module to generate random data to plot."""

    def connect(self, channels: ExampleGatewayChannel) -> None:
        trigger = csp.timer(interval=timedelta(seconds=1), value=True)
        data = self._generate_data(trigger)
        channels.set_channel("data", data)

    @staticmethod
    @csp.node
    def _generate_data(trigger: ts[bool]) -> csp.Outputs(ts[ExampleData]):
        with csp.state():
            s_data = np.zeros(3)

        if csp.ticked(trigger):
            wt = np.random.normal(size=3)
            s_data += wt
            return ExampleData(
                x=s_data[0],
                y=s_data[1],
                z=s_data[2],
            )


class ExamplePanelApp(BaseModel):
    """Class representing our example panel app. it will plot a timeseries of ExampleData using Plotly. This is a
    ccflow BaseModel. This means it is configurable via YAML."""

    port: int = Field(description="Port you want to serve the panel app on.")

    _data: Optional[pd.DataFrame] = PrivateAttr(default=None)
    _plotly_pane: pn.reactive.Reactive = PrivateAttr(default_factory=pn.pane.Plotly)
    _plotly_data: Dict[str, Any] = PrivateAttr(default_factory=dict)
    _queue: Queue = PrivateAttr(default_factory=Queue)

    def _create_panel(self):
        app = pn.Column(pn.pane.Markdown("# Example Gateway Panel App"), self._plotly_pane)
        return app

    def accumulate_data(self, timestamp, data) -> None:
        """Accumulate a new data point by putting it into a queue.

        Args:
            timestamp: Timestamp of the data.
            data: Instance of ExampleData.
        """
        self._queue.put((timestamp, data))

    def _process_queue(self):
        """Process new data. Update the plotly plots."""
        while True:
            timestamp, data = self._queue.get()
            if self._data is None:
                self._plotly_data = {"data": [], "layout": dict(title="Timeseries of data", xaxis={"title": "timestamp"})}

                self._data = pd.DataFrame({"x": data.x, "y": data.y, "z": data.z}, index=[timestamp])
            else:
                self._data.loc[timestamp] = [data.x, data.y, data.z]

            # It is HIGHLY recommended that you use the graph_objects plotly API instead of the plotly express API
            # for performance reasons.
            traces = [go.Scatter(x=self._data.index, y=self._data[c], mode="lines+markers", name=c) for c in self._data.columns]
            self._plotly_data["data"] = traces
            # Update the panel plotly pane. This will automatically push new data to any clients currently viewing the pane.
            self._plotly_pane.object = self._plotly_data

    def run(self):
        """Run the panel app and serve it."""
        t = Thread(target=self._process_queue, daemon=True)
        t.start()

        pn.extension("plotly")
        pn.serve(
            self._create_panel,
            port=self.port,
            websocket_origin="*",
            title="Example Panel Gateway App",
            show=False,
        )


class ExamplePanelModule(GatewayModule):
    """Example module that visualizes the data channel in Panel."""

    app: ExamplePanelApp

    @csp.node
    def _send_data_to_panel(self, data: ts[ExampleData]):
        if csp.ticked(data):
            self.app.accumulate_data(csp.now(), data)

    def connect(self, channels: ExampleGatewayChannel) -> None:
        t = Thread(target=self.app.run, daemon=True)
        t.start()
        data = channels.get_channel("data")
        self._send_data_to_panel(data=data)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    panel_app = ExamplePanelApp(port=8066)
    gateway = Gateway(
        modules=[
            ExampleDataModule(),
            ExamplePanelModule(app=panel_app),
        ],
        channels=ExampleGatewayChannel(),
        channels_model=ExampleGatewayChannel,
    )
    gateway.start()
