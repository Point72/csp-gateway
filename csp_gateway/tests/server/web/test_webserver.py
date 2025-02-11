import csp.impl.error_handling
import logging
import os
import os.path
import pytest
import time
from fastapi.testclient import TestClient
from packaging import version
from platform import python_version
from unittest import mock

from csp_gateway import (
    Gateway,
    MountControls,
    MountFieldRestRoutes,
    MountOutputsFolder,
    MountPerspectiveTables,
    MountRestRoutes,
    MountWebSocketRoutes,
    __version__,
)
from csp_gateway.client import GatewayClient, GatewayClientConfig
from csp_gateway.server.demo import (
    ExampleCustomTable,
    ExampleEnum,
    ExampleGatewayChannels,
    ExampleModule,
)

csp.impl.error_handling.set_print_full_exception_stack(True)

if version.parse(python_version()) >= version.parse("3.11"):
    HTTPX_PATCH = "csp_gateway.client.client"
else:
    HTTPX_PATCH = "csp_gateway.client"


@pytest.fixture(scope="class")
def gateway(free_port):
    # instantiate gateway
    gateway = Gateway(
        modules=[
            ExampleModule(),
            ExampleCustomTable(),
            MountControls(),
            MountOutputsFolder(),
            MountPerspectiveTables(perspective_field="perspective", layouts={"example": "test"}),
            MountRestRoutes(force_mount_all=True),
            MountFieldRestRoutes(fields=[ExampleGatewayChannels.metadata]),
            MountWebSocketRoutes(),
        ],
        channels=ExampleGatewayChannels(),
        settings={"PORT": free_port},
    )
    return gateway


@pytest.fixture(scope="class")
def webserver(gateway):
    gateway.start(rest=True, _in_test=True)
    yield gateway
    gateway.stop()


@pytest.fixture(scope="class")
def rest_client(webserver) -> TestClient:
    return TestClient(webserver.web_app.get_fastapi())


class TestGatewayWebserver:
    server_data_flowing = None

    ############################
    # "Built in" Functionality #
    def test_openapi(self, rest_client: TestClient):
        response = rest_client.get("/openapi.json")
        assert response.status_code == 200
        json = response.json()
        assert json["info"]["title"] == "Gateway"
        assert json["info"]["version"] == __version__

    def test_docs(self, rest_client: TestClient):
        response = rest_client.get("/docs")
        assert response.status_code == 200

    def test_redoc(self, rest_client: TestClient):
        response = rest_client.get("/redoc")
        assert response.status_code == 200

    def test_unknown_404(self, rest_client: TestClient):
        response = rest_client.get("/an/unknown/route")
        assert response.status_code == 404
        assert response.json() == {"detail": "Not Found"}

    ######################
    # Core Functionality #
    def test_log_viewer(self, rest_client: TestClient):
        # make a temporary path that is known
        os.makedirs(os.path.join(os.getcwd(), "outputs", "testing", "temp"), exist_ok=True)
        with open(os.path.join(os.getcwd(), "outputs", "testing", "temp", "tempfile.txt"), "w") as fp:
            fp.write("test content")

        for sub_route in ("/outputs", "/outputs/testing", "/outputs/testing/temp"):
            response = rest_client.get(sub_route)
            assert response.status_code == 200

        response = rest_client.get("/outputs/somethingelseentirely")
        assert response.status_code == 404

        response = rest_client.get("/outputs/testing/temp/tempfile.txt")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; charset=utf-8"

    def test_control_heartbeat(self, rest_client: TestClient):
        response = rest_client.get("/api/v1/controls/heartbeat")
        assert response.status_code == 200
        data = response.json()
        assert data[0]["name"] == "heartbeat"
        assert data[0]["status"] == "ok"

    #####################
    # CSP Functionality #
    def _wait_for_data(self, rest_client: TestClient):
        if self.server_data_flowing:
            return self.server_data_flowing

        # Helper function to wait for csp data to start
        # flowing before making subsequent tests
        tries = 0
        data = []
        while len(data) == 0 and tries < 50:
            # wait for some data to flow
            time.sleep(0.1)

            response = rest_client.get("/api/v1/last/example")
            assert response.status_code == 200

            data = response.json()
            assert isinstance(data, list)

            if data:
                self.server_data_flowing = data
                return data
            tries += 1
        assert "No data returned" and False

    @pytest.mark.parametrize("route", ["example", "example_list"])
    def test_csp_last(self, rest_client: TestClient, route):
        self._wait_for_data(rest_client=rest_client)

        response = rest_client.get(f"/api/v1/last/{route}")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

        datum = data[0]
        assert "x" in datum
        assert "y" in datum
        assert "data" in datum
        assert "mapping" in datum
        assert str(datum["x"]) * 3 == datum["y"]
        assert isinstance(datum["data"], list)
        assert isinstance(datum["mapping"], dict)

    def test_csp_last_basket(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        response = rest_client.get("/api/v1/last/basket")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 3

        for channel_name, multiplier in ExampleEnum.__metadata__.items():
            response = rest_client.get(f"/api/v1/last/basket/{channel_name}")
            assert response.status_code == 200

            data = response.json()
            assert isinstance(data, list)
            assert len(data) == 1

            datum = data[0]
            assert "x" in datum
            assert "y" in datum
            assert str(datum["x"]) * multiplier == datum["y"]

    def test_csp_last_str_basket(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        response = rest_client.get("/api/v1/last/str_basket")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 3

        for channel_name, multiplier in [("a", 1), ("b", 2), ("c", 3)]:
            response = rest_client.get(f"/api/v1/last/str_basket/{channel_name}")
            assert response.status_code == 200

            data = response.json()
            assert isinstance(data, list)
            assert len(data) == 1

            datum = data[0]
            assert "x" in datum
            assert "y" in datum
            assert str(datum["x"]) * multiplier == datum["y"]

    @pytest.mark.parametrize("route", ["example", "example_list"])
    def test_csp_next(self, rest_client: TestClient, route):
        self._wait_for_data(rest_client=rest_client)

        response = rest_client.get(f"/api/v1/next/{route}")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

        datum = data[0]
        assert "x" in datum
        assert "y" in datum
        assert str(datum["x"]) * 3 == datum["y"]

    def test_csp_next_basket(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        response = rest_client.get("/api/v1/next/basket")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 3

        for channel_name, multiplier in ExampleEnum.__metadata__.items():
            response = rest_client.get(f"/api/v1/next/basket/{channel_name}")
            assert response.status_code == 200

            data = response.json()
            assert isinstance(data, list)
            assert len(data) == 1

            datum = data[0]
            assert "x" in datum
            assert "y" in datum
            assert str(datum["x"]) * multiplier == datum["y"]

    def test_csp_state(self, rest_client: TestClient):
        last_data = self._wait_for_data(rest_client=rest_client)

        # Get state data
        response = rest_client.get("/api/v1/state/example")
        assert response.status_code == 200

        state_data = response.json()
        assert isinstance(state_data, list)

        assert last_data[0] in state_data

    def test_csp_state_query(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        # Get state data
        response = rest_client.get('/api/v1/state/example?query={"filters":[{"attr":"x","by":{"value":1,"where":"=="}}]}')
        assert response.status_code == 200

        state_data = response.json()
        assert isinstance(state_data, list)
        assert len(state_data) == 1
        assert state_data[0]["x"] == 1

    @pytest.mark.parametrize("send_as_list", (True, False))
    def test_csp_send_validation_fails(self, rest_client: TestClient, send_as_list):
        send_data = {"x": -11, "y": "999999999"}

        response = rest_client.post("/api/v1/send/example", json=[send_data] if send_as_list else send_data)
        assert response.status_code == 422

        response_detail = response.json()["detail"]
        # This target error comes from the ExampleData
        # validation function
        target_error = "value must be non-negative."
        for val in response_detail:
            # if any message includes the target error
            # test passes
            if target_error in val["msg"]:
                return

        # should never be hit
        assert False

    @pytest.mark.parametrize("send_as_list", (True, False))
    def test_csp_send(self, rest_client: TestClient, send_as_list, caplog):
        send_data = {"x": 999, "y": "999999999", "internal_csp_struct": {"z": 15}}

        response = rest_client.post("/api/v1/send/example", json=[send_data] if send_as_list else send_data)
        assert response.status_code == 200

        return_data = response.json()
        assert isinstance(return_data, list)
        return_datum = return_data[0]
        assert "id" in return_datum
        assert (return_datum["x"], return_datum["y"], return_datum["internal_csp_struct"]) == (
            send_data["x"],
            send_data["y"],
            send_data["internal_csp_struct"],
        )

        # Perform a lookup just to make sure
        lookup_response = rest_client.get(f"/api/v1/lookup/example/{return_datum['id']}")
        assert return_data == lookup_response.json()

        time.sleep(1)
        for record in caplog.records:
            if record.levelname == "ERROR":
                raise ValueError(str(record))

    @pytest.mark.parametrize("send_as_list", (True, False))
    def test_csp_send_basket(self, rest_client: TestClient, send_as_list):
        send_data = {"x": 999, "y": "999999999"}

        response = rest_client.post("/api/v1/send/basket/A", json=[send_data] if send_as_list else send_data)
        assert response.status_code == 200

        return_data = response.json()
        assert isinstance(return_data, list)
        return_datum = return_data[0]
        assert "id" in return_datum
        assert (return_datum["x"], return_datum["y"]) == (
            send_data["x"],
            send_data["y"],
        )

    def test_csp_send_basket_whole(self, rest_client: TestClient):
        send_data = {"A": {"x": 999, "y": "999999999"}}

        response = rest_client.post("/api/v1/send/basket", json=send_data)
        assert response.status_code == 200

        return_data = response.json()
        assert isinstance(return_data, list)
        return_datum = return_data[0]
        assert (return_datum["x"], return_datum["y"]) == (
            return_datum["x"],
            return_datum["y"],
        )

    def test_csp_lookup(self, rest_client: TestClient):
        # get an existing object to fetch its ID
        data = self._wait_for_data(rest_client=rest_client)
        datum = data[0]
        assert "id" in datum
        id = datum["id"]

        # now lookup the data
        response = rest_client.get(f"/api/v1/lookup/example/{id}")
        assert data == response.json()

    def test_csp_lookup_list(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)
        # get an existing object to fetch its ID
        response = rest_client.get("/api/v1/last/example_list")
        data = response.json()
        datum = data[0]
        assert "id" in datum
        id = datum["id"]

        # now lookup the data
        response = rest_client.get(f"/api/v1/lookup/example_list/{id}")
        assert datum == response.json()[0]

    def test_csp_toplevel_last(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        response_last = rest_client.get("/api/v1/last")
        assert response_last.status_code == 200
        assert sorted(response_last.json()) == [
            "basket",
            "controls",
            "example",
            "example_list",
            "never_ticks",
            "str_basket",
        ]

    def test_csp_toplevel_next(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        response_last = rest_client.get("/api/v1/next")
        assert response_last.status_code == 200
        assert sorted(response_last.json()) == [
            "basket",
            "controls",
            "example",
            "example_list",
            "never_ticks",
            "str_basket",
        ]

    def test_csp_toplevel_state(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)
        response_state = rest_client.get("/api/v1/state")
        assert response_state.status_code == 200
        assert sorted(response_state.json()) == ["example"]

    def test_csp_toplevel_send(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)
        response_send = rest_client.get("/api/v1/send")
        assert response_send.status_code == 200
        assert sorted(response_send.json()) == [
            "basket",
            "basket/A",
            "basket/B",
            "basket/C",
            "controls",
            "example",
        ]

    @mock.patch(HTTPX_PATCH + ".POST", autospec=True)
    @mock.patch(HTTPX_PATCH + ".GET", autospec=True)
    def test_gateway_client(self, mock_get, mock_post, rest_client: TestClient, gateway: Gateway):
        mock_get.side_effect = rest_client.get
        mock_post.side_effect = rest_client.post

        gateway_client = GatewayClient(GatewayClientConfig(port=gateway.settings.PORT))
        self._wait_for_data(rest_client=rest_client)
        response_state = gateway_client.state()
        assert response_state == ["example"]

        for route in ["example", "example_list"]:
            data = gateway_client.last(route)
            assert isinstance(data, list)

            datum = data[0]
            assert "x" in datum
            assert "y" in datum
            assert "data" in datum
            assert "mapping" in datum
            assert str(datum["x"]) * 3 == datum["y"]
            assert isinstance(datum["data"], list)
            assert isinstance(datum["mapping"], dict)

        data_response = gateway_client.last("example", return_raw_json_override=False)
        expected_columns = {"id", "timestamp", "x", "y", "data", "dt", "d", "internal_csp_struct.z", "mapping"}
        data_pd = data_response.as_pandas_df()
        actual_columns_pd = set(data_pd.columns)
        assert expected_columns.issubset(actual_columns_pd)

        data_pl = data_response.as_polars_df()
        actual_columns_pl = set(data_pl.columns)
        assert expected_columns.issubset(actual_columns_pl)

        send_data = {"x": 999, "y": "999999999"}
        return_data = gateway_client.send("basket/A", send_data)
        assert isinstance(return_data, list)
        return_datum = return_data[0]
        assert "id" in return_datum
        assert (return_datum["x"], return_datum["y"]) == (
            send_data["x"],
            send_data["y"],
        )

        send_data = {"x": 9999, "y": "9999999999"}
        return_data = gateway_client.send("basket/A", [send_data])
        assert isinstance(return_data, list)
        return_datum = return_data[0]
        assert "id" in return_datum
        assert (return_datum["x"], return_datum["y"]) == (
            send_data["x"],
            send_data["y"],
        )

    def test_csp_specific_channels(self, caplog):
        caplog.set_level(logging.INFO)
        gateway = Gateway(
            modules=[
                ExampleModule(),
                ExampleCustomTable(),
                MountControls(),
                MountOutputsFolder(),
                MountPerspectiveTables(perspective_field="perspective", layouts={"example": "test"}),
                MountRestRoutes(
                    mount_send=[
                        ExampleGatewayChannels.example,
                        ExampleGatewayChannels.never_ticks,
                    ],
                    mount_last=[
                        ExampleGatewayChannels.example,
                        ExampleGatewayChannels.basket,
                    ],
                ),
                MountFieldRestRoutes(fields=[ExampleGatewayChannels.metadata]),
                MountWebSocketRoutes(),
            ],
            channels=ExampleGatewayChannels(),
        )
        gateway.start(rest=True, _in_test=True)
        rest_client = TestClient(gateway.web_app.get_fastapi())
        self._wait_for_data(rest_client=rest_client)

        response_last = rest_client.get("/api/v1/last")
        assert response_last.status_code == 200
        assert sorted(response_last.json()) == ["basket", "example"]

        response_send = rest_client.get("/api/v1/send")
        assert response_send.status_code == 200
        assert sorted(response_send.json()) == [
            "example",
        ]

        send_data = {"A": {"x": 999, "y": "999999999"}}

        response = rest_client.post("/api/v1/send/basket", json=send_data)
        assert response.status_code == 404
        gateway.stop()
        assert f"Requested channels missing send routes are: ['{ExampleGatewayChannels.never_ticks}']" in caplog.text

    def test_websocket_subscribe_unsubscribe(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        with rest_client.websocket_connect("/api/v1/stream") as websocket:
            # subscribe
            websocket.send_json({"action": "subscribe", "channel": "example"}, mode="text")

            # receive data
            data = websocket.receive_json()
            assert "channel" in data
            assert "data" in data

            msg = data["data"][0]
            assert "id" in msg
            assert "timestamp" in msg
            assert "x" in msg
            assert "y" in msg

            # send data
            websocket.send_json(
                {
                    "action": "send",
                    "channel": "example",
                    "data": {"x": 12345, "y": "54321"},
                }
            )

            data = websocket.receive_json()

            assert "channel" in data
            assert "data" in data

            msg = data["data"][0]
            assert "id" in msg
            assert "timestamp" in msg
            assert msg["x"] == 12345
            assert msg["y"] == "54321"

            # send data as list
            websocket.send_json(
                {
                    "action": "send",
                    "channel": "example",
                    "data": [{"x": 54321, "y": "12345"}],
                }
            )

            data = websocket.receive_json()
            assert "channel" in data
            assert "data" in data

            msg = data["data"][0]
            assert "id" in msg
            assert "timestamp" in msg
            assert msg["x"] == 54321
            assert msg["y"] == "12345"

            # unsubscribe
            websocket.send_json({"action": "unsubscribe", "channel": "example"}, mode="text")

            websocket.send_json(
                {
                    "action": "send",
                    "channel": "example",
                    "data": {"x": 12345, "y": "54321"},
                }
            )
            with pytest.raises(Exception):
                websocket._send_queue.get(timeout=2.0)

    def test_perspective_tables(self, rest_client: TestClient):
        response_last = rest_client.get("/api/v1/perspective/tables")
        assert response_last.status_code == 200
        assert sorted(response_last.json().keys()) == [
            "basket",
            "controls",
            "example",
            "example_list",
            "my_custom_table",
            "never_ticks",
            "str_basket",
        ]

    def test_perspective_layouts(self, rest_client: TestClient):
        response_last = rest_client.get("/api/v1/perspective/layouts")
        assert response_last.status_code == 200
        assert response_last.json() == {"example": "test"}

    def test_fields(self, rest_client: TestClient):
        response_field = rest_client.get("/api/v1/field/metadata")
        assert response_field.status_code == 200
        assert response_field.json() == {"name": "Demo"}

        response_field = rest_client.get("/api/v1/field/garbage")
        assert response_field.status_code == 404

        # Get list of fields
        response = rest_client.get("/api/v1/field")
        assert response.status_code == 200

        assert response.json() == ["metadata"]


def test_MountRestRoutes_validator(caplog):
    """Test for backwards compatibility given API change of mount_all->force_mount_all"""
    r = MountRestRoutes(mount_all=False)
    assert not r.force_mount_all
    assert "mount_all is deprecated, please use force_mount_all instead" in caplog.text

    r = MountRestRoutes(mount_all=True)
    assert r.force_mount_all
