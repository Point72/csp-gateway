import logging
import os
import os.path
import time
from platform import python_version
from unittest import mock

import csp.impl.error_handling
import pytest
from fastapi.testclient import TestClient
from packaging import version

from csp_gateway import (
    Filter,
    Gateway,
    GatewaySettings,
    MountAPIKeyMiddleware,
    MountControls,
    MountFieldRestRoutes,
    MountOutputsFolder,
    MountPerspectiveTables,
    MountRestRoutes,
    MountWebSocketRoutes,
    Query,
    __version__,
)
from csp_gateway.client import GatewayClient, GatewayClientConfig
from csp_gateway.server.demo import (
    ExampleEnum,
    ExampleGatewayChannels,
    ExampleModule,
    ExampleModuleCustomTable,
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
            ExampleModuleCustomTable(),
            MountControls(),
            MountOutputsFolder(),
            MountPerspectiveTables(perspective_field="perspective", layouts={"example": "test"}),
            MountRestRoutes(force_mount_all=True),
            MountFieldRestRoutes(fields=[ExampleGatewayChannels.metadata]),
            MountWebSocketRoutes(),
            MountAPIKeyMiddleware(),
        ],
        channels=ExampleGatewayChannels(),
        settings=GatewaySettings(PORT=free_port, AUTHENTICATE=True, API_KEY="test"),
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
        response = rest_client.get("/openapi.json?token=test")
        assert response.status_code == 200
        json = response.json()
        assert json["info"]["title"] == "Gateway"
        assert json["info"]["version"] == __version__

    def test_docs(self, rest_client: TestClient):
        response = rest_client.get("/docs?token=test")
        assert response.status_code == 200

    def test_redoc(self, rest_client: TestClient):
        response = rest_client.get("/redoc?token=test")
        assert response.status_code == 200

    def test_unknown_404(self, rest_client: TestClient):
        response = rest_client.get("/an/unknown/route?token=test")
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
            response = rest_client.get(f"{sub_route}?token=test")
            assert response.status_code == 200

        response = rest_client.get("/outputs/somethingelseentirely?token=test")
        assert response.status_code == 404

        response = rest_client.get("/outputs/testing/temp/tempfile.txt?token=test")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")

    def test_control_heartbeat(self, rest_client: TestClient):
        response = rest_client.get("/api/v1/controls/heartbeat?token=test")
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

            response = rest_client.get("/api/v1/last/example?token=test")
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

        response = rest_client.get(f"/api/v1/last/{route}?token=test")
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

        response = rest_client.get("/api/v1/last/basket?token=test")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 3

        for channel_name, multiplier in ExampleEnum.__metadata__.items():
            response = rest_client.get(f"/api/v1/last/basket/{channel_name}?token=test")
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

        response = rest_client.get("/api/v1/last/str_basket?token=test")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 3

        for channel_name, multiplier in [("a", 1), ("b", 2), ("c", 3)]:
            response = rest_client.get(f"/api/v1/last/str_basket/{channel_name}?token=test")
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

        response = rest_client.get(f"/api/v1/next/{route}?token=test")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

        datum = data[0]
        assert "x" in datum
        assert "y" in datum
        assert str(datum["x"]) * 3 == datum["y"]

    def test_csp_next_basket(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        response = rest_client.get("/api/v1/next/basket?token=test")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 3

        for channel_name, multiplier in ExampleEnum.__metadata__.items():
            response = rest_client.get(f"/api/v1/next/basket/{channel_name}?token=test")
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
        response = rest_client.get("/api/v1/state/example?token=test")
        assert response.status_code == 200

        state_data = response.json()
        assert isinstance(state_data, list)

        assert last_data[0] in state_data

    def test_csp_state_query(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        # Get state data
        response = rest_client.get('/api/v1/state/example?token=test&query={"filters":[{"attr":"x","by":{"value":1,"where":"=="}}]}')
        assert response.status_code == 200

        state_data = response.json()
        assert isinstance(state_data, list)
        assert len(state_data) == 1
        assert state_data[0]["x"] == 1

    @pytest.mark.parametrize("send_as_list", (True, False))
    def test_csp_send_validation_fails(self, rest_client: TestClient, send_as_list):
        send_data = {"x": -11, "y": "999999999"}

        response = rest_client.post("/api/v1/send/example?token=test", json=[send_data] if send_as_list else send_data)
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

        response = rest_client.post("/api/v1/send/example?token=test", json=[send_data] if send_as_list else send_data)
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
        lookup_response = rest_client.get(f"/api/v1/lookup/example/{return_datum['id']}?token=test")
        assert return_data == lookup_response.json()

        time.sleep(1)
        for record in caplog.records:
            if record.levelname == "ERROR":
                raise ValueError(str(record))

    @pytest.mark.parametrize("send_as_list", (True, False))
    def test_csp_send_basket(self, rest_client: TestClient, send_as_list):
        send_data = {"x": 999, "y": "999999999"}

        response = rest_client.post("/api/v1/send/basket/A?token=test", json=[send_data] if send_as_list else send_data)
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

        response = rest_client.post("/api/v1/send/basket?token=test", json=send_data)
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
        response = rest_client.get(f"/api/v1/lookup/example/{id}?token=test")
        assert data == response.json()

    def test_csp_lookup_list(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)
        # get an existing object to fetch its ID
        response = rest_client.get("/api/v1/last/example_list?token=test")
        data = response.json()
        datum = data[0]
        assert "id" in datum
        id = datum["id"]

        # now lookup the data
        response = rest_client.get(f"/api/v1/lookup/example_list/{id}?token=test")
        assert datum == response.json()[0]

    def test_csp_toplevel_last(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        response_last = rest_client.get("/api/v1/last?token=test")
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

        response_last = rest_client.get("/api/v1/next?token=test")
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
        response_state = rest_client.get("/api/v1/state?token=test")
        assert response_state.status_code == 200
        assert sorted(response_state.json()) == ["example"]

    def test_csp_toplevel_send(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)
        response_send = rest_client.get("/api/v1/send?token=test")
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

        gateway_client = GatewayClient(GatewayClientConfig(port=gateway.settings.PORT, authenticate=True, api_key="test"))
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

        return_data = gateway_client.state("example", query=Query(filters=[Filter(attr="x", by={"value": 1, "where": "=="})]))
        assert isinstance(return_data, list)
        return_datum = return_data[0]
        assert "id" in return_datum
        assert return_datum["x"] == 1

    def test_csp_specific_channels(self, caplog):
        caplog.set_level(logging.INFO)
        gateway = Gateway(
            modules=[
                ExampleModule(),
                ExampleModuleCustomTable(),
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

        response_last = rest_client.get("/api/v1/last?token=test")
        assert response_last.status_code == 200
        assert sorted(response_last.json()) == ["basket", "example"]

        response_send = rest_client.get("/api/v1/send?token=test")
        assert response_send.status_code == 200
        assert sorted(response_send.json()) == [
            "example",
        ]

        send_data = {"A": {"x": 999, "y": "999999999"}}

        response = rest_client.post("/api/v1/send/basket?token=test", json=send_data)
        assert response.status_code == 404
        gateway.stop()
        assert f"Requested channels missing send routes are: ['{ExampleGatewayChannels.never_ticks}']" in caplog.text

    def test_websocket_subscribe_unsubscribe(self, rest_client: TestClient):
        self._wait_for_data(rest_client=rest_client)

        with rest_client.websocket_connect("/api/v1/stream?token=test") as websocket:
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
            # subscribe dict-basket
            # We subscribe via enum name
            websocket.send_json({"action": "subscribe", "channel": "basket", "key": "A"}, mode="text")

            data = websocket.receive_json()

            assert data["channel"] == "basket"
            assert data["key"] == "A"
            assert "data" in data

            # send data as list
            websocket.send_json(
                {
                    "action": "send",
                    "channel": "basket",
                    "key": "A",
                    "data": [{"x": 9989, "y": "1273"}],
                }
            )
            data = websocket.receive_json()

            assert data["channel"] == "basket"
            assert data["key"] == "A"
            msg = data["data"][0]

            assert "id" in msg
            assert "timestamp" in msg
            assert msg["x"] == 9989
            assert msg["y"] == "1273"

            # send data as single item
            # but we don't receive it back
            # since we aren't subscribed.
            websocket.send_json(
                {
                    "action": "send",
                    "channel": "basket",
                    "key": "B",
                    "data": {"x": 9989, "y": "1273"},
                }
            )
            data = websocket.receive_json()
            assert data["channel"] == "basket"
            # We sent to B
            assert data["key"] == "A"
            msg = data["data"][0]
            assert "id" in msg
            assert "timestamp" in msg

            websocket.send_json({"action": "subscribe", "channel": "str_basket", "key": "a"}, mode="text")

            # unsubscribe dict-basket
            # since no key, we unsubscribe from everything
            websocket.send_json({"action": "unsubscribe", "channel": "basket"}, mode="text")

            data = websocket.receive_json()

            # We unsubscribed from 'basket'
            assert data["channel"] == "str_basket"
            assert data["key"] == "a"
            msg = data["data"][0]
            assert "id" in msg
            assert "timestamp" in msg

            # unsubscribe dict-basket
            # since no key, we unsubscribe from everything
            websocket.send_json({"action": "unsubscribe", "channel": "str_basket", "key": "a"}, mode="text")

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
        response_last = rest_client.get("/api/v1/perspective/tables?token=test")
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
        response_last = rest_client.get("/api/v1/perspective/layouts?token=test")
        assert response_last.status_code == 200
        assert response_last.json() == {"example": "test"}

    def test_fields(self, rest_client: TestClient):
        response_field = rest_client.get("/api/v1/field/metadata?token=test")
        assert response_field.status_code == 200
        assert response_field.json() == {"name": "Demo"}

        response_field = rest_client.get("/api/v1/field/garbage?token=test")
        assert response_field.status_code == 404

        # Get list of fields
        response = rest_client.get("/api/v1/field?token=test")
        assert response.status_code == 200

        assert response.json() == ["metadata"]

    def test_stream(self, rest_client: TestClient):
        response_stream = rest_client.get("/api/v1/stream?token=test")
        expected = [
            "basket/A",
            "basket/B",
            "basket/C",
            "controls",
            "example",
            "example_list",
            "heartbeat",
            "never_ticks",
            "str_basket/a",
            "str_basket/b",
            "str_basket/c",
        ]
        assert response_stream.status_code == 200
        assert sorted(response_stream.json()) == expected


def test_MountRestRoutes_validator(caplog):
    """Test for backwards compatibility given API change of mount_all->force_mount_all"""
    r = MountRestRoutes(mount_all=False)
    assert not r.force_mount_all
    assert "mount_all is deprecated, please use force_mount_all instead" in caplog.text

    r = MountRestRoutes(mount_all=True)
    assert r.force_mount_all
