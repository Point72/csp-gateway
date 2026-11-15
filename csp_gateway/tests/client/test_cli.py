import io
import json
import logging
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest

from csp_gateway import Query, ServerRouteNotFoundException
from csp_gateway.client import GatewayClientConfig, ReturnType
from csp_gateway.client.cli import GatewayClientCLI, argument, command, json_argument, main


class FakeClient:
    """Records the client calls a command makes and returns canned responses."""

    instances: list["FakeClient"] = []
    responses: dict[str, object] = {}

    def __init__(self, config):
        self.config = config
        self.calls = []
        FakeClient.instances.append(self)

    @property
    def openapi_spec(self):
        return {"openapi": "3.1.0"}

    @property
    def mounted_apis(self):
        return {"last": ["example"]}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def method(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            response = FakeClient.responses.get(name, {"method": name})
            if isinstance(response, BaseException):
                raise response
            return response

        return method


class FakeCLI(GatewayClientCLI):
    client_class = FakeClient


@pytest.fixture(autouse=True)
def _reset_fake_client():
    FakeClient.instances = []
    FakeClient.responses = {}


def run(argv, cli_class=FakeCLI):
    stdout, stderr = io.StringIO(), io.StringIO()
    code = cli_class(stdout=stdout, stderr=stderr).run(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def last_call():
    return FakeClient.instances[-1].calls[-1]


class TestBuiltInCommands:
    def test_help_lists_builtin_commands(self, capsys):
        assert GatewayClientCLI().run(["--help"]) == 0
        out = capsys.readouterr().out
        for name in ("controls", "last", "lookup", "next", "openapi", "routes", "send", "stage", "state", "stream"):
            assert name in out

    def test_missing_command_is_a_usage_error(self, capsys):
        assert GatewayClientCLI().run([]) == 2
        assert "COMMAND" in capsys.readouterr().err

    def test_last_prints_compact_json(self):
        FakeClient.responses["last"] = [{"x": 1, "y": "a"}]
        code, out, err = run(["last", "example"])
        assert (code, err) == (0, "")
        assert out == '[{"x":1,"y":"a"}]\n'
        assert last_call() == ("last", ("example",), {})

    def test_last_without_channel_lists_channels(self):
        run(["last"])
        assert last_call() == ("last", ("",), {})

    def test_basket_key_passes_through_as_field(self):
        run(["last", "basket/A"])
        assert last_call() == ("last", ("basket/A",), {})

    def test_next_and_timeout(self):
        run(["--timeout", "2.5", "next", "example"])
        assert last_call() == ("next", ("example",), {"timeout": 2.5})

    def test_lookup(self):
        run(["lookup", "example", "123"])
        assert last_call() == ("lookup", ("example", "123"), {})

    def test_openapi_and_routes(self):
        assert json.loads(run(["openapi"])[1]) == {"openapi": "3.1.0"}
        assert json.loads(run(["routes"])[1]) == {"last": ["example"]}

    def test_controls(self):
        run(["controls", "shutdown", "--data", '{"reason": "test"}'])
        assert last_call() == ("controls", ("shutdown",), {"data": {"reason": "test"}})
        run(["controls"])
        assert last_call() == ("controls", ("",), {"data": None})

    def test_send_inline_file_and_stdin(self, tmp_path, monkeypatch):
        run(["send", "example", '{"x": 1}'])
        assert last_call() == ("send", ("example", {"x": 1}), {})

        path = tmp_path / "data.json"
        path.write_text('[{"x": 2}]')
        run(["send", "example", f"@{path}"])
        assert last_call() == ("send", ("example", [{"x": 2}]), {})

        monkeypatch.setattr(sys, "stdin", io.StringIO('{"x": 3}'))
        run(["send", "example", "-"])
        assert last_call() == ("send", ("example", {"x": 3}), {})

    def test_send_invalid_json_is_a_usage_error(self):
        code, _, err = run(["send", "example", "{not json"])
        assert code == 2
        assert "invalid JSON" in err

    def test_json_argument_missing_file(self, tmp_path):
        with pytest.raises(Exception, match="cannot read"):
            json_argument(f"@{tmp_path / 'missing.json'}")

    def test_state_filters_and_query(self):
        run(["state", "example", "--filter", "x", ">=", "5", "--filter", "y", "==", "abc"])
        name, args, kwargs = last_call()
        assert (name, args) == ("state", ("example",))
        query = kwargs["query"]
        assert isinstance(query, Query)
        assert [(f.attr, f.by.where, f.by.value) for f in query.filters] == [("x", ">=", 5), ("y", "==", "abc")]

        base = {"filters": [{"attr": "z", "by": {"value": 1, "where": "<"}}]}
        run(["state", "example", "--query", json.dumps(base), "--filter", "x", "!=", '"5"'])
        query = last_call()[2]["query"]
        assert [(f.attr, f.by.where, f.by.value) for f in query.filters] == [("z", "<", 1), ("x", "!=", "5")]

        run(["state"])
        assert last_call() == ("state", ("",), {"query": None})

    def test_state_rejects_unknown_operator(self):
        code, _, err = run(["state", "example", "--filter", "x", "~", "5"])
        assert code == 1
        assert "invalid filter operator" in err

    @pytest.mark.parametrize(
        "argv, expected",
        [
            (["stage", "list", "ch"], ("stage_list", ("ch",), {"staging_id": None})),
            (["stage", "list", "ch", "--id", "a"], ("stage_list", ("ch",), {"staging_id": "a"})),
            (["stage", "lookup", "ch", "--id", "a"], ("stage_lookup", ("ch",), {"staging_id": "a"})),
            (["stage", "new", "ch"], ("stage_new", ("ch",), {})),
            (["stage", "add", "ch", '{"x": 1}'], ("stage_add", ("ch",), {"data": {"x": 1}, "staging_ids": None})),
            (["stage", "add", "ch", '{"x": 1}', "--id", "a", "--id", "b"], ("stage_add", ("ch",), {"data": {"x": 1}, "staging_ids": ["a", "b"]})),
            (["stage", "remove", "ch", '{"x": 1}', "--all"], ("stage_remove", ("ch",), {"data": {"x": 1}, "staging_ids": []})),
            (["stage", "clear", "ch", "--id", "a"], ("stage_clear", ("ch",), {"staging_ids": ["a"]})),
            (["stage", "release", "ch"], ("stage_release", ("ch",), {"staging_ids": None})),
            (["stage", "release", "ch", "--all"], ("stage_release", ("ch",), {"staging_ids": []})),
        ],
    )
    def test_stage(self, argv, expected):
        code, _, err = run(argv)
        assert (code, err) == (0, "")
        assert last_call() == expected

    @pytest.mark.parametrize(
        "argv, message",
        [
            (["stage", "release", "ch", '{"x": 1}'], "does not take data"),
            (["stage", "add", "ch", "--all", "--id", "a"], "mutually exclusive"),
            (["stage", "list", "ch", "--id", "a", "--id", "b"], "at most one --id"),
            (["stage", "new", "ch", "--id", "a"], "does not take --id"),
        ],
    )
    def test_stage_validation(self, argv, message):
        code, _, err = run(argv)
        assert code == 1
        assert message in err


class TestStream:
    @staticmethod
    def _cli(messages, closed):
        class StreamCLI(FakeCLI):
            @staticmethod
            def iter_stream(client, channels, idle_timeout=None):
                client.calls.append(("iter_stream", (channels,), {"idle_timeout": idle_timeout}))
                try:
                    yield from messages
                finally:
                    closed.append(True)

        return StreamCLI

    def test_stream_prints_ndjson_and_skips_heartbeats(self):
        closed = []
        messages = [
            {"channel": "heartbeat", "data": "PING"},
            {"channel": "example", "data": [{"x": 1}]},
            {"channel": "basket", "key": "A", "data": []},
        ]
        code, out, _ = run(["stream", "example", "basket/A", "--idle-timeout", "3"], self._cli(messages, closed))
        assert code == 0
        assert [json.loads(line) for line in out.splitlines()] == messages[1:]
        assert last_call() == ("iter_stream", ([("example"), ("basket", "A")],), {"idle_timeout": 3.0})
        assert closed == [True]

    def test_stream_heartbeats_and_limit_close_the_stream(self):
        closed = []
        messages = [{"channel": "heartbeat", "data": "PING"}, {"channel": "example", "data": 1}, {"channel": "example", "data": 2}]
        code, out, _ = run(["stream", "example", "--heartbeats", "-n", "2"], self._cli(messages, closed))
        assert code == 0
        assert [json.loads(line) for line in out.splitlines()] == messages[:2]
        assert closed == [True]

    def test_stream_zero_limit_does_not_connect(self):
        closed = []
        code, out, _ = run(["stream", "example", "-n", "0"], self._cli([{"channel": "example"}], closed))
        assert (code, out, closed) == (0, "", [])


class TestOptionsAndOutput:
    def test_connection_options_build_raw_config(self):
        run(["--host", "gw.example.org", "--port", "9000", "--api-version", "v2", "--api-key", "k", "last"])
        config = FakeClient.instances[-1].config
        assert isinstance(config, GatewayClientConfig)
        assert (config.host, config.port, config.api_version, config.api_key) == ("gw.example.org", 9000, "v2", "k")
        assert config.return_type == ReturnType.Raw

    def test_defaults_come_from_config(self):
        run(["last"])
        config = FakeClient.instances[-1].config
        assert (config.host, config.port, config.protocol) == ("localhost", 8000, "http")

    def test_environment_is_read_by_the_config(self, monkeypatch):
        monkeypatch.setenv("HOST", "env.example.org")
        monkeypatch.setenv("PORT", "9100")
        run(["last"])
        config = FakeClient.instances[-1].config
        assert (config.host, config.port, config.return_type) == ("env.example.org", 9100, ReturnType.Raw)

        run(["--port", "9200", "last"])
        assert FakeClient.instances[-1].config.port == 9200

    def test_help_lists_environment_variables(self, capsys):
        GatewayClientCLI().run(["--help"])
        out = " ".join(capsys.readouterr().out.split())
        assert "[env: PORT]" in out
        assert "[env: BEARER_TOKEN]" in out

    def test_global_options_accepted_after_command(self):
        FakeClient.responses["last"] = {"b": 1, "a": [1, 2]}
        code, out, _ = run(["--port", "9000", "last", "example", "--sort-keys", "--timeout", "1"])
        assert code == 0
        assert out == '{"a":[1,2],"b":1}\n'
        assert FakeClient.instances[-1].config.port == 9000
        assert last_call() == ("last", ("example",), {"timeout": 1.0})

    def test_pretty(self):
        FakeClient.responses["last"] = {"a": [1]}
        assert run(["--pretty", "last"])[1] == '{\n  "a": [\n    1\n  ]\n}\n'
        assert run(["last", "--pretty"])[1] == '{\n  "a": [\n    1\n  ]\n}\n'

    def test_non_json_types_are_serialized(self):
        FakeClient.responses["last"] = {
            "when": datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC),
            "delta": timedelta(seconds=90),
            "ids": {1},
            "query": Query(),
            "return_type": ReturnType.Raw,
        }
        out = json.loads(run(["last"])[1])
        assert out == {"when": "2024-01-02T03:04:05+00:00", "delta": 90.0, "ids": [1], "query": {"filters": []}, "return_type": "raw"}

    def test_server_errors_go_to_stderr(self):
        FakeClient.responses["last"] = ServerRouteNotFoundException("no such channel")
        code, out, err = run(["last", "nope"])
        assert (code, out) == (1, "")
        assert err == "csp-gateway-client: error: ServerRouteNotFoundException: no such channel\n"

    def test_connection_errors_go_to_stderr(self):
        FakeClient.responses["last"] = ConnectionRefusedError(61, "Connection refused")
        code, _, err = run(["last"])
        assert code == 1
        assert "Connection refused" in err

    def test_invalid_config_is_reported(self):
        code, _, err = run(["--api-key", "k", "--bearer-token", "t", "last"])
        assert code == 1
        assert "Cannot provide both" in err

    def test_keyboard_interrupt(self):
        FakeClient.responses["last"] = KeyboardInterrupt()
        assert run(["last"])[0] == 130

    def test_version(self, capsys):
        from csp_gateway import __version__

        assert GatewayClientCLI().run(["--version"]) == 0
        assert capsys.readouterr().out.strip() == f"csp-gateway-client {__version__}"


class TestExtension:
    def test_subclass_adds_overrides_and_removes_commands(self):
        class AppCLI(FakeCLI):
            prog = "my-app"
            openapi = None

            @command(aliases=["po"])
            @argument("account")
            @argument("--limit", type=int, default=10)
            def positions(self, client, args):
                """Positions for an account.

                Longer description.
                """
                return {"account": args.account, "limit": args.limit}

            @command(name="last", help="Last ids")
            @argument("channel")
            def last_ids(self, client, args):
                return [row["id"] for row in client.last(args.channel)]

        commands = AppCLI.commands()
        assert "openapi" not in commands
        assert commands["positions"][0].help == "Positions for an account."
        assert commands["positions"][0].description.endswith("Longer description.")
        assert "openapi" in GatewayClientCLI.commands()

        assert json.loads(run(["po", "acct", "--limit", "3"], AppCLI)[1]) == {"account": "acct", "limit": 3}

        FakeClient.responses["last"] = [{"id": "1"}, {"id": "2"}]
        assert json.loads(run(["last", "example"], AppCLI)[1]) == ["1", "2"]

        code, _, err = run(["openapi"], AppCLI)
        assert code == 2
        assert "invalid choice" in err

    def test_overriding_a_builtin_method_keeps_its_registration(self):
        class AppCLI(FakeCLI):
            @command(help="Custom routes")
            def routes(self, client, args):
                return "custom"

        assert AppCLI.commands()["routes"][1] == "routes"
        assert json.loads(run(["routes"], AppCLI)[1]) == "custom"

    def test_custom_config_and_global_arguments(self):
        class AppConfig(GatewayClientConfig):
            region: str = "us"

        class AppCLI(FakeCLI):
            config_class = AppConfig

            def add_global_arguments(self, parser):
                super().add_global_arguments(parser)
                parser.add_argument("--region", default=None)

            def config_kwargs(self, args):
                kwargs = super().config_kwargs(args)
                if getattr(args, "region", None):
                    kwargs["region"] = args.region
                return kwargs

            @command
            def region(self, client, args):
                return client.config.region

        code, out, _ = run(["--port", "9300", "region", "--region", "eu"], AppCLI)
        assert (code, json.loads(out)) == (0, "eu")
        assert isinstance(FakeClient.instances[-1].config, AppConfig)
        assert FakeClient.instances[-1].config.port == 9300

    def test_iterator_results_are_printed_as_lines(self):
        class AppCLI(FakeCLI):
            @command
            def count(self, client, args):
                yield from ({"n": n} for n in range(3))

        assert run(["count"], AppCLI)[1] == '{"n":0}\n{"n":1}\n{"n":2}\n'
        assert run(["count", "--pretty"], AppCLI)[1] == '{\n  "n": 0\n}\n{\n  "n": 1\n}\n{\n  "n": 2\n}\n'

    def test_none_result_prints_nothing(self):
        class AppCLI(FakeCLI):
            @command
            def quiet(self, client, args):
                return None

        assert run(["quiet"], AppCLI)[:2] == (0, "")


def test_main_entry_point(monkeypatch, capsys):
    monkeypatch.setattr(GatewayClientCLI, "client_class", FakeClient)
    FakeClient.responses["last"] = ["example"]
    assert main(["last"]) == 0
    assert capsys.readouterr().out == '["example"]\n'


def test_module_entry_point():
    result = subprocess.run([sys.executable, "-m", "csp_gateway.client", "--help"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "csp-gateway-client" in result.stdout


def test_connection_refused_against_real_client():
    code, _, err = run(["--port", "1", "--timeout", "1", "last"], GatewayClientCLI)
    assert code == 1
    assert "ConnectError" in err


class TestAgainstGateway:
    @pytest.fixture(scope="class")
    def rest_client(self, free_port):
        from fastapi.testclient import TestClient

        from csp_gateway import Gateway, GatewaySettings, MountControls, MountRestRoutes
        from csp_gateway.server.demo import ExampleGatewayChannels, ExampleModule

        gateway = Gateway(
            modules=[ExampleModule(), MountControls(), MountRestRoutes(force_mount_all=True)],
            channels=ExampleGatewayChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        gateway.start(rest=True, _in_test=True)
        yield TestClient(gateway.web_app.get_fastapi())
        gateway.stop()

    def test_commands(self, rest_client, monkeypatch, free_port):
        import time
        from importlib import import_module

        client_module = import_module("csp_gateway.client.client")
        monkeypatch.setattr(client_module, "GET", rest_client.get)
        monkeypatch.setattr(client_module, "POST", rest_client.post)
        cli = ["--port", str(free_port)]

        code, out, err = run([*cli, "routes"], GatewayClientCLI)
        assert (code, err) == (0, "")
        assert "example" in json.loads(out)["last"]

        for _ in range(50):
            code, out, _ = run([*cli, "last", "example"], GatewayClientCLI)
            if code == 0 and json.loads(out):
                break
            time.sleep(0.1)
        rows = json.loads(out)
        assert rows and {"id", "x", "y"} <= rows[0].keys()

        code, out, _ = run([*cli, "lookup", "example", rows[0]["id"]], GatewayClientCLI)
        assert code == 0
        assert json.loads(out)[0]["id"] == rows[0]["id"]

        code, out, _ = run([*cli, "send", "example", '{"x": 12345, "y": "sent"}'], GatewayClientCLI)
        assert code == 0
        assert json.loads(out)[0]["x"] == 12345

        code, out, _ = run([*cli, "state", "example", "--filter", "x", "==", "12345"], GatewayClientCLI)
        assert code == 0
        assert all(row["x"] == 12345 for row in json.loads(out))

        code, out, err = run([*cli, "last", "not_a_channel"], GatewayClientCLI)
        assert code == 1
        assert "ServerRouteNotMountedException" in err


class TestReviewRegressions:
    def test_validation_errors_do_not_echo_credentials(self):
        code, _, err = run(["--api-key", "ABC123", "--bearer-token", "XYZ789", "last"])
        assert code == 1
        assert "Cannot provide both" in err
        assert "ABC123" not in err and "XYZ789" not in err

    def test_error_messages_and_tracebacks_are_redacted(self, caplog):
        logger = logging.getLogger("csp_gateway")
        level = logger.level
        FakeClient.responses["last"] = ServerRouteNotFoundException("GET http://h/api/v1/last?token=SECRET1 failed for SECRET1")
        try:
            with caplog.at_level(logging.DEBUG, logger="csp_gateway"):
                code, _, err = run(["-vv", "--api-key", "SECRET1", "last"])
        finally:
            logger.setLevel(level)
        assert code == 1
        assert "token=***" in err
        assert "SECRET1" not in err
        assert "Traceback" in caplog.text
        assert "SECRET1" not in caplog.text

    def test_verbose_does_not_enable_http_library_logging(self):
        logger = logging.getLogger("csp_gateway")
        level = logger.level
        try:
            run(["-v", "last"])
            assert logger.level == logging.INFO
        finally:
            logger.setLevel(level)
        assert logging.getLogger("httpx2").getEffectiveLevel() >= logging.WARNING

    def test_aiohttp_errors_are_reported(self):
        from aiohttp import ClientError

        FakeClient.responses["last"] = ClientError("handshake failed")
        code, _, err = run(["last"])
        assert code == 1
        assert "ClientError: handshake failed" in err

    def test_stream_limit_closes_the_connection(self, monkeypatch):
        import asyncio
        import socket
        import threading

        from aiohttp import web

        closed = threading.Event()

        async def handler(request):
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            await ws.send_json({"channel": "example", "data": [1]})
            async for _ in ws:
                pass
            closed.set()
            return ws

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        loop = asyncio.new_event_loop()
        ready = threading.Event()

        def serve():
            asyncio.set_event_loop(loop)
            app = web.Application()
            app.router.add_get("/api/v1/stream", handler)
            runner = web.AppRunner(app)
            loop.run_until_complete(runner.setup())
            loop.run_until_complete(web.TCPSite(runner, "127.0.0.1", port).start())
            ready.set()
            loop.run_forever()
            loop.run_until_complete(runner.cleanup())

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        ready.wait(5)

        sessions = []
        original = GatewayClientConfig._streaming_session

        def capture(config):
            sessions.append(original(config))
            return sessions[-1]

        monkeypatch.setattr(GatewayClientConfig, "_streaming_session", capture)
        try:
            code, out, _ = run(["--host", "127.0.0.1", "--port", str(port), "stream", "example", "-n", "1"], GatewayClientCLI)
            assert code == 0
            assert json.loads(out) == {"channel": "example", "data": [1]}
            assert sessions[0].closed
            assert closed.wait(5)
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(5)
