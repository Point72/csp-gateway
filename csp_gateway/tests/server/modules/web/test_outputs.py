"""Tests for `MountOutputsFolder`'s listing and chunk endpoints (the spaday log viewer's backend)."""

import json
import os
from base64 import b64decode
from datetime import timedelta
from gzip import compress
from urllib.parse import urlsplit

import csp
import pytest
from csp import ts
from fastapi.testclient import TestClient

from csp_gateway import (
    Gateway,
    GatewayChannels,
    GatewayModule,
    GatewaySettings,
    GatewayStruct,
    MountChannelsGraph,
    MountOutputsFolder,
)


class Example(GatewayStruct):
    value: float


class ExampleChannels(GatewayChannels):
    example: ts[Example] = None


class ExampleModule(GatewayModule):
    @csp.node
    def _produce(self, trigger: ts[bool]) -> ts[Example]:
        if csp.ticked(trigger):
            return Example(value=1.0)

    def connect(self, channels: ExampleChannels) -> None:
        channels.set_channel("example", self._produce(csp.timer(interval=timedelta(seconds=0.1), value=True)))


@pytest.fixture(scope="class")
def outputs_dir(tmp_path_factory):
    """An outputs tree, plus a sibling directory sharing its name as a prefix."""
    root = tmp_path_factory.mktemp("logviewer")
    outputs = root / "outputs"
    (outputs / "run" / "nested").mkdir(parents=True)
    (outputs / "run" / "app.log").write_text("".join(f"line {i}\n" for i in range(1000)))
    (outputs / "run" / "nested" / "config.yaml").write_text("a: 1\n")
    # `<dir>-evil` shares `<dir>` as a string prefix; a startswith() containment check lets it through.
    sibling = root / "outputs-evil"
    sibling.mkdir()
    (sibling / "secret.txt").write_text("do not serve me")
    # A symlink *inside* the tree pointing out of it: abspath() keeps it under `dir`, realpath() does not.
    (outputs / "escape").symlink_to(sibling, target_is_directory=True)
    return outputs


@pytest.fixture(scope="class")
def client(outputs_dir, free_port):
    gateway = Gateway(
        modules=[ExampleModule(), MountOutputsFolder(dir=str(outputs_dir), chunk_bytes=256)],
        channels=ExampleChannels(),
        settings=GatewaySettings(PORT=free_port),
    )
    gateway.start(rest=True, _in_test=True)
    try:
        yield TestClient(gateway.web_app.get_fastapi())
    finally:
        gateway.stop()


class TestOutputsApi:
    @pytest.mark.parametrize(
        ("name", "content", "media_type", "kind", "text"),
        [
            ("app.log.gz", compress(b"log line\n"), "application/gzip", "download", ""),
            ("app.log.1", b"log line\n", "text/plain", "text", "log line\n"),
            ("stdout", b"log line\n", "text/plain", "text", "log line\n"),
            ("notes.md", b"# Notes\n", "text/plain", "text", "# Notes\n"),
            ("job.err", b"error\n", "text/plain", "text", "error\n"),
            ("capture", b"\x00\xff\x01", "application/octet-stream", "download", ""),
        ],
    )
    def test_file_types_without_libmagic(self, client, outputs_dir, monkeypatch, name, content, media_type, kind, text):
        from csp_gateway.server.modules.web import outputs as outputs_module

        monkeypatch.setattr(outputs_module, "Magic", None)
        if name == "notes.md":
            monkeypatch.setattr(outputs_module.mimetypes, "guess_type", lambda _: (None, None))
        path = outputs_dir / name
        path.write_bytes(content)
        try:
            body = client.get("/outputs/_chunk", params={"path": name}).json()
            assert body["media_type"] == media_type
            assert body["kind"] == kind
            assert body["text"] == text
            raw = client.get(f"/outputs/{name}")
            assert raw.headers["content-type"].split(";")[0] == media_type
            assert raw.content == content
        finally:
            path.unlink()

    def test_png_is_not_decoded_as_text(self, client, outputs_dir, monkeypatch):
        from csp_gateway.server.modules.web import outputs as outputs_module

        monkeypatch.setattr(outputs_module, "Magic", None)
        image = b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jWZkAAAAASUVORK5CYII=")
        path = outputs_dir / "plot with spaces.png"
        path.write_bytes(image)
        try:
            body = client.get("/outputs/_chunk", params={"path": path.name}).json()
            assert body["media_type"] == "image/png"
            assert body["kind"] == "image"
            assert body["text"] == ""
            assert body["url"] == "outputs/plot%20with%20spaces.png"
            raw = client.get("/outputs/plot%20with%20spaces.png")
            assert raw.headers["content-type"] == "image/png"
            assert raw.content == image
        finally:
            path.unlink()

    def test_lists_relative_paths(self, client):
        body = client.get("/outputs/_tree").json()
        assert body["paths"] == ["run/app.log", "run/nested/config.yaml"]
        assert body["truncated"] is False

    def test_caps_entries(self, client):
        body = client.get("/outputs/_tree?limit=1").json()
        assert body["paths"] == ["run/app.log"]
        assert body["truncated"] is True

    def test_tails_by_default(self, client, outputs_dir):
        size = (outputs_dir / "run" / "app.log").stat().st_size
        body = client.get("/outputs/_chunk?path=run/app.log").json()
        assert body["size"] == size
        assert body["end"] == size
        assert body["start"] == size - 256
        assert body["text"].endswith("line 999\n")
        assert len(body["text"].encode()) == 256

    def test_reads_an_explicit_range(self, client):
        body = client.get("/outputs/_chunk?path=run/app.log&start=0&end=7").json()
        assert body["text"] == "line 0\n"
        assert (body["start"], body["end"]) == (0, 7)

    def test_small_file_is_served_whole(self, client):
        body = client.get("/outputs/_chunk?path=run/nested/config.yaml").json()
        assert body["text"] == "a: 1\n"
        assert body["start"] == 0

    def test_rejects_escaping_paths(self, client):
        for path in ("../outputs-evil/secret.txt", "/etc/passwd", "run/../../outputs-evil/secret.txt"):
            assert client.get(f"/outputs/_chunk?path={path}").status_code == 404

    def test_rejects_symlinks_out_of_the_tree(self, client):
        assert client.get("/outputs/_chunk?path=escape/secret.txt").status_code == 404

    def test_legacy_browser_rejects_escaping_paths(self, client):
        for path in ("../outputs-evil/secret.txt", "escape/secret.txt"):
            assert client.get(f"/outputs/{path}").status_code == 404

    def test_missing_file(self, client):
        assert client.get("/outputs/_chunk?path=run/nope.log").status_code == 404

    def test_directory_is_not_a_chunk(self, client):
        assert client.get("/outputs/_chunk?path=run").status_code == 404

    def test_legacy_browser_still_serves(self, client):
        """The HTML listing the default UI provider links to is untouched."""
        assert client.get("/outputs").status_code == 200
        assert client.get("/outputs/run/app.log").status_code == 200


class TestSpadayViewer:
    """The spaday provider gets the in-page viewer instead of the link that navigated away."""

    @pytest.fixture(scope="class", params=["", "/gateway"])
    def client(self, outputs_dir, free_port, request):
        pytest.importorskip("spaday")
        gateway = Gateway(
            modules=[ExampleModule(), MountOutputsFolder(dir=str(outputs_dir), chunk_bytes=256), MountChannelsGraph()],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday", ROOT_PATH=request.param),
        )
        gateway.start(rest=True, ui=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_page_carries_the_tree_and_reader(self, client):
        tree = client.get("/tree.json").text
        assert "spaday-tree" in tree
        assert "/outputs/_tree" in tree
        assert "/outputs/_chunk" in tree

    def test_panel_shows_the_serving_pid(self, client):
        """The HTML log page has always shown it; the tab must not lose it."""
        assert f"pid[{os.getpid()}]" in client.get("/tree.json").text

    def test_logs_open_in_a_tab_not_a_link(self, client):
        tree = client.get("/tree.json").text
        # The drawer button opens the registered tab; nothing should link out to the HTML browser.
        assert '"logs"' in tree
        assert '"href": "/outputs"' not in tree

    @pytest.mark.parametrize("hold_bootstrap", [False, True])
    def test_shared_log_url_restores_the_file(self, client, outputs_dir, tmp_path, hold_bootstrap):
        playwright_api = pytest.importorskip("playwright.sync_api")
        with playwright_api.sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
            except playwright_api.Error as exc:
                if "Executable doesn't exist" in str(exc):
                    pytest.skip("Playwright Chromium is not installed")
                raise
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 720})
                page.set_default_timeout(5000)
                page.add_init_script("window.gatewayReady = false; document.addEventListener('spaday:ready', () => { window.gatewayReady = true; });")
                if hold_bootstrap:
                    page.add_init_script(
                        """
                        const originalFetch = window.fetch;
                        window.fetch = async (...args) => {
                            const response = await originalFetch(...args);
                            const url = args[0] instanceof Request ? args[0].url : args[0];
                            if (new URL(url, location.href).pathname.endsWith('/tree.json')) {
                                await new Promise(resolve => { window.releaseBootstrap = resolve; });
                            }
                            return response;
                        };
                        """
                    )

                def wait_for_bootstrap():
                    if hold_bootstrap:
                        page.wait_for_function("typeof window.releaseBootstrap === 'function'")
                        assert page.evaluate("window.gatewayReady") is False
                        assert page.locator("#gateway-log-panel pre").count() == 0
                        page.evaluate("window.releaseBootstrap()")
                    page.wait_for_function("window.gatewayReady", timeout=12000)

                held_reads = []
                held_field = None

                def serve(route):
                    url = urlsplit(route.request.url)
                    response = client.request(
                        route.request.method,
                        url.path + (f"?{url.query}" if url.query else ""),
                        content=route.request.post_data_buffer,
                        headers={"content-type": route.request.headers.get("content-type", ""), "accept-encoding": "identity"},
                    )
                    if held_field and route.request.post_data and held_field in json.loads(route.request.post_data):
                        held_reads.append((route, response))
                        return
                    route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)

                page.route("http://gateway.test/**", serve)
                base = f"http://gateway.test{client.app.root_path}"
                page.goto(f"{base}/?tab=logs&file=run/nested/config.yaml")
                wait_for_bootstrap()
                playwright_api.expect(page.locator("#gateway-log-panel pre")).to_have_text("a: 1\n")
                assert page.locator("#gateway-main-layout").evaluate("layout => layout.save().tabs[layout.save().selected]") == "logs"
                assert page.locator("#gateway-log-tree").evaluate("tree => tree.selected_paths") == ["run/nested/config.yaml"]
                page.locator("#gateway-log-tree").click(position={"x": 150, "y": 145})
                page.wait_for_function("new URL(location.href).searchParams.get('file') === 'run/app.log'")
                playwright_api.expect(page.locator("#gateway-log-panel pre")).to_contain_text("line 999")
                page.go_back()
                playwright_api.expect(page.locator("#gateway-log-panel pre")).to_have_text("a: 1\n")
                page.go_forward()
                playwright_api.expect(page.locator("#gateway-log-panel pre")).to_contain_text("line 999")
                page.reload()
                wait_for_bootstrap()
                playwright_api.expect(page.locator("#gateway-log-panel pre")).to_contain_text("line 999")
                for control, held_field in (("Older", "end"), ("Newer", "start")):
                    page.goto(f"{base}/?tab=logs&file=run/app.log")
                    wait_for_bootstrap()
                    playwright_api.expect(page.locator("#gateway-log-panel pre")).to_contain_text("line 999")
                    page.get_by_role("button", name=control, exact=True).click()
                    page.locator("#gateway-log-panel").evaluate(
                        "panel => panel.dispatchEvent(new CustomEvent('gateway-log-path', {detail: {path: 'run/nested/config.yaml'}, bubbles: true}))"
                    )
                    playwright_api.expect(page.locator("#gateway-log-panel pre")).to_have_text("a: 1\n")
                    assert len(held_reads) == 1
                    route, response = held_reads.pop()
                    with page.expect_response(lambda reply, request_field=held_field: request_field in json.loads(reply.request.post_data or "{}")):
                        route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)
                    page.evaluate("() => new Promise(requestAnimationFrame)")
                    playwright_api.expect(page.locator("#gateway-log-panel pre")).to_have_text("a: 1\n")
                    playwright_api.expect(page.locator("#gateway-log-panel strong")).to_have_text("run/nested/config.yaml")
                held_field = None
                page.goto(f"{base}/?tab=channels-graph")
                wait_for_bootstrap()
                page.wait_for_function(
                    "document.querySelector('#gateway-main-layout')?.save().tabs[document.querySelector('#gateway-main-layout').save().selected] === 'channels-graph'"
                )
                playwright_api.expect(page.locator("spaday-dagre")).to_be_visible()
                page.locator("#gateway-main-layout").evaluate("layout => layout.openPanel('workspace')")
                page.wait_for_function("!new URL(location.href).searchParams.has('tab')")
                page.go_back()
                page.wait_for_function(
                    "document.querySelector('#gateway-main-layout').save().tabs[document.querySelector('#gateway-main-layout').save().selected] === 'channels-graph'"
                )
                image_path = outputs_dir / "plot #?.png"
                image_path.write_bytes(b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jWZkAAAAASUVORK5CYII="))
                try:
                    page.goto(f"{base}/?tab=logs&file=plot%20%23%3F.png")
                    wait_for_bootstrap()
                    preview = page.locator("#gateway-log-panel img")
                    playwright_api.expect(preview).to_be_visible()
                    page.wait_for_function("document.querySelector('#gateway-log-panel img').naturalWidth === 1")
                    playwright_api.expect(page.locator("#gateway-log-panel pre")).not_to_be_visible()
                    assert preview.get_attribute("src") == f"{client.app.root_path}/outputs/plot%20%23%3F.png"
                    page.screenshot(path=str(tmp_path / "logs-image-desktop.png"))
                    page.set_viewport_size({"width": 390, "height": 844})
                    playwright_api.expect(preview).to_be_visible()
                    page.screenshot(path=str(tmp_path / "logs-image-mobile.png"))
                    page.locator("#gateway-log-panel").evaluate(
                        "panel => panel.dispatchEvent(new CustomEvent('gateway-log-path', {detail: {path: 'run/nested/config.yaml'}, bubbles: true}))"
                    )
                    playwright_api.expect(page.locator("#gateway-log-panel pre")).to_have_text("a: 1\n")
                    playwright_api.expect(preview).not_to_be_visible()
                finally:
                    image_path.unlink()
            finally:
                browser.close()


class TestChunkWindowing:
    """Walking backwards must stay bounded: the Older gesture sends only an `end`."""

    @pytest.fixture(scope="class")
    def client(self, outputs_dir, free_port):
        gateway = Gateway(
            modules=[ExampleModule(), MountOutputsFolder(dir=str(outputs_dir), chunk_bytes=256)],
            channels=ExampleChannels(),
            settings=GatewaySettings(PORT=free_port),
        )
        gateway.start(rest=True, _in_test=True)
        try:
            yield TestClient(gateway.web_app.get_fastapi())
        finally:
            gateway.stop()

    def test_end_only_reads_one_chunk_not_everything_before(self, client):
        body = client.get("/outputs/_chunk?path=run/app.log&end=5000").json()
        assert (body["start"], body["end"]) == (4744, 5000)
        assert len(body["text"].encode()) == 256

    def test_end_only_clamps_at_the_start_of_file(self, client):
        body = client.get("/outputs/_chunk?path=run/app.log&end=100").json()
        assert body["start"] == 0
        assert len(body["text"].encode()) == 100

    def test_posting_the_trees_selection_shape_opens_the_tail(self, client, outputs_dir):
        size = (outputs_dir / "run" / "app.log").stat().st_size
        body = client.post("/outputs/_chunk", json={"paths": ["run/app.log"]}).json()
        assert body["path"] == "run/app.log"
        assert body["end"] == size

    def test_posting_an_empty_selection_is_not_an_error(self, client):
        body = client.post("/outputs/_chunk", json={"paths": []}).json()
        assert body["text"] == ""
        assert body["kind"] == ""
        assert body["media_type"] == ""
        assert body["url"] == ""

    def test_posting_a_directory_selection_is_not_an_error(self, client):
        """Expanding a directory in the tree emits a selection; it must not read as a failure."""
        body = client.post("/outputs/_chunk", json={"paths": ["run"]})
        assert body.status_code == 200
        assert body.json()["text"] == ""

    def test_posting_an_escaping_selection_is_still_rejected(self, client):
        assert client.post("/outputs/_chunk", json={"paths": ["../outputs-evil/secret.txt"]}).status_code == 404
