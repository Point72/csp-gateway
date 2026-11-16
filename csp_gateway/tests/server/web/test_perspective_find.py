"""Exercise gateway-owned Find against the released Perspective browser component."""

import threading
from datetime import date, datetime, timedelta

import csp
import pytest
import uvicorn
from csp import ts

from csp_gateway import Gateway, GatewayChannels, GatewayModule, GatewaySettings, GatewayStruct, MountPerspectiveTables

pytest.importorskip("spaday")


class Trade(GatewayStruct):
    symbol: str
    quantity: int
    price: float
    active: bool
    trade_date: date
    trade_time: datetime


class Channels(GatewayChannels):
    trades: ts[list[Trade]] = None


class Feed(GatewayModule):
    def connect(self, channels):
        channels.set_channel(
            "trades",
            csp.const(
                [
                    Trade(
                        id=str(i),
                        symbol=symbol,
                        quantity=i,
                        price=i + 0.5,
                        active=bool(i),
                        trade_date=date(2026, 1, 2),
                        trade_time=datetime(2026, 1, 2, 12, 30),
                    )
                    for i, symbol in enumerate(["A", "B", "C"])
                ]
            ),
        )


@pytest.mark.parametrize("architecture", ["server", "client-server"])
def test_find_filters_active_viewer_and_preserves_other_filters(free_port, architecture):
    playwright = pytest.importorskip("playwright.sync_api")
    gateway = Gateway(
        channels=Channels(),
        modules=[
            Feed(),
            MountPerspectiveTables(
                default_architecture=architecture,
                indexes={"trades": "id"},
                tables={"recent": {"channel": "trades", "limit": 2, "architecture": architecture}},
                update_interval=timedelta(milliseconds=50),
            ),
        ],
        settings=GatewaySettings(PORT=free_port, UI_PROVIDER="spaday"),
    )
    gateway.start(rest=True, ui=True, _in_test=True)
    server = uvicorn.Server(uvicorn.Config(gateway.web_app.get_fastapi(), host="127.0.0.1", port=free_port, log_level="error"))
    gateway.web_app._uvicorn_server = server
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        with playwright.sync_playwright() as runtime:
            browser = runtime.chromium.launch()
            page = browser.new_page(timezone_id="UTC")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(f"http://127.0.0.1:{free_port}/")
            find = page.get_by_role("button", name="Find", exact=True)
            playwright.expect(find).to_be_enabled(timeout=30000)
            workspace = page.locator("#gateway-workspace")
            recent = workspace.evaluate("async host => Object.entries((await host.saveWorkspace()).panels).find(([,p]) => p.table === 'recent')[0]")
            read_recent = "async panel => (await document.querySelector('#gateway-workspace').viewer.getView({panel, mode:'live'})).to_json()"
            assert {row["symbol"] for row in page.evaluate(read_recent, recent)} == {"B", "C"}
            module = next(module for module in gateway.modules if isinstance(module, MountPerspectiveTables))
            module._table_insts["recent"].update('[{"symbol":"D"}]', format="json")
            page.wait_for_function(
                "async panel => { const rows = await (await document.querySelector('#gateway-workspace').viewer.getView({panel, mode:'live'})).to_json(); "
                "return rows.length === 2 && rows.some(row => row.symbol === 'D'); }",
                arg=recent,
            )
            workspace.evaluate("""async host => {
                const saved = await host.saveWorkspace();
                const config = Object.values(saved.panels).find(panel => panel.table === 'trades');
                await host.viewer.restoreWorkspace({
                    layout: {type:'split-layout', orientation:'horizontal', sizes:[0.5,0.5], children:[
                        {type:'tab-layout', tabs:['left']}, {type:'tab-layout', tabs:['right']} ]},
                    panels: {left: {...config, filter: [['symbol','==','A']]}, right: {...config, filter: [['quantity','>',0]]}}
                });
                await host.viewer.setActivePanel('right');
            }""")
            dialog = page.locator("#gateway-find-dialog")
            column = page.locator("#gateway-find-column")
            value = page.locator("#gateway-find-value")

            def filters():
                return workspace.evaluate("async host => (await host.saveWorkspace()).panels.right.filter")

            # The header button uses the active viewer even when another viewer shows the same table.
            find.click()
            playwright.expect(dialog).to_be_visible()
            column.select_option("symbol")
            value.fill("B")
            dialog.get_by_role("button", name="Cancel").click()
            assert filters() == [["quantity", ">", 0]]

            # A focused Perspective viewer intercepts Ctrl/Cmd+F; ordinary page focus does not.
            for shortcut in ("Control+f", "Meta+f"):
                workspace.locator("regular-table").last.locator("td").first.click()
                page.keyboard.press(shortcut)
                playwright.expect(dialog).to_be_visible()
                dialog.get_by_role("button", name="Cancel").click()
            find.focus()
            page.keyboard.press("Control+f")
            playwright.expect(dialog).to_be_hidden()

            for name, text, expected in [
                ("symbol", "B", "B"),
                ("quantity", "1", 1),
                ("price", "1.5", 1.5),
                ("active", "true", True),
                ("trade_date", "2026-01-02", 1767312000000),
                ("trade_time", "2026-01-02T12:30", 1767357000000),
            ]:
                find.click()
                column.select_option(name)
                if name == "active":
                    page.locator("#gateway-find-boolean").select_option(text)
                else:
                    value.fill(text)
                dialog.get_by_role("button", name="Apply filter").click()
                playwright.expect(dialog).to_be_hidden()
                assert [name, "==", expected] in filters()
            assert ["quantity", ">", 0] not in filters()
            saved = workspace.evaluate("host => host.saveWorkspace()")
            assert saved["panels"]["left"]["filter"] == [["symbol", "==", "A"]]
            rows = workspace.evaluate("async host => (await host.viewer.getView({panel:'right', mode:'live'})).to_json()")
            assert [row["symbol"] for row in rows] == ["B"]

            find.click()
            column.select_option("quantity")
            value.fill("1.5")
            dialog.get_by_role("button", name="Apply filter").click()
            playwright.expect(dialog).to_be_visible()
            assert ["quantity", "==", 1] in filters()
            value.fill("1")
            workspace.evaluate("host => host.viewer.removePanel('right')")
            dialog.get_by_role("button", name="Apply filter").click()
            playwright.expect(page.locator("#gateway-find-error")).to_contain_text("viewer was closed")
            assert not errors
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        gateway.stop()
