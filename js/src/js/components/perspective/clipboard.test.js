import assert from "node:assert/strict";
import test from "node:test";

import { installClipboardHandlers } from "../../../../../csp_gateway/server/web/templates/js/perspective_clipboard.mjs";

function fixture() {
  const listeners = {};
  const notices = [];
  const writes = [];
  const exports = [];
  const node = (selector, props = {}) => ({
    isConnected: true,
    matches: (value) => value.split(", ").includes(selector),
    ...props,
  });
  const viewer = node("perspective-viewer", {
    getSelection: ({ panel }) =>
      panel === "focused" ? { start_row: 0, end_row: 1 } : null,
    export: async (options) => {
      exports.push(options);
      return "9000000000000000001\t0.00\t";
    },
  });
  const path = [
    node("td"),
    node("perspective-viewer-datagrid", { slot: "focused" }),
    viewer,
    { id: "gateway-workspace" },
  ];
  const doc = {
    hasFocus: () => true,
    addEventListener: (type, handler, capture) => {
      listeners[type] = { handler, capture };
    },
    removeEventListener: (type, handler) => {
      if (listeners[type]?.handler === handler) delete listeners[type];
    },
    execCommand: (command) => {
      assert.equal(command, "copy");
      const event = {
        clipboardData: {
          setData: (type, value) => writes.push(new Blob([value], { type })),
        },
        preventDefault() {},
        stopImmediatePropagation() {},
      };
      listeners.copy?.handler(event);
      return true;
    },
    getElementById: () => ({ notify: (notice) => notices.push(notice) }),
  };
  const browser = {
    isSecureContext: true,
    getSelection: () => "",
    navigator: {
      clipboard: {
        write: async (items) => {
          writes.push(await items[0]["text/plain"]);
        },
      },
    },
    ClipboardItem: class {
      constructor(data) {
        Object.assign(this, data);
      }
    },
  };
  const event = {
    key: "c",
    ctrlKey: true,
    button: 2,
    composedPath: () => path,
    preventDefault() {
      this.defaultPrevented = true;
    },
    stopPropagation() {
      this.stopped = true;
    },
  };
  installClipboardHandlers(doc, browser);
  return {
    listeners,
    notices,
    writes,
    exports,
    viewer,
    path,
    browser,
    event,
    node,
    doc,
  };
}

test("Ctrl+C and Cmd+C export only the focused grid's selected text", async () => {
  for (const metaKey of [false, true]) {
    const f = fixture();
    Object.assign(f.event, { metaKey, ctrlKey: !metaKey });
    await f.listeners.keydown.handler(f.event);
    assert.equal(f.event.defaultPrevented, true);
    assert.deepEqual(f.exports, [{ method: "plugin", panel: "focused" }]);
    assert.equal(await f.writes[0].text(), "9000000000000000001\t0.00\t");
    assert.deepEqual(f.notices, []);
  }
});

test("ordinary text and unrelated keys or panels retain browser behavior", async () => {
  const cases = [
    (f) => {
      f.event.key = "v";
    },
    (f) => {
      f.event.ctrlKey = false;
    },
    (f) => {
      f.event.shiftKey = true;
    },
    (f) => {
      f.event.altKey = true;
    },
    (f) => {
      f.browser.getSelection = () => "selected text";
    },
    (f) => {
      f.path.unshift(f.node("input"));
    },
    (f) => {
      f.path.unshift(f.node("textarea"));
    },
    (f) => {
      f.path.unshift(f.node("div", { isContentEditable: true }));
    },
    (f) => {
      f.path.pop();
    },
    (f) => {
      f.path[1].slot = "another";
    },
    (f) => {
      f.path[1].slot = "";
    },
    (f) => {
      f.viewer.getSelection = () => null;
    },
    (f) => {
      f.path.splice(1, 1);
    },
  ];
  for (const change of cases) {
    const f = fixture();
    change(f);
    await f.listeners.keydown.handler(f.event);
    assert.equal(f.event.defaultPrevented, undefined);
    assert.deepEqual(f.writes, []);
  }
});

test("HTTP, unavailable APIs and denied secure writes use ordinary text copying", async () => {
  for (const kind of ["http", "unavailable", "permission"]) {
    const f = fixture();
    if (kind === "http") f.browser.isSecureContext = false;
    if (kind === "unavailable") delete f.browser.navigator.clipboard;
    if (kind === "permission")
      f.browser.navigator.clipboard.write = async () => {
        throw new Error("Permission denied");
      };
    await f.listeners.keydown.handler(f.event);
    assert.equal(await f.writes[0].text(), "9000000000000000001\t0.00\t");
    assert.deepEqual(f.notices, []);
    assert.equal(f.listeners.copy, undefined);
  }
});

test("blocked HTTP copying offers Export and removes its temporary listener", async () => {
  for (const failure of ["denied", "throws", "no-event"]) {
    const f = fixture();
    f.browser.isSecureContext = false;
    f.doc.execCommand = () => {
      if (failure === "throws") throw new Error("Blocked");
      return failure === "no-event";
    };
    await f.listeners.keydown.handler(f.event);
    assert.equal(f.notices.length, 1);
    assert.match(f.notices[0].message, /Copy failed:.*Export menu/);
    assert.equal(f.listeners.copy, undefined);
    assert.deepEqual(f.writes, []);
  }
});

test("expired user activation offers Export without claiming a copy", async () => {
  const f = fixture();
  f.browser.isSecureContext = false;
  f.browser.navigator.userActivation = { isActive: false };
  f.doc.execCommand = () => {
    assert.fail("Must not copy after activation expires");
  };
  await f.listeners.keydown.handler(f.event);
  assert.equal(f.notices.length, 1);
  assert.match(f.notices[0].message, /Copy failed:.*Export menu/);
  assert.deepEqual(f.writes, []);
});

test("export errors are reported without copying", async () => {
  for (const secure of [false, true]) {
    const f = fixture();
    f.browser.isSecureContext = secure;
    f.viewer.export = async () => {
      throw new Error("Export failed");
    };
    await f.listeners.keydown.handler(f.event);
    assert.equal(f.notices.length, 1);
    assert.match(f.notices[0].message, /Export failed/);
    assert.deepEqual(f.writes, []);
  }
});

test("superseded copies, changed selections and removed panels do not write stale data", async () => {
  for (const change of [
    "new-copy",
    "input-copy",
    "selection",
    "pointer",
    "removed",
    "escape",
    "blur",
  ]) {
    const f = fixture();
    f.browser.isSecureContext = false;
    let resolve;
    f.viewer.export = () =>
      new Promise((done) => {
        resolve = done;
      });
    const pending = f.listeners.keydown.handler(f.event);
    if (change === "new-copy") {
      f.viewer.export = async () => "new";
      f.event.defaultPrevented = false;
      await f.listeners.keydown.handler(f.event);
    } else if (change === "input-copy") {
      f.path.unshift(f.node("input"));
      f.event.defaultPrevented = false;
      await f.listeners.keydown.handler(f.event);
    } else if (change === "selection")
      f.listeners["perspective-select"].handler();
    else if (change === "pointer") f.listeners.pointerdown.handler();
    else if (change === "removed") f.path[1].isConnected = false;
    else if (change === "blur") f.doc.hasFocus = () => false;
    else await f.listeners.keydown.handler({ key: "Escape" });
    resolve("old");
    await pending;
    assert.deepEqual(
      await Promise.all(f.writes.map((value) => value.text())),
      change === "new-copy" ? ["new"] : [],
    );
    assert.deepEqual(f.notices, []);
  }
});

test("right-click preserves selected cells without intercepting the native menu", () => {
  const f = fixture();
  assert.equal(f.listeners.mousedown.capture, true);
  f.listeners.mousedown.handler(f.event);
  assert.equal(f.event.stopped, true);
  assert.equal(f.event.defaultPrevented, undefined);
  assert.equal(f.listeners.contextmenu, undefined);
});

test("HTTP native Copy options warn instead of calling the unavailable Clipboard API", () => {
  const f = fixture();
  f.browser.isSecureContext = false;
  f.event.button = 0;
  f.event.composedPath = () => [
    f.node("span"),
    f.node(".dropdown-menu-item"),
    f.node("perspective-copy-menu"),
  ];
  f.listeners.mousedown.handler(f.event);
  assert.equal(f.event.defaultPrevented, true);
  assert.equal(f.event.stopped, true);
  assert.equal(f.notices.length, 1);
  assert.match(f.notices[0].message, /Copy menu requires HTTPS/);
  assert.match(f.notices[0].message, /Ctrl\+C or Cmd\+C/);
  assert.deepEqual(f.exports, []);
  assert.deepEqual(f.writes, []);
});

test("secure Copy, Export options and Copy group labels are not intercepted", () => {
  for (const [secure, menu, item] of [
    [true, "perspective-copy-menu", ".dropdown-menu-item"],
    [false, "perspective-export-menu", ".dropdown-menu-item"],
    [false, "perspective-copy-menu", ".dropdown-group-label"],
    [false, "unrelated-menu", ".dropdown-menu-item"],
  ]) {
    const f = fixture();
    f.browser.isSecureContext = secure;
    f.event.button = 0;
    f.event.composedPath = () => [f.node(item), f.node(menu)];
    f.listeners.mousedown.handler(f.event);
    assert.equal(f.event.defaultPrevented, undefined);
    assert.equal(f.event.stopped, undefined);
    assert.deepEqual(f.notices, []);
  }
});

test("left-click, shift-right-click, controls and empty grids are unaffected", () => {
  for (const change of [
    (f) => {
      f.event.button = 0;
    },
    (f) => {
      f.event.shiftKey = true;
    },
    (f) => {
      f.event.defaultPrevented = true;
    },
    (f) => {
      f.path.shift();
    },
    (f) => {
      f.path.unshift(f.node("input"));
    },
    (f) => {
      f.viewer.getSelection = () => null;
    },
  ]) {
    const f = fixture();
    change(f);
    f.listeners.mousedown.handler(f.event);
    assert.equal(f.event.stopped, undefined);
  }
});
