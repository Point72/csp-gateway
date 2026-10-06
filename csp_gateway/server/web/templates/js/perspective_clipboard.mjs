function selectedGrid(event) {
  const path = event.composedPath();
  if (
    !path.some((node) => node.id === "gateway-workspace") ||
    path.some(
      (node) =>
        node.matches?.("input, textarea, select") || node.isContentEditable,
    )
  ) {
    return;
  }
  const grid = path.find((node) =>
    node.matches?.("perspective-viewer-datagrid"),
  );
  const viewer = path.find((node) => node.matches?.("perspective-viewer"));
  if (grid?.slot && viewer?.getSelection({ panel: grid.slot })) {
    return { viewer, grid, options: { method: "plugin", panel: grid.slot } };
  }
}

function copyText(doc, text) {
  let handled = false;
  const onCopy = (event) => {
    if (!event.clipboardData) return;
    event.clipboardData.setData("text/plain", text);
    event.preventDefault();
    event.stopImmediatePropagation();
    handled = true;
  };
  doc.addEventListener("copy", onCopy, true);
  try {
    // Unlike the async Clipboard API, this legacy command can work over HTTP.
    return doc.execCommand("copy") && handled;
  } catch {
    return false;
  } finally {
    doc.removeEventListener("copy", onCopy, true);
  }
}

export function installClipboardHandlers(doc, browser) {
  let generation = 0;
  const invalidate = () => {
    generation++;
  };
  doc.addEventListener("pointerdown", invalidate, true);
  doc.addEventListener("perspective-select", invalidate);
  doc.addEventListener(
    "keydown",
    async (event) => {
      if (event.key === "Escape") invalidate();
      if (
        !(event.ctrlKey || event.metaKey) ||
        event.altKey ||
        event.shiftKey ||
        event.key.toLowerCase() !== "c"
      ) {
        return;
      }
      const request = ++generation;
      if (event.defaultPrevented || browser.getSelection()?.toString()) return;
      const selected = selectedGrid(event);
      if (!selected) return;
      event.preventDefault();
      event.stopPropagation();
      const { viewer, grid, options } = selected;
      const current = () =>
        request === generation && grid.isConnected && doc.hasFocus();
      try {
        const text = Promise.resolve(viewer.export(options)).then(
          async (value) => (typeof value === "string" ? value : value.text()),
        );
        if (
          browser.isSecureContext &&
          browser.navigator.clipboard?.write &&
          browser.ClipboardItem
        ) {
          const blob = text.then((value) => {
            if (!current()) throw new Error("Copy cancelled");
            return new Blob([value], { type: "text/plain" });
          });
          // A denied write may reject before consuming the item's promise.
          blob.catch(() => {});
          try {
            // Start the write during the gesture, before the async export finishes.
            await browser.navigator.clipboard.write([
              new browser.ClipboardItem({
                "text/plain": blob,
              }),
            ]);
            return;
          } catch {
            // Permissions or browser policy may still allow ordinary text copying.
          }
        }
        const value = await text;
        if (!current()) return;
        if (
          browser.navigator.userActivation?.isActive === false ||
          !copyText(doc, value)
        ) {
          throw new Error(
            "Automatic copying is unavailable. Use Perspective's Export menu to download the data.",
          );
        }
      } catch (error) {
        if (!current()) return;
        doc.getElementById("gateway-toasts")?.notify({
          message: `Copy failed: ${error.message || error}`,
          tone: "danger",
        });
      }
    },
    true,
  );

  doc.addEventListener(
    "mousedown",
    (event) => {
      const path = event.composedPath();
      if (
        !browser.isSecureContext &&
        path.some((node) => node.matches?.("perspective-copy-menu")) &&
        path.some((node) => node.matches?.(".dropdown-menu-item"))
      ) {
        event.preventDefault();
        event.stopPropagation();
        doc.getElementById("gateway-toasts")?.notify({
          message:
            "Perspective's Copy menu requires HTTPS. On this HTTP page, select cells and press Ctrl+C or Cmd+C instead.",
          tone: "warning",
        });
        return;
      }
      if (
        event.button === 2 &&
        !event.shiftKey &&
        !event.defaultPrevented &&
        path.some((node) => node.matches?.("td, th")) &&
        selectedGrid(event)
      ) {
        // Perspective 5.5 clears region selection on right-button mousedown.
        // Keep the selection for its native context menu; leave contextmenu untouched.
        event.stopPropagation();
      }
    },
    true,
  );
}

if (typeof document !== "undefined") {
  installClipboardHandlers(document, window);
}
