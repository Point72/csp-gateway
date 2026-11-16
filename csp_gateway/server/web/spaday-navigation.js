import { registerHandler } from "./js/cdn/index.js";

const layouts = new WeakMap();
const readers = new WeakSet();

function emit(element, name, detail) {
  element.dispatchEvent(new CustomEvent(name, { detail, bubbles: true }));
}

function firstSelected(panel) {
  if (panel.tabs) return panel.tabs[panel.selected ?? 0];
  for (const child of panel.children ?? []) {
    const selected = firstSelected(child);
    if (selected) return selected;
  }
}

function selectedTab(layout) {
  const saved = layout.save();
  const active = layouts.get(layout)?.active;
  const panel = active ? layout.getPanel(active, saved) : null;
  return firstSelected(panel ?? saved) ?? "workspace";
}

registerHandler("gateway-open-tab", async (_event, button) => {
  const layout = button.getRootNode().querySelector("#gateway-main-layout");
  if (!layout) return;
  const state = layouts.get(layout);
  if (state) await state.open(button.dataset.tab, true);
  else await layout.openPanel(button.dataset.tab);
});

registerHandler("gateway-tab-repeat", (_event, button) => {
  const layout = button.getRootNode().querySelector("#gateway-main-layout");
  if (layout && selectedTab(layout) === button.dataset.tab) {
    emit(layout, "gateway-tab-open", { tab: button.dataset.tab });
  }
});

registerHandler("gateway-tabs", (event, layout) => {
  if (event.target !== layout) return;
  let state = layouts.get(layout);
  if (!state) {
    state = { routing: false, active: null, queue: Promise.resolve() };
    layouts.set(layout, state);
    const activate = (tab) => {
      if (state.active === tab) return;
      state.active = tab;
      emit(layout, "gateway-tab-open", { tab });
    };
    const nativeOpen = layout.openPanel.bind(layout);
    state.open = (tab, repeat = false) => {
      if (!tab) return Promise.resolve();
      const opening = state.queue.then(async () => {
        state.routing = true;
        try {
          if (
            selectedTab(layout) !== tab ||
            layout.calculatePath(tab) === null
          ) {
            const placement = JSON.parse(layout.dataset.tabPlacements || "{}")[
              tab
            ];
            if (placement) await layout.ensurePanel(tab, placement);
            else await nativeOpen(tab);
          }
          const value = tab === "workspace" ? "" : tab;
          if ((layout.dataset.activeTab || "") !== value)
            emit(layout, "gateway-tab-change", { tab: value });
          if (repeat && state.active === tab)
            emit(layout, "gateway-tab-open", { tab });
          else activate(tab);
        } finally {
          state.routing = false;
        }
      });
      state.queue = opening.catch(() => {});
      return opening;
    };
    layout.openPanel = (tab) => state.open(tab);
    const navigate = () => {
      const requested = layout.dataset.activeTab || "workspace";
      const names = [...layout.children].map((frame) =>
        frame.getAttribute("name"),
      );
      state
        .open(names.includes(requested) ? requested : "workspace")
        .catch((error) =>
          console.error("Gateway tab navigation failed", error),
        );
    };
    state.activate = activate;
    new MutationObserver(navigate).observe(layout, {
      attributes: true,
      attributeFilter: ["data-active-tab"],
    });
    navigate();
    return;
  }
  if (state.routing || layout.restoring) return;
  const tab =
    event.type === "regular-layout-select"
      ? event.detail.name
      : selectedTab(layout);
  const value = tab === "workspace" ? "" : tab;
  if ((layout.dataset.activeTab || "") !== value)
    emit(layout, "gateway-tab-change", { tab: value });
  state.activate(tab);
});

registerHandler("gateway-logs", (_event, layout) => {
  const panel = layout.querySelector("#gateway-log-panel");
  if (!panel || readers.has(panel)) return;
  readers.add(panel);
  let previous;
  const read = () => {
    const path = panel.dataset.logPath || "";
    if (path === previous) return;
    previous = path;
    emit(panel, "gateway-log-open", { path });
  };
  new MutationObserver(read).observe(panel, {
    attributes: true,
    attributeFilter: ["data-log-path"],
  });
  read();
});

registerHandler("gateway-log-selection", (event, tree) => {
  const path = event.detail?.paths?.[0] || "";
  if (path && !tree.paths.includes(path)) return;
  emit(tree.closest("#gateway-log-panel"), "gateway-log-path", { path });
});

registerHandler("gateway-copy-link", async () => {
  const toasts = document.getElementById("gateway-toasts");
  try {
    await navigator.clipboard.writeText(window.location.href);
    toasts?.notify({ message: "Layout link copied", tone: "success" });
  } catch {
    toasts?.notify({
      message: "Layout link is in the address bar",
      tone: "info",
    });
  }
});

const findDialogs = new WeakMap();

function findColumn(dialog) {
  const state = findDialogs.get(dialog);
  const column = dialog.querySelector("#gateway-find-column").value;
  const type = state?.schema[column];
  const input = dialog.querySelector("#gateway-find-value");
  const boolean = dialog.querySelector("#gateway-find-boolean");
  input.disabled = input.hidden = type === "boolean";
  boolean.disabled = boolean.hidden = type !== "boolean";
  input.type = { integer: "number", float: "number", date: "date", datetime: "datetime-local" }[type] || "text";
  input.step = type === "integer" ? "1" : "any";
  input.value = "";
  boolean.value = "true";
  dialog.querySelector("#gateway-find-error").textContent = "";
}

registerHandler("gateway-find-column", (_event, select) => findColumn(select.closest("dialog")));

registerHandler("gateway-find-open", async (event) => {
  if (
    event.type === "keydown" &&
    (!(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey || event.key.toLowerCase() !== "f")
  ) return;
  event.preventDefault();
  const workspace = document.getElementById("gateway-workspace");
  const dialog = document.getElementById("gateway-find-dialog");
  if (!workspace?.viewer || !dialog || dialog.open || findDialogs.get(dialog)?.opening) return;
  const state = { workspace, opening: true };
  findDialogs.set(dialog, state);
  try {
    const saved = await workspace.saveWorkspace();
    state.panel = workspace.viewer.getActivePanel() ?? saved.active ?? firstSelected(saved.layout);
    const panel = saved.panels?.[state.panel];
    if (!panel) throw new Error("Select a table before using Find.");
    const table = await workspace.viewer.getTable({ panel: state.panel, wait: false });
    state.schema = await table.schema();
    state.table = panel.table;
    dialog.querySelector("#gateway-find-title").textContent = `Find in ${panel.title || panel.table}`;
    const columns = dialog.querySelector("#gateway-find-column");
    columns.replaceChildren(...Object.keys(state.schema).map((column) => new Option(column, column)));
    findColumn(dialog);
    dialog.showModal();
    columns.focus();
  } catch (error) {
    document.getElementById("gateway-toasts")?.notify({ message: String(error), tone: "danger" });
  } finally {
    state.opening = false;
  }
});

registerHandler("gateway-find-apply", async (event, form) => {
  event.preventDefault();
  const dialog = form.closest("dialog");
  const state = findDialogs.get(dialog);
  if (!state || state.applying || !form.reportValidity()) return;
  state.applying = true;
  try {
    const column = form.querySelector("#gateway-find-column").value;
    const type = state.schema[column];
    const input = form.querySelector("#gateway-find-value");
    let value = input.value;
    if (type === "integer" || type === "float") value = input.valueAsNumber;
    else if (type === "boolean") value = form.querySelector("#gateway-find-boolean").value === "true";
    else if (type === "date" || type === "datetime") value = new Date(`${input.value}${type === "date" ? "T00:00:00" : ""}`).getTime();
    const saved = await state.workspace.saveWorkspace();
    const panel = saved.panels?.[state.panel];
    if (!panel) throw new Error("This viewer was closed. Reopen Find to select another viewer.");
    if (panel.table !== state.table) throw new Error("This viewer changed tables. Reopen Find to search it.");
    await state.workspace.restorePanel(state.panel, {
      filter: [...(panel.filter || []).filter((clause) => clause[0] !== column), [column, "==", value]],
    });
    dialog.close();
  } catch (error) {
    form.querySelector("#gateway-find-error").textContent = String(error);
  } finally {
    state.applying = false;
  }
});
