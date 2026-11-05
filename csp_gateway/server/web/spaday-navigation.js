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

document.addEventListener("gateway-focus-table", async (event) => {
  const { table, filter } = event.detail || {};
  const panel = document.getElementById("gateway-workspace");
  if (!table || !panel) return;
  try {
    await panel.openChannel(table);
    if (!filter) return;
    const workspace = await panel.save();
    const masters = new Set(workspace.masters || []);
    const [id, config] =
      Object.entries(workspace.panels || {}).find(
        ([key, p]) => p.table === table && !masters.has(key),
      ) || [];
    if (!id) return;
    const columns = new Set(filter.map((clause) => clause[0]));
    const kept = (config.filter || []).filter((clause) => !columns.has(clause[0]));
    await panel.restorePanel(id, { filter: [...kept, ...filter] });
  } catch (error) {
    console.error("Gateway table focus failed", error);
  }
});
