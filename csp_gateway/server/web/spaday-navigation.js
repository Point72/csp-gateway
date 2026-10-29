import { registerHandler } from "./js/cdn/index.js";

const layouts = new WeakMap();
const readers = new WeakSet();

function emit(element, name, detail) {
  element.dispatchEvent(new CustomEvent(name, { detail, bubbles: true }));
}

function selectedTab(layout) {
  const saved = layout.save();
  return saved.tabs?.[saved.selected ?? 0] ?? "workspace";
}

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
    const navigate = () => {
      state.queue = state.queue
        .then(async () => {
          const requested = layout.dataset.activeTab || "workspace";
          const names = [...layout.children].map((frame) =>
            frame.getAttribute("name"),
          );
          const tab = names.includes(requested) ? requested : "workspace";
          state.routing = true;
          try {
            if (selectedTab(layout) !== tab) await layout.openPanel(tab);
            if (tab !== requested)
              emit(layout, "gateway-tab-change", { tab: "" });
            activate(tab);
          } finally {
            state.routing = false;
          }
        })
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
  const tab = selectedTab(layout);
  emit(layout, "gateway-tab-change", { tab: tab === "workspace" ? "" : tab });
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

// Show one table in the workspace without replacing the user's layout: spaday-perspective selects
// the panel already showing it or opens one beside the detail panels, then optionally filters that
// panel alone. Both steps run on the panel's own queue, which also waits for the workspace to load.
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
    const kept = (config.filter || []).filter(
      (clause) => !columns.has(clause[0]),
    );
    await panel.restorePanel(id, { filter: [...kept, ...filter] });
  } catch (error) {
    console.error("Gateway table focus failed", error);
  }
});
