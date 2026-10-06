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
