import React, {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";
import { getDefaultViewerConfig } from "./gateway";
import { fetchTables } from "./tables";
import {
  buildEmptyLayout,
  getServerLayouts,
  getCustomLayout,
  saveCustomLayout,
  getUrlLayout,
  setUrlLayout,
} from "./layout";
import { getCurrentTheme, getViewerTheme } from "./theme";

/**
 * Self-contained Perspective workspace component.
 *
 * Uses the raw <perspective-workspace> custom element directly
 * to control the exact order of load() → restore().
 *
 * Exposes imperative methods via ref:
 *   - getLayouts()       → current layouts map
 *   - getActiveLayout()  → name of active layout
 *   - setActiveLayout(n) → switch to a named layout
 *   - saveLayout()       → persist current workspace state as "Custom Layout"
 *   - exportLayout()     → returns current workspace state as JSON string
 */
export const Workspace = forwardRef(function Workspace(
  { processTables, onReady },
  ref,
) {
  const wsRef = useRef(null);
  const [layouts, setLayouts] = useState({});
  const [activeLayoutName, setActiveLayoutName] = useState(null);
  const [restoreCount, setRestoreCount] = useState(0);
  const initializedRef = useRef(false);

  // ── Imperative handle for Header and other consumers ──────────────
  useImperativeHandle(
    ref,
    () => ({
      getLayouts: () => layouts,
      getActiveLayout: () => activeLayoutName,
      setActiveLayout: (name) => {
        if (layouts[name]) {
          setActiveLayoutName(name);
          setRestoreCount((c) => c + 1);
        }
      },
      saveLayout: async () => {
        const ws = wsRef.current;
        if (!ws) return;
        const config = await ws.save();
        saveCustomLayout(config);
        setLayouts((prev) => ({ ...prev, "Custom Layout": config }));
        setActiveLayoutName("Custom Layout");
      },
      exportLayout: async () => {
        const ws = wsRef.current;
        if (!ws) return null;
        const config = await ws.save();
        return JSON.stringify(config).replace(
          /PERSPECTIVE_GENERATED_/g,
          "CSP_GATEWAY_GENERATED_",
        );
      },
    }),
    [layouts, activeLayoutName],
  );

  // ── Bootstrap: fetch tables → load client → restore layout ────────
  // The critical ordering is: load(client) MUST complete before restore(layout).
  // PerspectiveWorkspace's React wrapper runs restore before load (both effects
  // fire on the same render, restore is first), which crashes. Using the raw
  // element lets us control the sequence explicitly.
  useEffect(() => {
    const ws = wsRef.current;
    if (!ws) return;

    let cancelled = false;

    (async () => {
      // 1. Fetch tables from perspective server
      const { worker, websocket, tables } = await fetchTables();
      if (cancelled) return;

      // 2. Build default layout from tables
      const defaultLayout = buildEmptyLayout();
      const theme = getCurrentTheme();

      if (processTables) {
        processTables(defaultLayout, tables, theme);
      } else {
        const sortedNames = Object.keys(tables).sort();
        sortedNames.forEach((tableName, index) => {
          const { schema } = tables[tableName];
          const generated_id = `${tableName.toUpperCase()}_GENERATED_${index + 1}`;
          defaultLayout.detail.main.widgets.push(generated_id);
          defaultLayout.viewers[generated_id] = getDefaultViewerConfig(
            tableName,
            schema,
            theme,
          );
        });
      }

      // 3. Fetch server + custom layouts and merge
      let serverLayouts = {};
      try {
        serverLayouts = await getServerLayouts();
      } catch (e) {
        console.warn("Failed to fetch server layouts:", e);
      }
      const customLayout = getCustomLayout();
      const allLayouts = {
        Default: defaultLayout,
        ...serverLayouts,
        ...customLayout,
      };
      if (cancelled) return;

      // 4. CRITICAL: load client FIRST, then restore layout
      //    Load local worker first (has client-server tables as local copies).
      //    Load websocket second (for server-only tables).
      //    The workspace iterates clients in order, so client-server tables
      //    will match on the local worker, giving each viewer an independent
      //    local table (no shared views / no scroll sync between viewers).
      await ws.load(worker);
      if (websocket !== worker) {
        await ws.load(websocket);
      }
      // 5. Restore: prefer URL layout (shared link), otherwise use Default
      const urlLayout = await getUrlLayout();
      if (urlLayout) {
        await ws.restore(applyThemeToLayout(urlLayout));
      } else {
        await ws.restore(applyThemeToLayout(allLayouts["Default"]));
      }

      // 6. Update React state (for header dropdown, etc.)
      setLayouts(allLayouts);
      setActiveLayoutName(urlLayout ? null : "Default");
      initializedRef.current = true;

      // 7. Sync layout to URL on every workspace change
      ws.addEventListener("workspace-layout-update", async () => {
        if (!initializedRef.current) return;
        const config = await ws.save();
        setUrlLayout(config);
      });

      onReady?.();
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  // ── Handle layout switching (user picks from dropdown) ────────────
  useEffect(() => {
    if (!initializedRef.current) return;
    if (!activeLayoutName || !layouts[activeLayoutName]) return;
    const ws = wsRef.current;
    if (!ws) return;

    ws.restore(applyThemeToLayout(layouts[activeLayoutName]));
  }, [activeLayoutName, restoreCount]);

  // ── Apply theme to newly added viewers (right-click → add table) ──
  // Only fires AFTER initial restore is complete (guarded by initializedRef)
  // so it doesn't race with the bootstrap sequence.
  useEffect(() => {
    const ws = wsRef.current;
    if (!ws) return;

    const onNewView = ({ detail: { widget } }) => {
      if (!initializedRef.current) return;
      if (widget?.viewer) {
        const theme = getCurrentTheme();
        widget.viewer.setAttribute("theme", getViewerTheme(theme));
        // Enable region selection on newly created viewers
        widget.viewer.restore({
          plugin_config: { edit_mode: "SELECT_REGION" },
        });
      }
    };

    ws.addEventListener("workspace-new-view", onNewView);
    return () => ws.removeEventListener("workspace-new-view", onNewView);
  }, []);

  return <perspective-workspace id="workspace" ref={wsRef} />;
});

/** Clone a layout config and fill in missing viewer themes */
function applyThemeToLayout(layout) {
  const theme = getCurrentTheme();
  const cloned = structuredClone(layout);
  if (cloned?.viewers) {
    Object.keys(cloned.viewers).forEach((id) => {
      if (!cloned.viewers[id].theme) {
        cloned.viewers[id].theme = getViewerTheme(theme);
      }
    });
  }
  return cloned;
}

export default Workspace;
