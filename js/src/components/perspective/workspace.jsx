import React, { useEffect, useRef, useState } from "react";
import { getDefaultViewerConfig } from "./gateway";
import { fetchTables } from "./tables";
import { getDefaultWorkspaceLayout } from "./layout";
import { getCurrentTheme } from "./theme";

export function Workspace(props) {
  // standard attributes
  const { layouts } = props;

  // standard modifiers
  const { changeLayouts } = props;

  // any overrides to process tables with custom logic
  const { processTables, hideLoader } = props;

  const workspace = useRef(null);
  const [workspaceReady, setWorkspaceReady] = useState(false);
  let prevLayouts = useRef({ ...layouts });
  let layoutUpdate = useRef(false);

  // restore layout when it changes
  useEffect(() => {
    (async () => {
      if (
        workspace.current &&
        workspaceReady &&
        layouts &&
        layouts.active &&
        Object.keys(layouts[layouts.active] || {}).length > 0 &&
        layoutUpdate.current == false
      ) {
        if (
          prevLayouts.current.active !== layouts.active &&
          JSON.stringify(prevLayouts.current[prevLayouts.current.active]) !==
            JSON.stringify(layouts[layouts.active])
        ) {
          layoutUpdate.current = true;

          // handle theme if not set
          const theme = getCurrentTheme();

          const layout = structuredClone(layouts[layouts.active]);
          if (layout !== undefined && Object.keys(layout.viewers).length > 0) {
            Object.keys(layout.viewers).forEach((viewer_id) => {
              const viewer = layout.viewers[viewer_id];
              if (!viewer.theme) {
                viewer.theme = theme === "dark" ? "Pro Dark" : "Pro Light";
              }
            });
            await workspace.current.restore(layout);
          }

          // update previous ref
          prevLayouts.current = { ...layouts, active: layouts.active };
          layoutUpdate.current = false;
        }
      }
    })();
  }, [layouts, workspaceReady]);

  // setup tables
  useEffect(() => {
    if (workspace.current) {
      // load tables into perspective workspace
      const defaultLayout = getDefaultWorkspaceLayout();

      fetchTables().then(({ worker, tables }) => {
        workspace.current.load(worker).then(() => {
          // handle theme
          const theme = getCurrentTheme();

          // handle tables
          if (processTables) {
            processTables(defaultLayout, tables, workspace.current, theme);
          } else {
            const sortedTables = Object.keys(tables);
            sortedTables.sort();
            sortedTables.forEach((tableName, index) => {
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
        });

        // hide the progress bar
        hideLoader();

        // restore
        workspace.current.restore({}).then(() => {
          setWorkspaceReady(true);
        });

        // setup new default layout
        // NOTE: order matters here, if server defines default we want that to clobber
        // our generated default
        if (layouts.Default === undefined) {
          changeLayouts({ Default: defaultLayout, ...layouts });
        }

        // handle light/dark theme
        workspace.current.addEventListener(
          "workspace-new-view",
          async (event) => {
            const { widget } = event.detail;
            event.preventDefault();
            event.stopPropagation();
            const theme = getCurrentTheme();
            if (!layoutUpdate.current) {
              if (theme === "dark") {
                await widget.restore({
                  theme: "Pro Dark",
                  sort: [["timestamp", "desc"]],
                });
              } else {
                await widget.restore({
                  theme: "Pro Light",
                  sort: [["timestamp", "desc"]],
                });
              }
            }
          },
        );
      });
    }
  }, []);

  return <perspective-workspace id="workspace" ref={workspace} />;
}

export default Workspace;
