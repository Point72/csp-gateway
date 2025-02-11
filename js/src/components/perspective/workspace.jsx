import React, { useEffect, useRef, useState } from "react";
import { getDefaultViewerConfig } from "./gateway";
import { fetchTables } from "./tables";
import { getDefaultWorkspaceLayout } from "./layout";
import { getCurrentTheme } from "./theme";
import { hideLoader } from "../../common";

export function Workspace(props) {
  // standard attributes
  const { layouts } = props;

  // standard modifiers
  const { changeLayouts } = props;

  // any overrides to process tables with custom logic
  const { processTables } = props;

  const workspace = useRef(null);
  let prevLayouts = useRef({ ...layouts, active: "Default" });
  let layoutUpdate = useRef(false);

  // restore layout when it changes
  useEffect(() => {
    (async () => {
      if (
        workspace.current &&
        layouts &&
        Object.keys(layouts[layouts.active] || {}).length > 0
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
  }, [layouts]);

  // setup tables
  useEffect(() => {
    if (workspace.current) {
      fetchTables().then((tables) => {
        // load tables into perspective workspace
        const to_restore = getDefaultWorkspaceLayout();

        // handle theme
        const theme = getCurrentTheme();

        // handle tables
        if (processTables) {
          processTables(to_restore, tables, workspace.current, theme);
        } else {
          const sortedTables = Object.keys(tables);
          sortedTables.sort();
          sortedTables.forEach((tableName, index) => {
            const { table, schema } = tables[tableName];
            workspace.current.addTable(tableName, table);
            const generated_id = `${tableName.toUpperCase()}_GENERATED_${index + 1}`;
            to_restore.detail.main.widgets.push(generated_id);
            to_restore.viewers[generated_id] = getDefaultViewerConfig(
              tableName,
              schema,
              theme,
            );
          });
        }

        // hide the progress bar
        hideLoader();

        // restore
        workspace.current.restore(to_restore).then(() => {
          // setup new default layout
          prevLayouts = { ...layouts, Default: to_restore, active: "Default" };
          changeLayouts(prevLayouts);

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
                  // console.log("calling restore dark from workspace-new-view");
                  await widget.restore({
                    theme: "Pro Dark",
                    sort: [["timestamp", "desc"]],
                  });
                } else {
                  // console.log("calling restore light from workspace-new-view");
                  await widget.restore({
                    theme: "Pro Light",
                    sort: [["timestamp", "desc"]],
                  });
                }
              }
            },
          );
        });
      });
    }
  }, []);

  return <perspective-workspace id="workspace" ref={workspace} />;
}

export default Workspace;
