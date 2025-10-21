// eslint-disable-next-line import/no-mutable-exports, prefer-const
export let CUSTOM_LAYOUT_CONFIG_NAME = "csp_gateway_demo_config";

export const changeLayoutConfigName = (newName) => {
  CUSTOM_LAYOUT_CONFIG_NAME = newName;
};

export const hideLoader = () => {
  setTimeout(() => {
    const progress = document.getElementById("progress");
    progress.setAttribute("style", "display:none;");
  }, 3000);
};

export const getOpenApi = async () => {
  const openapi = await fetch(
    `${window.location.protocol}//${window.location.host}/openapi.json`,
  );
  const json = await openapi.json();
  return json;
};

export const shutdownDefault = async () => {
  // TODO check if can shutdown by checking openapi
  await fetch(
    `${window.location.protocol}//${window.location.host}/api/v1/controls/shutdown`,
    { method: "POST" },
  );
};

export const processTables = (to_restore, tables, workspace, theme) => {
  // handle tables
  // sort, but then put them into "best" order
  const sortedTables = Object.keys(tables);
  sortedTables.sort();

  const allTables = [];

  sortedTables.forEach((name) => {
    if (allTables.indexOf(name) < 0) {
      allTables.push(name);
    }
  });

  allTables.forEach((tableName, index) => {
    const { table } = tables[tableName];
    const { schema } = tables[tableName];

    workspace.addTable(tableName, table);

    const generated_id = `${tableName.toUpperCase()}_GENERATED_${index + 1}`;

    to_restore.detail.main.widgets.push(generated_id);

    const viewer_config = {
      title: tableName,
      table: tableName,
      sort: [["timestamp", "desc"]],
      theme: theme === "dark" ? "Pro Dark" : "Pro Light",
    };
    // include all columns except id by default
    viewer_config.columns = Object.keys(schema).filter((col) => col !== "id");

    if (tableName === "my_bad_struct") {
      viewer_config.group_by = [
        "group_by_col_a",
        "group_by_col_b",
        "group_by_col_c",
      ];
      viewer_config.columns = Object.keys(schema).filter(
        (col) =>
          ![
            "id",
            "group_by_col_a",
            "group_by_col_b",
            "group_by_col_c",
          ].includes(col),
      );
    }
    // groupby last for all by default
    viewer_config.aggregates = Object.keys(schema).reduce((attrs, key) => {
      // eslint-disable-next-line no-param-reassign
      attrs[key] = "last";
      return attrs;
    }, {});

    to_restore.viewers[generated_id] = viewer_config;
  });
};
