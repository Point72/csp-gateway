import { version } from "@perspective-dev/client/package.json";

export const getDefaultViewerConfig = (tableName, schema, theme = "light") => {
  const viewer_config = {
    title: tableName,
    table: tableName,
    sort: Object.keys(schema).includes("timestamp")
      ? [["timestamp", "desc"]]
      : [],
    theme: theme === "dark" ? "Pro Dark" : "Pro Light",
    plugin_config: { edit_mode: "SELECT_REGION" },
    version,
  };

  // setup groupbys and pivoting if available
  if (Object.keys(schema).includes("id")) {
    // include all columns except id
    viewer_config.columns = Object.keys(schema).filter((col) => col !== "id");
  }

  return viewer_config;
};
