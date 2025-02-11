import { version } from "@finos/perspective/package.json";

export const getDefaultViewerConfig = (tableName, schema, theme = "light") => {
  const viewer_config = {
    title: tableName,
    table: tableName,
    sort: [["timestamp", "desc"]],
    theme: theme === "dark" ? "Pro Dark" : "Pro Light",
    version,
  };

  // setup groupbys and pivoting if available
  if (Object.keys(schema).includes("id")) {
    // include all columns except id
    viewer_config.columns = Object.keys(schema).filter((col) => col !== "id");
  }

  return viewer_config;
};
