import perspective from "@finos/perspective";
import perspective_viewer from "@finos/perspective-viewer";
import SERVER_WASM from "@finos/perspective/dist/wasm/perspective-server.wasm";
import CLIENT_WASM from "@finos/perspective-viewer/dist/wasm/perspective-viewer.wasm";

import "@finos/perspective-workspace";
import "@finos/perspective-viewer-datagrid";
import "@finos/perspective-viewer-d3fc";

const perspective_init_promise = Promise.all([
  perspective.init_server(fetch(SERVER_WASM)),
  perspective_viewer.init_client(fetch(CLIENT_WASM)),
]);

export const fetchTables = async () => {
  await perspective_init_promise;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const websocket = await perspective.websocket(
    `${protocol}//${window.location.host}/api/v1/perspective`,
  );

  const response = await fetch("/api/v1/perspective/tables");
  const schemas = await response.json();
  const table_names = [...Object.keys(schemas)];
  const tables = await Promise.all(
    table_names.map((table_name) => websocket.open_table(table_name)),
  );
  const new_tables = {};
  table_names.forEach((table_name, index) => {
    new_tables[table_name] = {
      table: tables[index],
      schema: schemas[table_name],
    };
  });
  return new_tables;
};
