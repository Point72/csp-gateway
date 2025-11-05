import perspective from "@perspective-dev/client";
import perspective_viewer from "@perspective-dev/viewer";
import SERVER_WASM from "@perspective-dev/server/dist/wasm/perspective-server.wasm";
import CLIENT_WASM from "@perspective-dev/viewer/dist/wasm/perspective-viewer.wasm";

import "@perspective-dev/workspace";
import "@perspective-dev/viewer-datagrid";
import "@perspective-dev/viewer-d3fc";
import "perspective-summary";

const perspective_init_promise = Promise.all([
  perspective.init_server(fetch(SERVER_WASM)),
  perspective_viewer.init_client(fetch(CLIENT_WASM)),
]);

export const fetchTables = async () => {
  await perspective_init_promise;
  const worker = await perspective.worker();
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const websocket = await perspective.websocket(
    `${protocol}//${window.location.host}/api/v1/perspective`,
  );

  const meta = await (await fetch("/api/v1/perspective/meta")).json();
  const schemas = meta.tables;

  const table_names = [...Object.keys(schemas)];
  const table_handles = await Promise.all(
    table_names.map((table_name) => websocket.open_table(table_name)),
  );

  const tables = await Promise.all(
    table_names.map(async (table_name, idx) => {
      const table_handle = table_handles[idx];
      const limit = meta.limits[table_name] || meta.default_limit || undefined;
      const index = meta.indexes[table_name] || meta.default_index || undefined;
      const architecture =
        meta.architectures[table_name] ||
        meta.default_architecture ||
        "client-server";

      if (architecture != "server") {
        const view = await table_handle.view();
        return worker.table(view, { index, limit });
      }
      return table_handle;
    }),
  );

  const new_tables = table_names.reduce((acc, table_name, index) => {
    acc[table_name] = {
      table: tables[index],
      schema: schemas[table_name],
    };
    return acc;
  }, {});
  return new_tables;
};
