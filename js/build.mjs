import { NodeModulesExternal } from "@finos/perspective-esbuild-plugin/external.js";
import { build } from "@finos/perspective-esbuild-plugin/build.js";
import { BuildCss } from "@prospective.co/procss/target/cjs/procss.js";
import cpy from "cpy";
import fs from "fs";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);

// Force all react imports to resolve to the same copy to avoid
// duplicate-React errors when dependencies (e.g. @perspective-dev/react)
// list a different React version.
const REACT_ALIAS = {
  react: path.dirname(require.resolve("react/package.json")),
  "react-dom": path.dirname(require.resolve("react-dom/package.json")),
  "react/jsx-runtime": require.resolve("react/jsx-runtime"),
};

const BUILD = [
  {
    define: {
      global: "window",
    },
    entryPoints: ["src/index.jsx"],
    plugins: [NodeModulesExternal()],
    format: "esm",
    loader: {
      ".css": "text",
      ".html": "text",
      ".jsx": "jsx",
      ".png": "file",
      ".ttf": "file",
      ".wasm": "file",
    },
    outfile: "./lib/index.js",
  },
  {
    define: {
      global: "window",
    },
    entryPoints: ["src/main.jsx"],
    bundle: true,
    plugins: [],
    format: "esm",
    alias: REACT_ALIAS,
    loader: {
      ".css": "text",
      ".html": "text",
      ".jsx": "jsx",
      ".png": "file",
      ".ttf": "file",
      ".wasm": "file",
    },
    outfile: "../csp_gateway/server/build/main.js",
    publicPath: "/static/",
  },
];

function add(builder, path, path2) {
  builder.add(path, fs.readFileSync(require.resolve(path2 || path)).toString());
}

async function compile_css() {
  const builder1 = new BuildCss("");
  add(builder1, "./src/style/index.css");
  add(builder1, "./src/style/base.css");
  add(builder1, "./src/style/nord.css");
  add(builder1, "./src/style/header_footer.css");
  add(builder1, "./src/style/perspective.css");
  add(builder1, "./src/style/settings.css");
  add(
    builder1,
    "perspective-viewer-pro.css",
    "@perspective-dev/viewer/dist/css/pro.css",
  );
  add(
    builder1,
    "perspective-viewer-pro-dark.css",
    "@perspective-dev/viewer/dist/css/pro-dark.css",
  );
  add(
    builder1,
    "perspective-viewer-monokai.css",
    "@perspective-dev/viewer/dist/css/monokai.css",
  );
  add(
    builder1,
    "perspective-viewer-vaporwave.css",
    "@perspective-dev/viewer/dist/css/vaporwave.css",
  );
  add(
    builder1,
    "perspective-viewer-dracula.css",
    "@perspective-dev/viewer/dist/css/dracula.css",
  );
  add(
    builder1,
    "perspective-viewer-gruvbox.css",
    "@perspective-dev/viewer/dist/css/gruvbox.css",
  );
  add(
    builder1,
    "perspective-viewer-gruvbox-dark.css",
    "@perspective-dev/viewer/dist/css/gruvbox-dark.css",
  );
  add(
    builder1,
    "perspective-viewer-solarized.css",
    "@perspective-dev/viewer/dist/css/solarized.css",
  );
  add(
    builder1,
    "perspective-viewer-solarized-dark.css",
    "@perspective-dev/viewer/dist/css/solarized-dark.css",
  );
  add(
    builder1,
    "react-modern-drawer.css",
    "react-modern-drawer/dist/index.css",
  );

  const css = builder1.compile().get("index.css");

  // write to extension
  fs.writeFileSync("./lib/index.css", css);
  fs.writeFileSync("../csp_gateway/server/build/index.css", css);
}

async function cp_to_paths(path) {
  await cpy(path, "../csp_gateway/server/build/", { flat: true });
}

async function build_all() {
  /* make directories */
  fs.mkdirSync("../csp_gateway/server/build/", { recursive: true });

  /* Compile and copy JS */
  await Promise.all(BUILD.map(build)).catch(() => process.exit(1));
  // await cp_to_paths("./src/style/*.css");
  await cp_to_paths("./src/html/*.html");
  await cp_to_paths(
    "node_modules/@perspective-dev/server/dist/wasm/perspective-server.wasm",
  );
  await cp_to_paths(
    "node_modules/@perspective-dev/viewer/dist/wasm/perspective-viewer.wasm",
  );

  /* Compile and copy css */
  await compile_css();
}

build_all();
