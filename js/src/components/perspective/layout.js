import { CUSTOM_LAYOUT_CONFIG_NAME } from "../../common";

/** Read custom layout from localStorage */
export const getCustomLayout = () => {
  const possibleLayout = window.localStorage.getItem(CUSTOM_LAYOUT_CONFIG_NAME);
  return possibleLayout ? { "Custom Layout": JSON.parse(possibleLayout) } : {};
};

/** Persist custom layout to localStorage */
export const saveCustomLayout = (layout) => {
  window.localStorage.setItem(
    CUSTOM_LAYOUT_CONFIG_NAME,
    JSON.stringify(layout),
  );
};

/** Fetch server-defined layouts from the gateway API */
export const getServerLayouts = async () => {
  const data = await fetch(
    `${window.location.protocol}//${window.location.host}/api/v1/perspective/layouts`,
  );
  if (data.status === 403) {
    window.location.replace(
      `${window.location.protocol}//${window.location.host}/login${window.location.search}`,
    );
  }
  const json = await data.json();
  Object.keys(json).forEach((key) => {
    json[key] = JSON.parse(json[key]);
  });
  return json;
};

/** URL query parameter name for shared layouts */
const LAYOUT_PARAM = "layout";

/** Compress a string with deflate-raw, return URL-safe base64 */
async function compress(str) {
  const stream = new Blob([str])
    .stream()
    .pipeThrough(new CompressionStream("deflate-raw"));
  const buf = await new Response(stream).arrayBuffer();
  // URL-safe base64: + → -, / → _, strip padding =
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Decompress a URL-safe base64 string from deflate-raw */
async function decompress(encoded) {
  // Restore standard base64
  const b64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const stream = new Blob([bytes])
    .stream()
    .pipeThrough(new DecompressionStream("deflate-raw"));
  return new Response(stream).text();
}

/** Read a layout from the URL query string (compressed + base64-encoded JSON) */
export const getUrlLayout = async () => {
  const params = new URLSearchParams(window.location.search);
  const encoded = params.get(LAYOUT_PARAM);
  if (!encoded) return null;
  try {
    return JSON.parse(await decompress(encoded));
  } catch (e) {
    console.warn("Failed to parse layout from URL:", e);
    return null;
  }
};

/** Write the current layout to the URL query string (compressed + base64-encoded JSON) */
export const setUrlLayout = async (layout) => {
  const params = new URLSearchParams(window.location.search);
  const encoded = await compress(JSON.stringify(layout));
  params.set(LAYOUT_PARAM, encoded);
  window.history.replaceState(
    null,
    "",
    `${window.location.pathname}?${params}`,
  );
};

/** Build an empty workspace layout shell that tables can be added into */
export const buildEmptyLayout = () => ({
  sizes: [1],
  detail: {
    main: {
      type: "tab-area",
      widgets: [],
      currentIndex: 0,
    },
  },
  master: {
    sizes: [],
    widgets: [],
  },
  mode: "globalFilters",
  viewers: {},
});
