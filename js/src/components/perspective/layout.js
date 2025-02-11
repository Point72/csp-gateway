import { CUSTOM_LAYOUT_CONFIG_NAME } from "../../common";

export const getCustomLayout = () => {
  const possibleLayout = window.localStorage.getItem(CUSTOM_LAYOUT_CONFIG_NAME);
  return possibleLayout ? { "Custom Layout": JSON.parse(possibleLayout) } : {};
};

export const saveCustomLayout = (layout) => {
  window.localStorage.setItem(
    CUSTOM_LAYOUT_CONFIG_NAME,
    JSON.stringify(layout),
  );
};

export const getServerDefinedLayouts = async () => {
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

export const getDefaultWorkspaceLayout = () => ({
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
