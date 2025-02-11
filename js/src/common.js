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
