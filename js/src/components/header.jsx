import React from "react";
import { FaBars, FaDownload, FaMoon, FaSave, FaSun } from "react-icons/fa";
import { CspGatewayLogo } from "./logo";
import { saveCustomLayout } from "./perspective/layout";
import { getCurrentTheme } from "./perspective/theme";

const ICON_SIZE = 20;

export function Header(props) {
  // theme and layout data
  const { layouts, theme } = props;

  // toggles and state changers
  const { changeLayouts, toggleTheme } = props;

  // settings toggle
  const { toggleSettings } = props;

  // openapi data
  const { openapi } = props;

  // overrideable data
  let { headerLogo } = props;

  if (headerLogo === undefined) {
    headerLogo = <CspGatewayLogo />;
  }

  if (openapi?.info.title) {
    document.title = openapi.info.title;
  }

  return (
    <div className="header">
      {/* Left Aligned header */}
      <div className="row">
        {headerLogo}
        <h1 className="header-title">{openapi?.info.title}</h1>
        <p className="header-version">{openapi?.info.version}</p>
      </div>

      {/* Right Aligned header */}
      <div className="row">
        {/* Layout dropdown */}
        <select
          className="layout-config"
          title="Choose Theme"
          onChange={(e) => {
            changeLayouts({ ...layouts, active: e.target.value });
          }}
          value={layouts.active}
        >
          {Object.keys(layouts).map(
            (k) =>
              k !== "active" && (
                <option className="layout-config" key={k} value={k}>
                  {k}
                </option>
              ),
          )}
        </select>

        {/* Save current layout */}
        <button
          className="icon-button"
          type="button"
          onClick={async () => {
            const workspace = document.getElementById("workspace");
            const modifiedConfig = await workspace.save();

            saveCustomLayout(modifiedConfig);
            changeLayouts({
              ...layouts,
              "Custom Layout": modifiedConfig,
              active: "Custom Layout",
            });
          }}
          title="Save Current Layout"
        >
          <FaSave size={ICON_SIZE} />
        </button>

        {/* Download current layout */}
        <button
          className="icon-button"
          type="button"
          onClick={async () => {
            const workspace = document.getElementById("workspace");
            const modifiedConfig = await workspace.save();
            const link = document.createElement("a");
            link.href = `data:application/json;base64,${btoa(JSON.stringify(modifiedConfig))}`;
            link.download = "layout.json";
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
          }}
          title="Download Layout"
        >
          <FaDownload size={ICON_SIZE} />
        </button>

        {/* Light / Dark theme switch */}
        <button
          className="icon-button"
          type="button"
          onClick={() =>
            toggleTheme(
              theme === "dark" || getCurrentTheme() == "dark"
                ? "light"
                : "dark",
            )
          }
          title="Toggle Theme"
        >
          {theme === "dark" && <FaSun size={ICON_SIZE} />}
          {theme !== "dark" && <FaMoon size={ICON_SIZE} />}
        </button>

        {/* Settings drawer */}
        <button
          className="icon-button"
          type="button"
          onClick={() => toggleSettings()}
          title="Open Settings"
        >
          <FaBars size={ICON_SIZE} />
        </button>
      </div>
    </div>
  );
}

export default Header;
