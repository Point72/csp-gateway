import React, { useCallback, useEffect, useState } from "react";
import { FaBars, FaDownload, FaMoon, FaSave, FaSun } from "react-icons/fa";
import { CspGatewayLogo } from "./logo";
import { getCurrentTheme } from "./perspective/theme";

const ICON_SIZE = 20;

export function Header(props) {
  const { theme, toggleTheme, toggleSettings, openapi, workspaceRef } = props;

  let { headerLogo } = props;
  if (headerLogo === undefined) {
    headerLogo = <CspGatewayLogo />;
  }

  if (openapi?.info.title) {
    document.title = openapi.info.title;
  }

  // ── Layout state from workspace ref ──
  const [layoutNames, setLayoutNames] = useState([]);
  const [activeLayout, setActiveLayout] = useState(null);

  // Poll the workspace ref for layout info once it's available
  useEffect(() => {
    const interval = setInterval(() => {
      const ws = workspaceRef?.current;
      if (!ws) return;
      const layouts = ws.getLayouts();
      const names = Object.keys(layouts);
      if (names.length > 0) {
        setLayoutNames(names);
        setActiveLayout(ws.getActiveLayout());
        clearInterval(interval);
      }
    }, 200);
    return () => clearInterval(interval);
  }, [workspaceRef]);

  const onLayoutChange = useCallback(
    (e) => {
      const name = e.target.value;
      workspaceRef?.current?.setActiveLayout(name);
      setActiveLayout(name);
    },
    [workspaceRef],
  );

  const onSave = useCallback(async () => {
    await workspaceRef?.current?.saveLayout();
    // update dropdown
    const ws = workspaceRef?.current;
    if (ws) {
      setLayoutNames(Object.keys(ws.getLayouts()));
      setActiveLayout(ws.getActiveLayout());
    }
  }, [workspaceRef]);

  const onDownload = useCallback(async () => {
    const json = await workspaceRef?.current?.exportLayout();
    if (!json) return;
    const link = document.createElement("a");
    link.href = `data:application/json;base64,${btoa(json)}`;
    link.download = "layout.json";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }, [workspaceRef]);

  return (
    <div className="header">
      {/* Left */}
      <div className="row">
        {headerLogo}
        <a
          href="/"
          onClick={(e) => {
            e.preventDefault();
            const url = new URL(window.location);
            url.searchParams.delete("layout");
            window.history.replaceState(null, "", url);
            window.location.reload();
          }}
        >
          <h1 className="header-title">{openapi?.info.title}</h1>
        </a>
        <p className="header-version">{openapi?.info.version}</p>
      </div>

      {/* Right */}
      <div className="row">
        {/* Layout dropdown */}
        <select
          className="layout-config"
          title="Choose Layout"
          onChange={onLayoutChange}
          value={activeLayout || ""}
        >
          {layoutNames.map((k) => (
            <option className="layout-config" key={k} value={k}>
              {k}
            </option>
          ))}
        </select>

        {/* Save */}
        <button
          className="icon-button"
          type="button"
          onClick={onSave}
          title="Save Current Layout"
        >
          <FaSave size={ICON_SIZE} />
        </button>

        {/* Download */}
        <button
          className="icon-button"
          type="button"
          onClick={onDownload}
          title="Download Layout"
        >
          <FaDownload size={ICON_SIZE} />
        </button>

        {/* Theme toggle */}
        <button
          className="icon-button"
          type="button"
          onClick={toggleTheme}
          title="Toggle Theme"
        >
          {theme === "dark" ? (
            <FaSun size={ICON_SIZE} />
          ) : (
            <FaMoon size={ICON_SIZE} />
          )}
        </button>

        {/* Settings */}
        <button
          className="icon-button"
          type="button"
          onClick={toggleSettings}
          title="Open Settings"
        >
          <FaBars size={ICON_SIZE} />
        </button>
      </div>
    </div>
  );
}

export default Header;
