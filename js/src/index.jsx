import React, { useCallback, useEffect, useRef, useState } from "react";
import { getOpenApi, hideLoader as hideDefaultLoader } from "./common";
import {
  Header,
  Footer,
  Loader as DefaultLoader,
  Settings,
  Workspace,
} from "./components";
import { getInitialTheme, applyTheme } from "./components/perspective";

/* exports */
export * from "./common";
export * from "./components";

export default function App(props) {
  const {
    headerLogo,
    footerLogo,
    processTables,
    overrideSettingsButtons,
    extraSettingsButtons,
    shutdown,
    hideLoader,
  } = props;

  // ── OpenAPI ──
  const [openapi, setOpenApi] = useState(null);
  useEffect(() => {
    getOpenApi().then(setOpenApi);
  }, []);

  // ── Theme ──
  const [theme, setTheme] = useState(getInitialTheme);
  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === "dark" ? "light" : "dark";
      applyTheme(next);
      return next;
    });
  }, []);

  // ── Workspace ref (for layout operations from header) ──
  const workspaceRef = useRef(null);

  // ── Loader ──
  const doHideLoader = hideLoader || hideDefaultLoader;
  const onWorkspaceReady = useCallback(() => doHideLoader(), [doHideLoader]);

  // ── Settings ──
  const [settingsOpen, setSettingsOpen] = useState(false);
  const toggleSettings = useCallback(
    () => setSettingsOpen((prev) => !prev),
    [],
  );

  const Loader = props.loader || DefaultLoader;

  return (
    <div id="main" className="container">
      <div id="loader">
        <Loader />
      </div>
      <Header
        headerLogo={headerLogo}
        openapi={openapi}
        theme={theme}
        toggleTheme={toggleTheme}
        toggleSettings={toggleSettings}
        workspaceRef={workspaceRef}
      />
      <Workspace
        ref={workspaceRef}
        processTables={processTables}
        onReady={onWorkspaceReady}
      />
      <Settings
        openapi={openapi}
        isOpen={settingsOpen}
        toggleSettings={toggleSettings}
        shutdown={shutdown}
        overrideSettingsButtons={overrideSettingsButtons}
        extraSettingsButtons={extraSettingsButtons}
      />
      <Footer footerLogo={footerLogo} />
    </div>
  );
}
