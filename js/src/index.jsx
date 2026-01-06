import React, { useEffect, useState } from "react";
import { getOpenApi, hideLoader as hideDefaultLoader } from "./common";
import {
  Header,
  Footer,
  Loader as DefaultLoader,
  Settings,
  Workspace,
} from "./components";
import {
  toggleTheme,
  setupStoredOrDefaultTheme,
  getCustomLayout,
  getServerDefinedLayouts,
} from "./components/perspective";

import { processTables } from "./common";

/* exports */
export * from "./common";
export * from "./components";

export default function App(props) {
  const {
    headerLogo,
    footerLogo,
    overrideSettingsButtons,
    extraSettingsButtons,
    shutdown,
    hideLoader,
  } = props;

  /**
   * OpenAPI
   */
  const [openapi, setOpenApi] = useState(null);
  useEffect(async () => setOpenApi(await getOpenApi()), []);

  /**
   * Layout
   */
  const [layouts, changeLayouts] = useState({});
  useEffect(() => {
    // fetch server defined layouts and merge with
    // default layout derived from tables.
    // Then set the active to be default
    if (layouts.Default) {
      getServerDefinedLayouts().then((serverLayouts) => {
        const newLayouts = {
          active: "Default",
          ...layouts,
          ...serverLayouts,
          ...getCustomLayout(),
        };
        if (JSON.stringify(newLayouts) !== JSON.stringify(layouts)) {
          changeLayouts(newLayouts);
        }
      });
    }
  }, [layouts]);

  /**
   * Theme
   */
  const storedOrDefaultTheme = setupStoredOrDefaultTheme();
  const [theme, changeTheme] = useState(storedOrDefaultTheme);
  const toggleThemeAndChangeState = toggleTheme(changeTheme);
  useEffect(() => toggleThemeAndChangeState(storedOrDefaultTheme), []);

  /**
   * Settings
   */
  const [settingsOpen, setLeftDrawerOpen] = useState(false);
  const toggleSettings = () => {
    setLeftDrawerOpen((prevState) => !prevState);
  };

  let Loader = props.loader || DefaultLoader;

  /**
   * Return nodes
   */
  return (
    <div id="main" className="container">
      <div id="loader">
        <Loader />
      </div>
      <Header
        headerLogo={headerLogo}
        openapi={openapi}
        layouts={layouts}
        changeLayouts={changeLayouts}
        theme={theme}
        toggleTheme={toggleThemeAndChangeState}
        toggleSettings={toggleSettings}
      />
      <Workspace
        openapi={openapi}
        layouts={layouts}
        changeLayouts={changeLayouts}
        processTables={processTables}
        theme={theme}
        hideLoader={hideLoader || hideDefaultLoader}
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
