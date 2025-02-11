import React, { useState } from "react";
import Drawer from "react-modern-drawer";

import {
  FaEnvelope,
  FaHistory,
  FaNetworkWired,
  FaPowerOff,
} from "react-icons/fa";

import { shutdownDefault } from "../common";

export function Settings(props) {
  /* Open / Toggle */
  const { isOpen, toggleSettings, shutdown } = props;

  /* Optional builtin settings/buttons */
  let {
    overrideSettingsButtons = false,
    includePowerButton = true,
    includeGraphButton = true,
    includeLogsButton = true,
    includeEmailButton = true,
  } = props;
  const { extraSettingsButtons } = props;

  const [confirm, setConfirm] = useState(false);
  const [doubleConfirm, setDoubleConfirm] = useState(false);

  /* Some buttons require backend modules,
  so let's parse those out */
  const { openapi } = props;
  if (openapi?.info.contact.email === undefined) {
    includeEmailButton = false;
  }
  if ((openapi?.paths || {})["/outputs/{full_path}"] === undefined) {
    includeLogsButton = false;
  }
  if ((openapi?.paths || {})["/channels_graph"] === undefined) {
    includeGraphButton = false;
  }

  /* reset when closed */
  const onClose = () => {
    toggleSettings();
    setConfirm(false);
    setDoubleConfirm(false);
  };

  const shutdownAndClose = async () => {
    if (shutdown) {
      await shutdown();
    } else {
      await shutdownDefault();
    }
    onClose();
    // eslint-disable-next-line no-alert
    alert("Server shutdown!");
  };

  /* view graph */
  const goToEmail = () => {
    window.open(
      `mailto:${openapi?.info.contact.email}?Subject=${openapi?.info.title}%20Support`,
      "_blank",
    );
  };

  /* go to log viewer */
  const goToLogs = () => {
    window.open(
      `${window.location.protocol}//${window.location.host}/outputs`,
      "_blank",
    );
  };

  /* view graph */
  const goToGraphView = () => {
    window.open(
      `${window.location.protocol}//${window.location.host}/channels_graph`,
      "_blank",
    );
  };

  return (
    <>
      {includePowerButton && confirm && !doubleConfirm && (
        <div
          className="confirm-shutdown column"
          style={{ display: isOpen ? "flex" : "none" }}
        >
          <h1>Confirm Shutdown</h1>
          <div className="row around">
            <button
              className="text-button"
              type="button"
              onClick={() => setDoubleConfirm(true)}
            >
              <h1>Yes</h1>
            </button>
            <button
              className="text-button"
              type="button"
              onClick={() => setConfirm(false)}
            >
              <h1>No</h1>
            </button>
          </div>
        </div>
      )}
      {includePowerButton && confirm && doubleConfirm && (
        <div
          className="confirm-shutdown-last column"
          style={{ display: isOpen ? "flex" : "none" }}
        >
          <h1>ARE YOU SURE</h1>
          <div className="row around">
            <button
              className="text-button"
              type="button"
              onClick={() => shutdownAndClose()}
            >
              <h1>Yes</h1>
            </button>
            <button
              className="text-button"
              type="button"
              onClick={() => setDoubleConfirm(false)}
            >
              <h1>No</h1>
            </button>
          </div>
        </div>
      )}
      <Drawer
        open={isOpen}
        onClose={onClose}
        direction="right"
        className="settings"
      >
        {!overrideSettingsButtons && (
          <div className="settings-content column">
            {includePowerButton && (
              <>
                <button
                  className="big-red-button"
                  type="button"
                  onClick={() => setConfirm(true)}
                  title="Shutdown Server"
                >
                  <FaPowerOff size={100} />
                </button>
                <div className="divider" />
              </>
            )}
            <div className="column">
              {includeEmailButton && (
                <div className="row full-width between">
                  <FaEnvelope size={40} />
                  <button
                    className="text-button full-width between"
                    type="button"
                    onClick={goToEmail}
                    title="Send Email"
                  >
                    {openapi?.info.contact?.name || "Contact"}
                  </button>
                </div>
              )}
              {includeLogsButton && (
                <div className="row full-width between">
                  <FaHistory size={40} />
                  <button
                    className="text-button full-width between"
                    type="button"
                    onClick={goToLogs}
                    title="View Logs"
                  >
                    Logs
                  </button>
                </div>
              )}
              {includeGraphButton && (
                <div className="row full-width between">
                  <FaNetworkWired size={40} />
                  <button
                    className="text-button full-width between"
                    type="button"
                    onClick={goToGraphView}
                    title="View Logs"
                  >
                    Graph View
                  </button>
                </div>
              )}
              <div className="divider" />
            </div>
            {extraSettingsButtons && (
              <div className="column">{extraSettingsButtons}</div>
            )}
          </div>
        )}
        {overrideSettingsButtons && (
          <div className="settings-content column">{extraSettingsButtons}</div>
        )}
      </Drawer>
    </>
  );
}

export default Settings;
