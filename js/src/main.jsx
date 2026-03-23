import React from "react";
import { createRoot } from "react-dom/client";
import App from "./index";

window.addEventListener("load", () => {
  const container = document.getElementById("gateway-root");

  // Clear selections on other viewers when clicking into a new one.
  document.addEventListener("mousedown", (e) => {
    const clicked = e.target.closest("perspective-viewer");
    if (!clicked) return;
    for (const v of document.querySelectorAll("perspective-viewer")) {
      if (v !== clicked && v.getSelection()) v.setSelection();
    }
  });

  // Ctrl+C / Cmd+C: copy selected cells from the focused viewer.
  document.addEventListener("keydown", async (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "c") {
      const viewer = document.activeElement?.closest("perspective-viewer");
      if (viewer?.getSelection()) {
        e.preventDefault();
        try {
          await viewer.copy("plugin");
        } catch (err) {
          console.warn("Copy failed:", err);
        }
      }
    }
  });

  if (container) {
    const root = createRoot(container);
    root.render(<App />);
  }
});
