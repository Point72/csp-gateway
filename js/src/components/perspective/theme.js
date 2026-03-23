/** Get the current theme from the DOM attribute */
export const getCurrentTheme = () =>
  document.documentElement.getAttribute("data-theme") || "light";

/** Return the perspective viewer theme name for a given app theme */
export const getViewerTheme = (theme) =>
  theme === "dark" ? "Pro Dark" : "Pro Light";

/** Read stored theme or detect from OS preference, apply to DOM, and return it */
export const getInitialTheme = () => {
  const theme =
    localStorage.getItem("theme") ||
    (window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light");
  document.documentElement.setAttribute("data-theme", theme);
  return theme;
};

/** Apply a theme to the DOM, persist it, and update all mounted perspective viewers */
export const applyTheme = (theme) => {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);
  const viewerTheme = getViewerTheme(theme);
  document.querySelectorAll("perspective-viewer").forEach((viewer) => {
    viewer.restore({ theme: viewerTheme });
  });
};
