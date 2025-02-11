export const getCurrentTheme = () =>
  // handle theme
  document.documentElement.getAttribute("data-theme") || "light";

export const setupStoredOrDefaultTheme = () => {
  const storedOrDefaultTheme =
    localStorage.getItem("theme") ||
    (window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light");
  document.documentElement.setAttribute("data-theme", storedOrDefaultTheme);
  return storedOrDefaultTheme;
};

export const toggleTheme = (updateState) => (targetTheme) => {
  document.documentElement.setAttribute("data-theme", targetTheme);
  localStorage.setItem("theme", targetTheme);

  if (targetTheme === "dark") {
    document.querySelectorAll("perspective-viewer").forEach((viewer) => {
      viewer.restore({ theme: "Pro Dark" });
    });
  } else {
    document.querySelectorAll("perspective-viewer").forEach((viewer) => {
      viewer.restore({ theme: "Pro Light" });
    });
  }

  updateState(targetTheme);
};
