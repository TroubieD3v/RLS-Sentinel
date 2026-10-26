(function () {
  try {
    var pref = localStorage.getItem("sentinel.theme") || "system";
    var dark = pref === "dark" || (pref === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    var rm = localStorage.getItem("sentinel.reducedMotion");
    if (rm === "1" || (rm === null && window.matchMedia("(prefers-reduced-motion: reduce)").matches)) {
      document.documentElement.setAttribute("data-reduced-motion", "1");
    }
  } catch (e) { document.documentElement.setAttribute("data-theme", "dark"); }
})();
