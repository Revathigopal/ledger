// Hover / keyboard-focus tooltips for the conversion-advisor charts.
// Loaded as an external file so the strict Content-Security-Policy stays intact.
(function () {
  "use strict";
  const tip = document.getElementById("viz-tooltip");
  if (!tip) return;

  function show(el, x, y) {
    tip.textContent = el.getAttribute("data-tip");
    tip.hidden = false;
    const pad = 14;
    const w = tip.offsetWidth, h = tip.offsetHeight;
    let left = x + pad, top = y + pad;
    if (left + w > window.innerWidth - 8) left = x - w - pad;
    if (top + h > window.innerHeight - 8) top = y - h - pad;
    tip.style.left = Math.max(8, left) + "px";
    tip.style.top = Math.max(8, top) + "px";
  }
  function hide() { tip.hidden = true; }

  document.querySelectorAll("[data-tip]").forEach(function (el) {
    // the native SVG <title> would double up with our tooltip
    el.querySelectorAll(":scope > title").forEach(function (t) {
      el.setAttribute("aria-label", t.textContent);
      t.remove();
    });
    el.addEventListener("mousemove", function (e) { show(el, e.clientX, e.clientY); });
    el.addEventListener("mouseleave", hide);
    el.addEventListener("focus", function () {
      const r = el.getBoundingClientRect();
      show(el, r.left + r.width / 2, r.top + r.height / 2);
    });
    el.addEventListener("blur", hide);
  });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") hide(); });
})();
