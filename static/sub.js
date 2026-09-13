"use strict";

// Copy buttons on the public subscription dashboard.
// No innerHTML anywhere: all values come from data attributes / textareas.
document.querySelectorAll("[data-copy], [data-copy-target]").forEach((btn) => {
  if (!btn.dataset.label) btn.dataset.label = btn.textContent;
  btn.addEventListener("click", async () => {
    const sel = btn.getAttribute("data-copy-target");
    const src = sel ? document.querySelector(sel) : null;
    const text = src ? src.value : btn.getAttribute("data-copy") || "";
    if (!text) return;
    let done = false;
    try {
      await navigator.clipboard.writeText(text);
      done = true;
    } catch (_) {
      // clipboard API needs a secure context: fall back to select+execCommand
      try {
        if (src) {
          src.focus();
          src.select();
          done = document.execCommand("copy");
        } else {
          const ta = document.createElement("textarea");
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          done = document.execCommand("copy");
          ta.remove();
        }
      } catch (_) {}
    }
    btn.textContent = done ? "Copied ✓" : "Copy failed";
    setTimeout(() => { btn.textContent = btn.dataset.label; }, 1500);
  });
});

// Progress bars carry their width in data-w (keeps markup CSP-clean).
document.querySelectorAll(".fill[data-w]").forEach((el) => {
  const pct = Math.max(0, Math.min(100, parseFloat(el.getAttribute("data-w")) || 0));
  el.style.width = pct + "%";
});
