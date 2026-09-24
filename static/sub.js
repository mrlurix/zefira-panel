"use strict";

// Copy buttons on the public subscription dashboard.
// No innerHTML anywhere: all values come from data attributes / textareas.
document.querySelectorAll("[data-copy], [data-copy-target]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const sel = btn.getAttribute("data-copy-target");
    const src = sel ? document.querySelector(sel) : null;
    const text = src ? src.value : btn.getAttribute("data-copy") || "";
    // Capture the CURRENT label (not a stale one from page load: the
    // language switcher may have retranslated the button since).
    const label = btn.textContent;
    if (!text) { btn.textContent = t("sub.copyFailed"); setTimeout(() => { btn.textContent = label; }, 1500); return; }
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
          ta.setAttribute("readonly", "");
          ta.style.position = "fixed";
          ta.style.top = "0";
          ta.style.opacity = "0";
          document.body.appendChild(ta);
          ta.select();
          done = document.execCommand("copy");
          ta.remove();
        }
      } catch (_) {}
    }
    btn.textContent = done ? t("sub.copied") : t("sub.copyFailed");
    // Re-read the i18n key on restore instead of the captured text: a
    // language switch inside the 1.5s window must not be clobbered.
    const restoreKey = btn.getAttribute("data-i18n");
    setTimeout(() => {
      btn.textContent = restoreKey && typeof t === "function" ? t(restoreKey) : label;
    }, 1500);
  });
});

// Progress bars carry their width in data-w (keeps markup CSP-clean).
document.querySelectorAll(".fill[data-w]").forEach((el) => {
  const pct = Math.max(0, Math.min(100, parseFloat(el.getAttribute("data-w")) || 0));
  el.style.width = pct + "%";
});

try { mountLangSwitcher("#lang-mount-sub"); } catch (_) {}
