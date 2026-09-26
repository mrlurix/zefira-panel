"use strict";

// Age of this server-rendered page (used by the visibility reload below).
window.__zefiraRenderedAt = Date.now();

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
    // i18n.js is a separate file: if it 404s during a deploy, `t` is not
    // defined and every copy button threw a ReferenceError - the clipboard
    // write succeeded and the customer got NO feedback at all.
    const T = (k) => (typeof t === "function" ? t(k) : (k === "sub.copied" ? "Copied ✓" : "Copy failed"));
    if (!text) { btn.textContent = T("sub.copyFailed"); setTimeout(() => { btn.textContent = label; }, 1500); return; }
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
    btn.textContent = done ? T("sub.copied") : T("sub.copyFailed");
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

// The page is server-rendered once, so usage / status / days-left froze at
// load time while the customer kept consuming quota. Reload when the tab
// comes back to the foreground (no polling, no background traffic) so a
// dashboard left open on a phone is not an hour stale.
//
// The threshold is the length of the HIDDEN period, not the age of the page:
// measuring the page age reloaded on every return to the tab, so copying a
// WireGuard config, switching to the VPN app and coming back three seconds
// later threw the customer to the top of the page and wiped the scroll.
let hiddenAt = 0;
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") { hiddenAt = Date.now(); return; }
  if (!hiddenAt) return;
  const away = Date.now() - hiddenAt;
  hiddenAt = 0;
  if (away > 120000) location.reload();
});

try { mountLangSwitcher("#lang-mount-sub"); } catch (_) {}

// The page language is rendered by the SERVER from the zefira_lang cookie
// (missing cookie = English), while the switcher is initialised from
// localStorage / navigator.language. A customer whose browser is fa-IR with
// no cookie therefore got an English page with "فارسی" shown as selected.
// Persist the detected language once so the server and the switcher agree on
// the next load; one-shot so a disagreement can never loop.
try {
  if (typeof Z_LANG === "string" && Z_LANG) {
    const rendered = (document.documentElement.getAttribute("lang") || "").slice(0, 2);
    if (rendered && rendered !== Z_LANG && !sessionStorage.getItem("zefira_lang_synced")) {
      sessionStorage.setItem("zefira_lang_synced", "1");
      document.cookie = "zefira_lang=" + Z_LANG + ";path=/;max-age=31536000;samesite=lax";
      location.reload();
    }
  }
} catch (_) {}
