"use strict";
// Active nav link
(function () {
  var path = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".sidebar a").forEach(function (a) {
    if (a.getAttribute("href") === path) a.classList.add("active");
  });
})();

var navToggle = document.getElementById("nav-toggle");
if (navToggle) {
  navToggle.addEventListener("click", function () {
    document.getElementById("sidebar").classList.toggle("open");
  });
  document.querySelectorAll(".sidebar a").forEach(function (a) {
    a.addEventListener("click", function () {
      document.getElementById("sidebar").classList.remove("open");
    });
  });
}

// Sidebar search filter
var navSearch = document.getElementById("nav-search");
if (navSearch) {
  navSearch.addEventListener("input", function (e) {
    var q = e.target.value.toLowerCase();
    document.querySelectorAll(".sidebar a").forEach(function (a) {
      a.style.display = a.textContent.toLowerCase().includes(q) ? "" : "none";
    });
    document.querySelectorAll(".sidebar .nav-group").forEach(function (g) {
      var next = g.nextElementSibling, visible = false;
      while (next && next.tagName === "A") {
        if (next.style.display !== "none") { visible = true; break; }
        next = next.nextElementSibling;
      }
      g.style.display = visible || !q ? "" : "none";
    });
  });
}

// Copy buttons for code blocks
document.querySelectorAll("pre").forEach(function (pre) {
  var btn = document.createElement("button");
  btn.className = "copy-btn";
  btn.textContent = "Copy";
  btn.addEventListener("click", function () {
    navigator.clipboard.writeText(pre.innerText.replace(/^Copy\n/, "")).then(function () {
      btn.textContent = "Copied ✓";
      setTimeout(function () { btn.textContent = "Copy"; }, 1500);
    });
  });
  pre.appendChild(btn);
});

// Scroll reveal animations
(function () {
  var els = document.querySelectorAll(".feat, .step, .shots figure, .cards .card, .callout");
  if (!("IntersectionObserver" in window) || !els.length) {
    els.forEach(function (el) { el.classList.add("in"); });
    return;
  }
  els.forEach(function (el) {
    el.classList.add("reveal");
    var sibs = Array.prototype.filter.call(el.parentNode.children, function (c) {
      return c.classList && c.classList.contains("reveal");
    });
    el.style.transitionDelay = ((sibs.length % 6) * 70) + "ms";
  });
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
    });
  }, { threshold: 0.12 });
  els.forEach(function (el) { io.observe(el); });
})();

// Command palette search (Ctrl+K / Cmd+K)
(function () {
  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function hi(text, q) {
    var idx = text.toLowerCase().indexOf(q);
    if (idx < 0 || !q) return esc(text);
    return esc(text.slice(0, idx)) + "<mark>" + esc(text.slice(idx, idx + q.length)) + "</mark>" + esc(text.slice(idx + q.length));
  }

  var topbar = document.querySelector(".topbar");
  if (!topbar) return;
  var trigger = document.createElement("button");
  trigger.className = "sp-trigger";
  trigger.type = "button";
  trigger.setAttribute("aria-label", "Search docs (Ctrl+K)");
  var isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0;
  trigger.innerHTML = "<svg width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><circle cx='11' cy='11' r='7'/><path d='m20 20-3.5-3.5'/></svg><span>Search</span><kbd>" + (isMac ? "⌘K" : "Ctrl K") + "</kbd>";
  var anchor = topbar.querySelector(".gh");
  topbar.insertBefore(trigger, anchor || topbar.querySelector(".spacer"));

  var overlay = document.createElement("div");
  overlay.className = "sp-overlay";
  overlay.hidden = true;
  overlay.innerHTML =
    "<div class='sp-modal' role='dialog' aria-modal='true' aria-label='Search documentation'>" +
    "<div class='sp-input-row'><svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='#ff2740' stroke-width='2'><circle cx='11' cy='11' r='7'/><path d='m20 20-3.5-3.5'/></svg>" +
    "<input id='sp-input' type='text' placeholder='Search documentation…' autocomplete='off' spellcheck='false'></div>" +
    "<div class='sp-results' id='sp-results'></div>" +
    "<div class='sp-foot'><span><kbd>↑↓</kbd>navigate</span><span><kbd>↵</kbd>open</span><span><kbd>esc</kbd>close</span></div></div>";
  document.body.appendChild(overlay);
  var input = overlay.querySelector("#sp-input");
  var resultsBox = overlay.querySelector("#sp-results");

  var index = null, items = [], sel = 0, lastQ = "";
  fetch("assets/search-index.json?v=3").then(function (r) { return r.json(); }).then(function (j) { index = j; }).catch(function () { index = []; });

  function render() {
    resultsBox.innerHTML = "";
    if (!items.length) {
      var empty = document.createElement("div");
      empty.className = "sp-empty";
      empty.textContent = index === null ? "Loading index…" : (lastQ ? "No results for “" + lastQ + "”" : "Type to search 45 doc sections…");
      resultsBox.appendChild(empty);
      return;
    }
    items.slice(0, 8).forEach(function (it, i) {
      var a = document.createElement("a");
      var hw = lastQ.split(/\s+/).filter(function (w) {
        return (it.s + " " + it.t).toLowerCase().indexOf(w) >= 0;
      })[0] || "";
      a.className = "sp-item" + (i === sel ? " sel" : "");
      a.href = it.u;
      a.innerHTML = "<div class='sp-page'>" + esc(it.p) + "</div><div class='sp-sec'>" + hi(it.s, hw) + "</div><div class='sp-snip'>" + hi(it.t.slice(0, 140), hw) + "</div>";
      a.addEventListener("click", close);
      a.addEventListener("mousemove", function () { sel = i; paintSel(); });
      resultsBox.appendChild(a);
    });
  }
  function paintSel() {
    resultsBox.querySelectorAll(".sp-item").forEach(function (el, i) {
      el.classList.toggle("sel", i === sel);
      if (i === sel) el.scrollIntoView({ block: "nearest" });
    });
  }
  function search(q) {
    lastQ = q.toLowerCase().trim();
    sel = 0;
    if (!index || !lastQ) { items = []; render(); return; }
    var words = lastQ.split(/\s+/);
    items = index.map(function (e) {
      var p = e.p.toLowerCase(), s = e.s.toLowerCase(), t = e.t.toLowerCase();
      var score = 0;
      for (var k = 0; k < words.length; k++) {
        var w = words[k], hit = false;
        if (p.indexOf(w) >= 0) { score += 5; hit = true; }
        if (s.indexOf(w) >= 0) { score += 3; hit = true; }
        if (t.indexOf(w) >= 0) { score += 1; hit = true; }
        if (!hit) return null;
      }
      return { e: e, score: score };
    }).filter(Boolean).sort(function (a, b) { return b.score - a.score; })
      .map(function (x) { return { u: x.e.u, p: x.e.p, s: x.e.s, t: x.e.t }; });
    render();
  }
  function open() {
    overlay.hidden = false;
    requestAnimationFrame(function () { requestAnimationFrame(function () { overlay.classList.add("show"); }); });
    input.value = "";
    search("");
    setTimeout(function () { input.focus(); }, 30);
  }
  function close() {
    overlay.classList.remove("show");
    setTimeout(function () { overlay.hidden = true; }, 180);
  }
  function isOpen() { return !overlay.hidden; }

  trigger.addEventListener("click", open);
  overlay.addEventListener("click", function (e) { if (e.target === overlay) close(); });
  input.addEventListener("input", function () { search(input.value); });
  input.addEventListener("keydown", function (e) {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(sel + 1, Math.min(items.length, 8) - 1); paintSel(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(sel - 1, 0); paintSel(); }
    else if (e.key === "Enter") { var link = resultsBox.querySelectorAll(".sp-item")[sel]; if (link) link.click(); }
  });
  document.addEventListener("keydown", function (e) {
    var tag = (document.activeElement && document.activeElement.tagName) || "";
    var typing = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
    // e.code is layout-independent (works with Persian keyboard too)
    var isK = e.key.toLowerCase() === "k" || e.code === "KeyK";
    var isSlash = e.key === "/" || e.code === "Slash";
    if ((e.ctrlKey || e.metaKey) && isK) { e.preventDefault(); isOpen() ? close() : open(); }
    else if (e.key === "Escape" && isOpen()) close();
    else if (isSlash && !typing && !isOpen()) { e.preventDefault(); open(); }
  });
  window.__zefiraSearch = { open: open, close: close, isOpen: isOpen };
})();

// Online donations via Shieldz (worker holds the secret key).
// Page works without configuration: amounts simply stay disabled.
(function () {
  var payBtn = document.getElementById("donate-pay");
  if (!payBtn) return;
  var box = document.getElementById("donate-amounts");
  var custom = document.getElementById("donate-custom");
  var status = document.getElementById("donate-status");
  var cfg = { api: "", currency: "USD", presets: [5, 10, 25, 50], min: 1, max: 500 };
  var selected = null;
  function say(msg) { if (status) status.textContent = msg; }
  function paint() {
    box.querySelectorAll(".amt-btn").forEach(function (b) {
      b.classList.toggle("sel", String(selected) === b.getAttribute("data-amt"));
    });
  }
  (cfg.presets || []).forEach(function (p) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "amt-btn";
    b.setAttribute("data-amt", String(p));
    b.textContent = "$" + p;
    b.addEventListener("click", function () {
      selected = p;
      if (custom) custom.value = "";
      paint();
    });
    box.appendChild(b);
  });
  if (custom) custom.addEventListener("input", function () { selected = null; paint(); });
  fetch("assets/donate-config.json").then(function (r) { return r.json(); }).then(function (j) {
    if (j && typeof j === "object") {
      if (typeof j.api === "string") cfg.api = j.api;
      if (j.min) cfg.min = j.min;
      if (j.max) cfg.max = j.max;
    }
    if (!cfg.api) {
      payBtn.disabled = true;
      say("Online payments are not connected yet — use a wallet address below.");
    }
  }).catch(function () {
    payBtn.disabled = true;
    say("Online payments are not connected yet — use a wallet address below.");
  });
  payBtn.addEventListener("click", async function () {
    var amount = selected;
    if (amount == null && custom && custom.value !== "") {
      amount = Math.floor(Number(custom.value));
    }
    if (!amount || !(amount >= cfg.min && amount <= cfg.max)) {
      say("Enter an amount between $" + cfg.min + " and $" + cfg.max + ".");
      return;
    }
    if (!cfg.api) { say("Online payments are not connected yet."); return; }
    payBtn.disabled = true;
    say("Creating secure checkout…");
    try {
      const res = await fetch(cfg.api, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ amount_usd: amount })
      });
      let data = null;
      try { data = await res.json(); } catch (_) {}
      if (!res.ok || !data || typeof data.pay_url !== "string" || !/^https:\/\/shieldz\.cash\//.test(data.pay_url)) {
        say("Payment service error — try again or use a wallet below.");
        payBtn.disabled = false;
        return;
      }
      say("Redirecting to secure checkout…");
      location.href = data.pay_url;
    } catch (_) {
      say("Network error — try again or use a wallet below.");
      payBtn.disabled = false;
    }
  });
})();

// Floating support bubble (bottom corner) — static links only, no backend.
(function () {
  var fab = document.createElement("button");
  fab.className = "sup-fab";
  fab.type = "button";
  fab.setAttribute("aria-label", "Get support");
  fab.textContent = "?";
  var panel = document.createElement("div");
  panel.className = "sup-panel";
  panel.hidden = true;
  var head = document.createElement("div");
  head.className = "sup-head";
  head.textContent = "Need help?";
  var sub = document.createElement("small");
  sub.textContent = "Answers, community and bug reports.";
  head.appendChild(sub);
  var links = document.createElement("div");
  links.className = "sup-links";
  function row(label, hint, href, onclick) {
    var el = href ? document.createElement("a") : document.createElement("button");
    if (href) { el.href = href; if (/^https?:/.test(href)) { el.target = "_blank"; el.rel = "noopener"; } }
    if (onclick) el.addEventListener("click", onclick);
    var dot = document.createElement("span");
    dot.className = "dot";
    var t = document.createElement("span");
    t.textContent = label;
    el.appendChild(dot);
    el.appendChild(t);
    if (hint) {
      var h = document.createElement("small");
      h.textContent = hint;
      el.appendChild(h);
    }
    return el;
  }
  links.appendChild(row("Search the docs", "Ctrl K", null, function () {
    closePanel();
    if (window.__zefiraSearch) window.__zefiraSearch.open();
  }));
  links.appendChild(row("Support page", null, "support.html", null));
  links.appendChild(row("FAQ & troubleshooting", null, "faq.html", null));
  links.appendChild(row("Ask the community", null, "https://github.com/mrlurix/zefira-panel/discussions", null));
  links.appendChild(row("Report a bug", null, "https://github.com/mrlurix/zefira-panel/issues", null));
  panel.appendChild(head);
  panel.appendChild(links);
  document.body.appendChild(fab);
  document.body.appendChild(panel);
  function closePanel() {
    panel.classList.remove("show");
    setTimeout(function () { panel.hidden = true; }, 180);
  }
  fab.addEventListener("click", function () {
    if (panel.hidden) {
      panel.hidden = false;
      requestAnimationFrame(function () { requestAnimationFrame(function () { panel.classList.add("show"); }); });
    } else closePanel();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !panel.hidden) closePanel();
  });
  document.addEventListener("click", function (e) {
    if (!panel.hidden && !panel.contains(e.target) && e.target !== fab && !fab.contains(e.target)) closePanel();
  });
})();
