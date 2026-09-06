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
  fetch("assets/search-index.json").then(function (r) { return r.json(); }).then(function (j) { index = j; }).catch(function () { index = []; });

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
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); isOpen() ? close() : open(); }
    else if (e.key === "Escape" && isOpen()) close();
    else if (e.key === "/" && !typing && !isOpen()) { e.preventDefault(); open(); }
  });
})();
