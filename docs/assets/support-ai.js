// Zefira site assistant — offline Q&A over site-knowledge.json.
// Behavior spec: assets/site-prompt.md (scope: site/panel questions only).
// No backend, no API key, nothing stored. All DOM via textContent.
(function () {
  var KB = null, kbLoading = false;
  var HISTORY = [];

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function loadKB(cb) {
    if (KB) { cb(KB); return; }
    if (kbLoading) { setTimeout(function () { loadKB(cb); }, 200); return; }
    kbLoading = true;
    fetch("assets/site-knowledge.json?v=3").then(function (r) { return r.json(); }).then(function (j) {
      KB = j; cb(KB);
    }).catch(function () { cb(null); });
  }

  var STOP = { what: 1, how: 1, the: 1, and: 1, for: 1, with: 1, are: 1, you: 1, can: 1, does: 1, please: 1 };
  // Two-letter words ("is", "of", "do", "to"…) match everywhere as
  // substrings and drown real keywords, defeating the off-topic guard.
  // Drop them except a tiny allowlist of meaningful short tokens.
  var KEEP2 = { ai: 1, qr: 1, dns: 1, ip: 1, os: 1 };
  function words(q) {
    return q.toLowerCase().split(/[^a-z0-9\u0600-\u06FF_]+/).filter(function (w) {
      if (w.length >= 3) return !STOP[w];
      return !!KEEP2[w];
    });
  }

  function rank(q) {
    var ws = words(q), out = [], i, k;
    if (!ws.length) return out;
    for (i = 0; i < KB.length; i++) {
      var e = KB[i], score = 0;
      var title = (e.title || "").toLowerCase();
      var keys = (e.keywords || "").toLowerCase();
      var text = (e.text || "").toLowerCase();
      for (k = 0; k < ws.length; k++) {
        var w = ws[k];
        if (title.indexOf(w) >= 0) score += 4;
        if (keys.indexOf(w) >= 0) score += 3;
        if (text.indexOf(w) >= 0) score += 1;
      }
      if (score > 0) out.push({ e: e, score: score });
    }
    out.sort(function (a, b) { return b.score - a.score; });
    return out.slice(0, 2);
  }

  // ---- DOM ----
  var overlay = null, msgsBox = null, inputEl = null;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function addLinkBtn(parent, label, href) {
    var a = document.createElement("a");
    a.className = "ai-link";
    a.textContent = label;
    // KB links are static, but never let a data-driven href become
    // javascript:/data: executable: allow http(s) + same-origin relative only.
    var h = String(href || "");
    if (/^https?:\/\//i.test(h)) {
      a.href = h;
      a.target = "_blank";
      a.rel = "noopener";
    } else if (/^[a-zA-Z0-9._~:/?#@!$&'()*+,;=%-]*$/.test(h) && !/^\s*javascript:/i.test(h) && !/^\s*data:/i.test(h)) {
      a.href = h;
    } else {
      return;
    }
    parent.appendChild(a);
  }

  function addWallet(parent, label, addr) {
    var r = el("div", "ai-wallet");
    r.appendChild(el("b", null, label));
    var c = el("code", null, addr);
    c.title = addr;
    var btn = el("button", null, t("docs.copy"));
    btn.type = "button";
    btn.addEventListener("click", function () {
      var done = function (ok) {
        btn.textContent = ok ? t("docs.copied") : t("docs.copyFailed");
        setTimeout(function () { btn.textContent = t("docs.copy"); }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(addr).then(function () { done(true); }, function () { done(false); });
      } else done(false);
    });
    r.appendChild(c);
    r.appendChild(btn);
    parent.appendChild(r);
  }

  function addEntry(parent, entry, lang) {
    var box = el("div", "ai-entry");
    box.appendChild(el("strong", null, entry.title));
    var lead = lang !== "en" ? (entry[lang] || entry.fa) : null;
    var body = lead ? (lead + "\n\n" + entry.text) : entry.text;
    body.split(/\n\n+/).forEach(function (para) {
      box.appendChild(el("p", null, para));
    });
    (entry.wallets || []).forEach(function (w) { addWallet(box, w.label, w.addr); });
    (entry.links || []).forEach(function (l) { addLinkBtn(box, l.label, l.href); });
    parent.appendChild(box);
  }

  function addRefusal(parent) {
    var box = el("div", "ai-entry");
    box.appendChild(el("strong", null, t("ai.refusalTitle")));
    box.appendChild(el("p", null, t("ai.refusalText")));
    addLinkBtn(box, t("docs.supSupport"), "support.html");
    addLinkBtn(box, t("docs.supFaq"), "faq.html");
    addLinkBtn(box, t("docs.supCommunity"), "https://github.com/mrlurix/zefira-panel/discussions");
    parent.appendChild(box);
  }

  function addMsg(cls) {
    var m = el("div", "ai-msg " + cls);
    msgsBox.appendChild(m);
    msgsBox.scrollTop = msgsBox.scrollHeight;
    return m;
  }

  function answerInner(q, lang, box, kb) {
    if (/^(hi|hello|hey|salam|سلام|درود|yo)\b/i.test(q.trim())) {
      var w = el("div", "ai-entry");
      w.appendChild(el("strong", null, t("ai.greetTitle")));
      w.appendChild(el("p", null, t("ai.greetText")));
      parentChips(w);
      box.appendChild(w);
      return;
    }
    if (!kb || !kb.length) {
      box.appendChild(el("p", null, t("ai.kbFail")));
      addLinkBtn(box, t("docs.supSupport"), "support.html");
      return;
    }
    var hits = rank(q);
    if (!hits.length || hits[0].score < 3) { addRefusal(box); return; }
    hits.forEach(function (h) { addEntry(box, h.e, lang); });
    msgsBox.scrollTop = msgsBox.scrollHeight;
  }

  function parentChips(parent) {
    var chips = [t("ai.chipDonate"), t("ai.chipNew"), t("ai.chipInstall")];
    var row = el("div", "ai-chips");
    chips.forEach(function (c) {
      var b = el("button", null, c);
      b.type = "button";
      b.addEventListener("click", function () { ask(c); });
      row.appendChild(b);
    });
    parent.appendChild(row);
  }

  function ask(q) {
    q = (q || "").trim().slice(0, 500);
    if (!q) return;
    addMsg("user").textContent = q;
    HISTORY.push(q);
    HISTORY = HISTORY.slice(-8);
    // No artificial delay: answers are local and instant. No timers are
    // used anywhere on this path, so throttled background tabs still work.
    loadKB(function (kb) {
      var box = addMsg("bot");
      try {
        answerInner(q, (typeof Z_LANG !== "undefined" ? Z_LANG : "en"), box, kb);
      } catch (err) {
        box.appendChild(el("p", null, t("ai.errPre") + String((err && err.message) || err).slice(0, 120) + t("ai.errPost")));
        addLinkBtn(box, t("docs.supSupport"), "support.html");
      }
      msgsBox.scrollTop = msgsBox.scrollHeight;
    });
  }

  function build() {
    overlay = el("div", "sp-overlay");
    overlay.hidden = true;
    var modal = el("div", "sp-modal ai-modal");
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-label", "Zefira site assistant");
    var head = el("div", "ai-head");
    head.appendChild(el("b", null, t("ai.chatHead")));
    var x = el("button", "ai-x", "×");
    x.type = "button";
    x.setAttribute("aria-label", t("ai.close"));
    x.addEventListener("click", close);
    head.appendChild(x);
    var sub = el("div", "ai-sub", t("ai.note"));
    msgsBox = el("div", "ai-msgs");
    var chips = el("div", "ai-chips");
    [t("ai.chipDonate"), t("ai.chipNew"), t("ai.chipInstall")].forEach(function (c) {
      var b = el("button", null, c);
      b.type = "button";
      b.addEventListener("click", function () { ask(c); });
      chips.appendChild(b);
    });
    var form = el("form", "ai-form");
    inputEl = document.createElement("input");
    inputEl.type = "text";
    inputEl.placeholder = t("ai.inputPh");
    inputEl.setAttribute("aria-label", t("ai.inputPh"));
    inputEl.maxLength = 500;
    inputEl.autocomplete = "off";
    var send = el("button", "ai-send", t("ai.sendBtn"));
    send.type = "submit";
    form.appendChild(inputEl);
    form.appendChild(send);
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var v = inputEl.value;
      inputEl.value = "";
      ask(v);
    });
    modal.appendChild(head);
    modal.appendChild(sub);
    modal.appendChild(msgsBox);
    modal.appendChild(chips);
    modal.appendChild(form);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    overlay.addEventListener("click", function (e) { if (e.target === overlay) close(); });
  }

  function open() {
    if (!overlay) build();
    overlay.hidden = false;
    requestAnimationFrame(function () { requestAnimationFrame(function () { overlay.classList.add("show"); }); });
    if (!msgsBox.children.length) {
      var w = addMsg("bot");
      var e = el("div", "ai-entry");
      e.appendChild(el("strong", null, t("ai.greetTitle")));
      e.appendChild(el("p", null, t("ai.greetText")));
      w.appendChild(e);
    }
    setTimeout(function () { if (inputEl) inputEl.focus(); }, 100);
  }
  function close() {
    if (!overlay) return;
    overlay.classList.remove("show");
    setTimeout(function () { overlay.hidden = true; }, 180);
  }

  window.__zefiraSiteAI = { open: open, close: close };
  var askCard = document.getElementById("ask-site-ai");
  if (askCard) {
    askCard.addEventListener("click", function (e) { e.preventDefault(); open(); });
  }
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && overlay && !overlay.hidden) close();
  });
})();
