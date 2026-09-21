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
    fetch("assets/site-knowledge.json?v=2").then(function (r) { return r.json(); }).then(function (j) {
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
    a.href = href;
    if (/^https?:/.test(href)) { a.target = "_blank"; a.rel = "noopener"; }
    parent.appendChild(a);
  }

  function addWallet(parent, label, addr) {
    var r = el("div", "ai-wallet");
    r.appendChild(el("b", null, label));
    var c = el("code", null, addr);
    c.title = addr;
    var btn = el("button", null, "Copy");
    btn.type = "button";
    btn.addEventListener("click", function () {
      var done = function (ok) {
        btn.textContent = ok ? "Copied ✓" : "Copy failed";
        setTimeout(function () { btn.textContent = "Copy"; }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(addr).then(function () { done(true); }, function () { done(false); });
      } else done(false);
    });
    r.appendChild(c);
    r.appendChild(btn);
    parent.appendChild(r);
  }

  function addEntry(parent, entry, faMode) {
    var box = el("div", "ai-entry");
    box.appendChild(el("strong", null, entry.title));
    var body = (faMode && entry.fa) ? (entry.fa + "\n\n" + entry.text) : entry.text;
    body.split(/\n\n+/).forEach(function (para) {
      box.appendChild(el("p", null, para));
    });
    (entry.wallets || []).forEach(function (w) { addWallet(box, w.label, w.addr); });
    (entry.links || []).forEach(function (l) { addLinkBtn(box, l.label, l.href); });
    parent.appendChild(box);
  }

  function addRefusal(parent) {
    var box = el("div", "ai-entry");
    box.appendChild(el("strong", null, "Out of scope"));
    box.appendChild(el("p", null, "I only answer Zefira site and panel questions — docs, setup, donating, changelog, GitHub. Ask me about those, or try the channels below."));
    addLinkBtn(box, "Support page", "support.html");
    addLinkBtn(box, "FAQ", "faq.html");
    addLinkBtn(box, "Community Q&A", "https://github.com/mrlurix/zefira-panel/discussions");
    parent.appendChild(box);
  }

  function addMsg(cls) {
    var m = el("div", "ai-msg " + cls);
    msgsBox.appendChild(m);
    msgsBox.scrollTop = msgsBox.scrollHeight;
    return m;
  }

  function answerInner(q, faMode, box, kb) {
    if (/^(hi|hello|hey|salam|سلام|درود|yo)\b/i.test(q.trim())) {
      var w = el("div", "ai-entry");
      w.appendChild(el("strong", null, faMode ? "سلام! من دستیار سایت زفیرا هستم" : "Hi! I'm the Zefira site assistant"));
      w.appendChild(el("p", null, faMode
        ? "فقط درباره سایت، داکس، پنل، دونیت، changelog و گیت‌هاب جواب می‌دهم. بپرس:"
        : "I answer Zefira site/panel questions only — docs, setup, donating, changelog, GitHub. Try:"));
      parentChips(w);
      box.appendChild(w);
      return;
    }
    if (!kb || !kb.length) {
      box.appendChild(el("p", null, "Knowledge base failed to load. Try the support page instead."));
      addLinkBtn(box, "Support page", "support.html");
      return;
    }
    var hits = rank(q);
    if (!hits.length || hits[0].score < 3) { addRefusal(box); return; }
    hits.forEach(function (h) { addEntry(box, h.e, faMode); });
    msgsBox.scrollTop = msgsBox.scrollHeight;
  }

  function parentChips(parent) {
    var chips = ["How do I donate?", "What is new in the changelog?", "What is the Zefira panel?"];
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
        answerInner(q, /[\u0600-\u06FF]/.test(q), box, kb);
      } catch (err) {
        box.appendChild(el("p", null, "Something broke on my side (" + String((err && err.message) || err).slice(0, 120) + "). Try the support page instead."));
        addLinkBtn(box, "Support page", "support.html");
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
    head.appendChild(el("b", null, "Zefira site assistant"));
    var x = el("button", "ai-x", "×");
    x.type = "button";
    x.setAttribute("aria-label", "Close");
    x.addEventListener("click", close);
    head.appendChild(x);
    var sub = el("div", "ai-sub", "Docs-powered answers. Offline, no account, no key.");
    msgsBox = el("div", "ai-msgs");
    var chips = el("div", "ai-chips");
    ["How do I donate?", "What is new?", "Install help"].forEach(function (c) {
      var b = el("button", null, c);
      b.type = "button";
      b.addEventListener("click", function () { ask(c); });
      chips.appendChild(b);
    });
    var form = el("form", "ai-form");
    inputEl = document.createElement("input");
    inputEl.type = "text";
    inputEl.placeholder = "Ask about the site, panel, donating…";
    inputEl.setAttribute("aria-label", "Ask about the site");
    inputEl.maxLength = 500;
    inputEl.autocomplete = "off";
    var send = el("button", "ai-send", "Send");
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
      e.appendChild(el("strong", null, "Hi! I'm the Zefira site assistant"));
      e.appendChild(el("p", null, "I answer from these docs only: donating, changelog, GitHub, panel features, install, subscriptions, troubleshooting."));
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
