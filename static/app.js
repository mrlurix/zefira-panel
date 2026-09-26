"use strict";

const $ = (sel, root = document) => root.querySelector(sel);

const PROTO_LABEL = {
  vless: "VLESS",
  reality: "REALITY",
  vmess: "VMess",
  trojan: "Trojan",
  ss: "Shadowsocks",
  hysteria2: "Hysteria2",
  wireguard: "WireGuard",
  openvpn: "OpenVPN",
  l2tp: "L2TP/IPsec",
  cisco: "Cisco AnyConnect",
  socks5: "SOCKS5"
};
function eventName(ev) {
  const k = "event." + ev;
  const v = t(k);
  return v === k ? ev : v;
}

let USERS_CACHE = [];
let SORT_MODE = "newest";

// One in-flight submit per form: a double-click / double-Enter fired two
// POSTs (duplicate rows, 409s, and burned rate-limit budget). Wraps the
// form's submit button: disabled while the handler awaits, restored after.
function guardSubmit(form) {
  if (form.__busy) return false;
  form.__busy = true;
  const btn = form.querySelector('button[type="submit"], button:not([type])');
  if (btn) { btn.disabled = true; form.__busyBtn = btn; }
  return true;
}
function releaseSubmit(form) {
  form.__busy = false;
  if (form.__busyBtn) { form.__busyBtn.disabled = false; form.__busyBtn = null; }
}

// Same in-flight guard for click buttons (add inbound/node/block/token).
function guardBtn(btn) {
  if (!btn || btn.disabled) return false;
  btn.disabled = true;
  return true;
}

let numFmt = new Intl.NumberFormat("en-US");
let dateFmt = new Intl.DateTimeFormat("en-US", { year: "numeric", month: "short", day: "2-digit" });
let dateTimeFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
function refreshI18nFormats() {
  try {
    const tag = zLocaleTag();
    numFmt = new Intl.NumberFormat(tag);
    dateFmt = new Intl.DateTimeFormat(tag, { year: "numeric", month: "short", day: "2-digit" });
    dateTimeFmt = new Intl.DateTimeFormat(tag, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  } catch (_) {}
}

async function api(url, opts = {}) {
  opts.headers = Object.assign({ "X-Requested-With": "XMLHttpRequest" }, opts.headers || {});
  if (opts.body && typeof opts.body !== "string") {
    opts.body = JSON.stringify(opts.body);
    opts.headers["Content-Type"] = "application/json";
  }
  const res = await fetch(url, Object.assign({ credentials: "same-origin" }, opts));
  if (res.status === 401) {
    location.href = "/login";
    throw new Error("auth");
  }
  let data = null;
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    const d = data && data.detail;
    let msg = Array.isArray(d)
      ? d.map((x) => (typeof x === "object" && x.msg ? x.msg : JSON.stringify(x))).join(", ")
      : (d && typeof d === "object" && d.message) || d || `Error (${res.status})`;
    // Cap raw backend text: a multi-error 422 would otherwise fill the
    // screen with an unlocalized wall of text.
    msg = String(msg);
    if (msg.length > 220) msg = msg.slice(0, 220) + "…";
    throw new Error(msg);
  }
  return data;
}

// Numeric input helper. parseInt/parseFloat were used for number fields, so
// "1e3" became 1 (wrong quota) and `parseInt(port) || 443` silently rewrote a
// typed 0 into 443. Number() keeps exponent notation honest; junk -> NaN,
// which every caller already validates.
function numInput(v) {
  const s = String(v == null ? "" : v).trim();
  if (!s) return NaN;
  return Number(s);
}

// window.open() downloads bypass the api() 401→login redirect (expired
// session would show raw JSON in a new tab). Pre-flight the session first.
async function ensureAuth() {
  // Only an explicit successful /api/me proves the session: network
  // failures and expired sessions both return false (expired sessions
  // already redirect to /login inside api()).
  try { await api("/api/me"); return true; }
  catch (_) { return false; }
}

// Download/open helper: window.open() after an await is a popup-blocker
// target (the user got "popup blocked" and no file). Pre-open a blank tab
// synchronously, then navigate it; if that is blocked, fall back to a
// same-tab anchor download so the guide/config still arrives.
function openDownload(url) {
  let w = null;
  try { w = window.open("", "_blank"); } catch (_) { w = null; }
  if (w) {
    try { w.location.href = url; } catch (_) { /* cross-origin edge */ }
    return true;
  }
  const a = document.createElement("a");
  a.href = url;
  a.target = "_blank";
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  return false;
}

function toast(msg, ok = true) {
  const box = document.getElementById("toast-box");
  const el = document.createElement("div");
  el.className = "toast" + (ok ? "" : " err");
  el.textContent = msg;
  box.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 400);
  }, 3200);
}

// Clipboard with fallback: navigator.clipboard only exists in secure
// contexts (https/localhost). Over plain http://IP it is undefined and
// every copy button silently died — fall back to select+execCommand.
async function copyText(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    throw new Error("no clipboard API");
  } catch (_) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "0";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return !!ok;
    } catch (_) {
      return false;
    }
  }
}

function daysLeft(isoZ) {
  return Math.ceil((new Date(isoZ).getTime() - Date.now()) / 86400000);
}
// datetime-local pickers are wall-clock (local zone) while the server
// speaks UTC: convert explicitly both ways so table and modal agree.
function utcToLocalInput(isoZ) {
  const d = new Date(isoZ);
  if (isNaN(d.getTime())) return "";
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
function localInputToUtc(v) {
  const d = new Date(v);
  if (isNaN(d.getTime())) return "";
  return d.toISOString().slice(0, 16);
}
function badge(text, cls) {
  const s = document.createElement("span");
  s.className = "badge " + cls;
  s.textContent = text;
  return s;
}
function expiryBadge(u) {
  if (!u.is_active) return badge(t("badge.disabled"), "off");
  // Pending users have a far-future sentinel expiry, not a real date:
  // never render "30000 days" or year-2108 for them.
  if (u.pending_start) return badge(t("badge.notStarted"), "pending");
  // Null/invalid expiry (hand-edited row): Expired badge, never 1970 or a
  // RangeError that blanks the whole table.
  const d = u.expires_at ? daysLeft(u.expires_at) : NaN;
  if (!Number.isFinite(d) || d <= 0) return badge(t("badge.expired"), "expired");
  if (d <= 7) return badge(t("badge.expSoon", {d}), "warn");
  return badge(t("badge.expSoon", {d}), "ok");
}
function statusBadge(u) {
  if (!u.is_active) return badge(t("badge.paused"), "off");
  if (u.pending_start) return badge(t("badge.notStarted"), "pending");
  // Expired first (same order as the sub page + CSV): an expired AND
  // over-quota user reads Expired everywhere, not Limited here.
  if (!u.expires_at || daysLeft(u.expires_at) <= 0) return badge(t("badge.expired"), "expired");
  if ((Number(u.used_gb) || 0) >= (Number(u.volume_gb) || 0)) return badge(t("badge.limited"), "limited");
  return badge(t("badge.active"), "ok");
}
function protoBadges(list) {
  const wrap = document.createElement("span");
  wrap.className = "proto-wrap";
  const show = list.slice(0, 3);
  show.forEach((p) => {
    const s = document.createElement("span");
    s.className = "badge proto";
    s.textContent = PROTO_LABEL[p] || p;
    wrap.appendChild(s);
  });
  if (list.length > 3) {
    const more = document.createElement("span");
    more.className = "badge proto";
    more.textContent = "+" + (list.length - 3);
    wrap.appendChild(more);
  }
  return wrap;
}

function volumeCell(u) {
  const wrap = document.createElement("div");
  wrap.className = "vol";
  // Number() guards: a hand-edited NULL row must degrade, never throw and
  // blank the entire table (backend coerces too; this is the last gate).
  const used = Number(u.used_gb) || 0, vol = Number(u.volume_gb) || 0;
  const label = document.createElement("span");
  label.className = "vol-label";
  label.textContent = `${used.toFixed(1)} / ${vol.toFixed(1)} GB`;
  const bar = document.createElement("div");
  bar.className = "bar";
  const fill = document.createElement("div");
  fill.className = "fill";
  const pct = vol > 0 ? Math.min(100, (used / vol) * 100) : 0;
  fill.style.width = pct + "%";
  if (pct >= 90) fill.classList.add("danger");
  bar.appendChild(fill);
  wrap.appendChild(label);
  wrap.appendChild(bar);
  return wrap;
}

const ICONS = {
  copy: '<svg viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
  qr: '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20v.01M17.5 17.5h3v3h-3z"/></svg>',
  download: '<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/></svg>',
  refresh: '<svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-2.64-6.36L21 8"/><path d="M21 3v5h-5"/></svg>',
  toggleOff: '<svg viewBox="0 0 24 24"><rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/></svg>',
  toggleOn: '<svg viewBox="0 0 24 24"><path d="M6 5l14 7-14 7z"/></svg>',
  edit: '<svg viewBox="0 0 24 24"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>',
  trash: '<svg viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>'
};

function iconBtn(title, svgPath, cls = "") {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "row-btn " + cls;
  b.title = title;
  b.innerHTML = svgPath;
  return b;
}

function userRow(u) {
  const tr = document.createElement("tr");

  const st = document.createElement("td");
  st.appendChild(statusBadge(u));

  const unTd = document.createElement("td");
  const unWrap = document.createElement("div");
  unWrap.className = "user-cell";
  const strong = document.createElement("strong");
  strong.textContent = u.username;
  unWrap.appendChild(strong);
  unWrap.appendChild(protoBadges(u.protocols || []));
  if (u.device_limit) {
    const dev = document.createElement("span");
    dev.className = "badge proto";
    dev.textContent = t("devBadge", {n: u.device_limit});
    dev.title = t("devTitle", {n: u.device_limit});
    unWrap.appendChild(dev);
  }
  unTd.appendChild(unWrap);

  const note = document.createElement("td");
  note.className = "muted";
  note.textContent = u.note || "\u2014";

  const vol = document.createElement("td");
  vol.appendChild(volumeCell(u));

  const exp = document.createElement("td");
  exp.className = "exp-cell";
  exp.appendChild(expiryBadge(u));
  const dateSmall = document.createElement("small");
  // Guarded: a null/garbage expires_at used to throw a RangeError here,
  // AFTER the table body was cleared - one bad row blanked every user.
  const expDate = u.pending_start ? null : new Date(u.expires_at);
  dateSmall.textContent = (!expDate || isNaN(expDate.getTime())) ? "\u2014" : dateFmt.format(expDate);
  exp.appendChild(dateSmall);

  const act = document.createElement("td");
  const editBtn = iconBtn(t("icon.editUser"), ICONS.edit, "");
  editBtn.dataset.act = "edit";
  editBtn.dataset.id = u.id;
  const qrBtn = iconBtn(t("icon.qr"), ICONS.qr, "accent");
  qrBtn.dataset.act = "qr";
  qrBtn.dataset.id = u.id;
  const copyBtn = iconBtn(t("icon.copySub"), ICONS.copy, "accent");
  copyBtn.dataset.act = "copy";
  copyBtn.dataset.id = u.id;
  const dlBtn = iconBtn(t("icon.dl"), ICONS.download, "accent");
  dlBtn.dataset.act = "download";
  dlBtn.dataset.id = u.id;
  const toggleBtn = iconBtn(
    u.is_active ? t("icon.pause") : t("icon.enable"),
    u.is_active ? ICONS.toggleOff : ICONS.toggleOn,
    u.is_active ? "warn" : "good"
  );
  toggleBtn.dataset.act = "toggle";
  toggleBtn.dataset.id = u.id;
  const resetBtn = iconBtn(t("icon.reset"), ICONS.refresh);
  resetBtn.dataset.act = "reset";
  resetBtn.dataset.id = u.id;
  const delBtn = iconBtn(t("icon.delete"), ICONS.trash, "bad");
  delBtn.dataset.act = "del";
  delBtn.dataset.id = u.id;
  delBtn.dataset.name = u.username;
  act.append(editBtn, qrBtn, copyBtn, dlBtn, toggleBtn, resetBtn, delBtn);

  tr.append(st, unTd, note, vol, exp, act);
  return tr;
}

function applySort(items) {
  const arr = [...items];
  if (SORT_MODE === "expiry") {
    arr.sort((a, b) => new Date(a.expires_at || "2099-01-01") - new Date(b.expires_at || "2099-01-01"));
  } else if (SORT_MODE === "usage") {
    // Math.max(volume, 1) was a divide-by-zero guard that CLAMPED UP, so every
    // plan under 1 GB was scored as if it were 1 GB: a 0.5/0.4 GB user (80 %
    // used) sorted below a 2/1 GB user (50 %), while the usage bar right next
    // to it showed the opposite.
    const ratio = (u) => u.used_gb / (Number(u.volume_gb) || 1);
    arr.sort((a, b) => ratio(b) - ratio(a));
  } else if (SORT_MODE === "name") {
    arr.sort((a, b) => a.username.localeCompare(b.username));
  } else {
    arr.sort((a, b) => b.id - a.id);
  }
  return arr;
}

function renderUserTable(items) {
  const tbody = $("#users-tbody");
  tbody.textContent = "";
  for (const u of applySort(items)) tbody.appendChild(userRow(u));
}

let usersSeq = 0;
let usersTotal = 0;
async function loadUsers(q = "") {
  // Last-issued query wins: a slow earlier fetch must not overwrite the
  // table with stale rows for a superseded query.
  const my = ++usersSeq;
  try {
    const data = await api("/api/users?q=" + encodeURIComponent(q));
    if (my !== usersSeq) return;
    USERS_CACHE = data.items;
    usersTotal = data.total || data.items.length;
    renderUserTable(USERS_CACHE);
    $("#empty-state").classList.toggle("hidden", data.items.length > 0);
    const trunc = document.getElementById("users-truncated");
    if (trunc) {
      const show = usersTotal > data.items.length;
      trunc.classList.toggle("hidden", !show);
      if (show) trunc.textContent = t("msg.showingOf", {n: data.items.length, total: usersTotal});
    }
    renderRecent([...USERS_CACHE].sort((a, b) => b.id - a.id).slice(0, 5));
  } catch (e) {
    if (e.message !== "auth") toast(e.message, false);
  }
}

function renderRecent(items) {
  const tbody = $("#recent-tbody");
  tbody.textContent = "";
  if (!items.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "muted";
    td.textContent = t("users.empty");
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const u of items) {
    const tr = document.createElement("tr");
    const c1 = document.createElement("td");
    const b = document.createElement("strong");
    b.textContent = u.username;
    c1.appendChild(b);
    const c2 = document.createElement("td");
    c2.appendChild(protoBadges(u.protocols || []));
    const c3 = document.createElement("td");
    c3.textContent = `${(Number(u.volume_gb) || 0).toFixed(0)} GB`;
    const c4 = document.createElement("td");
    const expD = u.pending_start ? null : new Date(u.expires_at || "");
    c4.textContent = expD && !isNaN(expD.getTime()) ? dateFmt.format(expD) : "—";
    const c5 = document.createElement("td");
    c5.appendChild(statusBadge(u));
    tr.append(c1, c2, c3, c4, c5);
    tbody.appendChild(tr);
  }
}

async function loadStats() {
  try {
    const s = await api("/api/stats");
    $("#s-total").textContent = numFmt.format(s.total_users);
    $("#s-active").textContent = numFmt.format(s.active_users);
    $("#s-expired").textContent = numFmt.format(s.expired_users);
    $("#s-disabled").textContent = numFmt.format(s.disabled_users);
    $("#s-soon").textContent =
      (s.expiring_soon > 0 ? t("dash.soonExpire", {n: s.expiring_soon}) : "") +
      (s.pending_start > 0 ? `${s.expiring_soon > 0 ? " · " : ""}` + t("dash.soonPending", {n: s.pending_start}) : "") +
      (s.limited_users > 0 ? `${s.expiring_soon + s.pending_start > 0 ? " · " : ""}` + t("dash.soonLimited", {n: s.limited_users}) : "");
    $("#s-volume").textContent = numFmt.format(Math.round(s.volume_total_gb)) + " GB";
    $("#s-used").textContent = t("dash.usedPre") + " " + (Number(s.used_total_gb) || 0).toFixed(1) + " GB";
  } catch (e) {}
}

async function loadSystem() {
  try {
    const sys = await api("/api/system");
    if (!sys.available) { $("#sys-card").classList.add("hidden"); return; }
    // The card was hidden by an earlier unavailable answer and never came
    // back: a single transient failure hid the System section for the rest
    // of the session.
    $("#sys-card").classList.remove("hidden");
    setBar("#bar-cpu", "#val-cpu", sys.cpu);
    setBar("#bar-mem", "#val-mem", sys.mem);
    setBar("#bar-disk", "#val-disk", sys.disk);
    $("#sys-uptime").textContent = t("dash.uptimePre") + " " + sys.uptime_hours + "h";
  } catch (_) {}
}
function setBar(barSel, valSel, pct) {
  $(barSel).style.width = pct + "%";
  $(barSel).classList.toggle("danger", pct >= 90);
  $(valSel).textContent = pct + "%";
}

document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".section").forEach((s) => s.classList.remove("active"));
    btn.classList.add("active");
    $("#section-" + btn.dataset.section).classList.add("active");
    $("#page-title").textContent = t(btn.dataset.titleKey || "title.dashboard");
    // Stop the update poller when leaving the section: no runaway
    // requests against a restarting server, no overlapping ticks.
    if (typeof updatePoll !== "undefined" && updatePoll && btn.dataset.section !== "update") {
      clearInterval(updatePoll);
      updatePoll = null;
    }
    if (btn.dataset.section === "dashboard") {
      loadStats();
      loadSystem();
      // Keep the visible query: reloading unfiltered left the search box
      // showing the old text while the table (and the CSV export built from
      // the same cache, and the Dashboard "latest users" card) held every row.
      loadUsers($("#search") ? $("#search").value.trim() : "");
    }
    // Anti-Censorship saves through the same #srv-form payload, so its fields
    // must be loaded even when Settings was never opened (blank ports parsed
    // to NaN and the save was rejected).
    if (btn.dataset.section === "reality") { loadSrvSettings(); }
    if (btn.dataset.section === "settings") { loadAudit(); loadSrvSettings(); loadTelegram(); loadSslStatus(); loadAi(); loadApiTokens(); }
    if (btn.dataset.section === "customize") { loadAppearance(); }
    if (btn.dataset.section === "tunnels") { loadNodes(); loadTunnelSettings(); }
    if (btn.dataset.section === "inbounds") loadInbounds();
    if (btn.dataset.section === "nodes") loadSrvNodes();
    if (btn.dataset.section === "update") loadUpdate();
    if (btn.dataset.section === "blocker") loadBlocklist();
  });
});
document.querySelectorAll("[data-goto]").forEach((el) => {
  el.addEventListener("click", () => $(`.nav-btn[data-section="${el.dataset.goto}"]`).click());
});

$("#logout-btn").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (_) {}
  location.href = "/login";
});

const overlay = $("#modal-overlay");
$("#add-user-btn").addEventListener("click", () => { bumpUserFormOp(); loadTemplates(); overlay.classList.remove("hidden"); });
$("#modal-close").addEventListener("click", () => { bumpUserFormOp(); overlay.classList.add("hidden"); });
overlay.addEventListener("click", (e) => { if (e.target === overlay) { bumpUserFormOp(); overlay.classList.add("hidden"); } });
// Operation generation: a finished add/edit from a modal the operator already
// closed used to reset+close the modal they had since reopened, wiping the
// new form. Each open/submit bumps the counter and only the newest op acts.
let userFormOp = 0;
function bumpUserFormOp() { userFormOp += 1; return userFormOp; }

const qrModal = $("#qr-modal");
$("#qr-close").addEventListener("click", () => qrModal.classList.add("hidden"));
qrModal.addEventListener("click", (e) => { if (e.target === qrModal) qrModal.classList.add("hidden"); });
let currentQrUrl = "";
// Monotonic counter for QR/copy actions: only the newest request may write
// the modal, the image, or the clipboard.
let qrSeq = 0;
$("#qr-copy-btn").addEventListener("click", async () => {
  if (!currentQrUrl) return;
  if (await copyText(currentQrUrl)) toast(t("msg.linkCopied"));
  else toast(t("msg.copyFailed"), false);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { bumpUserFormOp(); overlay.classList.add("hidden"); qrModal.classList.add("hidden"); }
});

$("#add-user-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  if (!guardSubmit(f)) return;
  const myOp = bumpUserFormOp();
  // Every early return must release the form: a validation error used to
  // leave __busy set and the button disabled, so the form only worked again
  // after a full page reload.
  const protos = Array.from(f.querySelectorAll('input[name="proto"]:checked')).map((c) => c.value);
  if (!protos.length) { toast(t("msg.selectProto"), false); releaseSubmit(f); return; }
  const volVal = Number(f.volume.value);
  const daysVal = numInput(f.days.value);
  if (!Number.isFinite(volVal) || volVal <= 0 || !Number.isFinite(daysVal) || daysVal < 1) {
    toast(t("msg.badNumbers"), false);
    releaseSubmit(f);
    return;
  }
  const devVal = numInput(f.device_limit.value);
  try {
    await api("/api/users", {
      method: "POST",
      body: {
        username: f.username.value.trim(),
        protocols: protos,
        volume_gb: volVal,
        days: daysVal,
        note: f.note.value.trim(),
        start_on_first_use: $("#sofu-check").checked,
        device_limit: Number.isFinite(devVal) && devVal >= 1 ? devVal : null
      }
    });
    // The modal was closed/reopened while this request was in flight:
    // resetting and closing it now would destroy the operator's new input.
    if (myOp !== userFormOp) return;
    f.reset();
    f.querySelector('input[value="vless"]').checked = true;
    f.volume.value = 30; f.days.value = 30;
    overlay.classList.add("hidden");
    toast(t("msg.userCreated", {n: protos.length}));
    loadUsers($("#search").value.trim());
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  } finally { releaseSubmit(f); }
});
async function loadTemplates() {
  try {
    const tpls = await api("/api/templates");
    const sel = $("#tpl-select");
    sel.textContent = "";
    const first = document.createElement("option");
    first.value = "";
    first.textContent = t("tpl.loadFirst");
    sel.appendChild(first);
    for (const t of tpls) {
      const o = document.createElement("option");
      o.value = t.id;
      o.textContent = `${t.name} (${t.volume_gb}GB/${t.days}d)`;
      o.dataset.payload = JSON.stringify(t);
      sel.appendChild(o);
    }
  } catch (_) {}
}
$("#tpl-select").addEventListener("change", () => {
  const sel = $("#tpl-select");
  const opt = sel.selectedOptions[0];
  if (!opt || !opt.dataset.payload) return;
  // `tpl`, not `t`: `t` is the translation function and the catch below used
  // t("...") with t undefined -> uncaught TypeError, no toast at all.
  let tpl;
  try { tpl = JSON.parse(opt.dataset.payload); }
  catch (_) { toast(t("msg.badNumbers"), false); return; }
  if (!tpl || !Array.isArray(tpl.protocols)) { toast(t("msg.badNumbers"), false); return; }
  const f = $("#add-user-form");
  f.querySelectorAll('input[name="proto"]').forEach((c) => { c.checked = tpl.protocols.includes(c.value); });
  f.volume.value = tpl.volume_gb;
  f.days.value = tpl.days;
  $("#sofu-check").checked = !!tpl.start_on_first_use;
  f.device_limit.value = tpl.device_limit || "";
});
$("#tpl-save-btn").addEventListener("click", async () => {
  const f = $("#add-user-form");
  const protos = Array.from(f.querySelectorAll('input[name="proto"]:checked')).map((c) => c.value);
  if (!protos.length) { toast(t("msg.tplSelectProto"), false); return; }
  const volVal = numInput(f.volume.value);
  const daysVal = numInput(f.days.value);
  if (!Number.isFinite(volVal) || volVal <= 0 || !Number.isFinite(daysVal) || daysVal < 1) {
    toast(t("msg.badNumbers"), false);
    return;
  }
  const name = (prompt(t("prm.tplName")) || "").trim();
  if (!name) return;
  try {
    await api("/api/templates", {
      method: "POST",
      body: { name, protocols: protos, volume_gb: volVal, days: daysVal, start_on_first_use: $("#sofu-check").checked, device_limit: (() => { const v = numInput(f.device_limit.value); return Number.isFinite(v) && v >= 1 ? v : null; })() }
    });
    toast(t("msg.tplSaved", {name}));
    loadTemplates();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#tpl-del-btn").addEventListener("click", async () => {
  const sel = $("#tpl-select");
  const id = sel.value;
  if (!id) { toast(t("msg.tplSelectDel"), false); return; }
  if (!confirm(t("cfm.tplDelete", {name: sel.selectedOptions[0].textContent}))) return;
  try {
    await api("/api/templates/" + id, { method: "DELETE" });
    toast(t("msg.tplDeleted"));
    loadTemplates();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

let searchTimer;
$("#search").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadUsers($("#search").value.trim()), 300);
});

$("#sort-sel").addEventListener("change", () => {
  SORT_MODE = $("#sort-sel").value;
  renderUserTable(USERS_CACHE);
});

$("#export-csv-btn").addEventListener("click", () => {
  if (!USERS_CACHE.length) { toast(t("msg.noUsersExport"), false); return; }
  const safeCell = (v) => {
    // Normalize fullwidth ASCII (＝+＠) and strip bidi controls first:
    // otherwise U+FF1D/= look-alikes and U+202E overrides dodge the
    // formula-prefix guard below (quoted, so no breakage — only spoofing).
    let s = String(v).normalize("NFKC").replace(/[‮‭‪‬⁦⁧]/g, "");
    return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  };
  const rows = [["username", "protocols", "volume_gb", "used_gb", "expires_at", "status", "note"]];
  for (const u of applySort(USERS_CACHE)) {
    // Same order as statusBadge()/the subscription page: expired wins over
    // limited. The CSV used to report "limited" for an account that is both.
    const expDays = u.expires_at ? daysLeft(u.expires_at) : NaN;
    const expired = !Number.isFinite(expDays) || expDays <= 0;
    const limited = (Number(u.used_gb) || 0) >= (Number(u.volume_gb) || 0);
    rows.push([
      u.username,
      (u.protocols || []).join("|"),
      u.volume_gb,
      u.used_gb,
      u.expires_at && !u.pending_start ? u.expires_at : "on-first-use",
      !u.is_active ? "disabled" : u.pending_start ? "pending" : expired ? "expired" : limited ? "limited" : "active",
      (u.note || "").replace(/[\r\n,]/g, " ")
    ]);
  }
  const csv = rows.map((r) => r.map((c) => `"${String(safeCell(c)).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob(["\ufeff" + csv], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "zefira-users.csv";
  a.click();
  URL.revokeObjectURL(a.href);
  const n = rows.length - 1;
  // Never claim completeness when the backend truncated at 500: the notice
  // above the table says the same.
  toast(usersTotal > n ? t("msg.exportedOf", {n, total: usersTotal}) : t("msg.exported", {n}));
});

$("#users-table").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  const id = btn.dataset.id;
  try {
    if (btn.dataset.act === "edit") {
      const u = USERS_CACHE.find((x) => String(x.id) === String(id));
      if (!u) { toast(t("msg.badNumbers"), false); loadUsers($("#search").value.trim()); return; }
      $("#edit-uname").textContent = u.username;
      const f = $("#edit-user-form");
      f.note.value = u.note || "";
      f.volume.value = u.volume_gb;
      f.expires.value = u.pending_start ? "" : utcToLocalInput(u.expires_at);
      f.device_limit.value = u.device_limit || "";
      f.reset_used.checked = false;
      f.dataset.uid = id;
      $("#edit-modal").classList.remove("hidden");
      return;
    }
    if (btn.dataset.act === "copy") {
      // Fetch the server-built URL (respects custom SUBSCRIPTION_PATH);
      // a location.origin + "/sub/" guess 404s for renamed paths.
      try {
        const seq = ++qrSeq;
        const d = await api(`/api/users/${id}/qr`);
        // A slower earlier request used to overwrite the newer action
        // (copy A, click B, then A's answer lands: B's URL on screen).
        if (seq !== qrSeq) return;
        if (await copyText(d.url)) toast(t("msg.subCopied"));
        else toast(t("msg.copyFailed"), false);
      } catch (err) { if (err.message !== "auth") toast(err.message, false); }
      return;
    }
    if (btn.dataset.act === "download") {
      // Check the WireGuard key BEFORE opening: otherwise the warning
      // always arrives after the download already started.
      let blocked = false;
      try {
        const u = (typeof USERS_CACHE !== "undefined" ? USERS_CACHE : []).find((x) => String(x.id) === String(id));
        if (u && (u.protocols || []).includes("wireguard")) {
          const srv = await api("/api/settings");
          if (!srv.wg_pub) {
            // Say what actually happened: nothing was downloaded.
            toast(t("msg.wgKeyWarn"), false);
            blocked = true;
          }
        }
      } catch (_) {}
      if (blocked) return;
      if (!(await ensureAuth())) return;
      openDownload(`/api/users/${id}/config`);
      return;
    }
    if (btn.dataset.act === "qr") {
      const seq = ++qrSeq;
      const d = await api(`/api/users/${id}/qr`);
      if (seq !== qrSeq) return;   // a newer QR/copy action won
      currentQrUrl = d.url;
      $("#user-qr-img").src = "data:image/svg+xml;base64," + d.qr_b64;
      $("#qr-url").textContent = d.url;
      qrModal.classList.remove("hidden");
      return;
    }
    if (btn.dataset.act === "toggle") {
      const isActive = btn.classList.contains("warn");
      await api("/api/users/" + id, { method: "PATCH", body: { is_active: !isActive } });
      toast(isActive ? t("msg.paused") : t("msg.enabled"));
    } else if (btn.dataset.act === "reset") {
      if (!confirm(t("cfm.userReset"))) return;
      // confirm() only blocks the dialog; a second click during the request
      // rotated the token twice (the first link was already dead).
      if (!guardBtn(btn)) return;
      // Always hand the button back: without this a failed request (409/500,
      // or the network dropping) left that row's icon greyed out for good and
      // the list unrefreshed, so the action was dead until you navigated away.
      try {
        await api("/api/users/" + id + "/reset-token", { method: "POST" });
        toast(t("msg.tokenRegen"));
      } finally {
        btn.disabled = false;
      }
    } else if (btn.dataset.act === "del") {
      if (!confirm(t("cfm.userDelete", {name: btn.dataset.name}))) return;
      if (!guardBtn(btn)) return;
      try {
        await api("/api/users/" + id, { method: "DELETE" });
        toast(t("msg.userDeleted"));
      } finally {
        btn.disabled = false;
      }
    }
    loadUsers($("#search").value.trim());
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
    loadUsers($("#search").value.trim());
  }
});

$("#pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  if (!guardSubmit(f)) return;
  if (f.new1.value !== f.new2.value) {
    toast(t("msg.pwMismatch"), false);
    releaseSubmit(f);
    return;
  }
  try {
    const r = await api("/api/change-password", {
      method: "POST",
      body: { current_password: f.current.value, new_password: f.new1.value }
    });
    f.reset();
    // Changing the password revokes every API token: bots must be
    // re-created. Say so instead of silently 401-ing them later.
    toast(r && r.api_tokens_revoked
      ? `${t("msg.pwChanged")} — ${r.api_tokens_revoked} API token(s) revoked`
      : t("msg.pwChanged"));
    loadApiTokens();
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  } finally { releaseSubmit(f); }
});

function applyBrand(name) {
  const b = (name || "").trim() || "ZEFIRA";
  document.querySelectorAll("[data-brand]").forEach((el) => { el.textContent = b; });
  document.title = b + " " + t("brand.panelSuffix");
}

// ---- Menu & dashboard layout ----
const MENU_IDS = ["dashboard", "users", "inbounds", "tunnels", "nodes", "reality", "blocker", "update", "customize", "settings"];
const MENU_LOCKED = ["dashboard", "users", "inbounds", "customize", "settings"];
const DASH_IDS = ["usage", "link", "groups", "apps"];
let MENU_STATE = MENU_IDS.map((id) => ({ id, hidden: false }));
let DASH_STATE = { order: DASH_IDS.slice(), hidden: [] };

function slotMissing(ordered, canonical) {
  const res = ordered.slice();
  const idx = {};
  canonical.forEach((c, i) => { idx[c] = i; });
  const present = new Set(res);
  const original = new Set(res);
  for (const m of canonical) {
    if (present.has(m)) continue;
    const earlier = canonical.slice(0, idx[m]);
    if (earlier.length && earlier.every((c) => original.has(c))) {
      let pos = res.length;
      for (let k = 0; k < res.length; k++) {
        if ((idx[res[k]] !== undefined ? idx[res[k]] : 1e9) > idx[m]) { pos = k; break; }
      }
      res.splice(pos, 0, m);
    } else {
      res.push(m);
    }
    present.add(m);
  }
  return res;
}
function normalizeMenu(v) {
  const out = [], seen = new Set();
  const arr = Array.isArray(v) ? v : [];
  for (const it of arr) {
    if (it && MENU_IDS.includes(it.id) && !seen.has(it.id)) {
      seen.add(it.id);
      out.push({ id: it.id, hidden: !!it.hidden && !MENU_LOCKED.includes(it.id) });
    }
  }
  const ordered = slotMissing(out.map((x) => x.id), MENU_IDS);
  const byId = {};
  out.forEach((x) => { byId[x.id] = x; });
  return ordered.map((id) => byId[id] || { id, hidden: false });
}
function normalizeDash(v) {
  const src = (v && typeof v === "object") ? v : {};
  const order = [], seen = new Set();
  for (const id of Array.isArray(src.order) ? src.order : []) {
    if (DASH_IDS.includes(id) && !seen.has(id)) { seen.add(id); order.push(id); }
  }
  const hidden = Array.isArray(src.hidden) ? src.hidden.filter((id) => DASH_IDS.includes(id)) : [];
  return { order: slotMissing(order, DASH_IDS), hidden };
}
function collectAppearance() {
  return {
    theme_accent: $("#ap-accent").value,
    theme_bg: $("#ap-bg").value,
    theme_card: $("#ap-card").value,
    theme_text: $("#ap-text").value,
    theme_muted: $("#ap-muted").value,
    brand_name: $("#ap-brand").value.trim(),
    dash_note: $("#ap-note").value.trim(),
    menu_layout: JSON.stringify(MENU_STATE),
    dash_layout: JSON.stringify(DASH_STATE)
  };
}
function applyMenuLayout(layout) {
  const first = document.querySelector(".nav-btn");
  if (!first || !Array.isArray(layout)) return;
  const nav = first.parentElement;
  const btns = {};
  nav.querySelectorAll(".nav-btn").forEach((b) => { btns[b.dataset.section] = b; });
  for (const item of layout) {
    const b = btns[item.id];
    if (!b) continue;
    nav.appendChild(b);
    const hide = !!item.hidden;
    b.classList.toggle("hidden", hide);
    const sec = document.getElementById("section-" + item.id);
    if (sec) sec.classList.toggle("hidden", hide);
  }
}
function layoutRow(label, locked, hidden, onUp, onDown, onEye) {
  const li = document.createElement("li");
  li.style.display = "flex";
  li.style.alignItems = "center";
  li.style.gap = "6px";
  const name = document.createElement("span");
  name.textContent = label;
  name.style.flex = "1";
  li.appendChild(name);
  const mk = (label, fn, disabled) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "row-btn mini-btn";
    b.textContent = label;
    b.title = label;
    b.disabled = !!disabled;
    b.style.opacity = disabled ? ".35" : "";
    if (!disabled) b.addEventListener("click", fn);
    li.appendChild(b);
    return b;
  };
  // Boundary arrows were rendered enabled and did nothing on click.
  const up = mk("▲", onUp, onUp === null);
  const down = mk("▼", onDown, onDown === null);
  up.dataset.edge = "up";
  down.dataset.edge = "down";
  const eye = mk(hidden ? t("menu.hide") : t("menu.show"), onEye, locked);
  if (locked) eye.title = t("menu.lockedNote");
  return li;
}
// Layout autosave runs one request per click. Two fast clicks (Up then Down)
// could land out of order and persist the pre-click order permanently, so
// saves are serialized and coalesced: only the newest payload is sent.
let layoutSaveChain = Promise.resolve();
let layoutSavePending = null;
async function saveLayout(silent) {
  const body = collectAppearance();
  layoutSavePending = body;
  layoutSaveChain = layoutSaveChain.then(async () => {
    const payload = layoutSavePending;
    layoutSavePending = null;
    if (!payload) return;
    try {
      await api("/api/appearance", { method: "PUT", body: payload });
      if (!silent) toast(t("msg.layoutSaved"));
    } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  });
  return layoutSaveChain;
}
function renderMenuLayout() {
  const ul = $("#menu-layout-list");
  ul.textContent = "";
  MENU_STATE.forEach((item, i) => {
    const locked = MENU_LOCKED.includes(item.id);
    ul.appendChild(layoutRow(
      t("menu." + item.id),
      locked,
      item.hidden,
      i > 0 ? () => { const t = MENU_STATE[i - 1]; MENU_STATE[i - 1] = item; MENU_STATE[i] = t; afterMenuChange(); } : null,
      i < MENU_STATE.length - 1 ? () => { const t = MENU_STATE[i + 1]; MENU_STATE[i + 1] = item; MENU_STATE[i] = t; afterMenuChange(); } : null,
      () => { if (!locked) { item.hidden = !item.hidden; afterMenuChange(); } }
    ));
  });
}
function afterMenuChange() {
  renderMenuLayout();
  applyMenuLayout(MENU_STATE);
  // If the section being viewed was just hidden, its pane goes blank
  // with no visible nav entry: fall back to Dashboard.
  const activeHidden = document.querySelector(".section.active.hidden");
  if (activeHidden) {
    const dash = document.querySelector('.nav-btn[data-section="dashboard"]');
    if (dash) dash.click();
  }
  saveLayout(true);
}
function renderDashLayout() {
  const ul = $("#dash-layout-list");
  ul.textContent = "";
  DASH_STATE.order.forEach((id, i) => {
    const hidden = DASH_STATE.hidden.includes(id);
    ul.appendChild(layoutRow(
      t("dlayout." + id),
      false,
      hidden,
      i > 0 ? () => {
        const o = DASH_STATE.order.slice();
        const t = o[i - 1]; o[i - 1] = o[i]; o[i] = t;
        DASH_STATE.order = o;
        afterDashChange();
      } : null,
      i < DASH_STATE.order.length - 1 ? () => {
        const o = DASH_STATE.order.slice();
        const t = o[i + 1]; o[i + 1] = o[i]; o[i] = t;
        DASH_STATE.order = o;
        afterDashChange();
      } : null,
      () => {
        const h = DASH_STATE.hidden.slice();
        const k = h.indexOf(id);
        if (k >= 0) h.splice(k, 1); else h.push(id);
        DASH_STATE.hidden = h;
        afterDashChange();
      }
    ));
  });
}
function afterDashChange() {
  renderDashLayout();
  saveLayout(true);
}
async function loadAppearance() {
  try {
    const a = await api("/api/appearance");
    $("#ap-accent").value = /^#[0-9a-fA-F]{6}$/.test(a.theme_accent || "") ? a.theme_accent : "#ff2740";
    $("#ap-bg").value = /^#[0-9a-fA-F]{6}$/.test(a.theme_bg || "") ? a.theme_bg : "#06060a";
    $("#ap-card").value = /^#[0-9a-fA-F]{6}$/.test(a.theme_card || "") ? a.theme_card : "#10101a";
    $("#ap-text").value = /^#[0-9a-fA-F]{6}$/.test(a.theme_text || "") ? a.theme_text : "#ececf2";
    $("#ap-muted").value = /^#[0-9a-fA-F]{6}$/.test(a.theme_muted || "") ? a.theme_muted : "#8b8c9e";
    $("#ap-brand").value = a.brand_name === "ZEFIRA" ? "" : (a.brand_name || "");
    $("#ap-note").value = a.dash_note || "";
    applyBrand(a.brand_name);
    MENU_STATE = normalizeMenu(a.menu_layout);
    DASH_STATE = normalizeDash(a.dash_layout);
    renderMenuLayout();
    renderDashLayout();
    applyMenuLayout(MENU_STATE);
  } catch (_) {}
}
$("#ap-save-btn").addEventListener("click", async () => {
  try {
    const r = await api("/api/appearance", { method: "PUT", body: collectAppearance() });
    applyBrand(r.brand_name);
    toast(t("msg.appearanceSaved"));
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#ap-reset-btn").addEventListener("click", async () => {
  if (!confirm(t("cfm.appearanceReset"))) return;
  try {
    // Full reset: colors/brand/note AND menu/dashboard layouts back to
    // defaults (collectAppearance would otherwise re-save the customized
    // layouts, silently keeping half the customization).
    const body = collectAppearance();
    body.theme_accent = ""; body.theme_bg = ""; body.theme_card = "";
    body.theme_text = ""; body.theme_muted = "";
    body.brand_name = ""; body.dash_note = "";
    body.menu_layout = JSON.stringify(MENU_IDS.map((id) => ({ id, hidden: false })));
    body.dash_layout = JSON.stringify({ order: DASH_IDS.slice(), hidden: [] });
    const r = await api("/api/appearance", { method: "PUT", body });
    applyBrand(r.brand_name);
    loadAppearance();
    toast(t("msg.appearanceReset"));
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

// Loader generation counters. Without them a slow earlier response overwrote
// whatever the operator had typed/saved in the meantime (stale address/port,
// list row vanished after a create, REALITY keys reset to empty).
const seq = {};
function nextSeq(name) {
  seq[name] = (seq[name] || 0) + 1;
  return seq[name];
}
function isCurrent(name, token) {
  return seq[name] === token;
}

async function loadSrvSettings() {
  const token = nextSeq("srv");
  try {
    const srv = await api("/api/settings");
    if (!isCurrent("srv", token)) return;
    const f = $("#srv-form");
    for (const [k, v] of Object.entries(srv)) {
      if (f.elements[k]) {
        if (f.elements[k].type === "checkbox") f.elements[k].checked = String(v) === "1" || v === true;
        else f.elements[k].value = v;
      }
    }
    const rp = document.querySelector('[name="reality_port"]');
    const rs = document.querySelector('[name="reality_sni"]');
    if (rp) rp.value = srv.reality_port;
    if (rs) rs.value = srv.reality_sni;
    const ce = document.querySelector('[name="cdn_enabled"]');
    const cs = document.querySelector('[name="cdn_sni"]');
    if (ce) ce.checked = String(srv.cdn_enabled) === "1" || srv.cdn_enabled === true;
    if (cs) cs.value = srv.cdn_sni || "";
    // The public key is not a secret: "Copy Both Keys" used to copy an EMPTY
    // public_key after a reload because only Generate ever filled it.
    const rpub = document.querySelector('[name="reality_pub"]') || $("#reality-pub");
    if (rpub && srv.reality_pub) {
      rpub.value = srv.reality_pub;
      // ...and the panel holding it must be VISIBLE, otherwise the freshly
      // loaded key sat in a hidden textarea and the only way to reach it was
      // Generate - which ROTATES the server keypair and kills every existing
      // REALITY link.
      $("#reality-out")?.classList.remove("hidden");
    }
    // Keep the preset dropdown in step with the stored SNI: it was only ever
    // written by the user, so after a reload it still read "Akamai" while the
    // field and the server held something else - and Save then persisted the
    // other value.
    const preset = document.getElementById("cdn-preset");
    if (preset) {
      const cur = String(srv.cdn_sni || "");
      preset.value = Array.from(preset.options).some((o) => o.value && o.value === cur) ? cur : "";
    }
  } catch (_) {}
}
document.getElementById("cdn-preset")?.addEventListener("change", (e) => {
  if (e.target.value) document.querySelector('[name="cdn_sni"]').value = e.target.value;
});

async function saveAllSettings() {
  const f = $("#srv-form");
  const body = {};
  body.domain = f.domain.value.trim();
  // Number(), not parseInt: "1e3" became 1 and every port was truncated.
  body.sub_port = numInput(f.sub_port.value);
  body.hy2_port = numInput(f.hy2_port.value);
  body.wg_port = numInput(f.wg_port.value);
  body.ovpn_port = numInput(f.ovpn_port.value);
  body.l2tp_port = numInput(f.l2tp_port.value) || 1701;
  body.cisco_port = numInput(f.cisco_port.value) || 443;
  body.socks5_port = numInput(f.socks5_port.value) || 1080;
  body.dns = f.dns.value.trim() || "1.1.1.1";
  body.ovpn_proto = f.ovpn_proto.value;
  body.wg_pub = f.wg_pub.value.trim();
  body.reality_port = numInput(document.querySelector('[name="reality_port"]').value) || 443;
  body.reality_sni = document.querySelector('[name="reality_sni"]').value.trim() || "www.yahoo.com,www.samsung.com,www.microsoft.com";
  body.obfuscated_host = f.obfuscated_host.value.trim();
  body.per_user_subdomain = f.per_user_subdomain.checked;
  body.block_direct_ip = f.block_direct_ip.checked;
  body.cdn_enabled = document.querySelector('[name="cdn_enabled"]').checked;
  body.cdn_sni = document.querySelector('[name="cdn_sni"]').value.trim();
  // A NaN port would be sent as null and 422 the whole save; say which field.
  for (const [k, v] of Object.entries(body)) {
    if (k.endsWith("_port") && !Number.isFinite(v)) {
      toast(t("msg.badNumbers"), false);
      return;
    }
  }
  try {
    await api("/api/settings", { method: "PUT", body });
    toast(t("msg.srvSaved"));
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
}
document.getElementById("save-reality-btn")?.addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  if (!guardBtn(btn)) return;
  try { await saveAllSettings(); } finally { btn.disabled = false; }
});
$("#srv-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!guardSubmit(e.target)) return;
  try { await saveAllSettings(); }
  finally { releaseSubmit(e.target); }
});

$("#reality-gen-btn").addEventListener("click", async (e) => {
  if (!confirm(t("cfm.realityGen"))) return;
  const btn = e.currentTarget;
  if (!guardBtn(btn)) return;
  try {
    const d = await api("/api/reality/generate", { method: "POST" });
    $("#reality-pub").value = d.public_key;
    $("#reality-priv").value = d.private_key;
    $("#reality-out").classList.remove("hidden");
    toast(t("msg.realityKeypair"));
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { btn.disabled = false; }
});
$("#reality-reveal-btn").addEventListener("click", async () => {
  try {
    const d = await api("/api/reality/private");
    $("#reality-priv").value = d.private_key;
    $("#reality-out").classList.remove("hidden");
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#reality-copy-btn").addEventListener("click", async () => {
  // The private box is only filled by Generate/Reveal, so after any reload
  // "Copy Both Keys" copied `private_key: ` + an empty line and reported
  // success - the operator then pasted an empty privateKey into Xray and
  // killed REALITY for every user. Fetch it on demand instead.
  let priv = $("#reality-priv").value;
  if (!priv) {
    try {
      const d = await api("/api/reality/private");
      priv = d.private_key || "";
      $("#reality-priv").value = priv;
    } catch (err) {
      if (err.message !== "auth") toast(err.message, false);
      return;
    }
  }
  if (!priv) { toast(t("msg.realityNoPriv"), false); return; }
  const both =
    `private_key: ${priv}\npublic_key: ${$("#reality-pub").value}`;
  if (await copyText(both)) toast(t("msg.keysCopied"));
  else toast(t("msg.copyFailed"), false);
});

async function loadTunnelSettings() {
  const token = nextSeq("tun");
  try {
    const t = await api("/api/tunnel-settings");
    if (!isCurrent("tun", token)) return;
    $("#tunnel-public-url").value = t.public_url || "";
    $("#tunnel-trusted").value = t.trusted_proxies || "";
  } catch (_) {}
}
$("#tunnel-save-btn").addEventListener("click", async () => {
  try {
    await api("/api/tunnel-settings", {
      method: "PUT",
      body: {
        public_url: $("#tunnel-public-url").value.trim(),
        trusted_proxies: $("#tunnel-trusted").value.trim()
      }
    });
    toast(t("msg.tunnelSaved"));
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
});
function nodeStatusText(st) {
  if (st === "online") return "\u25cf " + t("badge.online");
  if (st === "offline") return "\u25cb " + t("badge.offline");
  return "? " + t("badge.unknown");
}

function renderNodes(nodes) {
  const ul = $("#nodes-list");
  ul.textContent = "";
  if (!Array.isArray(nodes)) nodes = [];
  if (!nodes.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = t("msg.noTunnels");
    ul.appendChild(li);
    return;
  }
  for (const n of nodes) {
    const li = document.createElement("li");
    li.style.display = "flex";
    li.style.flexWrap = "wrap";
    li.style.alignItems = "center";
    li.style.gap = "6px";
    const main = document.createElement("span");
    main.textContent = `${n.name} [${n.transport}] ${n.iran_ip} \u21c4 ${n.kharej_ip}:${n.tunnel_port}`;
    const st = document.createElement("small");
    st.textContent = n.status ? nodeStatusText(n.status) : "";
    st.style.color = n.status === "online" ? "var(--green)" : n.status === "offline" ? "var(--red)" : "var(--muted)";
    li.appendChild(main);
    li.appendChild(st);
    const mk = (title, act, cls, id, extraName) => {
      const b = iconBtn(title, ICONS[act === "check" ? "refresh" : act] || ICONS.refresh, cls);
      b.dataset.act = act;
      b.dataset.id = id;
      if (extraName) b.dataset.name = extraName;
      return b;
    };
    li.appendChild(mk(t("icon.checkNode"), "check", "good", n.id));
    li.appendChild(mk(t("icon.copyToken"), "copy", "accent", n.id));
    li.appendChild(mk(t("icon.guide"), "download", "accent", n.id));
    li.appendChild(mk(t("icon.regen"), "refresh", "warn", n.id));
    const delBtn = iconBtn(t("icon.delTunnel"), ICONS.trash, "bad");
    delBtn.dataset.act = "del-node";
    delBtn.dataset.id = n.id;
    delBtn.dataset.name = n.name;
    li.appendChild(delBtn);
    ul.appendChild(li);
  }
}

async function loadNodes() {
  const token = nextSeq("nodes");
  try {
    const rows = await api("/api/nodes");
    if (!isCurrent("nodes", token)) return;
    renderNodes(rows);
  } catch (_) {}
}

// The setup guide is fetched with window.open (a plain navigation, so the
// session cookie decides - not the api() 401 handling). A window.open issued
// from a setTimeout is outside the click's user-gesture task, so the popup
// blocker eats it silently: the button said "create + get guide" and the
// operator got neither the file nor an error. Say so.
function openGuide(url) {
  if (!openDownload(url)) toast(t("msg.popupBlocked"), false);
}

$("#node-create-btn").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  const name = $("#node-name").value.trim();
  const iran = $("#node-iran").value.trim();
  const kharej = $("#node-kharej").value.trim();
  if (!name || !iran || !kharej) { toast(t("msg.fillTunnel"), false); return; }
  if (!guardBtn(btn)) return;
  try {
    const node = await api("/api/nodes", {
      method: "POST",
      body: {
        name,
        transport: $("#node-transport").value,
        iran_ip: iran,
        kharej_ip: kharej,
        // Validated here too: a NaN serialises to null and the schema field
        // is a plain int, so the operator saw a raw pydantic message.
        tunnel_port: (() => {
          const tp = numInput($("#node-tport").value);
          if (!Number.isFinite(tp) || tp < 1 || tp > 65535) {
            throw new Error(t("msg.badNumbers"));
          }
          return tp;
        })(),
        forwarded_ports: $("#node-fports").value.trim(),
        udp_forward: $("#node-udp").checked
      }
    });
    if (!await copyText(node.token_once)) prompt(t("prm.tokenOnce"), node.token_once);
    toast(t("msg.tunnelCreated"));
    $("#node-name").value = ""; $("#node-iran").value = ""; $("#node-kharej").value = "";
    loadNodes();
    setTimeout(() => openGuide(`/api/nodes/${node.id}/guide`), 500);
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { btn.disabled = false; }
});

$("#nodes-list").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  const id = btn.dataset.id;
  try {
    if (btn.dataset.act === "check") {
      const n = await api(`/api/nodes/${id}/check`, { method: "POST" });
      if (n.status === "online") {
        toast(t("msg.nodeOnline", {ip: n.iran_ip, port: n.tunnel_port}) + (n.latency_ms != null ? ` (${n.latency_ms}ms)` : ""));
      } else {
        // Distinguish bad host/DNS from host-down: same msg, reason appended.
        toast(t("msg.nodeOffline") + (n.reason ? ` (${n.reason})` : ""), false);
      }
      loadNodes();
    } else if (btn.dataset.act === "copy") {
      const r = await api(`/api/nodes/${id}/reveal-token`, { method: "POST" });
      if (await copyText(r.token)) toast(t("msg.tokenCopiedSame"));
      else {
        // Copy failed: the fallback prompt is the only way to keep the token.
        // Claiming "copied" while the prompt was dismissed lost it for good.
        prompt(t("prm.tokenOnce"), r.token);
        toast(t("msg.copyFailed"), false);
      }
    } else if (btn.dataset.act === "download") {
      if (!(await ensureAuth())) return;
      if (!openDownload(`/api/nodes/${id}/guide`)) toast(t("msg.popupBlocked"), false);
    } else if (btn.dataset.act === "refresh") {
      if (!confirm(t("cfm.nodeRegen"))) return;
      if (!guardBtn(btn)) return;
      try {
        // Same once-flow as create: the old token dies immediately, so copy
        // the new one and re-open the guide instead of stranding the operator.
        const r = await api(`/api/nodes/${id}/regen-token`, { method: "POST" });
        if (r && r.token) {
          if (!await copyText(r.token)) prompt(t("prm.tokenOnce"), r.token);
        }
        toast(t("msg.tokenRegenDl"));
        loadNodes();
        setTimeout(() => openGuide(`/api/nodes/${id}/guide`), 500);
      } finally {
        // Without this the row's button stayed disabled for the rest of the
        // session whenever the request failed (429 from the limiter, 5xx):
        // only the success path rebuilt the table and dropped the dead node.
        btn.disabled = false;
      }
    } else if (btn.dataset.act === "del-node") {
      if (!confirm(t("cfm.nodeDelete", {name: btn.dataset.name}))) return;
      await api("/api/nodes/" + id, { method: "DELETE" });
      toast(t("msg.tunnelDeleted"));
      loadNodes();
    }
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

const IB_PROTO_LABEL = {
  vless: "VLESS", reality: "REALITY", vmess: "VMess",
  trojan: "Trojan", ss: "Shadowsocks", hysteria2: "Hysteria2"
};

function inboundRow(ib) {
  const tr = document.createElement("tr");
  const c1 = document.createElement("td");
  const b = document.createElement("strong");
  b.textContent = ib.name;
  c1.appendChild(b);
  const c2 = document.createElement("td");
  const pb = document.createElement("span");
  pb.className = "badge proto";
  pb.textContent = IB_PROTO_LABEL[ib.protocol] || ib.protocol;
  c2.appendChild(pb);
  const c3 = document.createElement("td");
  c3.textContent = ib.port;
  c3.style.direction = "ltr";
  const c4 = document.createElement("td");
  c4.className = "muted";
  c4.textContent = ib.host || "—";
  const cNode = document.createElement("td");
  const nodeSel = document.createElement("select");
  nodeSel.className = "ib-node-sel";
  nodeSel.title = t("ib.nodeTitleOpt");
  const oLocal = document.createElement("option");
  oLocal.value = "";
  oLocal.textContent = t("ib.localPanel");
  nodeSel.appendChild(oLocal);
  for (const n of SERVER_NODES) {
    const o = document.createElement("option");
    o.value = String(n.id);
    o.textContent = n.name;
    nodeSel.appendChild(o);
  }
  nodeSel.value = ib.node_id ? String(ib.node_id) : "";
  if (ib.node_id && !nodeSel.value) {
    const oGone = document.createElement("option");
    oGone.value = String(ib.node_id);
    oGone.textContent = `node #${ib.node_id}?`;
    nodeSel.appendChild(oGone);
    nodeSel.value = String(ib.node_id);
  }
  nodeSel.dataset.id = ib.id;
  nodeSel.addEventListener("change", async () => {
    try {
      await api("/api/inbounds/" + ib.id, {
        method: "PATCH",
        body: { node_id: nodeSel.value ? numInput(nodeSel.value) : null }
      });
      toast(nodeSel.value ? t("msg.ibPinned") : t("msg.ibLocal"));
      loadInbounds();
    } catch (err) {
      if (err.message !== "auth") toast(err.message, false);
      loadInbounds();
    }
  });
  cNode.appendChild(nodeSel);
  const c5 = document.createElement("td");
  c5.appendChild(badge(ib.enabled ? t("badge.on") : t("badge.off"),
                        ib.enabled ? "ok" : "off"));
  const c6 = document.createElement("td");
  const tglBtn = iconBtn(ib.enabled ? t("icon.disable") : t("icon.enableObj"), ICONS.toggleOff, ib.enabled ? "warn" : "good");
  tglBtn.dataset.act = "ib-toggle";
  tglBtn.dataset.id = ib.id;
  const delBtn = iconBtn(t("icon.delete"), ICONS.trash, "bad");
  delBtn.dataset.act = "ib-del";
  delBtn.dataset.id = ib.id;
  delBtn.dataset.name = ib.name;
  c6.append(tglBtn, delBtn);
  tr.append(c1, c2, c3, c4, cNode, c5, c6);
  return tr;
}

async function loadInbounds() {
  // Generation guard like every other list loader: this one is triggered from
  // four unsynchronised places (nav, add, row toggle/delete, the per-row node
  // select) and each call is two sequential round-trips, so a slower earlier
  // response could clear the table and re-render an older snapshot - the
  // Enabled badge silently reverting while the server held the new value.
  const token = nextSeq("inbounds");
  try {
    await loadSrvNodes();
    const items = await api("/api/inbounds");
    if (!isCurrent("inbounds", token)) return;
    const tbody = $("#inbounds-tbody");
    tbody.textContent = "";
    // Null/garbage body used to throw for...of AFTER the tbody was cleared,
    // leaving the section permanently blank.
    const list = Array.isArray(items) ? items : [];
    for (const ib of list) tbody.appendChild(inboundRow(ib));
    $("#ib-empty").classList.toggle("hidden", list.length > 0);
  } catch (_) {}
}

$("#ib-add-btn").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  const name = $("#ib-name").value.trim();
  const port = numInput($("#ib-port").value);
  if (!name || !port) { toast(t("msg.ibNamePort"), false); return; }
  // `!port` let 70000 through (truthy) and NaN serialises to null, so both
  // produced a raw schema error instead of the field-level message.
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    toast(t("msg.badNumbers"), false);
    return;
  }
  if (!guardBtn(btn)) return;
  try {
    await api("/api/inbounds", {
      method: "POST",
      body: {
        name,
        protocol: $("#ib-proto").value,
        port,
        host: $("#ib-host").value.trim(),
        enabled: true,
        node_id: $("#ib-node") && $("#ib-node").value ? numInput($("#ib-node").value) : null
      }
    });
    $("#ib-name").value = ""; $("#ib-port").value = ""; $("#ib-host").value = "";
    toast(t("msg.ibAdded", {name}));
    loadInbounds();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { btn.disabled = false; }
});

$("#inbounds-tbody").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  try {
    if (btn.dataset.act === "ib-toggle") {
      const on = btn.classList.contains("warn");
      await api("/api/inbounds/" + btn.dataset.id, { method: "PATCH", body: { enabled: !on } });
      toast(on ? t("msg.ibDisabled") : t("msg.ibEnabled"));
    } else if (btn.dataset.act === "ib-del") {
      if (!confirm(t("cfm.ibDelete", {name: btn.dataset.name}))) return;
      await api("/api/inbounds/" + btn.dataset.id, { method: "DELETE" });
      toast(t("msg.ibDeleted"));
    }
    loadInbounds();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

// ---- Server nodes ----
let SERVER_NODES = [];

function srvNodeStatus(n) {
  if (!n.enabled) return badge(t("badge.disabled"), "off");
  if (n.status === "online") return badge(t("badge.online"), "ok");
  if (n.status === "offline") return badge(t("badge.offline"), "expired");
  return badge(t("badge.unknown"), "pending");
}

function fillNodeSelect(sel, current) {
  if (!sel) return;
  sel.textContent = "";
  const o0 = document.createElement("option");
  o0.value = "";
  o0.textContent = t("ib.localPanel");
  sel.appendChild(o0);
  for (const n of SERVER_NODES) {
    const o = document.createElement("option");
    o.value = String(n.id);
    o.textContent = n.enabled ? n.name : `${n.name} (${t("badge.off")})`;
    sel.appendChild(o);
  }
  if (current) sel.value = String(current);
}

function renderSrvNodes(nodes) {
  SERVER_NODES = Array.isArray(nodes) ? nodes : [];
  nodes = SERVER_NODES;
  fillNodeSelect($("#ib-node"), $("#ib-node") ? $("#ib-node").value : "");
  const ul = $("#snodes-list");
  ul.textContent = "";
  if (!nodes.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = t("tpl.noNodes");
    ul.appendChild(li);
    return;
  }
  for (const n of nodes) {
    const li = document.createElement("li");
    li.style.display = "flex";
    li.style.flexWrap = "wrap";
    li.style.alignItems = "center";
    li.style.gap = "6px";
    const main = document.createElement("span");
    main.textContent = `${n.name} [${n.address}:${n.check_port}]`;
    const meta = document.createElement("small");
    const bits = [];
    if (n.latency_ms != null) bits.push(`${n.latency_ms} ms`);
    bits.push(n.uptime_pct != null ? `${n.uptime_pct}% ${t("meta.uptime")}` : t("meta.notChecked"));
    if (n.note) bits.push(n.note);
    meta.textContent = bits.join(" · ");
    const st = document.createElement("span");
    st.appendChild(srvNodeStatus(n));
    li.appendChild(main);
    li.appendChild(meta);
    li.appendChild(st);
    const checkBtn = iconBtn(t("icon.checkNow"), ICONS.refresh, "good");
    checkBtn.dataset.act = "check";
    checkBtn.dataset.id = n.id;
    const tglBtn = iconBtn(n.enabled ? t("icon.disable") : t("icon.enableObj"), n.enabled ? ICONS.toggleOff : ICONS.toggleOn, n.enabled ? "warn" : "good");
    tglBtn.dataset.act = "toggle";
    tglBtn.dataset.id = n.id;
    const delBtn = iconBtn(t("icon.delNode"), ICONS.trash, "bad");
    delBtn.dataset.act = "del-snode";
    delBtn.dataset.id = n.id;
    delBtn.dataset.name = n.name;
    li.append(checkBtn, tglBtn, delBtn);
    ul.appendChild(li);
  }
}

async function loadSrvNodes() {
  const token = nextSeq("snodes");
  try {
    const rows = await api("/api/server-nodes");
    if (!isCurrent("snodes", token)) return;
    renderSrvNodes(rows);
  } catch (_) {}
}

$("#snode-create-btn").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  const name = $("#snode-name").value.trim();
  const address = $("#snode-addr").value.trim();
  // 0 was not a valid port: `parseInt(...) || 443` silently created the node
  // on 443 while the operator had typed 0.
  const portRaw = numInput($("#snode-port").value);
  const port = Number.isFinite(portRaw) && portRaw >= 1 && portRaw <= 65535 ? portRaw : NaN;
  if (!name || !address) { toast(t("msg.snodeNameAddr"), false); return; }
  // A NaN that reaches JSON.stringify becomes `null`, and the schema field is
  // a non-optional int: the operator got a raw "Input should be a valid
  // integer" toast instead of the field-level message below.
  if (!Number.isFinite(port)) { toast(t("msg.badNumbers"), false); return; }
  if (!guardBtn(btn)) return;
  try {
    await api("/api/server-nodes", {
      method: "POST",
      body: { name, address, check_port: port, note: $("#snode-note").value.trim() }
    });
    $("#snode-name").value = ""; $("#snode-addr").value = ""; $("#snode-note").value = "";
    toast(t("msg.snodeAdded", {name}));
    loadSrvNodes();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { btn.disabled = false; }
});

$("#snodes-list").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  const id = btn.dataset.id;
  try {
    if (btn.dataset.act === "check") {
      const n = await api(`/api/server-nodes/${id}/check`, { method: "POST" });
      // latency_ms is nullable: the toast used to read "name ONLINE (null ms)".
      const latTxt = n.latency_ms != null ? ` (${n.latency_ms} ms)` : "";
      toast(n.status === "online"
        ? t("msg.snodeOnline", {name: n.name}) + latTxt
        : t("msg.snodeOffline", {name: n.name}), n.status === "online");
      loadSrvNodes();
    } else if (btn.dataset.act === "toggle") {
      const cur = SERVER_NODES.find((x) => String(x.id) === String(id));
      await api(`/api/server-nodes/${id}`, { method: "PATCH", body: { enabled: !(cur && cur.enabled) } });
      toast(t("msg.nodeUpdated"));
      loadSrvNodes();
    } else if (btn.dataset.act === "del-snode") {
      if (!confirm(t("cfm.snodeDelete", {name: btn.dataset.name}))) return;
      await api(`/api/server-nodes/${id}`, { method: "DELETE" });
      toast(t("msg.snodeDeleted"));
      loadSrvNodes();
    }
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#snodes-refresh").addEventListener("click", loadSrvNodes);

async function loadBlocklist() {
  try {
    const data = await api("/api/blocklist");
    const chk = $("#porn-toggle");
    if (chk) chk.checked = !!data.porn_enabled;
    const cnt = $("#porn-count");
    if (cnt) cnt.textContent = data.porn_enabled ? t("blocker.countOn", {porn: data.porn_count, n: data.sites.length}) : t("blocker.countOff", {n: data.sites.length});
    const ul = $("#block-list");
    ul.textContent = "";
    for (const site of data.sites) {
      const li = document.createElement("li");
      const span = document.createElement("span");
      span.textContent = site.domain;
      li.appendChild(span);
      const delBtn = iconBtn(t("icon.unblock"), ICONS.trash, "bad");
      delBtn.dataset.id = site.id;
      delBtn.dataset.domain = site.domain;
      li.appendChild(delBtn);
      li.style.display = "flex";
      li.style.alignItems = "center";
      li.style.justifyContent = "space-between";
      ul.appendChild(li);
    }
    const empty = $("#block-empty");
    if (empty) empty.classList.toggle("hidden", data.sites.length > 0);
  } catch (_) {}
}

$("#porn-toggle")?.addEventListener("change", async (e) => {
  try {
    await api("/api/blocklist/porn", { method: "PUT", body: { porn_enabled: e.target.checked } });
    toast(e.target.checked ? t("msg.pornOn") : t("msg.pornOff"));
    loadBlocklist();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); e.target.checked = !e.target.checked; }
});

$("#block-add-btn")?.addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  const inp = $("#block-domain");
  const domain = inp.value.trim().toLowerCase();
  if (!domain) { toast(t("msg.domainEmpty"), false); return; }
  if (!guardBtn(btn)) return;
  try {
    await api("/api/blocklist", { method: "POST", body: { domain } });
    inp.value = "";
    toast(t("msg.blocked", {domain}));
    loadBlocklist();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { btn.disabled = false; }
});

$("#block-list")?.addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  if (!confirm(t("cfm.unblock", {domain: btn.dataset.domain}))) return;
  try {
    await api(`/api/blocklist/${btn.dataset.id}`, { method: "DELETE" });
    toast(t("msg.domainUnblocked"));
    loadBlocklist();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

$("#edit-close").addEventListener("click", () => { bumpUserFormOp(); $("#edit-modal").classList.add("hidden"); });
$("#edit-modal").addEventListener("click", (e) => { if (e.target === $("#edit-modal")) { bumpUserFormOp(); $("#edit-modal").classList.add("hidden"); } });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { bumpUserFormOp(); $("#edit-modal").classList.add("hidden"); } });

$("#edit-user-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  if (!guardSubmit(f)) return;
  const myOp = bumpUserFormOp();
  const body = {};
  // Always send the note: omitting it when emptied made "clear the note"
  // impossible (the UI said "nothing changed" / the old note survived).
  body.set_note = f.note.value.trim();
  if (f.volume.value !== "") {
    const vv = numInput(f.volume.value);
    if (!Number.isFinite(vv) || vv < 0.01) { toast(t("msg.badNumbers"), false); releaseSubmit(f); return; }
    body.set_volume_gb = vv;
  }
  if (f.expires.value) body.set_expires_at = localInputToUtc(f.expires.value);
  if (!body.set_expires_at && f.expires.value) { toast(t("msg.badNumbers"), false); releaseSubmit(f); return; }
  if (f.device_limit.value !== "") {
    const dv = numInput(f.device_limit.value);
    // Garbage/-3 previously became 0 → limit silently removed. Validate.
    if (!/^\d+$/.test(f.device_limit.value.trim()) || !Number.isFinite(dv) || dv < 0) {
      toast(t("msg.badNumbers"), false); releaseSubmit(f); return;
    }
    body.set_device_limit = dv >= 1 ? dv : 0;
  }
  if (f.reset_used.checked) body.reset_used = true;
  if (!Object.keys(body).length) { toast(t("msg.nothingChanged"), false); releaseSubmit(f); return; }
  try {
    await api("/api/users/" + f.dataset.uid, { method: "PATCH", body });
    if (myOp !== userFormOp) return;   // modal closed/reopened meanwhile
    $("#edit-modal").classList.add("hidden");
    toast(t("msg.userUpdated"));
    loadUsers($("#search").value.trim());
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { releaseSubmit(f); }
});

// ---- Panel update ----
let updatePoll = null;
// The exact upstream commit the operator is looking at. /api/update/apply
// requires it, so a release pushed between the status page and the click is
// refused instead of silently installed.
let approvedUpdateSha = "";
function renderChangelog(items, prefix) {
  const ul = $("#update-changelog");
  ul.textContent = "";
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = prefix || t("update.nothing");
    ul.appendChild(li);
    return;
  }
  for (const c of items.slice(0, 20)) {
    const li = document.createElement("li");
    const b = document.createElement("strong");
    b.textContent = c.sha;
    const meta = document.createElement("small");
    meta.textContent = (c.date ? c.date + " · " : "") + c.message;
    li.appendChild(b);
    li.appendChild(meta);
    ul.appendChild(li);
  }
}
async function loadUpdate(announce, fresh, quietNetErr) {
  try {
    // ?fresh=1 bypasses the server-side status cache. The poller used to read
    // the CACHED pre-update answer ("updating: false") right after applying
    // the update and immediately declared the update finished.
    const st = await api("/api/update/status" + (fresh ? "?fresh=1" : ""));
    const badge = $("#update-badge");
    const sum = $("#update-summary");
    $("#update-repo").textContent = st.repo + "@" + st.branch;
    // `error` arrives whenever GitHub could not be reached (rate limit,
    // offline) - and `current` is still populated then, so requiring
    // `!st.current` made this branch unreachable: a failed check fell
    // through to the "up to date" card and told the operator the panel was
    // current when nobody had checked. Any error means "could not check".
    if (st.error) {
      badge.textContent = t("update.error");
      badge.className = "badge proto off";
      sum.textContent = t("update.errStatus", {err: st.error});
      $("#update-now-btn").classList.add("hidden");
      renderChangelog(st.local_log || [], t("update.noLocal"));
    } else if (st.updating) {
      badge.textContent = t("update.updating");
      badge.className = "badge proto warn";
      sum.textContent = t("update.inProgress");
      $("#update-now-btn").classList.add("hidden");
      renderChangelog(st.incoming || [], t("update.fetching"));
    } else if (st.update_available) {
      badge.textContent = t("update.available");
      badge.className = "badge proto warn";
      sum.textContent = t("update.review", {cur: st.current, latest: st.latest});
      $("#update-now-btn").classList.remove("hidden");
      renderChangelog(st.incoming || [], t("update.noChangelog"));
    } else {
      badge.textContent = t("update.uptodate");
      badge.className = "badge proto ok";
      sum.textContent = t("update.clean", {ver: (st.latest || st.current) + (st.version ? " (v" + st.version + ")" : "")});
      $("#update-now-btn").classList.add("hidden");
      renderChangelog(st.local_log || [], t("update.noLocal"));
    }
    // Stale systemd unit: the in-panel updater only refreshes code+deps,
    // never the unit — surface it loudly or updates silently degrade.
    const uw = $("#update-unit-warning");
    if (uw) {
      if (st.unit_warning) {
        uw.textContent = t("update.unitStale", {warn: st.unit_warning});
        uw.classList.remove("hidden");
      } else {
        uw.classList.add("hidden");
      }
    }
    // Upstream commit signature: advisory by default, a hard gate when the
    // operator sets ZEFIRA_REQUIRE_SIGNED_UPDATE=1. Say which one it is.
    const sw = $("#update-signature");
    if (sw) {
      if (st.signature === "verified") {
        sw.textContent = t("update.sigOk");
        sw.className = "hint ok-text";
      } else if (st.signature === "unverified") {
        sw.textContent = t("update.sigBad", {why: st.signature_detail || "unsigned"});
        sw.className = "hint warn-text";
      } else if (st.signature === "unknown") {
        sw.textContent = t("update.sigUnknown");
        sw.className = "hint";
      } else {
        sw.classList.add("hidden");
        sw.textContent = "";
      }
    }
    // The server sends the full 40-char SHA as `latest_full` so the apply
    // call can bind to exactly this commit.
    if (st.latest_full) approvedUpdateSha = st.latest_full;
    if (announce) toast(t("msg.updateChecked"));
    return st;
  } catch (err) {
    // While the panel is restarting, every poll tick's fetch REJECTS (a
    // transport failure, not an HTTP error) and used to be toasted as a red
    // "Failed to fetch" - a stack of them during a perfectly normal,
    // successful update. The poller passes quietNetErr so a transport
    // failure inside the restart window is silent. A throttle (429) is the
    // same class of noise for the same reason: it says nothing about the
    // update, it only says the poller asked too often.
    const isNetErr = err instanceof TypeError;
    const isThrottled = /throttled|429|too many/i.test(String(err && err.message));
    if ((!isNetErr && !isThrottled) || !quietNetErr) {
      if (err.message !== "auth") toast(err.message, false);
    }
    return null;
  }
}
$("#update-check-btn").addEventListener("click", () => loadUpdate(true));
$("#update-now-btn").addEventListener("click", async (e) => {
  if (!confirm(t("cfm.updateNow"))) return;
  const pw = prompt(t("prm.updatePw"));
  if (!pw) return;
  // The handler spans four awaits, so without this a second click started a
  // second /api/update/apply and the operator saw a 409/429 error toast on
  // top of "Update started".
  const btn = e.currentTarget;
  if (!guardBtn(btn)) return;
  try {
    const before = await api("/api/update/status?fresh=1");
    // Bind to the commit the CARD SHOWED, never to a value re-read here.
    // The server refuses when upstream advertises something other than the
    // approved SHA - but re-reading the head at click time made the approved
    // SHA *be* that fresh head, so the check could never fire and a release
    // pushed after the operator read the card was installed unseen.
    let sha = approvedUpdateSha;
    if (!/^[0-9a-f]{40}$/.test(sha || "")) {
      // The card was never rendered with a SHA (first paint, or a cached
      // answer): refresh it once and approve THAT, so the operator still
      // consents to one specific commit.
      const shown = await loadUpdate(false, true);
      sha = (shown && shown.latest_full) || "";
    }
    if (!/^[0-9a-f]{40}$/.test(sha)) {
      toast(t("msg.updateNoSha"), false);
      return;
    }
    await api("/api/update/apply", {
      method: "POST",
      body: { password_confirm: pw, expected_sha: sha },
    });
    toast(t("msg.updateStarted"));
    loadUpdate(false, true);
    let n = 0, inFlight = false, sawUpdating = false;
    if (updatePoll) clearInterval(updatePoll);
    updatePoll = setInterval(async () => {
      // No overlapping ticks: a slow server must not stack requests.
      if (inFlight) return;
      inFlight = true;
      try {
        n += 1;
        const st = await loadUpdate(false, true, true);
        if (st && st.updating) sawUpdating = true;
        // Stop only after the server was actually seen mid-update (or after
        // the tick budget). A cached/stale "not updating" first answer must
        // not end the poll while the update is still running.
        if (st && !st.updating && (sawUpdating || n >= 3)) {
          clearInterval(updatePoll);
          updatePoll = null;
          try {
            const after = await api("/api/update/status");
            // Compare the RUNNING commit, not `latest` (the upstream head,
            // which is identical before and after a successful install - so
            // this always took the "nothing changed" branch and every
            // successful update ended on the red systemd warning).
            // `restart_pending` is the server saying the code landed but the
            // process did not restart: git already reports the new commit, so
            // the SHA compare alone would call it a success.
            if (after.restart_pending
                || ((after.current || "") === (before.current || "") && !after.updating)) {
              toast(t("msg.updateNoSystemd"), false);
            } else {
              toast(t("msg.updateDone"));
            }
          } catch (_) {}
          return;
        }
        if (n >= 20 && updatePoll) {
          clearInterval(updatePoll);
          updatePoll = null;
          try {
            const after = await api("/api/update/status");
            if (after.restart_pending
                || ((after.current || "") === (before.current || "") && !after.updating)) {
              toast(t("msg.updateNoSystemd"), false);
            } else {
              toast(t("msg.updateDone"));
            }
          } catch (_) {}
        }
      } finally {
        inFlight = false;
      }
    }, 5000);
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  } finally {
    // The card hides this button on success; on a failed apply it must come
    // back, or the operator cannot retry without reloading the page.
    btn.disabled = false;
  }
});

// ---- AI assistant ----
let AI_HISTORY = [];
function aiAddMsg(text, cls) {
  const box = $("#ai-msgs");
  const el = document.createElement("div");
  el.className = "ai-msg " + cls;
  el.textContent = text;
  box.appendChild(el);
  box.scrollTop = box.scrollHeight;
  return el;
}
async function loadAi() {
  const token = nextSeq("ai");
  try {
    const a = await api("/api/ai/settings");
    if (!isCurrent("ai", token)) return;   // a newer save/load won
    $("#ai-enabled").checked = !!a.enabled;
    $("#ai-provider").value = a.provider || "groq";
    $("#ai-base").value = a.base_url || "";
    $("#ai-model").value = a.model || "";
    $("#ai-extra").value = a.extra || "";
    const badge = $("#ai-badge");
    if (badge) {
      const ready = a.enabled && a.has_key && a.model;
      badge.textContent = ready ? t("ai.ready") : t("badge.off");
      badge.className = "badge proto " + (ready ? "ok" : "off");
    }
  } catch (_) {}
}
$("#ai-save-btn").addEventListener("click", async () => {
  try {
    await api("/api/ai/settings", {
      method: "PUT",
      body: {
        enabled: $("#ai-enabled").checked,
        provider: $("#ai-provider").value,
        base_url: $("#ai-base").value.trim(),
        model: $("#ai-model").value.trim(),
        api_key: $("#ai-key").value,
        extra: $("#ai-extra").value.trim()
      }
    });
    $("#ai-key").value = "";
    toast(t("msg.aiSaved"));
    loadAi();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#ai-test-btn").addEventListener("click", async () => {
  const btn = $("#ai-test-btn");
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    const r = await api("/api/ai/test", { method: "POST", body: {} });
    toast(`${t("ai.testOk")}: ${r.reply || "ok"}`);
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { btn.disabled = false; }
});
$("#ai-fab").addEventListener("click", () => {
  $("#ai-chat").classList.toggle("hidden");
  if (!$("#ai-chat").classList.contains("hidden")) {
    // Badge may be stale (saved/disabled in another tab): refresh on open.
    loadAi();
    if (!$("#ai-msgs").children.length) {
      aiAddMsg(t("ai.greeting"), "bot");
    }
    $("#ai-input").focus();
  }
});
$("#ai-close").addEventListener("click", () => $("#ai-chat").classList.add("hidden"));
let aiSending = false;
async function aiSend() {
  // No overlapping requests: double-send interleaves history and burns
  // AI quota with out-of-order replies.
  if (aiSending) return;
  const inp = $("#ai-input");
  const text = inp.value.trim().slice(0, 4000);
  if (!text) return;
  if (aiSending) return;
  aiSending = true;
  $("#ai-send").disabled = true;
  inp.value = "";
  aiAddMsg(text, "user");
  AI_HISTORY.push({ role: "user", content: text });
  AI_HISTORY = AI_HISTORY.slice(-11);
  const userMsgEl = $("#ai-msgs").lastElementChild;
  const typing = aiAddMsg("…", "bot typing");
  try {
    const r = await api("/api/ai/chat", { method: "POST", body: { messages: AI_HISTORY } });
    typing.remove();
    const reply = String(r.reply || "").slice(0, 4000);
    aiAddMsg(reply, "bot");
    AI_HISTORY.push({ role: "assistant", content: reply });
    AI_HISTORY = AI_HISTORY.slice(-12);
  } catch (err) {
    typing.remove();
    // A failed turn must not destroy the prompt or poison the history
    // (quota 429 / 502 are exactly when the user retries): restore input
    // and drop the un-answered user turn.
    if (userMsgEl) userMsgEl.remove();
    AI_HISTORY.pop();
    inp.value = text;
    aiAddMsg(err.message === "auth" ? t("ai.sessionExpired") : (t("ai.errorPre") + err.message), "bot");
  } finally {
    aiSending = false;
    $("#ai-send").disabled = false;
    inp.focus();
  }
}
$("#ai-send").addEventListener("click", aiSend);
$("#ai-input").addEventListener("keydown", (e) => { if (e.key === "Enter") aiSend(); });

// ---- API tokens (bots & integrations) ----
async function renderApiTokens(items) {
  const ul = $("#apitoken-list");
  ul.textContent = "";
  // A null/garbage response must not throw after the list was cleared: the
  // outer catch then leaves the section permanently blank.
  if (!Array.isArray(items)) items = [];
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = t("tokens.empty");
    ul.appendChild(li);
    return;
  }
  // Loop variable must NOT be `t`: that shadows the global translation
  // function and every t("...") below threw "t is not a function", which
  // blanked the whole token list as soon as one token existed.
  for (const tk of items) {
    const li = document.createElement("li");
    li.style.display = "flex";
    li.style.flexWrap = "wrap";
    li.style.alignItems = "center";
    li.style.gap = "6px";
    const main = document.createElement("span");
    main.textContent = tk.name;
    const meta = document.createElement("small");
    const bits = [`${tk.prefix}…`];
    // Format the timestamp like every other date in the panel: the raw
    // "2026-09-20T10:00:00Z" string was rendered verbatim, so the token list
    // was the one place showing UTC ISO next to local-time columns.
    if (tk.last_used_at) {
      const _d = new Date(tk.last_used_at);
      bits.push(t("tokens.lastUsed", {
        dt: isNaN(_d.getTime()) ? String(tk.last_used_at) : dateTimeFmt.format(_d)
      }));
    } else {
      bits.push(t("tokens.neverUsed"));
    }
    meta.textContent = bits.join(" · ");
    li.appendChild(main);
    li.appendChild(meta);
    const delBtn = iconBtn(t("icon.revoke"), ICONS.trash, "bad");
    delBtn.dataset.act = "del-token";
    delBtn.dataset.id = tk.id;
    delBtn.dataset.name = tk.name;
    li.appendChild(delBtn);
    ul.appendChild(li);
  }
}
async function loadApiTokens() {
  try {
    renderApiTokens(await api("/api/api-tokens"));
  } catch (_) {}
}
$("#apitoken-create-btn").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  const name = $("#apitoken-name").value.trim();
  if (!name) { toast(t("msg.tokenNameEmpty"), false); return; }
  if (!guardBtn(btn)) return;
  try {
    const r = await api("/api/api-tokens", { method: "POST", body: { name } });
    $("#apitoken-name").value = "";
    // The token is shown once and never stored: copy it AND always show
    // it for manual backup (clipboard content is easily lost/overwritten).
    // The prompt is deliberately unconditional - a dismissed prompt plus a
    // "copied" toast meant the bot credential was simply gone.
    await copyText(r.token_once);
    prompt(t("prm.tokenOnce"), r.token_once);
    toast(t("msg.tokenCreated"));
    loadApiTokens();  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { btn.disabled = false; }
});
$("#apitoken-list").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  try {
    if (btn.dataset.act === "del-token") {
      if (!confirm(t("cfm.tokenRevoke", {name: btn.dataset.name}))) return;
      if (!guardBtn(btn)) return;
      // Same as the user row: a failed revoke used to leave the button dead
      // and the list stale.
      try {
        await api("/api/api-tokens/" + btn.dataset.id, { method: "DELETE" });
        toast(t("msg.tokenRevoked"));
      } finally {
        btn.disabled = false;
        loadApiTokens();
      }
    }
  } catch (err) { if (err.message !== "auth") toast(err.message, false); loadApiTokens(); }
});

// ---- Telegram ----
async function loadTelegram() {
  try {
    const tg = await api("/api/telegram");
    $("#tg-chat").value = tg.chat_id || "";
    // Was `t.has_token ? t("tg.hasToken") : ...` — `t` is the translation
    // fn and `t(...)` on a boolean throws ReferenceError, swallowed by the
    // catch below: the "token saved" hint never rendered.
    $("#tg-hint").textContent = tg.has_token
      ? t("tg.hasToken")
      : t("tg.noToken");
  } catch (_) {}
}
$("#tg-save-btn").addEventListener("click", async () => {
  try {
    await api("/api/telegram", {
      method: "PUT",
      body: { bot_token: $("#tg-token").value.trim(), chat_id: $("#tg-chat").value.trim() }
    });
    $("#tg-token").value = "";
    toast(t("msg.tgSaved"));
    loadTelegram();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#tg-test-btn").addEventListener("click", async () => {
  try {
    await api("/api/telegram/test", { method: "POST", body: {} });
    toast(t("msg.tgSent"));
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

// ---- SSL certificate ----
function renderSslStatus(st) {
  const el = $("#ssl-status");
  if (!el) return;
  if (!st.installed) {
    el.textContent = t("ssl.noCertbot");
    return;
  }
  if (st.domains && st.domains.length && st.expires) {
    el.textContent = t("ssl.validUntil", {domains: st.domains.join(", "), exp: st.expires});
  } else if (st.domains && st.domains.length) {
    el.textContent = t("ssl.filesFound", {domains: st.domains.join(", ")});
  } else {
    el.textContent = t("ssl.noneYet");
  }
}
async function loadSslStatus() {
  try {
    renderSslStatus(await api("/api/ssl/status"));
  } catch (_) {}
}
$("#ssl-issue-btn").addEventListener("click", async () => {
  const domain = $("#ssl-domain").value.trim().toLowerCase();
  let subdomain = $("#ssl-subdomain").value.trim().toLowerCase();
  const email = $("#ssl-email").value.trim();
  if (!domain || !email) { toast(t("msg.domainEmailReq"), false); return; }
  // Mirror the backend: a subdomain already contained in the domain is
  // dropped, otherwise the confirm shows panel.panel.example.com.
  if (subdomain && (domain === subdomain || domain.startsWith(subdomain + "."))) subdomain = "";
  const fqdn = subdomain ? `${subdomain}.${domain}` : domain;
  if (!confirm(t("cfm.sslIssue", {fqdn}))) return;
  toast(t("ssl.requesting"));
  try {
    const r = await api("/api/ssl/issue", { method: "POST", body: { domain, subdomain, email } });
    renderSslStatus(r);
    toast(t("msg.certIssued", {cert: r.cert_path || "?", key: r.key_path || "?"}));
    loadAudit();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#ssl-renew-btn").addEventListener("click", async () => {
  try {
    const r = await api("/api/ssl/renew", { method: "POST", body: {} });
    renderSslStatus(r);
    toast(t("msg.certRenewed"));
    loadAudit();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

$("#backup-btn").addEventListener("click", async () => {
  const pw = prompt(t("prm.backupPw"));
  if (!pw) return;
  // Two-step choice so Cancel always means abort: first confirm the
  // download itself, then pick encrypted vs plain (previously Cancel
  // silently downloaded a PLAINTEXT backup full of secrets).
  if (!confirm(t("cfm.backupDl"))) return;
  const enc = confirm(t("prm.backupEnc"));
  try {
    const res = await fetch("/api/backup", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
      body: JSON.stringify({ password_confirm: pw, encrypt: enc })
    });
    if (res.status === 401) { location.href = "/login"; return; }
    if (!res.ok) { toast(t("msg.backupFail"), false); return; }
    const blob = await res.blob();
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = enc ? `zefira-backup-${stamp}.enc.json` : `zefira-backup-${stamp}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast(enc ? t("msg.backupEncStarted") : t("msg.backupStarted"));
  } catch (_) {
    toast(t("msg.backupFailed"), false);
  }
});

// After a restore the whole panel state is stale: users, stats, settings,
// Reality/CDN, Telegram, SSL, AI, tokens, inbounds, nodes, blocklist and the
// customized layout. Only users+stats were reloaded, so the operator kept
// editing the PRE-restore configuration and saving it back over the restore.
function reloadAfterRestore() {
  loadStats();
  loadUsers($("#search").value.trim());
  loadSrvSettings();
  loadAppearance();
  loadTelegram();
  loadSslStatus();
  loadAi();
  loadApiTokens();
  loadInbounds();
  loadSrvNodes();
  loadNodes();
  loadTunnelSettings();
  loadBlocklist();
  loadAudit();
}

const restoreFile = $("#restore-file");
restoreFile.addEventListener("change", () => {
  $("#restore-btn").disabled = !restoreFile.files.length;
});
function restoreNote(r) {
  // The server reports what it deliberately did NOT import (admin passwords,
  // API tokens, the public origin). Silently dropping that left operators
  // wondering where their reseller tokens went after a migration.
  if (r && r.credentials_note) toast(r.credentials_note, false);
  if (r && r.tunnel_note) toast(r.tunnel_note);
}

$("#restore-btn").addEventListener("click", async () => {
  const file = restoreFile.files[0];
  if (!file) return;
  if (file.size > 64 * 1048576) { toast(t("msg.fileTooBig"), false); return; }
  let parsed;
  try {
    parsed = JSON.parse(await file.text());
  } catch (_) {
    toast(t("msg.invalidJson"), false);
    return;
  }
  if (!parsed || (parsed.zefira_backup !== true && parsed.encrypted !== true)) {
    toast(t("msg.notBackup"), false);
    return;
  }
  const isEnc = parsed.encrypted === true;
  if (!confirm(isEnc
    ? t("cfm.restoreEnc")
    : t("cfm.restorePlain", {n: parsed.users ? parsed.users.length : 0}))) return;
  const pw = prompt(t("prm.restorePw"));
  if (!pw) return;
  if (isEnc) {
    // Encrypted backups decrypt with the password that created them
    // (usually the same admin password — the server falls back to it).
    try {
      const r = await api("/api/restore-encrypted", {
        method: "POST",
        body: { password_confirm: pw, salt: parsed.salt, payload: parsed.payload, backup_password: pw }
      });
      toast(t("msg.restored", {added: r.added_users, skipped: r.skipped}));
      restoreNote(r);
      restoreFile.value = "";
      $("#restore-btn").disabled = true;
      reloadAfterRestore();
    } catch (err) {
      if (err.message !== "auth") toast(err.message, false);
    }
    return;
  }
  delete parsed.exported_at;
  parsed.zefira_backup = true;
  parsed.password_confirm = pw;
  try {
    const r = await api("/api/restore", { method: "POST", body: parsed });
    toast(t("msg.restored", {added: r.added_users, skipped: r.skipped}));
    restoreNote(r);
    restoreFile.value = "";
    $("#restore-btn").disabled = true;
    reloadAfterRestore();
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
});

async function loadAudit() {
  try {
    const rows = await api("/api/audit");
    const ul = $("#audit-list");
    ul.textContent = "";
    if (!rows.length) {
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent = t("audit.empty");
      ul.appendChild(li);
      return;
    }
    for (const r of rows) {
      const li = document.createElement("li");
      if (!r.ok) li.classList.add("bad");
      const main = document.createElement("span");
      main.textContent = eventName(r.event) + (r.detail ? ` \u2014 ${r.detail}` : "");
      const meta = document.createElement("small");
      // One corrupt timestamp must not blank the whole events list.
      const tsD = new Date(r.ts);
      const tsTxt = isNaN(tsD.getTime()) ? String(r.ts || "?") : dateTimeFmt.format(tsD);
      meta.textContent = `${tsTxt}${r.ip && r.ip !== "?" ? " \u00b7 " + r.ip : ""}`;
      li.appendChild(main);
      li.appendChild(meta);
      ul.appendChild(li);
    }
  } catch (_) {}
}
$("#audit-refresh").addEventListener("click", loadAudit);

(async function init() {
  try {
    refreshI18nFormats();
    mountLangSwitcher("#lang-mount");
    const me = await api("/api/me");
    $("#admin-name").textContent = me.username;
  } catch (err) {
    // A failed /api/me used to abort the whole init silently: an empty
    // dashboard, "…" as the admin name and no clue why. api() already routes
    // a 401 to the login page, so anything here is a real failure.
    if (err && err.message !== "auth") toast(err.message, false);
    return;
  }
  loadAppearance();
  loadStats();
  loadSystem();
  loadUsers($("#search") ? $("#search").value.trim() : "");
  loadTemplates();
})();
