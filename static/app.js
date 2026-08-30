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
  openvpn: "OpenVPN"
};
const EVENT_EN = {
  LOGIN_OK: "Successful login",
  LOGIN_FAIL: "Failed login",
  LOGIN_2FA_FAIL: "Wrong 2FA code",
  RATE_LIMIT: "Rate limited",
  USER_CREATE: "User created",
  USER_PATCH: "User updated",
  USER_DELETE: "User deleted",
  TOKEN_RESET: "Token reset",
  PW_CHANGE: "Password changed",
  TFA_ENABLE: "2FA enabled",
  TFA_DISABLE: "2FA disabled",
  TFA_SETUP: "2FA setup started",
  SETTINGS_UPDATE: "Server settings updated",
  BACKUP_DL: "Backup downloaded",
  RESTORE: "Backup restored",
  RESTORE_FAIL: "Restore denied",
  REALITY_GENERATE: "REALITY keys generated",
  REALITY_REVEAL: "REALITY private key viewed",
  TEMPLATE_SAVE: "Template saved",
  TEMPLATE_DELETE: "Template deleted",
  USER_START: "User started (first use)",
  TUNNEL_SETTINGS: "Tunnel settings updated",
  NODE_CREATE: "Tunnel node created",
  NODE_DELETE: "Tunnel node removed",
  NODE_CHECK: "Node checked",
  NODE_TOKEN_REVEAL: "Node token revealed",
  NODE_TOKEN_REGEN: "Node token regenerated",
  NODE_GUIDE_DL: "Setup guide downloaded",
  INBOUND_CREATE: "Inbound added",
  INBOUND_PATCH: "Inbound updated",
  INBOUND_DELETE: "Inbound removed",
  TG_SAVE: "Telegram settings saved",
  TG_TEST: "Telegram test sent"
};

let USERS_CACHE = [];
let SORT_MODE = "newest";

const numFmt = new Intl.NumberFormat("en-US");
const dateFmt = new Intl.DateTimeFormat("en-US", { year: "numeric", month: "short", day: "2-digit" });
const dateTimeFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });

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
    const msg = Array.isArray(d)
      ? d.map((x) => (typeof x === "object" && x.msg ? x.msg : JSON.stringify(x))).join(", ")
      : (d && typeof d === "object" && d.message) || d || `Error (${res.status})`;
    throw new Error(msg);
  }
  return data;
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

function daysLeft(isoZ) {
  return Math.ceil((new Date(isoZ).getTime() - Date.now()) / 86400000);
}
function badge(text, cls) {
  const s = document.createElement("span");
  s.className = "badge " + cls;
  s.textContent = text;
  return s;
}
function expiryBadge(u) {
  if (!u.is_active) return badge("Disabled", "off");
  const d = daysLeft(u.expires_at);
  if (d <= 0) return badge("Expired", "expired");
  if (d <= 7) return badge(`${d} days`, "warn");
  return badge(`${d} days`, "ok");
}
function statusBadge(u) {
  if (!u.is_active) return badge("Paused", "off");
  if (u.pending_start) return badge("Not started", "pending");
  if (u.used_gb >= u.volume_gb) return badge("Limited", "limited");
  if (!u.expires_at || daysLeft(u.expires_at) <= 0) return badge("Expired", "expired");
  return badge("Active", "ok");
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
  const label = document.createElement("span");
  label.className = "vol-label";
  label.textContent = `${u.used_gb.toFixed(1)} / ${u.volume_gb.toFixed(1)} GB`;
  const bar = document.createElement("div");
  bar.className = "bar";
  const fill = document.createElement("div");
  fill.className = "fill";
  const pct = u.volume_gb > 0 ? Math.min(100, (u.used_gb / u.volume_gb) * 100) : 0;
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
  dateSmall.textContent = dateFmt.format(new Date(u.expires_at));
  exp.appendChild(dateSmall);

  const act = document.createElement("td");
  const subUrl = `${location.origin}/sub/${u.token}`;
  const qrBtn = iconBtn("Show QR code", ICONS.qr, "accent");
  qrBtn.dataset.act = "qr";
  qrBtn.dataset.id = u.id;
  const copyBtn = iconBtn("Copy subscription link", ICONS.copy, "accent");
  copyBtn.dataset.act = "copy";
  copyBtn.dataset.url = subUrl;
  const dlBtn = iconBtn("Download config file(s)", ICONS.download, "accent");
  dlBtn.dataset.act = "download";
  dlBtn.dataset.id = u.id;
  const toggleBtn = iconBtn(
    u.is_active ? "Pause service" : "Enable service",
    u.is_active ? ICONS.toggleOff : ICONS.toggleOn,
    u.is_active ? "warn" : "good"
  );
  toggleBtn.dataset.act = "toggle";
  toggleBtn.dataset.id = u.id;
  const resetBtn = iconBtn("Reset token & keys", ICONS.refresh);
  resetBtn.dataset.act = "reset";
  resetBtn.dataset.id = u.id;
  const delBtn = iconBtn("Delete", ICONS.trash, "bad");
  delBtn.dataset.act = "del";
  delBtn.dataset.id = u.id;
  delBtn.dataset.name = u.username;
  act.append(qrBtn, copyBtn, dlBtn, toggleBtn, resetBtn, delBtn);

  tr.append(st, unTd, note, vol, exp, act);
  return tr;
}

function applySort(items) {
  const arr = [...items];
  if (SORT_MODE === "expiry") {
    arr.sort((a, b) => new Date(a.expires_at || "2099-01-01") - new Date(b.expires_at || "2099-01-01"));
  } else if (SORT_MODE === "usage") {
    arr.sort((a, b) => b.used_gb / Math.max(b.volume_gb, 1) - a.used_gb / Math.max(a.volume_gb, 1));
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

async function loadUsers(q = "") {
  try {
    const data = await api("/api/users?q=" + encodeURIComponent(q));
    USERS_CACHE = data.items;
    renderUserTable(USERS_CACHE);
    $("#empty-state").classList.toggle("hidden", data.items.length > 0);
    renderRecent([...USERS_CACHE].sort((a, b) => b.id - a.id).slice(0, 5));
  } catch (e) {
    if (e.message !== "auth") toast(e.message, false);
  }
}

function renderRecent(items) {
  const tbody = $("#recent-tbody");
  tbody.textContent = "";
  for (const u of items) {
    const tr = document.createElement("tr");
    const c1 = document.createElement("td");
    const b = document.createElement("strong");
    b.textContent = u.username;
    c1.appendChild(b);
    const c2 = document.createElement("td");
    c2.appendChild(protoBadges(u.protocols || []));
    const c3 = document.createElement("td");
    c3.textContent = `${u.volume_gb.toFixed(0)} GB`;
    const c4 = document.createElement("td");
    c4.textContent = dateFmt.format(new Date(u.expires_at));
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
      (s.expiring_soon > 0 ? `${s.expiring_soon} expire within 7 days` : "") +
      (s.pending_start > 0 ? `${s.expiring_soon > 0 ? " · " : ""}${s.pending_start} not started yet` : "") +
      (s.limited_users > 0 ? `${s.expiring_soon + s.pending_start > 0 ? " · " : ""}${s.limited_users} out of volume` : "");
    $("#s-volume").textContent = numFmt.format(Math.round(s.volume_total_gb)) + " GB";
    $("#s-used").textContent = "Used: " + s.used_total_gb.toFixed(1) + " GB";
  } catch (e) {}
}

async function loadSystem() {
  try {
    const sys = await api("/api/system");
    if (!sys.available) { $("#sys-card").classList.add("hidden"); return; }
    setBar("#bar-cpu", "#val-cpu", sys.cpu);
    setBar("#bar-mem", "#val-mem", sys.mem);
    setBar("#bar-disk", "#val-disk", sys.disk);
    $("#sys-uptime").textContent = "Uptime: " + sys.uptime_hours + "h";
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
    $("#page-title").textContent = btn.dataset.title;
    if (btn.dataset.section === "dashboard") { loadStats(); loadSystem(); }
    if (btn.dataset.section === "settings") { loadTfa(); loadAudit(); loadSrvSettings(); loadTelegram(); }
    if (btn.dataset.section === "tunnels") { loadNodes(); loadTunnelSettings(); }
    if (btn.dataset.section === "inbounds") loadInbounds();
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
$("#add-user-btn").addEventListener("click", () => overlay.classList.remove("hidden"));
$("#modal-close").addEventListener("click", () => overlay.classList.add("hidden"));
overlay.addEventListener("click", (e) => { if (e.target === overlay) overlay.classList.add("hidden"); });

const qrModal = $("#qr-modal");
$("#qr-close").addEventListener("click", () => qrModal.classList.add("hidden"));
qrModal.addEventListener("click", (e) => { if (e.target === qrModal) qrModal.classList.add("hidden"); });
let currentQrUrl = "";
$("#qr-copy-btn").addEventListener("click", async () => {
  await navigator.clipboard.writeText(currentQrUrl);
  toast("Link copied");
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { overlay.classList.add("hidden"); qrModal.classList.add("hidden"); }
});

$("#add-user-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const protos = Array.from(f.querySelectorAll('input[name="proto"]:checked')).map((c) => c.value);
  if (!protos.length) { toast("Select at least one protocol", false); return; }
  try {
    await api("/api/users", {
      method: "POST",
      body: {
        username: f.username.value.trim(),
        protocols: protos,
        volume_gb: parseFloat(f.volume.value),
        days: parseInt(f.days.value, 10),
        note: f.note.value.trim(),
        start_on_first_use: $("#sofu-check").checked
      }
    });
    f.reset();
    f.querySelector('input[value="vless"]').checked = true;
    f.volume.value = 30; f.days.value = 30;
    overlay.classList.add("hidden");
    toast(`User created with ${protos.length} protocol(s)`);
    loadUsers($("#search").value.trim());
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
});

async function loadTemplates() {
  try {
    const tpls = await api("/api/templates");
    const sel = $("#tpl-select");
    sel.textContent = "";
    const first = document.createElement("option");
    first.value = "";
    first.textContent = "Load template...";
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
  const t = JSON.parse(opt.dataset.payload);
  const f = $("#add-user-form");
  f.querySelectorAll('input[name="proto"]').forEach((c) => { c.checked = t.protocols.includes(c.value); });
  f.volume.value = t.volume_gb;
  f.days.value = t.days;
  $("#sofu-check").checked = !!t.start_on_first_use;
});
$("#tpl-save-btn").addEventListener("click", async () => {
  const f = $("#add-user-form");
  const protos = Array.from(f.querySelectorAll('input[name="proto"]:checked')).map((c) => c.value);
  if (!protos.length) { toast("Select protocols first, then save as template", false); return; }
  const name = prompt("Template name:");
  if (!name) return;
  try {
    await api("/api/templates", {
      method: "POST",
      body: { name, protocols: protos, volume_gb: parseFloat(f.volume.value), days: parseInt(f.days.value, 10), start_on_first_use: $("#sofu-check").checked }
    });
    toast(`Template "${name}" saved`);
    loadTemplates();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#tpl-del-btn").addEventListener("click", async () => {
  const sel = $("#tpl-select");
  const id = sel.value;
  if (!id) { toast("Select a template to delete", false); return; }
  if (!confirm(`Delete template "${sel.selectedOptions[0].textContent}"?`)) return;
  try {
    await api("/api/templates/" + id, { method: "DELETE" });
    toast("Template deleted");
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
  if (!USERS_CACHE.length) { toast("No users to export", false); return; }
  const safeCell = (v) => {
    const s = String(v);
    return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  };
  const rows = [["username", "protocols", "volume_gb", "used_gb", "expires_at", "status", "note"]];
  for (const u of applySort(USERS_CACHE)) {
    rows.push([
      u.username,
      (u.protocols || []).join("|"),
      u.volume_gb,
      u.used_gb,
      u.expires_at || "on-first-use",
      u.is_active ? (u.pending_start ? "pending" : (u.used_gb >= u.volume_gb ? "limited" : (daysLeft(u.expires_at) <= 0 ? "expired" : "active"))) : "disabled",
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
  toast(`Exported ${rows.length - 1} users`);
});

$("#users-table").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  const id = btn.dataset.id;
  try {
    if (btn.dataset.act === "edit") {
      const u = USERS_CACHE.find((x) => String(x.id) === String(id));
      if (!u) return;
      $("#edit-uname").textContent = u.username;
      const f = $("#edit-user-form");
      f.note.value = u.note || "";
      f.volume.value = u.volume_gb;
      f.expires.value = u.pending_start ? "" : (u.expires_at || "").slice(0, 16);
      f.reset_used.checked = false;
      f.dataset.uid = id;
      $("#edit-modal").classList.remove("hidden");
      return;
    }
    if (btn.dataset.act === "copy") {
      await navigator.clipboard.writeText(btn.dataset.url);
      toast("Subscription link copied");
      return;
    }
    if (btn.dataset.act === "download") {
      window.open(`/api/users/${id}/config`, "_blank");
      toast("Downloading config...");
      return;
    }
    if (btn.dataset.act === "qr") {
      const d = await api(`/api/users/${id}/qr`);
      currentQrUrl = d.url;
      $("#user-qr-img").src = "data:image/svg+xml;base64," + d.qr_b64;
      $("#qr-url").textContent = d.url;
      qrModal.classList.remove("hidden");
      return;
    }
    if (btn.dataset.act === "toggle") {
      const isActive = btn.classList.contains("warn");
      await api("/api/users/" + id, { method: "PATCH", body: { is_active: !isActive } });
      toast(isActive ? "Service paused" : "Service enabled");
    } else if (btn.dataset.act === "reset") {
      if (!confirm("Invalidate the old token and generate completely new keys/configs?")) return;
      await api("/api/users/" + id + "/reset-token", { method: "POST" });
      toast("Token and keys regenerated");
    } else if (btn.dataset.act === "del") {
      if (!confirm(`Delete user "${btn.dataset.name}" permanently?`)) return;
      await api("/api/users/" + id, { method: "DELETE" });
      toast("User deleted");
    }
    loadUsers($("#search").value.trim());
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
});

$("#pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  if (f.new1.value !== f.new2.value) {
    toast("New passwords do not match", false);
    return;
  }
  try {
    await api("/api/change-password", {
      method: "POST",
      body: { current_password: f.current.value, new_password: f.new1.value }
    });
    f.reset();
    toast("Password changed successfully");
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
});

async function loadTfa() {
  try {
    const me = await api("/api/me");
    $("#tfa-chip").classList.toggle("hidden", !me.totp_enabled);
    const line = $("#tfa-status-line");
    line.textContent = "";
    if (me.totp_enabled) {
      const ok = document.createElement("p");
      ok.className = "tfa-on";
      ok.textContent = "\u2713 Two-factor auth is ENABLED";
      line.appendChild(ok);
      $("#tfa-setup-area").classList.add("hidden");
      $("#tfa-disable-btn").classList.remove("hidden");
    } else {
      const off = document.createElement("p");
      off.className = "tfa-off";
      off.textContent = "\u26a0 Two-factor auth is OFF \u2014 strongly recommended to enable it.";
      off.addEventListener("click", startSetup);
      line.appendChild(off);
      $("#tfa-disable-btn").classList.add("hidden");
    }
  } catch (_) {}
}

async function startSetup() {
  try {
    const d = await api("/api/2fa/setup", { method: "POST" });
    $("#tfa-qr").src = "data:image/svg+xml;base64," + d.qr_b64;
    $("#tfa-uri").textContent = d.uri;
    $("#tfa-setup-area").classList.remove("hidden");
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
}
$("#tfa-status-line").addEventListener("click", (e) => {
  if (e.target.classList.contains("tfa-off")) startSetup();
});

$("#tfa-enable-btn").addEventListener("click", async () => {
  const code = $("#tfa-code").value.trim();
  if (!/^[0-9]{6}$/.test(code)) { toast("Enter the 6-digit code", false); return; }
  try {
    await api("/api/2fa/enable", { method: "POST", body: { code } });
    $("#tfa-setup-area").classList.add("hidden");
    $("#tfa-code").value = "";
    toast("Two-factor auth enabled");
    loadTfa();
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
});

$("#tfa-disable-btn").addEventListener("click", async () => {
  const code = prompt("Enter the current 6-digit code to disable 2FA:");
  if (!code) return;
  try {
    await api("/api/2fa/disable", { method: "POST", body: { code } });
    toast("Two-factor auth disabled");
    loadTfa();
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
});

async function loadSrvSettings() {
  try {
    const srv = await api("/api/settings");
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
  } catch (_) {}
}
document.getElementById("cdn-preset")?.addEventListener("change", (e) => {
  if (e.target.value) document.querySelector('[name="cdn_sni"]').value = e.target.value;
});

async function saveAllSettings() {
  const f = $("#srv-form");
  const body = {};
  body.domain = f.domain.value.trim();
  body.sub_port = parseInt(f.sub_port.value, 10);
  body.hy2_port = parseInt(f.hy2_port.value, 10);
  body.wg_port = parseInt(f.wg_port.value, 10);
  body.ovpn_port = parseInt(f.ovpn_port.value, 10);
  body.dns = f.dns.value.trim() || "1.1.1.1";
  body.ovpn_proto = f.ovpn_proto.value;
  body.wg_pub = f.wg_pub.value.trim();
  body.reality_port = parseInt(document.querySelector('[name="reality_port"]').value, 10) || 443;
  body.reality_sni = document.querySelector('[name="reality_sni"]').value.trim() || "www.yahoo.com,www.samsung.com,www.microsoft.com";
  body.obfuscated_host = f.obfuscated_host.value.trim();
  body.per_user_subdomain = f.per_user_subdomain.checked;
  body.block_direct_ip = f.block_direct_ip.checked;
  body.cdn_enabled = document.querySelector('[name="cdn_enabled"]').checked;
  body.cdn_sni = document.querySelector('[name="cdn_sni"]').value.trim();
  try {
    await api("/api/settings", { method: "PUT", body });
    toast("Server settings saved — new configs will use them");
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
}
document.getElementById("save-reality-btn")?.addEventListener("click", saveAllSettings);
$("#srv-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await saveAllSettings();
});

$("#reality-gen-btn").addEventListener("click", async () => {
  if (!confirm("Generate a NEW REALITY keypair? Existing REALITY configs keep working only after you update the server's Xray config with the new private key.")) return;
  try {
    const d = await api("/api/reality/generate", { method: "POST" });
    $("#reality-pub").value = d.public_key;
    $("#reality-priv").value = d.private_key;
    $("#reality-out").classList.remove("hidden");
    toast("REALITY keypair generated");
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#reality-reveal-btn").addEventListener("click", async () => {
  try {
    const d = await api("/api/reality/private");
    $("#reality-priv").value = d.private_key;
    $("#reality-out").classList.remove("hidden");
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#reality-copy-btn").addEventListener("click", async () => {
  await navigator.clipboard.writeText(
    `private_key: ${$("#reality-priv").value}\npublic_key: ${$("#reality-pub").value}`
  );
  toast("Keys copied");
});

async function loadTunnelSettings() {
  try {
    const t = await api("/api/tunnel-settings");
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
    toast("Tunnel settings saved");
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
});
document.querySelectorAll("[data-tunnel-script]").forEach((btn) => {
  btn.addEventListener("click", () => window.open(`/api/tunnel/scripts/${btn.dataset.tunnelScript}`, "_blank"));
});

const NODE_STATUS_LABEL = { online: "\u25cf online", offline: "\u25cb offline", unknown: "? not checked" };

function renderNodes(nodes) {
  const ul = $("#nodes-list");
  ul.textContent = "";
  if (!nodes.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No tunnels yet. Create one above.";
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
    st.textContent = NODE_STATUS_LABEL[n.status] || n.status;
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
    li.appendChild(mk("Check reachability now", "check", "good", n.id));
    li.appendChild(mk("Copy token", "copy", "accent", n.id));
    li.appendChild(mk("Download BackPack setup guide", "download", "accent", n.id));
    li.appendChild(mk("Regenerate token", "refresh", "warn", n.id));
    const delBtn = iconBtn("Delete tunnel", ICONS.trash, "bad");
    delBtn.dataset.act = "del-node";
    delBtn.dataset.id = n.id;
    delBtn.dataset.name = n.name;
    li.appendChild(delBtn);
    ul.appendChild(li);
  }
}

async function loadNodes() {
  try {
    renderNodes(await api("/api/nodes"));
  } catch (_) {}
}

$("#node-create-btn").addEventListener("click", async () => {
  const name = $("#node-name").value.trim();
  const iran = $("#node-iran").value.trim();
  const kharej = $("#node-kharej").value.trim();
  if (!name || !iran || !kharej) { toast("Fill name, Iran IP and Kharej IP", false); return; }
  try {
    const node = await api("/api/nodes", {
      method: "POST",
      body: {
        name,
        transport: $("#node-transport").value,
        iran_ip: iran,
        kharej_ip: kharej,
        tunnel_port: parseInt($("#node-tport").value, 10),
        forwarded_ports: $("#node-fports").value.trim(),
        udp_forward: $("#node-udp").checked
      }
    });
    await navigator.clipboard.writeText(node.token_once).catch(() => {});
    toast(`Tunnel created \u2014 TOKEN copied to clipboard!`);
    $("#node-name").value = ""; $("#node-iran").value = ""; $("#node-kharej").value = "";
    loadNodes();
    setTimeout(() => window.open(`/api/nodes/${node.id}/guide`, "_blank"), 500);
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

$("#nodes-list").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  const id = btn.dataset.id;
  try {
    if (btn.dataset.act === "check") {
      const n = await api(`/api/nodes/${id}/check`, { method: "POST" });
      toast(n.status === "online" ? `Iran side is ONLINE (${n.iran_ip}:${n.tunnel_port})` : `Iran side UNREACHABLE`, n.status === "online");
      loadNodes();
    } else if (btn.dataset.act === "copy") {
      const r = await api(`/api/nodes/${id}/reveal-token`, { method: "POST" });
      await navigator.clipboard.writeText(r.token);
      toast("Token copied \u2014 use the SAME token on both servers");
    } else if (btn.dataset.act === "download") {
      window.open(`/api/nodes/${id}/guide`, "_blank");
    } else if (btn.dataset.act === "refresh") {
      if (!confirm("Generate a NEW token? You must update BOTH servers with it.")) return;
      await api(`/api/nodes/${id}/regen-token`, { method: "POST" });
      toast("Token regenerated \u2014 download the guide again");
      loadNodes();
    } else if (btn.dataset.act === "del-node") {
      if (!confirm(`Delete tunnel "${btn.dataset.name}"?`)) return;
      await api("/api/nodes/" + id, { method: "DELETE" });
      toast("Tunnel deleted");
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
  c4.textContent = ib.host || "\u2014";
  const c5 = document.createElement("td");
  c5.appendChild(badge(ib.enabled ? "ON" : "OFF", ib.enabled ? "ok" : "off"));
  const c6 = document.createElement("td");
  const tglBtn = iconBtn(ib.enabled ? "Disable" : "Enable", ICONS.toggleOff, ib.enabled ? "warn" : "good");
  tglBtn.dataset.act = "ib-toggle";
  tglBtn.dataset.id = ib.id;
  const delBtn = iconBtn("Delete", ICONS.trash, "bad");
  delBtn.dataset.act = "ib-del";
  delBtn.dataset.id = ib.id;
  delBtn.dataset.name = ib.name;
  c6.append(tglBtn, delBtn);
  tr.append(c1, c2, c3, c4, c5, c6);
  return tr;
}

async function loadInbounds() {
  try {
    const items = await api("/api/inbounds");
    const tbody = $("#inbounds-tbody");
    tbody.textContent = "";
    for (const ib of items) tbody.appendChild(inboundRow(ib));
    $("#ib-empty").classList.toggle("hidden", items.length > 0);
  } catch (_) {}
}

$("#ib-add-btn").addEventListener("click", async () => {
  const name = $("#ib-name").value.trim();
  const port = parseInt($("#ib-port").value, 10);
  if (!name || !port) { toast("Enter a name and port", false); return; }
  try {
    await api("/api/inbounds", {
      method: "POST",
      body: {
        name,
        protocol: $("#ib-proto").value,
        port,
        host: $("#ib-host").value.trim(),
        enabled: true
      }
    });
    $("#ib-name").value = ""; $("#ib-port").value = ""; $("#ib-host").value = "";
    toast(`Inbound "${name}" added \u2014 new user links include it`);
    loadInbounds();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

$("#inbounds-tbody").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  try {
    if (btn.dataset.act === "ib-toggle") {
      const on = btn.classList.contains("warn");
      await api("/api/inbounds/" + btn.dataset.id, { method: "PATCH", body: { enabled: !on } });
      toast(on ? "Inbound disabled" : "Inbound enabled");
    } else if (btn.dataset.act === "ib-del") {
      if (!confirm(`Delete inbound "${btn.dataset.name}"? User configs will stop using it.`)) return;
      await api("/api/inbounds/" + btn.dataset.id, { method: "DELETE" });
      toast("Inbound deleted");
    }
    loadInbounds();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

async function loadBlocklist() {
  try {
    const data = await api("/api/blocklist");
    const chk = $("#porn-toggle");
    if (chk) chk.checked = !!data.porn_enabled;
    const cnt = $("#porn-count");
    if (cnt) cnt.textContent = data.porn_enabled ? `Blocking ${data.porn_count} porn domains + ${data.sites.length} custom` : `Porn blocking is OFF — ${data.sites.length} custom domains blocked`;
    const ul = $("#block-list");
    ul.textContent = "";
    for (const site of data.sites) {
      const li = document.createElement("li");
      const span = document.createElement("span");
      span.textContent = site.domain;
      li.appendChild(span);
      const delBtn = iconBtn("Unblock", ICONS.trash, "bad");
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
    toast(e.target.checked ? "Porn blocking enabled" : "Porn blocking disabled");
    loadBlocklist();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); e.target.checked = !e.target.checked; }
});

$("#block-add-btn")?.addEventListener("click", async () => {
  const inp = $("#block-domain");
  const domain = inp.value.trim().toLowerCase();
  if (!domain) { toast("Enter a domain", false); return; }
  try {
    await api("/api/blocklist", { method: "POST", body: { domain } });
    inp.value = "";
    toast(`Blocked ${domain}`);
    loadBlocklist();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

$("#block-list")?.addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  if (!confirm(`Unblock "${btn.dataset.domain}"?`)) return;
  try {
    await api(`/api/blocklist/${btn.dataset.id}`, { method: "DELETE" });
    toast("Domain unblocked");
    loadBlocklist();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

$("#edit-close").addEventListener("click", () => $("#edit-modal").classList.add("hidden"));
$("#edit-modal").addEventListener("click", (e) => { if (e.target === $("#edit-modal")) $("#edit-modal").classList.add("hidden"); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#edit-modal").classList.add("hidden"); });

$("#edit-user-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const body = {};
  if (f.note.value.trim() !== "") body.set_note = f.note.value.trim();
  if (f.volume.value) body.set_volume_gb = parseFloat(f.volume.value);
  if (f.expires.value) body.set_expires_at = f.expires.value;
  if (f.reset_used.checked) body.reset_used = true;
  if (!Object.keys(body).length) { toast("Nothing changed", false); return; }
  try {
    await api("/api/users/" + f.dataset.uid, { method: "PATCH", body });
    $("#edit-modal").classList.add("hidden");
    toast("User updated");
    loadUsers($("#search").value.trim());
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

// ---- Telegram ----
async function loadTelegram() {
  try {
    const t = await api("/api/telegram");
    $("#tg-chat").value = t.chat_id || "";
    $("#tg-hint").textContent = t.has_token
      ? "\u2713 Bot token is saved."
      : "\u26a0 No bot token saved yet.";
  } catch (_) {}
}
$("#tg-save-btn").addEventListener("click", async () => {
  try {
    await api("/api/telegram", {
      method: "PUT",
      body: { bot_token: $("#tg-token").value.trim(), chat_id: $("#tg-chat").value.trim() }
    });
    $("#tg-token").value = "";
    toast("Telegram settings saved");
    loadTelegram();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#tg-test-btn").addEventListener("click", async () => {
  try {
    await api("/api/telegram/test", { method: "POST", body: {} });
    toast("Test message sent \u2014 check Telegram");
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

// ---- Docs two-column reader ----
function openDocPage(key) {
  document.querySelectorAll("#section-docs .doc-page").forEach((a) => {
    a.classList.toggle("hidden", a.dataset.key !== key);
  });
  document.querySelectorAll(".doc-link").forEach((b) => {
    b.classList.toggle("active", b.dataset.key === key);
  });
}

document.querySelectorAll(".doc-link").forEach((btn) => {
  btn.addEventListener("click", () => openDocPage(btn.dataset.key));
});

$("#doc-search").addEventListener("input", () => {
  const q = $("#doc-search").value.trim().toLowerCase();
  document.querySelectorAll(".doc-link").forEach((btn) => {
    btn.style.display = !q || btn.textContent.toLowerCase().includes(q) ? "" : "none";
  });
});

$("#backup-btn").addEventListener("click", () => {
  window.open("/api/backup", "_blank");
  toast("Backup download started");
});

const restoreFile = $("#restore-file");
restoreFile.addEventListener("change", () => {
  $("#restore-btn").disabled = !restoreFile.files.length;
});
$("#restore-btn").addEventListener("click", async () => {
  const file = restoreFile.files[0];
  if (!file) return;
  let parsed;
  try {
    parsed = JSON.parse(await file.text());
  } catch (_) {
    toast("Invalid JSON file", false);
    return;
  }
  if (!parsed || parsed.zefira_backup !== true) {
    toast("This file is not a Zefira backup", false);
    return;
  }
  if (!confirm(`Replace ALL current users and settings with ${parsed.users ? parsed.users.length : 0} restored users?\nThis cannot be undone.`)) return;
  const pw = prompt("Confirm your admin password to allow restore:");
  if (!pw) return;
  delete parsed.exported_at;
  parsed.zefira_backup = true;
  parsed.password_confirm = pw;
  try {
    const r = await api("/api/restore", { method: "POST", body: parsed });
    toast(`Restored ${r.added_users} users (${r.skipped} skipped)`);
    restoreFile.value = "";
    $("#restore-btn").disabled = true;
    loadStats();
    loadUsers();
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
      li.textContent = "No events recorded yet.";
      ul.appendChild(li);
      return;
    }
    for (const r of rows) {
      const li = document.createElement("li");
      if (!r.ok) li.classList.add("bad");
      const main = document.createElement("span");
      main.textContent = (EVENT_EN[r.event] || r.event) + (r.detail ? ` \u2014 ${r.detail}` : "");
      const meta = document.createElement("small");
      meta.textContent = `${dateTimeFmt.format(new Date(r.ts))}${r.ip && r.ip !== "?" ? " \u00b7 " + r.ip : ""}`;
      li.appendChild(main);
      li.appendChild(meta);
      ul.appendChild(li);
    }
  } catch (_) {}
}
$("#audit-refresh").addEventListener("click", loadAudit);

(async function init() {
  try {
    const me = await api("/api/me");
    $("#admin-name").textContent = me.username;
    $("#tfa-chip").classList.toggle("hidden", !me.totp_enabled);
  } catch (_) { return; }
  loadStats();
  loadSystem();
  loadUsers();
  openDocPage("start");
})();
