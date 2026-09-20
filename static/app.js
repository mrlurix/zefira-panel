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
const EVENT_EN = {
  LOGIN_OK: "Successful login",
  LOGIN_FAIL: "Failed login",
  RATE_LIMIT: "Rate limited",
  USER_CREATE: "User created",
  USER_PATCH: "User updated",
  USER_DELETE: "User deleted",
  TOKEN_RESET: "Token reset",
  USAGE_RESET: "Usage reset",  PW_CHANGE: "Password changed",
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
  TG_TEST: "Telegram test sent",
  SSL_ISSUE: "SSL certificate issued",
  SSL_RENEW: "SSL certificate renewed"
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
  if (u.device_limit) {
    const dev = document.createElement("span");
    dev.className = "badge proto";
    dev.textContent = `max ${u.device_limit} dev`;
    dev.title = `Up to ${u.device_limit} devices can use this account`;
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
  dateSmall.textContent = dateFmt.format(new Date(u.expires_at));
  exp.appendChild(dateSmall);

  const act = document.createElement("td");
  const subUrl = `${location.origin}/sub/${u.token}`;
  const editBtn = iconBtn("Edit user", ICONS.edit, "");
  editBtn.dataset.act = "edit";
  editBtn.dataset.id = u.id;
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
  act.append(editBtn, qrBtn, copyBtn, dlBtn, toggleBtn, resetBtn, delBtn);

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
  const devVal = parseInt(f.device_limit.value, 10);
  try {
    await api("/api/users", {
      method: "POST",
      body: {
        username: f.username.value.trim(),
        protocols: protos,
        volume_gb: parseFloat(f.volume.value),
        days: parseInt(f.days.value, 10),
        note: f.note.value.trim(),
        start_on_first_use: $("#sofu-check").checked,
        device_limit: Number.isFinite(devVal) && devVal >= 1 ? devVal : null
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
  f.device_limit.value = t.device_limit || "";
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
      body: { name, protocols: protos, volume_gb: parseFloat(f.volume.value), days: parseInt(f.days.value, 10), start_on_first_use: $("#sofu-check").checked, device_limit: (() => { const v = parseInt(f.device_limit.value, 10); return Number.isFinite(v) && v >= 1 ? v : null; })() }
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
      f.device_limit.value = u.device_limit || "";
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
      try {
        const u = (typeof USERS_CACHE !== "undefined" ? USERS_CACHE : []).find((x) => String(x.id) === String(id));
        if (u && (u.protocols || []).includes("wireguard")) {
          const srv = await api("/api/settings");
          if (!srv.wg_pub) {
            toast("Downloaded, but set the WireGuard server public key in Settings or it won't connect", false);
            return;
          }
        }
      } catch (_) {}
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

function applyBrand(name) {
  const b = (name || "").trim() || "ZEFIRA";
  document.querySelectorAll("[data-brand]").forEach((el) => { el.textContent = b; });
  document.title = b + " Panel";
}

// ---- Menu & dashboard layout ----
const MENU_LABELS = {
  dashboard: "Dashboard", users: "Users", inbounds: "Inbounds",
  tunnels: "Tunnels", nodes: "Nodes", reality: "Anti-Censorship",
  blocker: "Site Blocker", update: "Update", customize: "Personalize", settings: "Settings"
};
const MENU_IDS = Object.keys(MENU_LABELS);
const MENU_LOCKED = ["dashboard", "users", "inbounds", "customize", "settings"];
const DASH_LABELS = { usage: "Usage ring", link: "Subscription link", groups: "Config groups", apps: "Apps" };
const DASH_IDS = Object.keys(DASH_LABELS);
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
  mk("▲", onUp, false);
  mk("▼", onDown, false);
  const eye = mk(hidden ? "Show" : "Hide", onEye, locked);
  if (locked) eye.title = "Always visible";
  return li;
}
async function saveLayout(silent) {
  try {
    await api("/api/appearance", { method: "PUT", body: collectAppearance() });
    if (!silent) toast("Layout saved");
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
}
function renderMenuLayout() {
  const ul = $("#menu-layout-list");
  ul.textContent = "";
  MENU_STATE.forEach((item, i) => {
    const locked = MENU_LOCKED.includes(item.id);
    ul.appendChild(layoutRow(
      MENU_LABELS[item.id] || item.id,
      locked,
      item.hidden,
      () => { if (i > 0) { const t = MENU_STATE[i - 1]; MENU_STATE[i - 1] = item; MENU_STATE[i] = t; afterMenuChange(); } },
      () => { if (i < MENU_STATE.length - 1) { const t = MENU_STATE[i + 1]; MENU_STATE[i + 1] = item; MENU_STATE[i] = t; afterMenuChange(); } },
      () => { if (!locked) { item.hidden = !item.hidden; afterMenuChange(); } }
    ));
  });
}
function afterMenuChange() {
  renderMenuLayout();
  applyMenuLayout(MENU_STATE);
  saveLayout(true);
}
function renderDashLayout() {
  const ul = $("#dash-layout-list");
  ul.textContent = "";
  DASH_STATE.order.forEach((id, i) => {
    const hidden = DASH_STATE.hidden.includes(id);
    ul.appendChild(layoutRow(
      DASH_LABELS[id] || id,
      false,
      hidden,
      () => {
        if (i > 0) {
          const o = DASH_STATE.order.slice();
          const t = o[i - 1]; o[i - 1] = o[i]; o[i] = t;
          DASH_STATE.order = o;
          afterDashChange();
        }
      },
      () => {
        if (i < DASH_STATE.order.length - 1) {
          const o = DASH_STATE.order.slice();
          const t = o[i + 1]; o[i + 1] = o[i]; o[i] = t;
          DASH_STATE.order = o;
          afterDashChange();
        }
      },
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
    toast("Appearance saved");
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#ap-reset-btn").addEventListener("click", async () => {
  if (!confirm("Reset colors, brand and dashboard message to defaults?")) return;
  try {
    const body = collectAppearance();
    body.theme_accent = ""; body.theme_bg = ""; body.theme_card = "";
    body.theme_text = ""; body.theme_muted = "";
    body.brand_name = ""; body.dash_note = "";
    const r = await api("/api/appearance", { method: "PUT", body });
    applyBrand(r.brand_name);
    loadAppearance();
    toast("Appearance reset");
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
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
  body.l2tp_port = parseInt(f.l2tp_port.value, 10) || 1701;
  body.cisco_port = parseInt(f.cisco_port.value, 10) || 443;
  body.socks5_port = parseInt(f.socks5_port.value, 10) || 1080;
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
  c4.textContent = ib.host || "—";
  const cNode = document.createElement("td");
  const nodeSel = document.createElement("select");
  nodeSel.className = "ib-node-sel";
  nodeSel.title = "Server node (offline nodes are skipped in links)";
  const oLocal = document.createElement("option");
  oLocal.value = "";
  oLocal.textContent = "Local";
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
        body: { node_id: nodeSel.value ? parseInt(nodeSel.value, 10) : null }
      });
      toast(nodeSel.value ? "Inbound pinned to node" : "Inbound back to local");
      loadInbounds();
    } catch (err) {
      if (err.message !== "auth") toast(err.message, false);
      loadInbounds();
    }
  });
  cNode.appendChild(nodeSel);
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
  tr.append(c1, c2, c3, c4, cNode, c5, c6);
  return tr;
}

async function loadInbounds() {
  try {
    await loadSrvNodes();
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
        enabled: true,
        node_id: $("#ib-node") && $("#ib-node").value ? parseInt($("#ib-node").value, 10) : null
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

// ---- Server nodes ----
let SERVER_NODES = [];

function srvNodeStatus(n) {
  if (!n.enabled) return badge("Disabled", "off");
  if (n.status === "online") return badge("Online", "ok");
  if (n.status === "offline") return badge("Offline", "expired");
  return badge("Unknown", "pending");
}

function fillNodeSelect(sel, current) {
  if (!sel) return;
  sel.textContent = "";
  const o0 = document.createElement("option");
  o0.value = "";
  o0.textContent = "Local panel";
  sel.appendChild(o0);
  for (const n of SERVER_NODES) {
    const o = document.createElement("option");
    o.value = String(n.id);
    o.textContent = n.enabled ? n.name : `${n.name} (off)`;
    sel.appendChild(o);
  }
  if (current) sel.value = String(current);
}

function renderSrvNodes(nodes) {
  SERVER_NODES = nodes;
  fillNodeSelect($("#ib-node"), $("#ib-node") ? $("#ib-node").value : "");
  const ul = $("#snodes-list");
  ul.textContent = "";
  if (!nodes.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No server nodes yet. Add one above.";
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
    bits.push(n.uptime_pct != null ? `${n.uptime_pct}% uptime` : "not checked yet");
    if (n.note) bits.push(n.note);
    meta.textContent = bits.join(" · ");
    const st = document.createElement("span");
    st.appendChild(srvNodeStatus(n));
    li.appendChild(main);
    li.appendChild(meta);
    li.appendChild(st);
    const checkBtn = iconBtn("Check now", ICONS.refresh, "good");
    checkBtn.dataset.act = "check";
    checkBtn.dataset.id = n.id;
    const tglBtn = iconBtn(n.enabled ? "Disable" : "Enable", n.enabled ? ICONS.toggleOff : ICONS.toggleOn, n.enabled ? "warn" : "good");
    tglBtn.dataset.act = "toggle";
    tglBtn.dataset.id = n.id;
    const delBtn = iconBtn("Delete node", ICONS.trash, "bad");
    delBtn.dataset.act = "del-snode";
    delBtn.dataset.id = n.id;
    delBtn.dataset.name = n.name;
    li.append(checkBtn, tglBtn, delBtn);
    ul.appendChild(li);
  }
}

async function loadSrvNodes() {
  try {
    renderSrvNodes(await api("/api/server-nodes"));
  } catch (_) {}
}

$("#snode-create-btn").addEventListener("click", async () => {
  const name = $("#snode-name").value.trim();
  const address = $("#snode-addr").value.trim();
  const port = parseInt($("#snode-port").value, 10) || 443;
  if (!name || !address) { toast("Enter a name and address", false); return; }
  try {
    await api("/api/server-nodes", {
      method: "POST",
      body: { name, address, check_port: port, note: $("#snode-note").value.trim() }
    });
    $("#snode-name").value = ""; $("#snode-addr").value = ""; $("#snode-note").value = "";
    toast(`Server node "${name}" added`);
    loadSrvNodes();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

$("#snodes-list").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  const id = btn.dataset.id;
  try {
    if (btn.dataset.act === "check") {
      const n = await api(`/api/server-nodes/${id}/check`, { method: "POST" });
      toast(n.status === "online" ? `${n.name} ONLINE (${n.latency_ms} ms)` : `${n.name} UNREACHABLE`, n.status === "online");
      loadSrvNodes();
    } else if (btn.dataset.act === "toggle") {
      const cur = SERVER_NODES.find((x) => String(x.id) === String(id));
      await api(`/api/server-nodes/${id}`, { method: "PATCH", body: { enabled: !(cur && cur.enabled) } });
      toast("Node updated");
      loadSrvNodes();
    } else if (btn.dataset.act === "del-snode") {
      if (!confirm(`Delete server node "${btn.dataset.name}"? Its inbounds become local.`)) return;
      await api(`/api/server-nodes/${id}`, { method: "DELETE" });
      toast("Server node deleted");
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
  if (f.device_limit.value !== "") {
    const dv = parseInt(f.device_limit.value, 10);
    body.set_device_limit = Number.isFinite(dv) && dv >= 1 ? dv : 0;
  }
  if (f.reset_used.checked) body.reset_used = true;
  if (!Object.keys(body).length) { toast("Nothing changed", false); return; }
  try {
    await api("/api/users/" + f.dataset.uid, { method: "PATCH", body });
    $("#edit-modal").classList.add("hidden");
    toast("User updated");
    loadUsers($("#search").value.trim());
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

// ---- Panel update ----
let updatePoll = null;
function renderChangelog(items, prefix) {
  const ul = $("#update-changelog");
  ul.textContent = "";
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = prefix || "Nothing to show.";
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
async function loadUpdate(announce) {
  try {
    const st = await api("/api/update/status");
    const badge = $("#update-badge");
    const sum = $("#update-summary");
    $("#update-repo").textContent = st.repo + "@" + st.branch;
    if (st.error && !st.current) {
      badge.textContent = "error";
      badge.className = "badge proto off";
      sum.textContent = "Could not determine status: " + st.error;
      $("#update-now-btn").classList.add("hidden");
      renderChangelog([], "No data.");
    } else if (st.updating) {
      badge.textContent = "updating…";
      badge.className = "badge proto warn";
      sum.textContent = "Update in progress — the panel will restart any moment. Keep this page open.";
      $("#update-now-btn").classList.add("hidden");
      renderChangelog(st.incoming || [], "Fetching changelog…");
    } else if (st.update_available) {
      badge.textContent = "update available";
      badge.className = "badge proto warn";
      sum.textContent = `Running ${st.current} · latest is ${st.latest} — review the changes, then update.`;
      $("#update-now-btn").classList.remove("hidden");
      renderChangelog(st.incoming || [], "No changelog returned.");
    } else {
      badge.textContent = "up to date";
      badge.className = "badge proto ok";
      sum.textContent = `Running ${st.latest || st.current}${st.version ? " (v" + st.version + ")" : ""} — nothing to do.`;
      $("#update-now-btn").classList.add("hidden");
      renderChangelog(st.local_log || [], "No local history.");
    }
    if (announce) toast("Update check finished");
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
  }
}
$("#update-check-btn").addEventListener("click", () => loadUpdate(true));
$("#update-now-btn").addEventListener("click", async () => {
  if (!confirm("Update the panel now? It pulls the latest code, reinstalls dependencies and RESTARTS. Unsaved work in other tabs may be interrupted.")) return;
  const pw = prompt("Confirm your admin password to allow the update:");
  if (!pw) return;
  try {
    const before = await api("/api/update/status");
    await api("/api/update/apply", { method: "POST", body: { password_confirm: pw } });
    toast("Update started — panel will restart in about a minute");
    loadUpdate();
    let n = 0;
    if (updatePoll) clearInterval(updatePoll);
    updatePoll = setInterval(async () => {
      n += 1;
      try { await loadUpdate(); } catch (_) {}
      if (n >= 20 && updatePoll) {
        clearInterval(updatePoll);
        updatePoll = null;
        try {
          const after = await api("/api/update/status");
          if ((after.latest || "") === (before.latest || "") && !after.updating) {
            toast("Version unchanged — no systemd found? Restart the panel manually", false);
          } else {
            toast("Update finished ✓");
          }
        } catch (_) {}
      }
    }, 5000);
  } catch (err) {
    if (err.message !== "auth") toast(err.message, false);
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
  try {
    const a = await api("/api/ai/settings");
    $("#ai-enabled").checked = !!a.enabled;
    $("#ai-provider").value = a.provider || "openai";
    $("#ai-base").value = a.base_url || "";
    $("#ai-model").value = a.model || "";
    $("#ai-extra").value = a.extra || "";
    const badge = $("#ai-badge");
    if (badge) {
      const ready = a.enabled && a.has_key && a.model;
      badge.textContent = ready ? "ready" : "off";
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
    toast("AI settings saved");
    loadAi();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#ai-fab").addEventListener("click", () => {
  $("#ai-chat").classList.toggle("hidden");
  if (!$("#ai-chat").classList.contains("hidden")) {
    if (!$("#ai-msgs").children.length) {
      aiAddMsg("Hi! I know this panel inside-out — and I can act: create users, top up volume, extend days, reset usage, pause accounts. Just ask.", "bot");
    }
    $("#ai-input").focus();
  }
});
$("#ai-close").addEventListener("click", () => $("#ai-chat").classList.add("hidden"));
async function aiSend() {
  const inp = $("#ai-input");
  const text = inp.value.trim().slice(0, 2000);
  if (!text) return;
  inp.value = "";
  aiAddMsg(text, "user");
  AI_HISTORY.push({ role: "user", content: text });
  AI_HISTORY = AI_HISTORY.slice(-11);
  const typing = aiAddMsg("…", "bot typing");
  try {
    const r = await api("/api/ai/chat", { method: "POST", body: { messages: AI_HISTORY } });
    typing.remove();
    aiAddMsg(r.reply, "bot");
    AI_HISTORY.push({ role: "assistant", content: r.reply });
    AI_HISTORY = AI_HISTORY.slice(-12);
  } catch (err) {
    typing.remove();
    aiAddMsg(err.message === "auth" ? "Session expired." : ("Error: " + err.message), "bot");
  }
}
$("#ai-send").addEventListener("click", aiSend);
$("#ai-input").addEventListener("keydown", (e) => { if (e.key === "Enter") aiSend(); });

// ---- API tokens (bots & integrations) ----
function renderApiTokens(items) {
  const ul = $("#apitoken-list");
  ul.textContent = "";
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No API tokens yet. Create one above — it is shown only once.";
    ul.appendChild(li);
    return;
  }
  for (const t of items) {
    const li = document.createElement("li");
    li.style.display = "flex";
    li.style.flexWrap = "wrap";
    li.style.alignItems = "center";
    li.style.gap = "6px";
    const main = document.createElement("span");
    main.textContent = t.name;
    const meta = document.createElement("small");
    const bits = [`${t.prefix}…`];
    bits.push(t.last_used_at ? `last used ${t.last_used_at}` : "never used");
    meta.textContent = bits.join(" · ");
    li.appendChild(main);
    li.appendChild(meta);
    const delBtn = iconBtn("Revoke token", ICONS.trash, "bad");
    delBtn.dataset.act = "del-token";
    delBtn.dataset.id = t.id;
    delBtn.dataset.name = t.name;
    li.appendChild(delBtn);
    ul.appendChild(li);
  }
}
async function loadApiTokens() {
  try {
    renderApiTokens(await api("/api/api-tokens"));
  } catch (_) {}
}
$("#apitoken-create-btn").addEventListener("click", async () => {
  const name = $("#apitoken-name").value.trim();
  if (!name) { toast("Enter a token name", false); return; }
  try {
    const r = await api("/api/api-tokens", { method: "POST", body: { name } });
    $("#apitoken-name").value = "";
    try {
      await navigator.clipboard.writeText(r.token_once);
      toast(`Token created and copied — it will never be shown again`);
    } catch (_) {
      prompt("Copy your token now (shown only once):", r.token_once);
    }
    loadApiTokens();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#apitoken-list").addEventListener("click", async (e) => {
  const btn = e.target.closest(".row-btn");
  if (!btn) return;
  try {
    if (btn.dataset.act === "del-token") {
      if (!confirm(`Revoke API token "${btn.dataset.name}"? Connected bots stop working immediately.`)) return;
      await api("/api/api-tokens/" + btn.dataset.id, { method: "DELETE" });
      toast("Token revoked");
      loadApiTokens();
    }
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

// ---- SSL certificate ----
function renderSslStatus(st) {
  const el = $("#ssl-status");
  if (!el) return;
  if (!st.installed) {
    el.textContent = "\u26a0 certbot is not installed on this server (apt install certbot).";
    return;
  }
  if (st.domains && st.domains.length && st.expires) {
    el.textContent = `\u2713 ${st.domains.join(", ")} \u2014 valid until ${st.expires}`;
  } else if (st.domains && st.domains.length) {
    el.textContent = `\u2713 Certificate files found for ${st.domains.join(", ")}`;
  } else {
    el.textContent = "No certificate yet. Enter domain + email and press Issue.";
  }
}
async function loadSslStatus() {
  try {
    renderSslStatus(await api("/api/ssl/status"));
  } catch (_) {}
}
$("#ssl-issue-btn").addEventListener("click", async () => {
  const domain = $("#ssl-domain").value.trim();
  const subdomain = $("#ssl-subdomain").value.trim();
  const email = $("#ssl-email").value.trim();
  if (!domain || !email) { toast("Domain and email are required", false); return; }
  const fqdn = subdomain ? `${subdomain}.${domain}` : domain;
  if (!confirm(`Issue a Let's Encrypt certificate for ${fqdn}? Port 80 must be free. It can take a minute.`)) return;
  toast("Requesting certificate\u2026 this can take a minute");
  try {
    const r = await api("/api/ssl/issue", { method: "POST", body: { domain, subdomain, email } });
    renderSslStatus(r);
    toast("Certificate issued");
    loadAudit();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});
$("#ssl-renew-btn").addEventListener("click", async () => {
  try {
    const r = await api("/api/ssl/renew", { method: "POST", body: {} });
    renderSslStatus(r);
    toast("Certificate renewed");
    loadAudit();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
});

$("#backup-btn").addEventListener("click", async () => {
  const pw = prompt("Enter your admin password to download the backup:");
  if (!pw) return;
  try {
    const res = await fetch("/api/backup", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
      body: JSON.stringify({ password_confirm: pw })
    });
    if (res.status === 401) { location.href = "/login"; return; }
    if (!res.ok) { toast("Backup failed — wrong password?", false); return; }
    const blob = await res.blob();
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `zefira-backup-${stamp}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast("Backup download started");
  } catch (_) {
    toast("Backup failed", false);
  }
});

const restoreFile = $("#restore-file");
restoreFile.addEventListener("change", () => {
  $("#restore-btn").disabled = !restoreFile.files.length;
});
$("#restore-btn").addEventListener("click", async () => {
  const file = restoreFile.files[0];
  if (!file) return;
  if (file.size > 64 * 1048576) { toast("File is larger than 64 MB — the server will refuse it", false); return; }
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
  } catch (_) { return; }
  loadAppearance();
  loadStats();
  loadSystem();
  loadUsers();
})();
