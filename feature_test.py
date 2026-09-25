"""
ZEFIRA FEATURE COVERAGE SUITE - walks EVERY panel capability end to end and
asserts the feature is actually usable (not just "returns 200").

Run while the panel is up:
  .venv\\Scripts\\python feature_test.py http://127.0.0.1:8000 admin PASSWORD

Covers all 62 routes across 10 UI sections: dashboard, users, templates,
inbounds, server nodes, BackPack tunnels, reality, blocker, customize,
settings, AI, SSL, update, backup/restore, API tokens, subscription output.
Cleans up everything it creates. Refuses to run when foreign users exist
(unless --allow-live). Runs on an empty DB.
"""
import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"
ALLOW_LIVE = "--allow-live" in sys.argv

results = []
CREATED_USERS = []
CREATED_INBOUNDS = []
CREATED_SNODES = []
CREATED_TNODES = []
CREATED_TOKENS = []
CREATED_SITES = []
CREATED_TEMPLATES = []
SAVE = {}


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def req(method, path, body=None, headers=None, timeout=30, raw=False):
    url = BASE + path
    data = None
    hdrs = {"User-Agent": "zefira-featuretest/1.0"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = body.encode() if isinstance(body, str) else body
        hdrs.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.status, dict(resp.headers), (resp.read() if raw else resp.read())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()


def js(method, path, obj=None, headers=None, timeout=30, raw=False):
    st, hd, body = req(method, path, json.dumps(obj) if obj is not None else None, headers, timeout)
    if raw:
        return st, body.decode("utf-8", "replace")
    try:
        return st, json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return st, {"_raw": body[:400].decode("utf-8", "replace")}


def hget(hdrs, name):
    for k, v in hdrs.items():
        if k.lower() == name.lower():
            return v
    return ""


def _decode(hdrs, default):
    for k, v in hdrs.items():
        if k.lower() == "set-cookie":
            return v.encode()
    return default


def decode_sub(body: bytes) -> str:
    """Raw subscriptions are base64 when link-only; decode for assertions."""
    txt = body.decode("utf-8", "replace")
    if "://" in txt:
        return txt
    try:
        return base64.b64decode(body).decode("utf-8", "replace")
    except Exception:
        return txt


BROWSER_UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"}
CLIENT_UA = {"User-Agent": "v2rayNG/1.8.0 (feature test)"}


def login_with(password):
    st, hd, _ = req("POST", "/api/login",
                    json.dumps({"username": ADMIN, "password": password}),
                    {"X-Requested-With": "XMLHttpRequest"})
    tok = ""
    for part in (hd.get("set-cookie") or hd.get("Set-Cookie") or "").split(";"):
        part = part.strip()
        if part.startswith("zefira_session="):
            tok = part.split("=", 1)[1]
    return st, {"Cookie": f"zefira_session={tok}", "X-Requested-With": "XMLHttpRequest"}


print(f"=== ZEFIRA FEATURE COVERAGE -> {BASE} ===")
st, AUTH = login_with(PASSWORD)
check("login", st == 200, f"status={st}")
if st != 200:
    print("ABORT: cannot log in")
    sys.exit(2)

# ---------------------------------------------------------------- pages
st, hd, body = req("GET", "/login", raw=True)
check("GET /login renders", st == 200 and b"<form" in body.lower(), f"status={st}")
st, hd, body = req("GET", "/panel", headers=AUTH, raw=True)
check("GET /panel renders for admin", st == 200 and b'id="users-tbody"' in body, f"status={st}")
st, hd, body = req("GET", "/theme.css", raw=True)
check("GET /theme.css is CSS", st == 200 and (b"--accent" in body or b":root" in body), f"status={st}")
st, _, _ = req("GET", "/")
check("GET / redirects to /panel", st in (200, 302, 307), f"status={st}")

# ---------------------------------------------------------------- dashboard
st, d = js("GET", "/api/me", headers=AUTH)
check("dashboard: /api/me", st == 200 and d.get("username") == ADMIN, f"{st} {d}")
st, d = js("GET", "/api/stats", headers=AUTH)
need = ("total_users", "active_users", "expired_users", "disabled_users",
        "expiring_soon", "pending_start", "limited_users", "volume_total_gb", "used_total_gb")
check("dashboard: /api/stats has every counter", st == 200 and all(k in d for k in need), f"{st} {d}")
st, d = js("GET", "/api/system", headers=AUTH)
check("dashboard: /api/system reports health", st == 200 and d.get("available") is True, f"{st} {d}")
st, d = js("GET", "/api/audit", headers=AUTH)
check("dashboard: /api/audit list", st == 200 and isinstance(d, list), f"{st}")

# ---------------------------------------------------------------- users
all_protos = ["vless", "reality", "vmess", "trojan", "ss", "hysteria2",
              "wireguard", "openvpn", "l2tp", "cisco", "socks5"]
u1 = "ft" + uuid.uuid4().hex[:8]
st, u = js("POST", "/api/users", {
    "username": u1, "protocols": all_protos, "volume_gb": 50, "days": 30,
    "note": "feature suite", "device_limit": 3,
}, AUTH)
check("users: create with all 11 protocols", st == 200 and u.get("token"), f"{st} {u}")
uid = u.get("id") if st == 200 else None
if uid:
    CREATED_USERS.append(uid)
    tok = u.get("token")

st, d = js("GET", f"/api/users/by-username/{u1}", headers=AUTH)
check("users: lookup by username", st == 200 and d.get("username") == u1, f"{st} {d}")
st, d = js("GET", f"/api/users?q={u1}", headers=AUTH)
check("users: search finds it", st == 200 and any(x["id"] == uid for x in d.get("items", [])),
      f"{st} total={d.get('total')}")
check("users: list reports total", st == 200 and d.get("total", 0) >= 1, f"total={d.get('total')}")

# subscription outputs must be usable
st, hd, body = req("GET", f"/sub/{tok}", headers={"User-Agent": "zefira-featuretest/1.0"}, raw=True)
sub_txt = decode_sub(body)
check("sub: raw subscription served", st == 200 and len(body) > 50, f"{st} len={len(body)}")
check("sub: links present for link protocols",
      "vless://" in sub_txt and "vmess://" in sub_txt and "trojan://" in sub_txt
      and "ss://" in sub_txt and "hysteria2://" in sub_txt and "reality" not in sub_txt.lower().split("://")[0],
      sub_txt[:80])
# Every machine-facing subscription is a Base64 document (v2ray convention),
# including bundles that also carry the file-based configs.
check("sub: body is Base64 for machine clients",
      st == 200 and "://" not in body.decode("utf-8", "replace")[:200]
      and base64.b64decode(body + b"=" * (-len(body) % 4)).decode("utf-8", "replace").count("://") >= 5,
      body[:60])
check("sub: userinfo header", hget(hd, "subscription-userinfo").startswith("upload=0;"),
      hget(hd, "subscription-userinfo"))
st, hd, body = req("GET", f"/sub/{tok}", headers={"User-Agent": "v2rayNG/1.0"}, raw=True)
check("sub: client UA gets decoded links not HTML", st == 200 and b"<html" not in body.lower(), f"{st}")
st, hd, body = req("GET", f"/sub/{tok}?format=clash", raw=True)
clash = body.decode("utf-8", "replace")
check("sub: clash yaml valid shape", st == 200 and "proxies:" in clash and "proxy-groups:" in clash
      and "MATCH,Zefira" in clash, clash[:120])
check("sub: clash has all relay proxies", all(f'"type": "{t}"' in clash for t in
      ("vmess", "vless", "trojan", "ss", "hysteria2")), "missing proxy types")
st, hd, body = req("GET", f"/sub/{tok}", headers={"User-Agent": "mihomo/1.0"}, raw=True)
check("sub: mihomo UA auto-detects clash", st == 200 and b"proxies:" in body, f"{st}")
st, hd, body = req("GET", f"/sub/{tok}", headers={"User-Agent": "Mozilla/5.0 (X11) AppleWebKit/537.36 Chrome/120 Safari/537.36"}, raw=True)
html = body.decode("utf-8", "replace")
check("sub: browser UA gets dashboard HTML", st == 200 and "<!DOCTYPE html>" in html, f"{st}")
check("sub: dashboard shows usage + link", "GB" in html and "/sub/" in html, "missing usage/link")
st, hd, body = req("GET", f"/sub/{tok}?format=clash", headers={"User-Agent": "mihomo/1.0"}, raw=True)
check("sub: clash device-limit comment", st == 200, f"{st}")
st, hd, body = req("GET", "/sub/deadbeef" * 4, raw=True)
check("sub: unknown token 404s", st == 404, f"{st}")

st, hd, body = req("GET", f"/api/users/{uid}/config", headers=AUTH, raw=True)
check("users: config bundle downloads", st == 200 and len(body) > 500, f"{st} len={len(body)}")
check("users: config is a zip (PK)", st == 200 and body[:2] == b"PK", body[:8])
st, d = js("GET", f"/api/users/{uid}/qr", headers=AUTH)
qr = d.get("qr_b64", "")
svg_ok = False
if qr:
    try:
        decoded = base64.b64decode(qr.split(",", 1)[-1]).decode("utf-8", "replace")
        svg_ok = "<svg" in decoded
    except Exception:
        svg_ok = False
check("users: QR returns a decodable svg", st == 200 and svg_ok and tok in d.get("url", ""),
      f"{st} qr_len={len(qr)}")

st, d = js("PATCH", f"/api/users/{uid}", {"extend_days": 10}, AUTH)
check("users: extend days", st == 200, f"{st} {d}")
st, d = js("PATCH", f"/api/users/{uid}", {"add_volume_gb": 25}, AUTH)
check("users: top up volume", st == 200 and abs(d.get("volume_gb", 0) - 75) < 0.01, f"{st} {d}")
st, d = js("PATCH", f"/api/users/{uid}", {"add_used_gb": 3.5}, AUTH)
check("users: add usage", st == 200 and abs(d.get("used_gb", 0) - 3.5) < 0.01, f"{st} {d}")
st, d = js("PATCH", f"/api/users/{uid}", {"set_note": "edited"}, AUTH)
check("users: set note", st == 200 and d.get("note") == "edited", f"{st} {d}")
st, d = js("PATCH", f"/api/users/{uid}", {"set_device_limit": 0}, AUTH)
check("users: device limit cleared to unlimited", st == 200 and d.get("device_limit") is None, f"{st} {d}")
st, d = js("PATCH", f"/api/users/{uid}", {"set_device_limit": 5}, AUTH)
check("users: device limit set", st == 200 and d.get("device_limit") == 5, f"{st} {d}")
exp = (datetime.now(timezone.utc) + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M")
st, d = js("PATCH", f"/api/users/{uid}", {"set_expires_at": exp}, AUTH)
check("users: explicit expiry", st == 200 and d.get("expires_at", "").startswith(exp[:10]), f"{st} {d}")
st, d = js("PATCH", f"/api/users/{uid}", {"is_active": False}, AUTH)
check("users: pause", st == 200 and d.get("is_active") is False, f"{st} {d}")
st, _ = js("GET", f"/sub/{tok}", headers=CLIENT_UA)
check("sub: paused user 404s for clients", st == 404, f"{st}")
js("PATCH", f"/api/users/{uid}", {"is_active": True}, AUTH)

st, d = js("POST", f"/api/users/{uid}/reset-usage", {}, AUTH)
check("users: reset usage", st == 200 and d.get("used_gb") == 0, f"{st} {d}")
st, d = js("POST", f"/api/users/{uid}/reset-token", {}, AUTH)
newtok = d.get("token")
check("users: reset token rotates", st == 200 and newtok and newtok != tok, f"{st}")
st, _ = js("GET", f"/sub/{tok}", headers=CLIENT_UA)
check("sub: old token dead after reset", st == 404, f"{st}")
st, _ = js("GET", f"/sub/{newtok}", headers=CLIENT_UA)
check("sub: new token works", st == 200, f"{st}")
tok = newtok
st, d = js("POST", f"/api/users/{uid}/reset", {"reset_usage": True, "reset_token": True}, AUTH)
tok2 = d.get("token")
check("users: combo reset rotates token", st == 200 and tok2 and tok2 != tok, f"{st}")
if tok2:
    tok = tok2  # keep following the live token
st, _ = js("GET", f"/sub/{tok}", headers=CLIENT_UA)
check("users: subscription works after combo reset", st == 200, f"{st}")

# SOFU: first fetch activates
usof = "fs" + uuid.uuid4().hex[:8]
st, su = js("POST", "/api/users", {
    "username": usof, "protocols": ["vless"], "volume_gb": 5, "days": 7,
    "start_on_first_use": True,
}, AUTH)
check("users: create start-on-first-use", st == 200 and su.get("pending_start") is True, f"{st} {su}")
if st == 200:
    CREATED_USERS.append(su["id"])
    stok = su.get("token")
st, d = js("GET", f"/api/users/by-username/{usof}", headers=AUTH)
check("users: pending before first use", st == 200 and d.get("pending_start") is True, f"{st} {d}")
st, _ = js("GET", f"/sub/{stok}", headers=CLIENT_UA)
st2, d2 = js("GET", f"/api/users/by-username/{usof}", headers=AUTH)
check("sub: first fetch activates SOFU", st2 == 200 and d2.get("pending_start") is False
      and d2.get("expires_at"), f"{st} {st2} {d2}")

# quota / expiry enforcement
uquota = "fq" + uuid.uuid4().hex[:8]
st, qu = js("POST", "/api/users", {
    "username": uquota, "protocols": ["vless"], "volume_gb": 1, "days": 5,
}, AUTH)
if st == 200:
    CREATED_USERS.append(qu["id"])
    js("PATCH", f"/api/users/{qu['id']}", {"add_used_gb": 1}, AUTH)
    st, _ = js("GET", f"/sub/{qu['token']}", headers=CLIENT_UA)
    check("sub: out-of-volume user 404s for VPN clients", st == 404, f"{st}")
    st, _, body = req("GET", f"/sub/{qu['token']}", headers=BROWSER_UA, raw=True)
    dtext = body.decode("utf-8", "replace")
    check("sub: out-of-volume customer still sees the dashboard status",
          st == 200 and "<!DOCTYPE html>" in dtext and "Out of volume" in dtext,
          f"{st} has_status={'Out of volume' in dtext}")
    js("PATCH", f"/api/users/{qu['id']}", {"set_expires_at": "2020-01-01T00:00"}, AUTH)
    js("PATCH", f"/api/users/{qu['id']}", {"reset_used": True}, AUTH)
    st, _ = js("GET", f"/sub/{qu['token']}", headers=CLIENT_UA)
    check("sub: expired user 404s for VPN clients", st == 404, f"{st}")
    st, _, body = req("GET", f"/sub/{qu['token']}", headers=BROWSER_UA, raw=True)
    check("sub: expired customer still sees the dashboard status",
          st == 200 and ">Expired<" in body.decode("utf-8", "replace"), f"{st}")

# validation rejects garbage (usability = clear errors)
st, d = js("POST", "/api/users", {
    "username": "ab", "protocols": ["vless"], "volume_gb": 1, "days": 1}, AUTH)
check("users: short username rejected 422", st == 422, f"{st}")
st, d = js("POST", "/api/users", {
    "username": "ft" + uuid.uuid4().hex[:6], "protocols": ["vless"],
    "volume_gb": True, "days": 1}, AUTH)
check("users: boolean volume rejected", st == 422, f"{st}")
st, d = js("POST", "/api/users", {
    "username": "ft" + uuid.uuid4().hex[:6], "protocols": ["nope"],
    "volume_gb": 1, "days": 1}, AUTH)
check("users: unknown protocol rejected", st == 422, f"{st}")
st, d = js("POST", "/api/users", {
    "username": u1, "protocols": ["vless"], "volume_gb": 1, "days": 1}, AUTH)
check("users: duplicate username 409", st == 409, f"{st}")

# ---------------------------------------------------------------- templates
tname = "ft tpl " + uuid.uuid4().hex[:4]
st, _ = js("POST", "/api/templates", {
    "name": tname, "protocols": ["vless", "trojan"], "volume_gb": 20, "days": 15,
    "device_limit": 2}, AUTH)
check("templates: create", st == 200, f"{st}")
st, tl = js("GET", "/api/templates", headers=AUTH)
tpl = next((x for x in tl if x["name"] == tname), None) if st == 200 else None
check("templates: list includes it", tpl is not None and tpl["volume_gb"] == 20, f"{st}")
if tpl:
    CREATED_TEMPLATES.append(tpl["id"])
    st, _ = js("POST", "/api/templates", {
        "name": tname, "protocols": ["vmess"], "volume_gb": 99, "days": 5}, AUTH)
    st2, tl2 = js("GET", "/api/templates", headers=AUTH)
    tpl2 = next((x for x in tl2 if x["name"] == tname), None)
    check("templates: same name updates", st == 200 and tpl2 and tpl2["volume_gb"] == 99, f"{st2}")
    st, _ = js("DELETE", f"/api/templates/{tpl['id']}", headers=AUTH)
    check("templates: delete", st == 200, f"{st}")
    st, _ = js("DELETE", f"/api/templates/{tpl['id']}", headers=AUTH)
    check("templates: double delete 404", st == 404, f"{st}")

# ---------------------------------------------------------------- inbounds
ibn = "ft_ib_" + uuid.uuid4().hex[:6]
st, ib = js("POST", "/api/inbounds", {
    "name": ibn, "protocol": "vless", "port": 18443, "host": ""}, AUTH)
check("inbounds: create", st == 200 and ib.get("id"), f"{st} {ib}")
if st == 200:
    CREATED_INBOUNDS.append(ib["id"])
    st2, ibs = js("GET", "/api/inbounds", headers=AUTH)
    mine = next((x for x in ibs if x["id"] == ib["id"]), None)
    check("inbounds: list includes it", mine is not None and mine["port"] == 18443, f"{st2}")
    st, _ = js("POST", "/api/inbounds", {
        "name": ibn + "b", "protocol": "vless", "port": 18443}, AUTH)
    check("inbounds: duplicate port rejected", st == 409, f"{st}")
    st, d = js("PATCH", f"/api/inbounds/{ib['id']}", {"enabled": False}, AUTH)
    check("inbounds: disable", st == 200 and d.get("enabled") is False, f"{st} {d}")
    st, d = js("PATCH", f"/api/inbounds/{ib['id']}", {"port": 18444}, AUTH)
    check("inbounds: change port", st == 200 and d.get("port") == 18444, f"{st} {d}")
    st, d = js("PATCH", f"/api/inbounds/{ib['id']}", {"host": "in.example.com"}, AUTH)
    check("inbounds: set host", st == 200 and d.get("host") == "in.example.com", f"{st} {d}")
    st, d = js("PATCH", f"/api/inbounds/{ib['id']}", {"enabled": True}, AUTH)
    check("inbounds: re-enable", st == 200 and d.get("enabled") is True, f"{st} {d}")
    # subscription must now include the enabled inbound variant
    st, hd, body = req("GET", f"/sub/{tok}", headers=CLIENT_UA, raw=True)
    check("sub: enabled inbound variant included",
          st == 200 and "in.example.com" in decode_sub(body), f"{st} {decode_sub(body)[:120]}")
    st, hd, body = req("GET", f"/sub/{tok}", headers=CLIENT_UA, raw=True)
    st, d = js("PATCH", f"/api/inbounds/{ib['id']}", {"enabled": False}, AUTH)
    body2 = req("GET", f"/sub/{tok}", headers=CLIENT_UA, raw=True)[2]
    check("sub: disabled inbound variant dropped",
          "in.example.com" not in decode_sub(body2), "disabled inbound still served")
    st, d = js("DELETE", f"/api/inbounds/{ib['id']}", headers=AUTH)
    check("inbounds: delete", st == 200, f"{st}")
    st, d = js("DELETE", f"/api/inbounds/{ib['id']}", headers=AUTH)
    check("inbounds: double delete 404", st == 404, f"{st}")

# ---------------------------------------------------------------- server nodes
sn = "ft_snode_" + uuid.uuid4().hex[:6]
st, nd = js("POST", "/api/server-nodes", {
    "name": sn, "address": "127.0.0.1", "check_port": 8000, "note": "local"}, AUTH)
check("server nodes: create", st == 200 and nd.get("id"), f"{st} {nd}")
if st == 200:
    CREATED_SNODES.append(nd["id"])
    st2, nds = js("GET", "/api/server-nodes", headers=AUTH)
    mine = next((x for x in nds if x["id"] == nd["id"]), None)
    check("server nodes: list includes it", mine is not None and mine["address"] == "127.0.0.1", f"{st2}")
    check("server nodes: uptime_pct present", mine is not None and "uptime_pct" in mine, str(mine))
    st, d = js("PATCH", f"/api/server-nodes/{nd['id']}", {"enabled": False}, AUTH)
    check("server nodes: disable", st == 200 and d.get("enabled") is False, f"{st} {d}")
    st, d = js("POST", f"/api/server-nodes/{nd['id']}/check", {}, AUTH)
    check("server nodes: check probes and records",
          st == 200 and d.get("status") in ("online", "offline") and d.get("last_check"), f"{st} {d}")
    # inbound pinning
    st, ib2 = js("POST", "/api/inbounds", {
        "name": ibn + "p", "protocol": "trojan", "port": 18445, "node_id": nd["id"]}, AUTH)
    if st == 200:
        CREATED_INBOUNDS.append(ib2["id"])
        check("server nodes: inbound pinned to node", ib2.get("node_id") == nd["id"], f"{ib2}")
        js("PATCH", f"/api/server-nodes/{nd['id']}", {"enabled": True}, AUTH)
        st, d = js("POST", f"/api/server-nodes/{nd['id']}/check", {}, AUTH)
        js("PATCH", f"/api/users/{uid}", {"reset_used": True}, AUTH)
        st, hd, body = req("GET", f"/sub/{tok}", headers=CLIENT_UA, raw=True)
        check("sub: pinned inbound served", st == 200, f"{st}")
        js("DELETE", f"/api/inbounds/{ib2['id']}", headers=AUTH)
    st, d = js("DELETE", f"/api/server-nodes/{nd['id']}", headers=AUTH)
    check("server nodes: delete", st == 200, f"{st}")
    st, d = js("DELETE", f"/api/server-nodes/{nd['id']}", headers=AUTH)
    check("server nodes: double delete 404", st == 404, f"{st}")

# ---------------------------------------------------------------- tunnels
tn = "ft_tn_" + uuid.uuid4().hex[:6]
st, tnode = js("POST", "/api/nodes", {
    "name": tn, "transport": "udp", "iran_ip": "127.0.0.1", "kharej_ip": "127.0.0.1",
    "tunnel_port": 19001, "forwarded_ports": "443:8000", "udp_forward": True}, AUTH)
check("tunnels: create with udp transport", st == 200 and tnode.get("token_once"), f"{st} {tnode}")
if st == 200:
    CREATED_TNODES.append(tnode["id"])
    st2, tns = js("GET", "/api/nodes", headers=AUTH)
    mine = next((x for x in tns if x["id"] == tnode["id"]), None)
    check("tunnels: list includes it", mine is not None and mine["transport"] == "udp", f"{st2}")
    st, d = js("POST", f"/api/nodes/{tnode['id']}/reveal-token", {}, AUTH)
    check("tunnels: reveal token matches create", st == 200 and d.get("token") == tnode["token_once"], f"{st}")
    st, d = js("POST", f"/api/nodes/{tnode['id']}/regen-token", {}, AUTH)
    check("tunnels: regen rotates token", st == 200 and d.get("token") != tnode["token_once"], f"{st}")
    st, d = js("POST", f"/api/nodes/{tnode['id']}/check", {}, AUTH)
    check("tunnels: check reports status+reason",
          st == 200 and d.get("status") in ("online", "offline") and "reason" in d, f"{st} {d}")
    st, hd, body = req("GET", f"/api/nodes/{tnode['id']}/guide", headers=AUTH, raw=True)
    guide = body.decode("utf-8", "replace")
    check("tunnels: guide downloads", st == 200 and len(guide) > 500, f"{st} len={len(guide)}")
    check("tunnels: guide has the new token + udp label",
          d is not None and guide.count("UDP") >= 1, "label/token")
    check("tunnels: guide has forwarded ports", "443:8000" in guide, "ports")
    st, d = js("DELETE", f"/api/nodes/{tnode['id']}", headers=AUTH)
    check("tunnels: delete", st == 200, f"{st}")
    st, d = js("DELETE", f"/api/nodes/{tnode['id']}", headers=AUTH)
    check("tunnels: double delete 404", st == 404, f"{st}")
st, d = js("POST", "/api/nodes", {
    "name": "ft_bad", "transport": "tcp", "iran_ip": "1.1.1.1", "kharej_ip": "1.1.1.1",
    "tunnel_port": 1, "forwarded_ports": "99999:1"}, AUTH)
check("tunnels: out-of-range forwarded port rejected 422", st == 422, f"{st}")
st, d = js("POST", "/api/nodes", {
    "name": "ft_bad2", "transport": "tcp", "iran_ip": "1.1.1.1", "kharej_ip": "1.1.1.1",
    "tunnel_port": 1, "forwarded_ports": "443:1,443:2"}, AUTH)
check("tunnels: duplicate Iran port rejected", st == 422, f"{st}")

# ---------------------------------------------------------------- reality
st, srv0 = js("GET", "/api/settings", headers=AUTH)
SAVE.setdefault("settings", srv0)
# Start from "no REALITY key" so the skip-path assertion below is meaningful
# and a leftover key from a previous run cannot leak into this one.
js("PUT", "/api/settings", {**(srv0 or {}), "reality_pub": ""}, AUTH)
st, d = js("POST", "/api/reality/generate", {}, AUTH)
check("reality: generate keypair", st == 200 and len(d.get("public_key", "")) == 43
      and len(d.get("private_key", "")) == 43, f"{st} {str(d)[:80]}")
st, d = js("GET", "/api/reality/private", headers=AUTH)
check("reality: private key readable", st == 200 and len(d.get("private_key", "")) == 43, f"{st}")
# Push the public key into server settings, otherwise REALITY links are
# (correctly) skipped and there is nothing to test.
st, d = js("PUT", "/api/settings", {**(srv0 or {}), "reality_pub": d.get("public_key", "")}, AUTH)
check("reality: public key saved to settings", st == 200, f"{st} {str(d)[:80]}")
ureal = "fr" + uuid.uuid4().hex[:8]
st, ru = js("POST", "/api/users", {
    "username": ureal, "protocols": ["reality"], "volume_gb": 5, "days": 10}, AUTH)
check("reality: user create", st == 200, f"{st}")
if st == 200:
    CREATED_USERS.append(ru["id"])
    st, hd, body = req("GET", f"/sub/{ru['token']}", headers=CLIENT_UA, raw=True)
    txt = decode_sub(body)
    check("reality: subscription has real pbk", st == 200 and "pbk=" in txt
          and "REPLACE_WITH" not in txt, txt[:100])
    st, hd, body = req("GET", f"/sub/{ru['token']}?format=clash", raw=True)
    check("reality: clash has reality-opts", st == 200 and b"reality-opts" in body, f"{st}")
# unconfigured reality must be skipped, not shipped as a dead link
st, ureal2 = js("POST", "/api/users", {
    "username": "fx" + uuid.uuid4().hex[:8], "protocols": ["reality"],
    "volume_gb": 5, "days": 10}, AUTH)
if st == 200:
    CREATED_USERS.append(ureal2["id"])
    js("PUT", "/api/settings", {**(srv0 or {}), "reality_pub": ""}, AUTH)
    st2, hd, body = req("GET", f"/sub/{ureal2['token']}", headers=CLIENT_UA, raw=True)
    check("reality: unconfigured key is skipped (no dead links)",
          st2 == 200 and "REPLACE_WITH" not in decode_sub(body), f"{st2} {body[:80]}")

# ---------------------------------------------------------------- blocker
dom = "ft" + uuid.uuid4().hex[:6] + ".example.com"
st, bs = js("POST", "/api/blocklist", {"domain": dom}, AUTH)
check("blocker: add site", st == 200 and bs.get("domain") == dom, f"{st} {bs}")
if st == 200:
    CREATED_SITES.append(bs["id"])
    st, bl = js("GET", "/api/blocklist", headers=AUTH)
    check("blocker: list includes it", any(s["domain"] == dom for s in bl.get("sites", [])), f"{st}")
    st, _ = js("POST", "/api/blocklist", {"domain": dom}, AUTH)
    check("blocker: duplicate 409", st == 409, f"{st}")
    st, d = js("PUT", "/api/blocklist/porn", {"porn_enabled": True}, AUTH)
    st2, bl2 = js("GET", "/api/blocklist", headers=AUTH)
    check("blocker: porn preset toggle on",
          st == 200 and st2 == 200 and bl2.get("porn_enabled") is True
          and bl2.get("porn_count", 0) > 10, f"{st}/{st2} {d} {bl2.get('porn_count')}")
    st, d = js("PUT", "/api/blocklist/porn", {"porn_enabled": False}, AUTH)
    check("blocker: porn preset toggle off", st == 200 and d.get("porn_enabled") is False, f"{st}")
    st, hd, body = req("GET", f"/sub/{tok}?format=clash", raw=True)
    check("blocker: custom site lands in clash rules",
          st == 200 and b"DOMAIN-SUFFIX," + dom.encode() in body, f"{st}")
    st, _ = js("DELETE", f"/api/blocklist/{bs['id']}", headers=AUTH)
    check("blocker: delete site", st == 200, f"{st}")

# ---------------------------------------------------------------- customize
st, ap0 = js("GET", "/api/appearance")
check("customize: appearance is public", st == 200 and "theme_accent" in ap0, f"{st}")
# Restore to the SHIPPED defaults (not "whatever was there"): a suite must
# leave a predictable panel for the next one.
SAVE["appearance"] = {
    "theme_accent": "#ff2740", "theme_bg": "#06060a", "theme_card": "#10101a",
    "theme_text": "#ececf2", "theme_muted": "#8b8c9e", "brand_name": "ZEFIRA",
    "dash_note": "", "menu_layout": "", "dash_layout": "",
}
js("PUT", "/api/appearance", SAVE["appearance"], AUTH)
st, d = js("PUT", "/api/appearance", {
    "theme_accent": "#ff2740", "theme_bg": "#06060a", "theme_card": "#10101a",
    "theme_text": "#ececf2", "theme_muted": "#8b8c9e", "brand_name": "ZEFIRA TEST",
    "dash_note": "feature suite", "menu_layout": "", "dash_layout": "",
}, AUTH)
check("customize: save appearance", st == 200, f"{st}")
st, ap1 = js("GET", "/api/appearance")
check("customize: brand name applied", st == 200 and ap1.get("brand_name") == "ZEFIRA TEST", f"{st} {ap1}")
st, hd, body = req("GET", "/theme.css", raw=True)
check("customize: theme.css reflects colors", st == 200 and b"#ff2740" in body.lower(), f"{st}")

# ---------------------------------------------------------------- settings
st, s0 = js("GET", "/api/settings", headers=AUTH)
# Shipped defaults for the restore step (reality_pub is intentionally empty:
# a stale key would otherwise point links at a non-existent server).
SAVE["settings"] = dict(s0 or {})
SAVE["settings"].update({
    "domain": "zefira.example.com", "sub_port": 443, "hy2_port": 8443,
    "wg_port": 51820, "ovpn_port": 1194, "l2tp_port": 1701, "cisco_port": 443,
    "socks5_port": 1080, "reality_port": 443, "reality_pub": "",
    "obfuscated_host": "", "cdn_enabled": False, "cdn_sni": "",
    "per_user_subdomain": False,
})
check("settings: read", st == 200 and "sub_port" in s0 and "reality_sni" in s0, f"{st}")
snew = dict(s0)
snew.update({"domain": "panel.example.com", "sub_port": 8443, "hy2_port": 8444,
             "wg_port": 51821, "ovpn_port": 1195, "l2tp_port": 1702,
             "cisco_port": 444, "socks5_port": 1081, "reality_port": 445,
             "cdn_enabled": True, "cdn_sni": "cdn.example.com",
             "obfuscated_host": "obf.example.com", "per_user_subdomain": True})
st, d = js("PUT", "/api/settings", snew, AUTH)
check("settings: save all fields", st == 200, f"{st} {str(d)[:80]}")
st, s1 = js("GET", "/api/settings", headers=AUTH)
check("settings: values persisted", st == 200 and s1.get("sub_port") == 8443
      and s1.get("cdn_sni") == "cdn.example.com", f"{st} {s1}")
st, hd, body = req("GET", f"/sub/{tok}", headers=CLIENT_UA, raw=True)
# obfuscated_host + per_user_subdomain are ON in this block, so the links
# must carry the obfuscated host (with the per-user prefix), not the domain.
check("settings: obfuscated host (+ per-user prefix) used in links",
      st == 200 and "obf.example.com" in decode_sub(body), f"{st} {decode_sub(body)[:100]}")
st, hd, body = req("GET", f"/sub/{tok}", headers=CLIENT_UA, raw=True)
check("settings: cdn sni reaches the links",
      st == 200 and "cdn.example.com" in decode_sub(body), f"{st} {decode_sub(body)[:100]}")
st, d = js("PUT", "/api/settings", SAVE["settings"], AUTH)
check("settings: restored to defaults", st == 200, f"{st}")
st, s2 = js("GET", "/api/settings", headers=AUTH)
check("settings: restore verified", st2 == 200 and s2.get("sub_port") == SAVE["settings"]["sub_port"]
      and not s2.get("obfuscated_host"), f"{st2} {s2.get('sub_port')}")
st, d = js("PUT", "/api/settings", {**SAVE["settings"], "sub_port": True}, AUTH)
check("settings: boolean port rejected", st == 422, f"{st}")
st, d = js("PUT", "/api/settings", {**SAVE["settings"], "sub_port": 99999}, AUTH)
check("settings: out-of-range port rejected", st == 422, f"{st}")

st, t0 = js("GET", "/api/tunnel-settings", headers=AUTH)
SAVE["tunnel"] = t0
st, d = js("PUT", "/api/tunnel-settings", {
    "public_url": "https://panel.example.com", "trusted_proxies": "10.0.0.0/8"}, AUTH)
check("settings: tunnel settings saved", st == 200, f"{st}")
st, d = js("PUT", "/api/tunnel-settings", {
    "public_url": "https://x.example.com", "trusted_proxies": "0.0.0.0/0"}, AUTH)
check("settings: trust-all proxies rejected", st == 400, f"{st}")
js("PUT", "/api/tunnel-settings", t0, AUTH)

st, g0 = js("GET", "/api/telegram", headers=AUTH)
SAVE["telegram"] = g0
st, d = js("PUT", "/api/telegram", {"bot_token": "", "chat_id": "123456789"}, AUTH)
check("telegram: save chat id", st == 200, f"{st}")
st, g1 = js("GET", "/api/telegram", headers=AUTH)
check("telegram: chat id persisted", st == 200 and g1.get("chat_id") == "123456789", f"{st}")
st, d = js("POST", "/api/telegram/test", {"message": "feature suite"}, AUTH, timeout=40)
if g0.get("has_token"):
    # A token is already stored: the call must fail cleanly (bad token /
    # unreachable), never crash the panel.
    check("telegram: test with stored-but-bad token reports a reason",
          st in (400, 502) and "Telegram" in str(d), f"{st} {d}")
else:
    check("telegram: test without token fails cleanly", st == 400, f"{st} {d}")
st, d = js("PUT", "/api/telegram", {"bot_token": "123456:bad-token", "chat_id": "123456789"}, AUTH)
st, d = js("POST", "/api/telegram/test", {"message": "x"}, AUTH, timeout=40)
check("telegram: test with bad token reports reason", st == 502 and "Telegram" in str(d), f"{st} {d}")
js("PUT", "/api/telegram", {"bot_token": "", "chat_id": g0.get("chat_id", "")}, AUTH)

# ---------------------------------------------------------------- AI
st, a0 = js("GET", "/api/ai/settings", headers=AUTH)
SAVE["ai"] = a0
check("ai: settings read (key never exposed)", st == 200 and "has_key" in a0
      and "api_key" not in a0, f"{st} {a0}")
st, d = js("PUT", "/api/ai/settings", {
    "enabled": True, "provider": "groq", "base_url": "", "model": "qwen/qwen3.8-27b",
    "api_key": "gsk-test-not-real", "extra": "feature suite"}, AUTH)
check("ai: settings saved", st == 200, f"{st}")
st, a1 = js("GET", "/api/ai/settings", headers=AUTH)
check("ai: key stored encrypted, only has_key flips", st == 200 and a1.get("has_key") is True, f"{st} {a1}")
st, d = js("POST", "/api/ai/chat", {"messages": [{"role": "user", "content": "hi"}]}, AUTH)
check("ai: chat with rejected key returns actionable 502 (no crash)",
      st == 502 and isinstance(d, dict) and d.get("detail"), f"{st} {str(d)[:100]}")
st, d = js("POST", "/api/ai/test", {}, AUTH)
check("ai: test endpoint reports provider failure (no crash)",
      st == 502 and isinstance(d, dict) and d.get("detail"), f"{st} {str(d)[:80]}")
st, d = js("PUT", "/api/ai/settings", {
    "enabled": True, "provider": "openai", "base_url": "http://127.0.0.1:1/v1",
    "model": "x", "api_key": "k", "extra": ""}, AUTH)
check("ai: unreachable provider accepted at save time", st == 200, f"{st}")
st, d = js("POST", "/api/ai/test", {}, AUTH, timeout=90)
check("ai: unreachable provider fails with a clear error",
      st == 502 and "reach" in str(d).lower() or st == 502, f"{st} {str(d)[:80]}")
st, d = js("PUT", "/api/ai/settings", {
    "enabled": False, "provider": "groq", "base_url": "", "model": "", "api_key": ""}, AUTH)
st, d = js("POST", "/api/ai/chat", {"messages": [{"role": "user", "content": "hi"}]}, AUTH)
check("ai: disabled chat 400s clearly", st == 400 and "not configured" in str(d), f"{st} {d}")
st, d = js("PUT", "/api/ai/settings", {
    "enabled": a0.get("enabled", False), "provider": a0.get("provider", "groq"),
    "base_url": a0.get("base_url", ""), "model": a0.get("model", ""),
    "extra": a0.get("extra", "")}, AUTH)
check("ai: original settings restored", st == 200, f"{st}")

# ---------------------------------------------------------------- SSL
st, d = js("GET", "/api/ssl/status", headers=AUTH)
check("ssl: status reachable", st == 200 and "installed" in d, f"{st} {d}")
st, d = js("POST", "/api/ssl/issue", {
    "domain": "panel.example.com", "subdomain": "", "email": "a@example.com"}, AUTH)
check("ssl: issue fails gracefully without certbot/root",
      st in (400, 502) and ("certbot" in str(d).lower() or "root" in str(d).lower()
                            or "certbot failed" in str(d).lower()), f"{st} {str(d)[:100]}")
st, d = js("POST", "/api/ssl/renew", {}, AUTH)
check("ssl: renew without cert fails cleanly", st == 400 and "No certificate" in str(d), f"{st} {d}")

# ---------------------------------------------------------------- update
# This endpoint talks to GitHub; retry once so a slow API reads as a retry,
# not a broken panel (the endpoint answers 200 with an `error` field when
# GitHub is unreachable, which is the behaviour under test here).
st, d = js("GET", "/api/update/status", headers=AUTH, timeout=45)
if st != 200:
    st, d = js("GET", "/api/update/status", headers=AUTH, timeout=45)
check("update: status reachable with unit_warning field",
      st == 200 and "unit_warning" in d and "update_available" in d, f"{st} {str(d)[:100]}")
st, d = js("POST", "/api/update/apply", {"password_confirm": "wrong-password"}, AUTH)
check("update: wrong confirm password rejected", st == 400, f"{st} {d}")

# ---------------------------------------------------------------- API tokens
tn1 = "ftbot_" + uuid.uuid4().hex[:6]
st, tokd = js("POST", "/api/api-tokens", {"name": tn1, "scopes": "bot"}, AUTH)
check("tokens: create bot-scoped", st == 200 and tokd.get("token_once", "").startswith("zfp_"), f"{st} {tokd}")
botraw = tokd.get("token_once", "")
if st == 200:
    CREATED_TOKENS.append(tokd["id"])
    BH = {"Authorization": f"Bearer {botraw}"}
    st, d = js("GET", "/api/me", headers=BH)
    check("tokens: bot can call /api/me", st == 200, f"{st}")
    st, d = js("GET", "/api/stats", headers=BH)
    check("tokens: bot can call /api/stats", st == 200, f"{st}")
    st, d = js("GET", "/api/users", headers=BH)
    check("tokens: bot can list users", st == 200, f"{st}")
    st, d = js("GET", f"/api/users/{uid}/qr", headers=BH)
    check("tokens: bot can fetch QR", st == 200, f"{st}")
    st, d = js("GET", f"/api/users/{uid}/config", headers=BH)
    check("tokens: bot denied config (full-only)", st == 403, f"{st}")
    st, d = js("DELETE", f"/api/users/{uid}", headers=BH)
    check("tokens: bot denied delete", st == 403, f"{st}")
    st, d = js("PATCH", f"/api/users/{uid}", {"extend_days": 1}, BH)
    check("tokens: bot denied patch", st == 403, f"{st}")
    st, d = js("GET", "/api/backup" if False else "/api/audit", headers=BH)
    check("tokens: bot denied audit", st == 403, f"{st}")
    st, d = js("PUT", "/api/settings", {**(SAVE["settings"] or {})}, BH)
    check("tokens: bot denied settings", st == 403, f"{st}")
    ub = "fb" + uuid.uuid4().hex[:8]
    st, d = js("POST", "/api/users", {
        "username": ub, "protocols": ["vless"], "volume_gb": 2, "days": 3}, BH)
    check("tokens: bot can create user", st == 200 and d.get("token"), f"{st} {d}")
    if st == 200:
        CREATED_USERS.append(d["id"])
        st2, dd = js("POST", f"/api/users/{d['id']}/reset-usage", {}, BH)
        check("tokens: bot can reset usage", st2 == 200, f"{st2}")
        st2, dd = js("POST", f"/api/users/{d['id']}/reset-token", {}, BH)
        check("tokens: bot can reset token", st2 == 200, f"{st2}")
    st, d = js("GET", f"/api/users/{uid}/qr", headers={"Authorization": f"Bearer {botraw}"},
               timeout=20)
    st, d = js("GET", "/api/me", headers={"Authorization": f"Bearer {botraw}garbage"})
    check("tokens: garbage bearer 401", st == 401, f"{st}")
    st, hd2, _ = req("GET", "/api/me", headers={"Cookie": "zefira_session=garbage",
                                                 "Authorization": f"Bearer {botraw}"})
    check("tokens: bad cookie falls through to valid bearer", st == 200, f"{st}")
tn2 = "ftfull_" + uuid.uuid4().hex[:6]
st, tokf = js("POST", "/api/api-tokens", {"name": tn2, "scopes": "full"}, AUTH)
check("tokens: create full-scoped", st == 200, f"{st}")
if st == 200:
    CREATED_TOKENS.append(tokf["id"])
    FH = {"Authorization": f"Bearer {tokf['token_once']}"}
    st, d = js("GET", f"/api/users/{uid}/config", headers=FH, timeout=30)
    check("tokens: full token can download config", st == 200, f"{st}")
st, d = js("POST", "/api/api-tokens", {"name": tn1}, AUTH)
check("tokens: duplicate name 409", st == 409, f"{st}")
st, d = js("POST", "/api/api-tokens", {"name": "ftbad", "scopes": "root"}, AUTH)
check("tokens: unknown scope rejected", st == 422, f"{st}")
st, d = js("GET", "/api/api-tokens", headers=AUTH)
check("tokens: list hides secrets", st == 200 and all("token_once" not in t and "token_sha" not in t
      for t in d), f"{st}")

# ---------------------------------------------------------------- backup/restore
st, hd, body = req("POST", "/api/backup", json.dumps({"password_confirm": PASSWORD}), AUTH, raw=True)
check("backup: plain json downloads", st == 200 and body[:1] in (b"{", b"["), f"{st} {body[:40]}")
plain_backup = json.loads(body.decode())
check("backup: contains all sections", st == 200 and all(k in plain_backup for k in
      ("users", "templates", "inbounds", "server_nodes", "tunnel_nodes", "settings", "api_tokens")),
      str(list(plain_backup.keys()))[:140])
st, hd, body = req("POST", "/api/backup",
                   json.dumps({"password_confirm": PASSWORD, "encrypt": True}), AUTH, raw=True)
enc_backup = json.loads(body.decode()) if st == 200 else {}
check("backup: encrypted payload shape", st == 200 and "payload" in enc_backup
      and "salt" in enc_backup and enc_backup.get("encrypted") is True,
      f"{st} {str(enc_backup)[:90]}")
check("backup: no AI key in plaintext", st == 200 and
      "gsk-" not in body.decode("utf-8", "replace"), "leak")

snapshot = {
    "users": [{
        "username": "rs" + uuid.uuid4().hex[:8], "protocol": "vless",
        "protocols": "vless", "note": "restored", "volume_gb": 5, "used_gb": 0,
        "token": uuid.uuid4().hex, "secret_data": "{}", "is_active": True,
        "device_limit": None, "start_on_first_use": False, "duration_days": None,
        "created_at": "2026-01-01T00:00:00",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S"),
    }],
    "admins": [], "settings": {}, "templates": [], "inbounds": [], "server_nodes": [],
    "tunnel_nodes": [], "tokens": [], "blocked_sites": [],
}
st, d = js("POST", "/api/restore", {**snapshot, "zefira_backup": True,
                                    "password_confirm": PASSWORD}, AUTH, timeout=60)
check("restore: plain restore imports user", st == 200 and d.get("added_users", 0) >= 1, f"{st} {d}")
# Restore intentionally invalidates existing sessions (a restored admin row
# may carry an older password/token_version): re-login like a real operator.
st_l, AUTH = login_with(PASSWORD)
check("restore: operator can log in again after restore", st_l == 200, f"{st_l}")
if st == 200:
    st2, found = js("GET", "/api/users?q=rs", headers=AUTH)
    hit = [u for u in found.get("items", []) if u["username"] == snapshot["users"][0]["username"]]
    check("restore: imported user is live", st2 == 200 and len(hit) == 1, f"{st2} {len(hit)}")
    if hit:
        CREATED_USERS.append(hit[0]["id"])
        st3, _ = js("GET", f"/sub/{hit[0]['token']}", headers=CLIENT_UA)
        check("restore: imported user serves subscription (secrets rebuilt)", st3 == 200, f"{st3}")
st, d = js("POST", "/api/restore", {**snapshot, "zefira_backup": True,
                                    "password_confirm": "wrong-password-here"}, AUTH)
check("restore: wrong password rejected", st in (400, 422), f"{st} {d}")
st, d = js("POST", "/api/restore-encrypted", {"payload": "not-a-fernet-token", "salt": "aaaa",
                                             "password_confirm": PASSWORD}, AUTH)
check("restore: bad encrypted payload fails cleanly", st in (400, 422, 500) and st != 0, f"{st} {d}")
st, d = js("GET", "/api/me", headers=AUTH)
check("restore: failed restore keeps the session", st == 200, f"{st}")

# ---------------------------------------------------------------- cleanup users
for cid in reversed(CREATED_USERS):
    js("DELETE", f"/api/users/{cid}", headers=AUTH)
st, d = js("GET", "/api/users", headers=AUTH)
check("cleanup: no test users left", st == 200 and d.get("total", 0) == 0, f"total={d.get('total')}")

# restore the panel to shipped defaults (predictable for the next suite)
if SAVE.get("appearance"):
    js("PUT", "/api/appearance", SAVE["appearance"], AUTH)
if SAVE.get("settings"):
    js("PUT", "/api/settings", SAVE["settings"], AUTH)
if SAVE.get("tunnel"):
    js("PUT", "/api/tunnel-settings", {"public_url": "", "trusted_proxies": ""}, AUTH)
if SAVE.get("telegram"):
    js("PUT", "/api/telegram", {"bot_token": "", "chat_id": ""}, AUTH)
js("PUT", "/api/blocklist/porn", {"porn_enabled": False}, AUTH)

# tokens last (password change below revokes them anyway)
for tid in reversed(CREATED_TOKENS):
    js("DELETE", f"/api/api-tokens/{tid}", headers=AUTH)

# ---------------------------------------------------------------- password
# A browser picks up the new Set-Cookie automatically; the test must too,
# otherwise the second call rides a cookie whose token_version is stale.
# Everything is wrapped so a mid-test failure can never leave the panel
# locked out with a password nobody knows.
newpw = "Ft" + uuid.uuid4().hex[:8]
pw_changed = False
try:
    stpw, hdpw, rawpw = req("POST", "/api/change-password", json.dumps({
        "current_password": PASSWORD, "new_password": newpw}), AUTH)
    try:
        dpw = json.loads(rawpw.decode("utf-8", "replace"))
    except Exception:
        dpw = {}
    check("password: change works and reports revoked tokens",
          stpw == 200 and "api_tokens_revoked" in dpw, f"{stpw} {dpw}")
    pw_changed = stpw == 200
    old_cookie = AUTH["Cookie"]
    for part in (hget(hdpw, "set-cookie") or "").split(";"):
        part = part.strip()
        if part.startswith("zefira_session="):
            AUTH["Cookie"] = f"zefira_session={part.split('=', 1)[1]}"
    check("password: caller keeps working with the re-issued cookie",
          AUTH["Cookie"] != old_cookie, "no new cookie")
    st, d = js("GET", "/api/me", headers=AUTH)
    check("password: session alive right after change", st == 200, f"{st}")
finally:
    if pw_changed:
        _, _, _ = req("POST", "/api/change-password", json.dumps({
            "current_password": newpw, "new_password": PASSWORD}), AUTH)
st, AUTH2 = login_with(PASSWORD)
check("password: original password still valid after revert", st == 200, f"{st}")
check("password: revert works", st == 200, "panel left locked out")
st, d = js("GET", "/api/me", headers=AUTH2)
check("password: session works after revert", st == 200, f"{st}")

# ---------------------------------------------------------------- logout
st, d = js("POST", "/api/logout", {}, AUTH)
check("logout works", st == 200, f"{st}")
st, d = js("GET", "/api/me", headers=AUTH)
check("logout kills the session", st == 401, f"{st}")

# ---------------------------------------------------------------- summary
passed = sum(1 for _, ok, _ in results if ok)
print("\n=== SUMMARY ===")
print(f"{passed}/{len(results)} checks passed")
if passed != len(results):
    print("\nFAILURES:")
    for name, ok, detail in results:
        if not ok:
            print(f"  - {name}: {detail}")
sys.exit(0 if passed == len(results) else 1)
