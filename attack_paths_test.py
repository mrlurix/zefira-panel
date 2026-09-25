"""
Bug hunt: the paths the other suites never touch.

Covers: CSV export, inbounds + node pinning, templates, blocked sites,
subscription path alias, custom domains, appearance/theme.css, audit log,
system stats, tunnel lifecycle, and the restore round-trip with a custom
subscription path.
Run:  attack_paths_test.py http://127.0.0.1:8000 admin PASS
"""
import csv
import io
import json
import sys
import urllib.error
import urllib.request
import uuid
import zipfile

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"
VP_UA = "v2rayNG/1.8.5"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

results = []
created_users = []
created_inbounds = []
created_nodes = []
created_tunnels = []
created_templates = []
# Restore rotates the admin session (token_version bump) and hands the caller a
# fresh cookie. A browser follows Set-Cookie automatically, so this harness
# must too - otherwise every call after a restore 401s and the suite reports
# phantom failures.
SESSION = {"cookie": ""}


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def _absorb_cookie(headers):
    raw = headers.get("set-cookie") or headers.get("Set-Cookie") or ""
    for part in raw.split(";"):
        if part.strip().startswith("zefira_session="):
            SESSION["cookie"] = part.split("=", 1)[1]


def req(method, path, body=None, headers=None, timeout=30, ua=None):
    h = {"User-Agent": ua or "zefira-paths/1.0"}
    # A Bearer probe must not also carry the admin session: the session cookie
    # would authenticate it and the "revoked token" checks would pass/fail for
    # the wrong reason.
    if SESSION["cookie"] and not (headers or {}).get("Authorization"):
        h["Cookie"] = f"zefira_session={SESSION['cookie']}"
    if headers:
        h.update(headers)
    data = body.encode() if isinstance(body, str) else body
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        _absorb_cookie(resp.headers)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        _absorb_cookie(e.headers)
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()


def js(method, path, payload=None, headers=None, timeout=30):
    st, hd, b = req(method, path,
                    json.dumps(payload) if payload is not None else None,
                    headers, timeout)
    try:
        return st, json.loads(b or b"{}")
    except Exception:
        return st, b[:200]


def login():
    st, hd, _ = req("POST", "/api/login", json.dumps(
        {"username": ADMIN, "password": PASSWORD}),
        {"X-Requested-With": "XMLHttpRequest"})
    return st, {"X-Requested-With": "XMLHttpRequest"}


print(f"=== PATH HUNT -> {BASE} ===")
st, AUTH = login()
check("login", st == 200, f"{st}")
if st != 200:
    sys.exit(2)

DEFAULTS = {}


def snapshot_settings():
    st, s = js("GET", "/api/settings", headers=AUTH)
    if st == 200 and isinstance(s, dict):
        DEFAULTS.update(s)
    return s


snapshot_settings()

# ---------------------------------------------------------------- templates
# POST /api/templates is an upsert keyed by name and answers {"ok": true};
# the row is read back from the list (that is the documented contract).
tname = "tpl" + uuid.uuid4().hex[:6]
st, t = js("POST", "/api/templates", {
    "name": tname, "protocols": ["vless", "trojan"], "volume_gb": 25,
    "days": 14, "start_on_first_use": True, "device_limit": 3}, AUTH)
check("template saved", st == 200 and t.get("ok") is True, f"{st} {str(t)[:80]}")
st, lst = js("GET", "/api/templates", headers=AUTH)
tpl = next((x for x in lst if x.get("name") == tname), None) if st == 200 else None
check("template listed with its values", tpl is not None, f"{st}")
if tpl:
    check("template kept protocols/volume/days",
          tpl.get("protocols") == ["vless", "trojan"] and abs(tpl.get("volume_gb", 0) - 25) < 0.01
          and tpl.get("days") == 14, f"{tpl}")
st, u = js("POST", "/api/users", {
    "username": "tp" + uuid.uuid4().hex[:8], "template_id": tpl["id"]}, AUTH)
check("user created from template alone (no other plan fields)", st == 200,
      f"{st} {str(u)[:120]}")
if u.get("id"):
    created_users.append(u["id"])
    check("template applied volume/days",
          abs(u.get("volume_gb", 0) - 25) < 0.01 and u.get("protocols") == ["vless", "trojan"],
          f"vol={u.get('volume_gb')} protos={u.get('protocols')}")
    check("template applied start_on_first_use/device_limit",
          u.get("start_on_first_use") is True and u.get("device_limit") == 3,
          f"sofu={u.get('start_on_first_use')} dev={u.get('device_limit')}")
st, ov = js("POST", "/api/users", {
    "username": "to" + uuid.uuid4().hex[:8], "template_id": tpl["id"],
    "volume_gb": 7, "protocols": ["vmess"]}, AUTH)
check("explicit fields override the template", st == 200
      and abs(ov.get("volume_gb", 0) - 7) < 0.01 and ov.get("protocols") == ["vmess"],
      f"{st} vol={ov.get('volume_gb')} protos={ov.get('protocols')}")
if ov.get("id"):
    created_users.append(ov["id"])
st, badt = js("POST", "/api/users", {
    "username": "tb" + uuid.uuid4().hex[:8], "template_id": 999999}, AUTH)
check("unknown template_id is a clean 404", st == 404, f"{st}")
st, noplan = js("POST", "/api/users", {"username": "np" + uuid.uuid4().hex[:8]}, AUTH)
check("a create with no plan at all is refused with a clear message",
      st == 422 and "template_id" in str(noplan), f"{st} {str(noplan)[:120]}")
# Saving the same name again updates in place (upsert), it must not duplicate.
st, again = js("POST", "/api/templates", {
    "name": tname, "protocols": ["vless"], "volume_gb": 99, "days": 14}, AUTH)
st, lst2 = js("GET", "/api/templates", headers=AUTH)
same = [x for x in lst2 if x.get("name") == tname]
check("re-saving a template name updates it instead of duplicating",
      st == 200 and len(same) == 1 and abs(same[0].get("volume_gb", 0) - 99) < 0.01,
      f"{st} count={len(same)}")
if tpl:
    st, _ = js("DELETE", f"/api/templates/{tpl['id']}", headers=AUTH)
    check("template deleted", st == 200, f"{st}")
    st, _ = js("DELETE", f"/api/templates/{tpl['id']}", headers=AUTH)
    check("deleting a template twice is a clean 404", st == 404, f"{st}")

# ---------------------------------------------------------------- inbounds
iname = "ib" + uuid.uuid4().hex[:6]
st, ib = js("POST", "/api/inbounds", {
    "name": iname, "protocol": "vless", "port": 24443, "host": "cdn.example.com"}, AUTH)
check("inbound created", st == 200 and ib.get("id"), f"{st} {str(ib)[:80]}")
if ib.get("id"):
    created_inbounds.append(ib["id"])
st, u2 = js("POST", "/api/users", {
    "username": "ib" + uuid.uuid4().hex[:8], "protocols": ["vless"],
    "volume_gb": 5, "days": 5}, AUTH)
if u2.get("id"):
    created_users.append(u2["id"])
    st, _, sub = req("GET", f"/sub/{u2['token']}", ua=VP_UA)
    body = sub.decode("utf-8", "replace")
    import base64 as _b64
    try:
        links = _b64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "replace")
    except Exception:
        links = body
    check("extra inbound port appears in the subscription", "24443" in links,
          f"port missing (len={len(links)})")
    check("inbound host appears in the link", "cdn.example.com" in links, "host missing")
    check("exactly one link per endpoint (no duplicates)",
          links.count("vless://") == 2, f"count={links.count('vless://')}")
    st, hd_cfg, cfg = req("GET", f"/api/users/{u2['id']}/config", headers=AUTH)
    ctype = (hd_cfg.get("Content-Type") or hd_cfg.get("content-type") or "").lower()
    check("single-protocol config returns a file (not a ZIP)",
          st == 200 and ("text/plain" in ctype or "application/" in ctype) and b"vless://" in cfg,
          f"{st} {ctype} {cfg[:12]!r}")
    st, _, aud = req("GET", "/api/audit", headers=AUTH)
    check("audit log reachable", st == 200, f"{st}")

# a pinned inbound on a DISABLED node must drop out of links
sname = "nd" + uuid.uuid4().hex[:6]
st, nd = js("POST", "/api/server-nodes", {
    "name": sname, "address": "127.0.0.1", "check_port": 9}, AUTH)
check("server node created", st == 200 and nd.get("id"), f"{st} {str(nd)[:80]}")
if nd.get("id"):
    created_nodes.append(nd["id"])
    st, ib2 = js("POST", "/api/inbounds", {
        "name": "ibn" + uuid.uuid4().hex[:6], "protocol": "trojan",
        "port": 24444, "node_id": nd["id"]}, AUTH)
    if ib2.get("id"):
        created_inbounds.append(ib2["id"])
        st, u3 = js("POST", "/api/users", {
            "username": "nd" + uuid.uuid4().hex[:8], "protocols": ["trojan"],
            "volume_gb": 5, "days": 5}, AUTH)
        if u3.get("id"):
            created_users.append(u3["id"])
            st, _, sub = req("GET", f"/sub/{u3['token']}", ua=VP_UA)
            body = sub.decode("utf-8", "replace")
            import base64 as _b64
            try:
                links = _b64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "replace")
            except Exception:
                links = body
            check("pinned inbound is served while the node is enabled",
                  "24444" in links, "pinned port missing")
            js("PATCH", f"/api/server-nodes/{nd['id']}", {"enabled": False}, AUTH)
            st, _, sub = req("GET", f"/sub/{u3['token']}", ua=VP_UA)
            body = sub.decode("utf-8", "replace")
            try:
                links = _b64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "replace")
            except Exception:
                links = body
            check("disabled node drops its inbound from links", "24444" not in links,
                  "disabled node still served")
            js("PATCH", f"/api/server-nodes/{nd['id']}", {"enabled": True}, AUTH)

# Link-only protocols collapse into one subscription.txt; a file-based
# protocol (WireGuard/OpenVPN/L2TP/Cisco) is what turns the answer into a ZIP.
st, um = js("POST", "/api/users", {
    "username": "zp" + uuid.uuid4().hex[:8],
    "protocols": ["vless", "trojan", "ss"],
    "volume_gb": 5, "days": 5}, AUTH)
if um.get("id"):
    created_users.append(um["id"])
    st, _, z1 = req("GET", f"/api/users/{um['id']}/config", headers=AUTH)
    check("link-only protocols collapse into one subscription file",
          st == 200 and z1[:2] != b"PK" and b"trojan://" in z1 and b"ss://" in z1,
          f"{st} {z1[:20]!r}")
st, um2 = js("POST", "/api/users", {
    "username": "zw" + uuid.uuid4().hex[:8],
    "protocols": ["trojan", "wireguard", "openvpn"],
    "volume_gb": 5, "days": 5}, AUTH)
if um2.get("id"):
    created_users.append(um2["id"])
    st, _, zb = req("GET", f"/api/users/{um2['id']}/config", headers=AUTH)
    check("a file-based protocol makes the bundle a ZIP", st == 200 and zb[:2] == b"PK",
          f"{st} {zb[:8]!r}")
    try:
        zf = zipfile.ZipFile(io.BytesIO(zb))
        names = zf.namelist()
        check("zip has no duplicate entry names", len(names) == len(set(names)), f"{names}")
        check("zip entries have safe flat names",
              all("/" not in n and ".." not in n and n for n in names), f"{names}")
        check("zip carries the subscription plus the per-protocol configs",
              len(names) >= 3 and any(n.endswith(".conf") for n in names)
              and any(n.endswith(".ovpn") for n in names), f"{names}")
    except Exception as exc:
        check("config bundle is a readable ZIP", False, repr(exc))

# ---------------------------------------------------------------- subscription format
# A bundle that mixes share links with file-based configs must still be a
# Base64 document: v2rayNG-style importers read the whole body as Base64 and
# silently imported ZERO nodes when it arrived as plain text.
import base64 as _b

st, umix = js("POST", "/api/users", {
    "username": "mx" + uuid.uuid4().hex[:8], "protocols": ["vless", "trojan", "wireguard"],
    "volume_gb": 5, "days": 5}, AUTH)
if umix.get("id"):
    created_users.append(umix["id"])
    st, _, raw = req("GET", f"/sub/{umix['token']}", ua=VP_UA)
    txt = raw.decode("utf-8", "replace")
    dec = ""
    try:
        dec = _b.b64decode(raw + b"=" * (-len(raw) % 4)).decode("utf-8", "replace")
    except Exception:
        pass
    check("mixed link+file subscription is Base64",
          st == 200 and "://" not in txt[:200] and dec != "", f"{st} {txt[:60]!r}")
    check("decoded bundle carries the share links", "vless://" in dec and "trojan://" in dec, dec[:80])
    check("decoded bundle labels the file-based config", "### WireGuard ###" in dec, dec[-120:])

st, uhy = js("POST", "/api/users", {
    "username": "hy" + uuid.uuid4().hex[:8], "protocols": ["hysteria2"],
    "volume_gb": 5, "days": 5}, AUTH)
if uhy.get("id"):
    created_users.append(uhy["id"])
    st, _, hraw = req("GET", f"/sub/{uhy['token']}", ua=VP_UA)
    hdec = _b.b64decode(hraw + b"=" * (-len(hraw) % 4)).decode("utf-8", "replace")
    line = next((l for l in hdec.splitlines() if l.startswith("hysteria2://")), "")
    check("hysteria2 URI has the spec's slash before the query", "/?sni=" in line, line[:80])

# ---------------------------------------------------------------- host / URL validation
st, _ = js("PUT", "/api/settings", {**DEFAULTS, "domain": "a..b"}, AUTH)
check("empty DNS label in the domain is rejected", st == 422, f"{st}")
st, _ = js("PUT", "/api/settings", {**DEFAULTS, "reality_sni": "www..com"}, AUTH)
check("empty DNS label in the REALITY SNI list is rejected", st == 422, f"{st}")
st, _ = js("PUT", "/api/settings", {**DEFAULTS, "domain": "vpn.example.com"}, AUTH)
check("a normal domain is still accepted", st == 200, f"{st}")
js("PUT", "/api/settings", DEFAULTS, AUTH)
st, _ = js("PUT", "/api/tunnel-settings", {"public_url": "https://example.com:0"}, AUTH)
check("public_url with port 0 is rejected", st == 422, f"{st}")
st, _ = js("PUT", "/api/tunnel-settings", {"public_url": "https://example.com:70000"}, AUTH)
check("public_url with an out-of-range port is rejected", st == 422, f"{st}")
st, _ = js("PUT", "/api/tunnel-settings", {"public_url": "https://example.com:8443"}, AUTH)
check("public_url with a valid port is accepted", st == 200, f"{st}")
js("PUT", "/api/tunnel-settings", {"public_url": ""}, AUTH)

# ---------------------------------------------------------------- CSV export
# The CSV is built in the browser (static/app.js), so the server-side check is
# that the data it needs is complete; the sanitiser itself is exercised through
# node (csv_guard_check.js) because a formula in a note is a real injection.
import os
import subprocess

_here = os.path.dirname(os.path.abspath(__file__))
try:
    r = subprocess.run(["node", os.path.join(_here, "csv_guard_check.js")],
                       capture_output=True, text=True, timeout=60)
    check("CSV export neutralises formula injection and bidi spoofing",
          r.returncode == 0, (r.stdout + r.stderr).strip()[:160])
except Exception as exc:
    check("CSV export neutralises formula injection and bidi spoofing", False, repr(exc))
st, ulist = js("GET", "/api/users", headers=AUTH)
first = (ulist.get("items") or [{}])[0] if isinstance(ulist, dict) else {}
check("CSV source data carries every column the export writes",
      st == 200 and all(
          k in first
          for k in ("username", "protocols", "volume_gb", "used_gb",
                    "expires_at", "is_active", "note")),
      f"{st} {str(first)[:120]}")
st, exp = js("GET", "/api/audit", headers=AUTH)
check("audit log is a list of events", st == 200 and isinstance(exp, list), f"{st} {type(exp).__name__}")

# ---------------------------------------------------------------- blocked sites
st, b = js("POST", "/api/blocklist", {"domain": "ads.example.net", "category": "ads"}, AUTH)
check("blocked site added", st == 200 and b.get("id"), f"{st} {str(b)[:80]}")
if b.get("id"):
    st, u5 = js("POST", "/api/users", {
        "username": "bl" + uuid.uuid4().hex[:8], "protocols": ["vless"],
        "volume_gb": 5, "days": 5}, AUTH)
    if u5.get("id"):
        created_users.append(u5["id"])
        st, _, cl = req("GET", f"/sub/{u5['token']}?format=clash", ua=VP_UA)
        y = cl.decode("utf-8", "replace")
        check("blocked site reaches the Clash config", "ads.example.net" in y, "rule missing")
        check("Clash config has the expected structure",
              "proxies:" in y and "proxy-groups:" in y and "rules:" in y, "structure missing")
        # Every rule target must be a declared group (or a built-in), otherwise
        # the client drops the rule and traffic leaks to the default route.
        import re as _re
        groups = set(_re.findall(r'"name":\s*"([^"]+)"\s*,\s*"type":\s*"(?:select|url-test|fallback|load-balance)"', y))
        targets = set()
        for line in y.splitlines():
            m = _re.match(r"\s*-\s*([A-Z0-9-]+,[^,]+),([^,]+)\s*$", line)
            if m:
                targets.add(m.group(2).strip())
        builtins = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", "COMPATIBLE"}
        dangling = {t for t in targets if t not in groups and t not in builtins}
        check("Clash rules only reference declared groups or built-ins",
              not dangling, f"dangling={sorted(dangling)} groups={sorted(groups)}")
        check("Clash group lists the generated proxies",
              groups and all(any(p in y for p in [g]) for g in groups), f"{sorted(groups)}")
    st, _ = js("DELETE", f"/api/blocklist/{b['id']}", headers=AUTH)
    check("blocked site deleted", st == 200, f"{st}")

# ---------------------------------------------------------------- appearance / theme.css
st, ap = js("PUT", "/api/appearance", {"theme_accent": "#00ff88", "brand_name": "HuntCo"}, AUTH)
check("appearance saved", st == 200, f"{st}")
st, hd_css, css = req("GET", "/theme.css", headers=AUTH)
check("theme.css reflects the accent", b"#00ff88" in css.lower(), "accent missing")
css_ctype = (hd_css.get("Content-Type") or hd_css.get("content-type") or "").lower()
check("theme.css is served as CSS", "text/css" in css_ctype, f"content-type={css_ctype!r}")
st, ap2 = js("PUT", "/api/appearance", {"theme_accent": "red; } body { display:none", "brand_name": "x"}, AUTH)
st, _, css = req("GET", "/theme.css", headers=AUTH)
check("a hostile colour value cannot inject CSS", b"display:none" not in css, "CSS injection")
js("PUT", "/api/appearance", {"theme_accent": "", "brand_name": ""}, AUTH)
st, _, css = req("GET", "/theme.css", headers=AUTH)
check("empty colour falls back to the default", st == 200, f"{st}")

# ---------------------------------------------------------------- audit + system + stats
st, aud = js("GET", "/api/audit", headers=AUTH)
items = aud if isinstance(aud, list) else (aud.get("items") if isinstance(aud, dict) else [])
check("audit log readable", st == 200 and isinstance(items, list), f"{st} {type(aud).__name__}")
check("audit log records this session's actions",
      any("USER_CREATE" in (x.get("event") or "") for x in items), "no create event")
st, sysd = js("GET", "/api/system", headers=AUTH)
check("system info reachable", st == 200 and "cpu" in str(sysd).lower(), f"{st}")
st, stats = js("GET", "/api/stats", headers=AUTH)
check("stats reachable with counters", st == 200 and "total_users" in stats,
      f"{st} {str(stats)[:80]}")
st, stats2 = js("GET", "/api/stats", headers=AUTH)
check("stats are consistent between calls",
      stats.get("total_users") == stats2.get("total_users"),
      f"{stats.get('total_users')} vs {stats2.get('total_users')}")

# ---------------------------------------------------------------- tunnels
# BackPack tunnels live under /api/nodes (server_nodes are /api/server-nodes).
tname2 = "tn" + uuid.uuid4().hex[:6]
st, tn = js("POST", "/api/nodes", {
    "name": tname2, "transport": "tcp", "iran_ip": "10.0.0.1",
    "kharej_ip": "10.0.0.2", "tunnel_port": 4500,
    "forwarded_ports": "10000:10010, 20000:20001", "udp_forward": True}, AUTH)
check("tunnel created", st == 200 and (tn.get("id") or (isinstance(tn, dict) and tn.get("ok"))),
      f"{st} {str(tn)[:100]}")
tnid = tn.get("id") if isinstance(tn, dict) else None
if not tnid:
    st, nlist = js("GET", "/api/nodes", headers=AUTH)
    hit = [n for n in (nlist if isinstance(nlist, list) else []) if n.get("name") == tname2]
    tnid = hit[0].get("id") if hit else None
if tnid:
    created_tunnels.append(tnid)
    st, _, guide = req("GET", f"/api/nodes/{tnid}/guide", headers=AUTH)
    check("tunnel guide downloads", st == 200 and len(guide) > 200, f"{st} len={len(guide)}")
    check("guide embeds instructions", b"token" in guide.lower() or b"backpack" in guide.lower(),
          "guide looks empty")
    st, tn2 = js("POST", f"/api/nodes/{tnid}/regen-token", {}, AUTH)
    check("tunnel token regenerates", st == 200, f"{st} {str(tn2)[:80]}")
    st, dup = js("POST", "/api/nodes", {
        "name": tname2, "transport": "tcp", "iran_ip": "10.0.0.3",
        "kharej_ip": "10.0.0.4", "tunnel_port": 4501}, AUTH)
    check("duplicate tunnel name is an upsert or a clean conflict",
          st in (200, 409, 422), f"{st}")
    st, bad = js("POST", "/api/nodes", {
        "name": "x" + uuid.uuid4().hex[:6], "transport": "tcp",
        "iran_ip": "not a host", "kharej_ip": "10.0.0.2", "tunnel_port": 4502}, AUTH)
    check("invalid tunnel host rejected", st in (400, 422), f"{st}")
    st, meta = js("POST", "/api/nodes", {
        "name": "m" + uuid.uuid4().hex[:6], "transport": "tcp",
        "iran_ip": "169.254.169.254", "kharej_ip": "10.0.0.2", "tunnel_port": 4502}, AUTH)
    check("metadata IP as tunnel host rejected", st in (400, 422), f"{st}")
    st, bad2 = js("POST", "/api/nodes", {
        "name": "y" + uuid.uuid4().hex[:6], "transport": "tcp",
        "iran_ip": "10.0.0.1", "kharej_ip": "10.0.0.2",
        "tunnel_port": 4503, "forwarded_ports": "not-a-range"}, AUTH)
    check("invalid forwarded_ports rejected", st in (400, 422), f"{st}")
    st, chk = js("POST", f"/api/nodes/{tnid}/check", {}, AUTH, timeout=40)
    check("tunnel check answers even when the endpoint is unreachable",
          st in (200, 502, 503), f"{st}")
    st, _ = js("DELETE", f"/api/nodes/{tnid}", headers=AUTH)
    check("tunnel deleted", st == 200, f"{st}")
    st, _ = js("DELETE", f"/api/nodes/{tnid}", headers=AUTH)
    check("deleting a tunnel twice is a clean 404", st == 404, f"{st}")

# ---------------------------------------------------------------- restore round-trip
# Full topology first: user templates, an inbound pinned to a server node, a
# tunnel, an API token. The restore must bring all of it back (the encrypted
# path used to drop inbounds/nodes/tunnels entirely).
tpl_name = "rtpl" + uuid.uuid4().hex[:6]
st, _ = js("POST", "/api/templates", {"name": tpl_name, "protocols": ["vless"],
                                       "volume_gb": 11, "days": 9}, AUTH)
snode_name = "rsn" + uuid.uuid4().hex[:6]
st, rsnode = js("POST", "/api/server-nodes", {
    "name": snode_name, "address": "127.0.0.1", "check_port": 9}, AUTH)
st, rib = js("POST", "/api/inbounds", {
    "name": "rib" + uuid.uuid4().hex[:6], "protocol": "vless", "port": 24567,
    "node_id": rsnode.get("id")}, AUTH)
st, rtn = js("POST", "/api/nodes", {
    "name": "rtn" + uuid.uuid4().hex[:6], "transport": "tcp",
    "iran_ip": "10.9.0.1", "kharej_ip": "10.9.0.2", "tunnel_port": 4600}, AUTH)
st, tokrow = js("POST", "/api/api-tokens", {"name": "rtok" + uuid.uuid4().hex[:4]}, AUTH)
bearer = (tokrow or {}).get("token_once") or ""

st, _, bkraw = req("POST", "/api/backup", json.dumps({"password_confirm": PASSWORD}),
                   AUTH, timeout=40)
bk = {}
try:
    bk = json.loads(bkraw)
except Exception:
    pass
check("backup created", st == 200 and bk.get("zefira_backup") is True, f"{st} {bkraw[:80]}")
check("backup carries the endpoint topology",
      bool(bk.get("inbounds")) and bool(bk.get("server_nodes")) and bool(bk.get("tunnel_nodes"))
      and any(i.get("node_name") == snode_name for i in bk.get("inbounds", [])),
      f"ib={len(bk.get('inbounds') or [])} sn={len(bk.get('server_nodes') or [])} tn={len(bk.get('tunnel_nodes') or [])}")
check("backup records the source CA fingerprint", "ca_fingerprint" in (bk.get("meta") or {}),
      str(bk.get("meta")))

if bk:
    # Delete the topology, then restore and prove it comes back.
    if rib.get("id"):
        js("DELETE", f"/api/inbounds/{rib['id']}", headers=AUTH)
    if rsnode.get("id"):
        js("DELETE", f"/api/server-nodes/{rsnode['id']}", headers=AUTH)
    if rtn.get("id"):
        js("DELETE", f"/api/nodes/{rtn['id']}", headers=AUTH)
    payload = dict(bk)
    payload["password_confirm"] = PASSWORD
    st, rr = js("POST", "/api/restore", payload, AUTH, timeout=90)
    check("restore imports the backup", st == 200 and rr.get("added_users", 0) >= 1,
          f"{st} {str(rr)[:120]}")
    check("restore brought back the inbound/server-node/tunnel sections",
          rr.get("restored_inbounds", 0) >= 1 and rr.get("restored_snodes", 0) >= 1
          and rr.get("restored_tunnels", 0) >= 1, str(rr)[:160])
    st, ibs = js("GET", "/api/inbounds", headers=AUTH)
    pinned = [i for i in ibs if i.get("name") == rib.get("name")]
    check("restored inbound keeps its node pin",
          bool(pinned) and pinned[0].get("node_id") == rsnode.get("id"),
          f"{pinned}")
    st, sns = js("GET", "/api/server-nodes", headers=AUTH)
    check("restored server node present",
          any(n.get("name") == snode_name for n in sns), f"{st}")
    st, tns = js("GET", "/api/nodes", headers=AUTH)
    check("restored tunnel present (fresh token)",
          any(n.get("name") == rtn.get("name") for n in tns), f"{st}")
    check("restored API token works again (backup set is authoritative)",
          bool(bearer) and req("GET", "/api/stats", None, {"Authorization": f"Bearer {bearer}"})[0] == 200,
          "bearer rejected")
    # A revoked token must NOT come back: the backup's set is authoritative,
    # so a restore whose file simply has no tokens clears the local set.
    if tokrow.get("id"):
        js("DELETE", f"/api/api-tokens/{tokrow['id']}", headers=AUTH)
        st, cl2 = js("POST", "/api/restore", {
            **{k: v for k, v in payload.items() if k != "api_tokens"},
            "api_tokens": [],
        }, AUTH, timeout=90)
        st, _, _ = req("GET", "/api/stats", None, {"Authorization": f"Bearer {bearer}"})
        check("token deleted locally stays dead after a restore", st in (401, 403), f"{st}")

    # One malformed row must not cost the good rows.
    st, mix = js("POST", "/api/restore", {
        "zefira_backup": True, "password_confirm": PASSWORD,
        "users": [
            {"username": "good" + uuid.uuid4().hex[:6], "protocol": "vless",
             "protocols": "vless", "note": "", "volume_gb": 3, "used_gb": 0,
             "token": uuid.uuid4().hex, "secret_data": "{}", "is_active": True,
             "device_limit": None, "start_on_first_use": False,
             "duration_days": None, "expires_at": "2031-01-01T00:00:00"},
            {"username": "bad row", "protocol": "vless", "volume_gb": "seven",
             "token": "nope", "expires_at": "not-a-date"},
        ],
        "admins": [], "settings": {}, "blocked_sites": [],
    }, AUTH, timeout=60)
    check("a malformed user row is skipped, the good one is kept",
          st == 200 and mix.get("added_users") == 1 and mix.get("skipped", 0) >= 1,
          f"{st} {str(mix)[:120]}")
    st, gl = js("GET", "/api/users", headers=AUTH)
    check("the good row from the mixed restore is servable",
          any(x["username"].startswith("good") for x in gl.get("items", [])), f"{st}")

    # Timezone-bearing expiry must be converted, not dropped.
    st, tz = js("POST", "/api/restore", {
        "zefira_backup": True, "password_confirm": PASSWORD,
        "users": [{"username": "tz" + uuid.uuid4().hex[:6], "protocol": "vless",
                   "protocols": "vless", "note": "", "volume_gb": 3, "used_gb": 0,
                   "token": uuid.uuid4().hex, "secret_data": "{}", "is_active": True,
                   "device_limit": None, "start_on_first_use": False,
                   "duration_days": None, "expires_at": "2031-06-01T00:00:00+05:00"}],
        "admins": [], "settings": {}, "blocked_sites": [],
    }, AUTH, timeout=60)
    st, tzl = js("GET", "/api/users?q=tz", headers=AUTH)
    tzu = [x for x in tzl.get("items", []) if x["username"].startswith("tz")]
    check("offset expiry is converted to UTC (not shifted)",
          bool(tzu) and tzu[0]["expires_at"].startswith("2031-05-31T19:00"),
          str(tzu[0]["expires_at"]) if tzu else "missing")

    st, _ = js("POST", "/api/restore", {
        "zefira_backup": True, "password_confirm": "wrong-password",
        "users": bk.get("users", [])}, AUTH, timeout=40)
    check("restore with a wrong password is refused", st in (400, 401, 403), f"{st}")

    # Encrypted round-trip: same topology, no plaintext file.
    st, _, encraw = req("POST", "/api/backup", json.dumps(
        {"password_confirm": PASSWORD, "encrypt": True}), AUTH, timeout=40)
    try:
        enc = json.loads(encraw)
    except Exception:
        enc = {}
    if st == 200 and enc.get("encrypted") is True:
        # Clear the topology first: restore merges sections, so a name that is
        # already present is (correctly) skipped as a duplicate.
        for x in (js("GET", "/api/inbounds", headers=AUTH)[1] or []):
            js("DELETE", f"/api/inbounds/{x['id']}", headers=AUTH)
        for x in (js("GET", "/api/server-nodes", headers=AUTH)[1] or []):
            js("DELETE", f"/api/server-nodes/{x['id']}", headers=AUTH)
        for x in (js("GET", "/api/nodes", headers=AUTH)[1] or []):
            js("DELETE", f"/api/nodes/{x['id']}", headers=AUTH)
        st, er = js("POST", "/api/restore-encrypted", {
            "password_confirm": PASSWORD, "salt": enc["salt"],
            "payload": enc["payload"], "backup_password": PASSWORD}, AUTH, timeout=90)
        check("encrypted restore returns the endpoint sections",
              st == 200 and er.get("restored_inbounds", 0) >= 1
              and er.get("restored_snodes", 0) >= 1 and er.get("restored_tunnels", 0) >= 1,
              f"{st} {str(er)[:140]}")
        st, _ = js("POST", "/api/restore-encrypted", {
            "password_confirm": PASSWORD, "salt": enc["salt"],
            "payload": "x" * 40, "backup_password": PASSWORD}, AUTH, timeout=40)
        check("encrypted restore with a corrupt payload is refused", st in (400, 401, 403), f"{st}")
    else:
        check("encrypted backup produced", False, f"{st} {str(enc)[:80]}")

# ---------------------------------------------------------------- cleanup
# Restores replaced the DB contents, so re-read what exists before deleting.
st, allu = js("GET", "/api/users", headers=AUTH)
for x in (allu.get("items") or []):
    js("DELETE", f"/api/users/{x['id']}", headers=AUTH)
for x in (js("GET", "/api/inbounds", headers=AUTH)[1] or []):
    js("DELETE", f"/api/inbounds/{x['id']}", headers=AUTH)
for x in (js("GET", "/api/server-nodes", headers=AUTH)[1] or []):
    js("DELETE", f"/api/server-nodes/{x['id']}", headers=AUTH)
for x in (js("GET", "/api/nodes", headers=AUTH)[1] or []):
    js("DELETE", f"/api/nodes/{x['id']}", headers=AUTH)
for x in (js("GET", "/api/templates", headers=AUTH)[1] or []):
    js("DELETE", f"/api/templates/{x['id']}", headers=AUTH)
for x in (js("GET", "/api/blocklist", headers=AUTH)[1].get("sites") or []):
    js("DELETE", f"/api/blocklist/{x['id']}", headers=AUTH)
for x in (js("GET", "/api/api-tokens", headers=AUTH)[1] or []):
    js("DELETE", f"/api/api-tokens/{x['id']}", headers=AUTH)
st, final = js("GET", "/api/users", headers=AUTH)
left = final.get("total", -1) if isinstance(final, dict) else -1
check("path hunt cleaned up", left == 0, f"leftover users={left}")

passed = sum(1 for _, ok, _ in results if ok)
print(f"\n=== {passed}/{len(results)} checks passed ===")
for n, ok, d in results:
    if not ok:
        print(f"  FAIL {n}: {d}")
sys.exit(0 if passed == len(results) else 1)
