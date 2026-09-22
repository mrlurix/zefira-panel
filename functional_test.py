"""
ZEFIRA FUNCTIONAL TEST SUITE - exercises every feature end to end.
Run while the panel is up:  .venv\\Scripts\\python functional_test.py http://127.0.0.1:PORT admin PASSWORD
Only use against your own instance. Creates temp users (fte_*) and deletes
them; settings/telegram/tunnel/appearance are saved and restored.
Refuses to run when foreign users exist (unless --allow-live).
"""
import base64
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"

results = []
CREATED_IDS = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def req(method, path, body=None, headers=None, timeout=20):
    url = BASE + path
    data = None
    hdrs = {"User-Agent": "zefira-functionaltest/1.0"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = body.encode() if isinstance(body, str) else body
        hdrs.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:  # connection/timeout
        return 0, {}, str(e).encode()


def hget(hdrs, name):
    for k, v in hdrs.items():
        if k.lower() == name.lower():
            return v
    return ""


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


print(f"=== ZEFIRA FUNCTIONAL -> {BASE} ===")
st, AUTH = login_with(PASSWORD)
check("login works", st == 200, f"status={st}")
if st != 200:
    print("ABORT: cannot log in");
    sys.exit(2)

st, _, sbody = req("GET", "/api/stats", headers=AUTH)
total0 = -1
try:
    if st == 200:
        total0 = json.loads(sbody).get("total_users", -1)
except Exception:
    pass
if "--allow-live" not in sys.argv and total0 != 0:
    if total0 > 0:
        print(f"ABORT: panel has {total0} user(s). Re-run with --allow-live.")
    else:
        print("ABORT: could not verify the panel is empty. Refusing to run wipe tests.")
    sys.exit(2)

# ---- stats / system / audit / me ----
st, _, sb = req("GET", "/api/stats", headers=AUTH)
try:
    sj = json.loads(sb)
    check("stats shape", all(k in sj for k in ("total_users", "active_users", "volume_total_gb")))
except Exception:
    check("stats shape", False)
st, _, yb = req("GET", "/api/system", headers=AUTH)
try:
    yj = json.loads(yb)
    check("system shape", "available" in yj)
except Exception:
    check("system shape", False)
st, _, ab = req("GET", "/api/audit", headers=AUTH)
try:
    check("audit list", isinstance(json.loads(ab), list))
except Exception:
    check("audit list", False)
st, _, mb = req("GET", "/api/me", headers=AUTH)
try:
    check("me returns username", json.loads(mb).get("username") == ADMIN)
except Exception:
    check("me returns username", False)

# ---- settings round-trip ----
st, _, sob = req("GET", "/api/settings", headers=AUTH)
orig_settings = json.loads(sob)
mod = dict(orig_settings)
mod["domain"] = "ftest.example.com"
st, _, _ = req("PUT", "/api/settings", json.dumps(mod), AUTH)
st, _, sob2 = req("GET", "/api/settings", headers=AUTH)
check("settings put/get round-trip", st == 200 and json.loads(sob2).get("domain") == "ftest.example.com", f"got {st}")
st, _, _ = req("PUT", "/api/settings", json.dumps(orig_settings), AUTH)
st, _, sob3 = req("GET", "/api/settings", headers=AUTH)
check("settings restored", json.loads(sob3).get("domain") == orig_settings.get("domain"))

# ---- appearance round-trip ----
st, _, aob = req("GET", "/api/appearance", headers=AUTH)
orig_ap = json.loads(aob)
st, _, _ = req("PUT", "/api/appearance", json.dumps({
    "theme_accent": "#00c853", "theme_bg": "", "theme_card": "",
    "brand_name": "FTest", "dash_note": "hello"}), AUTH)
st, _, aob2 = req("GET", "/api/appearance", headers=AUTH)
check("appearance put/get", json.loads(aob2).get("brand_name") == "FTest", f"got {st}")
st, _, cssb = req("GET", "/theme.css")
css = cssb.decode("utf-8", "replace") if isinstance(cssb, bytes) else cssb
check("theme.css reflects custom accent", "#00c853" in css, f"got {st}")
st, _, _ = req("PUT", "/api/appearance", json.dumps({
    "theme_accent": orig_ap.get("theme_accent") or "", "theme_bg": orig_ap.get("theme_bg") or "",
    "theme_card": orig_ap.get("theme_card") or "", "brand_name": orig_ap.get("brand_name") or "",
    "dash_note": orig_ap.get("dash_note") or ""}), AUTH)
check("appearance restored", st == 200, f"got {st}")

# ---- tunnel settings round-trip ----
st, _, tob = req("GET", "/api/tunnel-settings", headers=AUTH)
orig_tun = json.loads(tob)
st, _, _ = req("PUT", "/api/tunnel-settings", json.dumps(
    {"public_url": "https://t.example.com:8443", "trusted_proxies": "10.9.9.9"}), AUTH)
st, _, tob2 = req("GET", "/api/tunnel-settings", headers=AUTH)
check("tunnel settings round-trip", json.loads(tob2).get("public_url") == "https://t.example.com:8443", f"got {st}")
req("PUT", "/api/tunnel-settings", json.dumps(
    {"public_url": orig_tun.get("public_url") or "", "trusted_proxies": orig_tun.get("trusted_proxies") or ""}), AUTH)

# ---- telegram (no real token) ----
st, _, tgb = req("GET", "/api/telegram", headers=AUTH)
orig_tg = json.loads(tgb)
st, _, _ = req("PUT", "/api/telegram", json.dumps({"bot_token": "", "chat_id": "999888777"}), AUTH)
st, _, tgb2 = req("GET", "/api/telegram", headers=AUTH)
check("telegram chat round-trip", json.loads(tgb2).get("chat_id") == "999888777", f"got {st}")
st, _, _ = req("POST", "/api/telegram/test", json.dumps({}), AUTH)
check("telegram test without token fails cleanly", st == 400, f"got {st}")
req("PUT", "/api/telegram", json.dumps(
    {"bot_token": "", "chat_id": orig_tg.get("chat_id") or ""}), AUTH)

# ---- templates CRUD ----
st, _, _ = req("POST", "/api/templates", json.dumps({
    "name": "ftest_tpl", "protocols": ["vless", "vmess"], "volume_gb": 5, "days": 7}), AUTH)
check("template create", st == 200, f"got {st}")
st, _, tlb = req("GET", "/api/templates", headers=AUTH)
tpls = json.loads(tlb)
tid = next((t["id"] for t in tpls if t["name"] == "ftest_tpl"), None)
check("template listed", tid is not None)
st, _, _ = req("POST", "/api/templates", json.dumps({
    "name": "ftest_tpl", "protocols": ["trojan"], "volume_gb": 9, "days": 9}), AUTH)
check("template upsert", st == 200, f"got {st}")
if tid:
    st, _, _ = req("DELETE", f"/api/templates/{tid}", headers=AUTH)
    check("template delete", st == 200, f"got {st}")
    st, _, _ = req("DELETE", f"/api/templates/{tid}", headers=AUTH)
    check("template re-delete 404", st == 404, f"got {st}")

# ---- inbounds CRUD ----
st, _, _ = req("POST", "/api/inbounds", json.dumps(
    {"name": "ftest_ib", "protocol": "vless", "port": 28443}), AUTH)
check("inbound create", st == 200, f"got {st}")
st, _, ilb = req("GET", "/api/inbounds", headers=AUTH)
ibs = json.loads(ilb)
iid = next((b["id"] for b in ibs if b["name"] == "ftest_ib"), None)
check("inbound listed", iid is not None)
if iid:
    st, _, _ = req("PATCH", f"/api/inbounds/{iid}", json.dumps({"enabled": False, "port": 28444}), AUTH)
    check("inbound patch", st == 200, f"got {st}")
    st, _, _ = req("DELETE", f"/api/inbounds/{iid}", headers=AUTH)
    check("inbound delete", st == 200, f"got {st}")

# ---- server nodes + offline failover ----
st, _, snb = req("POST", "/api/server-nodes", json.dumps({
    "name": "fte_srv", "address": "127.0.0.1", "check_port": 8000, "note": "func"}), AUTH)
try:
    snid = json.loads(snb).get("id")
    check("server node create", st == 200 and bool(snid), f"got {st}")
except Exception:
    snid = None
    check("server node create", False, f"got {st}")
failover_ok = False
if snid:
    st, _, ckb = req("POST", f"/api/server-nodes/{snid}/check", headers=AUTH, timeout=30)
    try:
        check("server node check online", st == 200 and json.loads(ckb).get("status") == "online", f"got {st}")
    except Exception:
        check("server node check online", False, f"got {st}")
    st, _, _ = req("POST", "/api/inbounds", json.dumps(
        {"name": "fte_nodeib", "protocol": "vless", "port": 29443, "node_id": snid}), AUTH)
    st, _, uub = req("POST", "/api/users", json.dumps({
        "username": "fte_srvuser", "protocols": ["vless"], "volume_gb": 5, "days": 7}), AUTH)
    try:
        szk = json.loads(uub)["token"]
        st, _, s1b = req("GET", f"/sub/{szk}", headers={"User-Agent": "v2rayNG/1.9"})
        s1 = s1b.decode("utf-8", "replace") if isinstance(s1b, bytes) else s1b
        inc1 = st == 200 and "fte_nodeib" in __import__("base64").b64decode(s1).decode("utf-8", "replace")
    except Exception:
        inc1 = False
    check("pinned inbound served while node online", inc1)
    req("PATCH", f"/api/server-nodes/{snid}", json.dumps({"address": "127.0.0.1", "check_port": 9}), AUTH)
    st, _, ckb2 = req("POST", f"/api/server-nodes/{snid}/check", headers=AUTH, timeout=30)
    off = st == 200
    try:
        off = off and json.loads(ckb2).get("status") == "offline"
    except Exception:
        off = False
    st, _, s2b = req("GET", f"/sub/{szk}", headers={"User-Agent": "v2rayNG/1.9"})
    s2 = s2b.decode("utf-8", "replace") if isinstance(s2b, bytes) else s2b
    try:
        exc2 = "fte_nodeib" not in __import__("base64").b64decode(s2).decode("utf-8", "replace")
    except Exception:
        exc2 = False
    check("offline node links excluded", off and st == 200 and exc2, f"off={off} got {st}")
    failover_ok = off and exc2
    st, _, _ = req("DELETE", f"/api/server-nodes/{snid}", headers=AUTH)
    check("server node delete", st == 200, f"got {st}")
    st, _, ilb2 = req("GET", "/api/inbounds", headers=AUTH)
    unpinned = any(b["name"] == "fte_nodeib" and not b.get("node_id") for b in json.loads(ilb2))
    check("delete unpins its inbounds", unpinned)
    for uname in ("fte_srvuser",):
        lst = json.loads(req("GET", f"/api/users?q={uname}", headers=AUTH)[2])
        for u2 in lst["items"]:
            req("DELETE", f"/api/users/{u2['id']}", headers=AUTH)
    for iname in ("fte_nodeib",):
        lst = [b for b in json.loads(req("GET", "/api/inbounds", headers=AUTH)[2]) if b["name"] == iname]
        for b in lst:
            req("DELETE", f"/api/inbounds/{b['id']}", headers=AUTH)
check("failover scenario complete", failover_ok)

# ---- blocklist CRUD ----
st, _, _ = req("POST", "/api/blocklist", json.dumps({"domain": "ftest-block.example.com"}), AUTH)
check("block add", st == 200, f"got {st}")
st, _, blb = req("GET", "/api/blocklist", headers=AUTH)
bls = json.loads(blb)
bid = next((b["id"] for b in bls["sites"] if b["domain"] == "ftest-block.example.com"), None)
check("block listed", bid is not None)
st, _, _ = req("PUT", "/api/blocklist/porn", json.dumps({"porn_enabled": True}), AUTH)
st, _, blb2 = req("GET", "/api/blocklist", headers=AUTH)
check("porn toggle on", json.loads(blb2).get("porn_enabled") is True, f"got {st}")
st, _, _ = req("PUT", "/api/blocklist/porn", json.dumps({"porn_enabled": False}), AUTH)
if bid:
    st, _, _ = req("DELETE", f"/api/blocklist/{bid}", headers=AUTH)
    check("block delete", st == 200, f"got {st}")

# ---- tunnel node full cycle ----
st, _, nb = req("POST", "/api/nodes", json.dumps({
    "name": "ftest_node", "transport": "tcp", "iran_ip": "192.0.2.1",
    "kharej_ip": "192.0.2.2", "tunnel_port": 4411}), AUTH)
try:
    nj = json.loads(nb)
    nid = nj.get("id")
    check("node create (+one-time token)", st == 200 and bool(nj.get("token_once")), f"got {st}")
except Exception:
    nid = None
    check("node create (+one-time token)", False, f"got {st}")
if nid:
    st, _, gb = req("GET", f"/api/nodes/{nid}/guide", headers=AUTH)
    gb = gb.decode("utf-8", "replace") if isinstance(gb, bytes) else gb
    check("node guide downloads", st == 200 and "ftest_node" in gb, f"got {st}")
    st, _, cb = req("POST", f"/api/nodes/{nid}/check", headers=AUTH, timeout=30)
    try:
        check("node check reports status", st == 200 and json.loads(cb).get("status") in ("online", "offline"), f"got {st}")
    except Exception:
        check("node check reports status", False, f"got {st}")
    st, _, rb = req("POST", f"/api/nodes/{nid}/reveal-token", headers=AUTH)
    try:
        check("node token reveal", st == 200 and len(json.loads(rb).get("token", "")) > 10, f"got {st}")
    except Exception:
        check("node token reveal", False, f"got {st}")
    st, _, _ = req("POST", f"/api/nodes/{nid}/regen-token", headers=AUTH)
    check("node token regen", st == 200, f"got {st}")
    st, _, _ = req("DELETE", f"/api/nodes/{nid}", headers=AUTH)
    check("node delete", st == 200, f"got {st}")

# ---- reality read-only ----
st, _, pb = req("GET", "/api/reality/private", headers=AUTH)
check("reality private read (200 or clean 404)", st in (200, 404), f"got {st}")

# ---- SSL + update status (read-only) ----
st, _, sb = req("GET", "/api/ssl/status", headers=AUTH)
try:
    check("ssl status shape", st == 200 and "installed" in json.loads(sb), f"got {st}")
except Exception:
    check("ssl status shape", False, f"got {st}")
st, _, ub = req("GET", "/api/update/status", headers=AUTH)
try:
    uj = json.loads(ub)
    check("update status shape", st == 200 and all(k in uj for k in ("current", "latest", "incoming", "local_log")), f"got {st}")
except Exception:
    check("update status shape", False, f"got {st}")

# ---- user full lifecycle (ALL protocols) ----
ALL = ["vless", "reality", "vmess", "trojan", "ss", "hysteria2", "wireguard", "openvpn", "l2tp", "cisco", "socks5"]
st, _, cub = req("POST", "/api/users", json.dumps({
    "username": "fte_full", "protocols": ALL, "volume_gb": 10, "days": 30, "note": "func test"}), AUTH)
try:
    cu = json.loads(cub)
    uid, utok = cu.get("id"), cu.get("token")
    check("create 8-protocol user", st == 200 and bool(uid and utok), f"got {st}")
except Exception:
    uid, utok = None, None
    check("create 8-protocol user", False, f"got {st}")
if uid:
    CREATED_IDS.append(uid)
    st, _, qb = req("GET", f"/api/users/{uid}/qr", headers=AUTH)
    try:
        check("user qr", st == 200 and bool(json.loads(qb).get("qr_b64")), f"got {st}")
    except Exception:
        check("user qr", False, f"got {st}")
    st, hdrc, cfb = req("GET", f"/api/users/{uid}/config", headers=AUTH)
    cfb = cfb if isinstance(cfb, bytes) else cfb.encode()
    check("config bundle downloads", st == 200 and len(cfb) > 500, f"got {st} len={len(cfb)}")
    st, _, ptb = req("PATCH", f"/api/users/{uid}", json.dumps({
        "add_volume_gb": 5, "extend_days": 7, "set_note": "edited",
        "set_device_limit": 3, "add_used_gb": 1.5}), AUTH)
    try:
        pj = json.loads(ptb)
        check("patch all fields", st == 200 and pj.get("volume_gb") == 15 and pj.get("note") == "edited"
              and pj.get("device_limit") == 3 and abs(pj.get("used_gb", 0) - 1.5) < 0.01, f"got {st}")
    except Exception:
        check("patch all fields", False, f"got {st}")
    st, _, rub = req("POST", f"/api/users/{uid}/reset-usage", headers=AUTH)
    try:
        check("reset-usage zeroes traffic", st == 200 and json.loads(rub).get("used_gb") == 0, f"got {st}")
    except Exception:
        check("reset-usage zeroes traffic", False, f"got {st}")
    st, _, rtb = req("POST", f"/api/users/{uid}/reset-token", headers=AUTH)
    try:
        check("reset token rotates", st == 200 and json.loads(rtb).get("token") != utok, f"got {st}")
        utok = json.loads(rtb).get("token")
    except Exception:
        check("reset token rotates", False, f"got {st}")
    # subscription in all 3 modes
    st, hdrr, rawb = req("GET", f"/sub/{utok}", headers={"User-Agent": "v2rayNG/1.9"})
    rawb = rawb.decode("utf-8", "replace") if isinstance(rawb, bytes) else rawb
    check("sub raw for client", st == 200 and len(rawb) > 100, f"got {st}")
    st, _, clb = req("GET", f"/sub/{utok}?format=clash", headers={"User-Agent": "v2rayNG/1.9"})
    clb = clb.decode("utf-8", "replace") if isinstance(clb, bytes) else clb
    check("sub clash format", st == 200 and clb.startswith("mixed-port:"), f"got {st}")
    st, _, dshb = req("GET", f"/sub/{utok}", headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537.36"})
    dsh = dshb.decode("utf-8", "replace") if isinstance(dshb, bytes) else dshb
    check("sub dashboard for browser", st == 200 and "fte_full" in dsh and any(
        marker in dsh for marker in ("Last active:", "آخرین فعالیت:", "上次活跃:", "Был(а):")), f"got {st}")
    st, _, _ = req("PATCH", f"/api/users/{uid}", json.dumps({"is_active": False}), AUTH)
    st, _, _ = req("GET", f"/sub/{utok}", headers={"User-Agent": "v2rayNG/1.9"})
    check("disabled user sub 404s", st == 404, f"got {st}")
    st, _, _ = req("DELETE", f"/api/users/{uid}", headers=AUTH)
    check("user delete", st == 200, f"got {st}")
    CREATED_IDS.clear()

# ---- backup round-trip (same data back) ----
st, _, bbb = req("POST", "/api/backup", json.dumps({"password_confirm": PASSWORD}), AUTH)
bok = st == 200
try:
    bj = json.loads(bbb)
    bok = bok and bj.get("zefira_backup") is True and isinstance(bj.get("users"), list)
    n_users = len(bj.get("users", []))
except Exception:
    bok, n_users = False, -1
check("backup downloads valid payload", bok, f"got {st}")
if bok:
    payload = json.loads(bbb)
    payload["password_confirm"] = PASSWORD
    st, _, rsb = req("POST", "/api/restore", json.dumps(payload), AUTH, timeout=60)
    try:
        rsj = json.loads(rsb)
        check("restore round-trip ok", st == 200 and rsj.get("ok") is True, f"got {st}")
    except Exception:
        check("restore round-trip ok", False, f"got {st}")
    st, AUTH = login_with(PASSWORD)  # restore bumps token_version: old cookie is dead
    st, _, sab = req("GET", "/api/stats", headers=AUTH)
    try:
        check("user count preserved by round-trip", json.loads(sab).get("total_users") == n_users,
              f"users={n_users}")
    except Exception:
        check("user count preserved by round-trip", False)

# ---- password change there and back ----
st, _, _ = req("POST", "/api/change-password", json.dumps(
    {"current_password": PASSWORD, "new_password": "FuncTmp12345"}), AUTH)
check("password change", st == 200, f"got {st}")
st, AUTH = login_with("FuncTmp12345")
check("login with new password", st == 200, f"got {st}")
st, _, _ = req("POST", "/api/change-password", json.dumps(
    {"current_password": "FuncTmp12345", "new_password": PASSWORD}), AUTH)
check("password reverted", st == 200, f"got {st}")
st, AUTH = login_with(PASSWORD)
check("login with original password", st == 200, f"got {st}")

print("\n=== SUMMARY ===")
passed = sum(1 for _, okk, _ in results if okk)
total = len(results)
for name, okk, detail in results:
    if not okk:
        print(f"  FAILED: {name} {detail}")
print(f"{passed}/{total} checks passed")
sys.exit(0 if passed == total else 1)
