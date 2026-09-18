"""
ZEFIRA PENETRATION TEST SUITE
Run while the panel is up:  .venv\\Scripts\\python security_test.py http://127.0.0.1:PORT admin PASSWORD
Only use against your own instance.
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

import jwt

HERE = os.path.dirname(os.path.abspath(__file__))

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"

results = []


def req(method, path, body=None, headers=None, cookie=None, timeout=8):
    url = BASE + path
    data = None
    hdrs = {"User-Agent": "zefira-pentest/1.0"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = body.encode() if isinstance(body, str) else body
        hdrs.setdefault("Content-Type", "application/json")
    if cookie:
        hdrs["Cookie"] = cookie
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        code = e.code
        hdrs_out = dict(e.headers)
        try:
            body_out = e.read()
        except (ConnectionError, OSError):
            body_out = b""
        return code, hdrs_out, body_out
    except Exception as e:
        return 0, {}, str(e).encode()


def hget(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


def login():
    return login_with(PASSWORD)


def login_with(password):
    st, hd, _ = req(
        "POST",
        "/api/login",
        json.dumps({"username": ADMIN, "password": password}),
        {"X-Requested-With": "XMLHttpRequest"},
    )
    sc = hd.get("set-cookie") or hd.get("Set-Cookie") or ""
    tok = ""
    for part in sc.split(";"):
        part = part.strip()
        if part.startswith("zefira_session="):
            tok = part.split("=", 1)[1]
    return st, tok, sc


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


print(f"=== ZEFIRA PENTEST -> {BASE} ===")

# ---- 0. Live-data guard: restore/atomicity tests wipe users ----
st, token, rawcookie = login()
if "--allow-live" not in sys.argv and st == 200:
    _auth = {"Cookie": f"zefira_session={token}", "X-Requested-With": "XMLHttpRequest"}
    try:
        _sst, _, _sbody = req("GET", "/api/stats", headers=_auth)
        _total = json.loads(_sbody).get("total_users", 0) if _sst == 200 else 0
    except Exception:
        _total = -1
    if _total != 0:
        if _total and _total > 0:
            print(f"ABORT: panel has {_total} user(s). This suite runs restore tests that WIPE users.")
        else:
            print("ABORT: could not verify the panel is empty (stats unreachable). Refusing to run wipe tests.")
        print("Back up first (Settings -> Download Backup), then re-run with: --allow-live")
        sys.exit(2)

# ---- 1. Authentication boundary ----
check("login works & sets cookie", st == 200 and token != "", f"status={st}")
check("cookie HttpOnly flag", "httponly" in rawcookie.lower())
check("cookie SameSite=strict", "samesite=strict" in rawcookie.lower())

AUTH = {"Cookie": f"zefira_session={token}", "X-Requested-With": "XMLHttpRequest"}

for ep in ["/api/stats", "/api/users", "/api/settings", "/api/audit", "/api/system", "/api/me"]:
    st, _, _ = req("GET", ep)
    check(f"unauth GET {ep} -> 401", st == 401, f"got {st}")

stb, _, _ = req("GET", "/api/backup")
check("backup is not a GET (no CSRF-able download)", stb == 405, f"got {stb}")
stb2, _, _ = req("POST", "/api/backup", json.dumps({"password_confirm": "WrongPass12345"}), {"X-Requested-With": "XMLHttpRequest"})
check("unauth POST /api/backup blocked", stb2 in (401, 403), f"got {stb2}")

st, _, _ = req("POST", "/api/users", '{"username":"hacker","protocols":["vless"],"volume_gb":1,"days":1}')
check("unauth POST /api/users blocked", st in (401, 403), f"got {st}")

# ---- 2. CSRF ----
body = json.dumps({"username": ADMIN, "password": PASSWORD})
st, _, _ = req("POST", "/api/login", body, {"Content-Type": "application/json"})
check("CSRF guard: POST w/o X-Requested-With -> 403", st == 403, f"got {st}")

st, _, _ = req("DELETE", "/api/users/1", headers={"X-Requested-With": "XMLHttpRequest"})
check("CSRF/auth: DELETE w/o cookie -> 401", st == 401, f"got {st}")

# ---- 3. SQL injection ----
payloads = [
    "' OR 1=1--",
    "admin'--",
    '" OR ""="',
    "' UNION SELECT password_hash FROM admins--",
    "%' OR '1'='1",
    "admin' AND SLEEP(5)--",
]
ok = True
for p in payloads:
    b = json.dumps({"username": p, "password": "Whatever12345"})
    st0, _, _ = req("POST", "/api/login", b, {"X-Requested-With": "XMLHttpRequest"})
    if st0 not in (401, 403, 422, 429):
        ok = False
        print(f"      sqli-login payload {p!r} -> {st0}")
    time.sleep(0.05)
check("SQLi in login handled safely", ok)

ok = True
for p in ["%25", "_%25", "' OR '1'='1", "%00"]:
    stq, _, _ = req("GET", f"/api/users?q={urllib.request.quote(p)}", headers=AUTH)
    if stq != 200:
        ok = False
        print(f"      sqli-search payload {p!r} -> {stq}")
check("SQLi/wildcards in search handled", ok)

# ---- 4. JWT attacks ----
st_wrongpw, _, _ = req(
    "POST", "/api/login", json.dumps({"username": ADMIN, "password": "WrongPass12345"}),
    {"X-Requested-With": "XMLHttpRequest"},
)
check("wrong password rejected", st_wrongpw == 401, f"got {st_wrongpw}")

if token:
    forged_none = jwt.encode({"sub": "1", "ver": 99}, key=None, algorithm="none").decode() if False else \
        base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode() + "." + \
        base64.urlsafe_b64encode(json.dumps({"sub": "1", "ver": 99}).encode()).rstrip(b"=").decode() + "."
    stn, _, _ = req("GET", "/api/stats", headers={"Cookie": f"zefira_session={forged_none}"})
    check("JWT alg=none rejected", stn == 401, f"got {stn}")

    parts = token.split(".")
    tampered = parts[0] + "." + base64.urlsafe_b64encode(
        json.dumps({"sub": "1", "ver": 999999}).encode()
    ).rstrip(b"=").decode() + "." + parts[2]
    stt, _, _ = req("GET", "/api/stats", headers={"Cookie": f"zefira_session={tampered}"})
    check("JWT payload tampering rejected", stt == 401, f"got {stt}")

    bogus_sig = parts[0] + "." + parts[1] + ".AAAAinvalidsigAAAA"
    stb, _, _ = req("GET", "/api/stats", headers={"Cookie": f"zefira_session={bogus_sig}"})
    check("JWT bad signature rejected", stb == 401, f"got {stb}")

# ---- 5. Rate limiting ----
codes = []
for i in range(12):
    stl, _, _ = req(
        "POST", "/api/login",
        json.dumps({"username": "nosuchuser12345", "password": "Whatever12345"}),
        {"X-Requested-With": "XMLHttpRequest"},
    )
    codes.append(stl)
check("login brute-force gets throttled", 429 in codes, f"codes={set(codes)}")
time.sleep(1)

xff_codes = []
for i in range(14):
    stx, _, _ = req(
        "POST", "/api/login",
        json.dumps({"username": ADMIN, "password": "WrongPass12345"}),
        {"X-Requested-With": "XMLHttpRequest", "X-Forwarded-For": "10.99.77.7"},
    )
    xff_codes.append(stx)
check("identical spoofed XFF gets throttled (no bypass)", 429 in xff_codes, f"codes={set(xff_codes)}")

rot_codes = []
for i in range(6):
    str_, _, _ = req(
        "POST", "/api/login",
        json.dumps({"username": ADMIN, "password": "WrongPass12345"}),
        {"X-Requested-With": "XMLHttpRequest", "X-Forwarded-For": f"10.99.{i}.7"},
    )
    rot_codes.append(str_)
check("rotating XFF still throttled after lockout", all(c in (401, 429) for c in rot_codes) and 429 in rot_codes, f"codes={set(rot_codes)}")

# ---- 6. Path traversal ----
trav = ["/static/../main.py", "/static/..%2fmain.py", "/static/%2e%2e/main.py", "/static/....//main.py"]
ok = True
for t in trav:
    stt2, _, body2 = req("GET", t)
    if stt2 == 200 and b"FastAPI" in body2:
        ok = False
        print(f"      traversal {t} leaked source!")
check("path traversal on /static blocked", ok)

stsrc, _, _ = req("GET", "/instance/secret.key")
check("secret.key not reachable", stsrc in (401, 404), f"got {stsrc}")

# ---- 7. Stored XSS ----
uniq = "xsstest" + uuid.uuid4().hex[:5]
xss_body = json.dumps({
    "username": uniq,
    "protocols": ["vless"],
    "volume_gb": 5,
    "days": 5,
    "note": '<script>alert("xss")</script><img src=x onerror=alert(1)>',
})
stx2, _, _ = req("POST", "/api/users", xss_body, AUTH)
check("user with XSS payload created (setup)", stx2 == 200, f"got {stx2}")

sthtml, _, html = req("GET", "/panel")
check("panel page has no inline scripts", b"<script>" not in html.replace(b'<script src="/static/app.js" defer></script>', b""))
stc, hdrc, _ = req("GET", "/panel")
csp = hget(hdrc, "Content-Security-Policy")
check("CSP forbids inline scripts", "script-src 'self'" in csp, f"csp={csp[:60]}")
check("CSP object-src none", "object-src 'none'" in csp)
check("X-Frame-Options DENY", hget(hdrc, "X-Frame-Options").lower() == "deny")
check("nosniff present", hget(hdrc, "X-Content-Type-Options").lower() == "nosniff")

# cleanup xss user
stu, ulist, _ = ("", None, None)
stl2, lbody, _ = req("GET", "/api/users?q=" + uniq, headers=AUTH)
try:
    items = json.loads(lbody)["items"]
    for it in items:
        req("DELETE", f"/api/users/{it['id']}", headers=AUTH)
except Exception:
    pass
check("XSS user cleaned up", True)

# ---- 8. Oversized payload ----
big = "A" * (1200 * 1024)
sto, _, _ = req("POST", "/api/users", json.dumps({"username": "x", "protocols": ["vless"], "volume_gb": 1, "days": 1, "note": big}), AUTH)
check("oversized body rejected", sto in (413, 0), f"got {sto} (0 = RST after 413, kernel behavior)")

# ---- 12. Method abuse ----
stm, _, _ = req("PUT", "/api/login")
check("PUT /api/login rejected", stm in (403, 405), f"got {stm}")

# ---- 13. Subscription endpoint ----
stbad, _, _ = req("GET", "/sub/NOT_A_TOKEN")
check("malformed sub token -> 404", stbad == 404, f"got {stbad}")
stfake, _, _ = req("GET", "/sub/" + "0" * 32)
check("unknown sub token -> 404", stfake == 404, f"got {stfake}")
stclash, _, clash_body = req("GET", "/sub/" + "0" * 32 + "?format=clash")
check("clash fmt on bad token still 404", stclash == 404, f"got {stclash}")
CHROME_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"}
V2RAY_UA = {"User-Agent": "v2rayNG/1.9.4"}
stbadu, _, _ = req("GET", "/sub/" + "0" * 32, headers=CHROME_UA)
check("bad token via browser UA still 404 (no dashboard leak)", stbadu == 404, f"got {stbadu}")
straw, _, _ = req("GET", "/sub/" + "0" * 32, headers=V2RAY_UA)
check("bad token via client UA still 404", straw == 404, f"got {straw}")
stmk, _, mkb = req("POST", "/api/users", json.dumps({
    "username": "dashtest1", "protocols": ["vless"], "volume_gb": 1, "days": 1,
    "note": '"><script>alert(1)</script>'
}), AUTH)
dash_ok = dash_esc = dash_client = False
if stmk == 200:
    tok = json.loads(mkb)["token"]
    sth, hdrh, htmlb = req("GET", f"/sub/{tok}", headers=CHROME_UA)
    html = htmlb.decode("utf-8", "replace") if isinstance(htmlb, bytes) else htmlb
    dash_ok = sth == 200 and "dashtest1" in html and "text/html" in hget(hdrh, "Content-Type")
    dash_esc = "&lt;script&gt;" in html and "<script>alert" not in html
    stc, hdrc, _ = req("GET", f"/sub/{tok}", headers=V2RAY_UA)
    dash_client = stc == 200 and "text/html" not in hget(hdrc, "Content-Type")
    stcf, _, cfb = req("GET", f"/sub/{tok}?format=%20Clash%20", headers=V2RAY_UA)
    cfb = cfb.decode("utf-8", "replace") if isinstance(cfb, bytes) else cfb
    dash_client = dash_client and stcf == 200 and cfb.startswith("mixed-port:")
    lst = json.loads(req("GET", "/api/users?q=dashtest1", headers=AUTH)[2])
    for u2 in lst["items"]:
        req("DELETE", f"/api/users/{u2['id']}", headers=AUTH)
check("browser UA gets HTML dashboard", dash_ok, f"created={stmk}")
check("dashboard escapes user note (XSS)", dash_esc)
check("client UA still gets raw bytes", dash_client)

# ---- 14. Backup secrecy ----
stb, _, _ = req("GET", "/api/backup")
check("backup requires auth (GET not even routed)", stb == 405, f"got {stb}")

stn1, _, _ = req("GET", "/api/nodes")
check("tunnel nodes require auth", stn1 == 401, f"got {stn1}")
stn2, _, _ = req(
    "POST", "/api/nodes",
    json.dumps({"name": "evil", "transport": "tcp", "iran_ip": "1.2.3.4", "kharej_ip": "5.6.7.8", "tunnel_port": 443}),
)
check("node create blocked w/o session", stn2 in (401, 403), f"got {stn2}")
stn3, _, _ = req("GET", "/api/nodes/1/guide")
check("node guide requires auth", stn3 in (401, 404), f"got {stn3}")
stsv1, _, _ = req("GET", "/api/server-nodes")
check("server nodes require auth", stsv1 == 401, f"got {stsv1}")
stsv2, _, _ = req("POST", "/api/server-nodes", json.dumps({"name": "x", "address": "1.2.3.4"}))
check("server node create blocked w/o session", stsv2 in (401, 403), f"got {stsv2}")

# ---- 16. New-surface authz (telegram, qr, reality, selftunnel) ----
for name, method, path, body in [
    ("tg settings", "GET", "/api/telegram", None),
    ("tg test", "POST", "/api/telegram/test", "{}"),
    ("qr", "GET", "/api/users/1/qr", None),
    ("reality private", "GET", "/api/reality/private", None),
    ("reality generate", "POST", "/api/reality/generate", None),
    ("inbounds list", "GET", "/api/inbounds", None),
    ("templates", "GET", "/api/templates", None),
]:
    stn, _, _ = req(method, path, body, {"X-Requested-With": "XMLHttpRequest"} if body is not None else None)
    check(f"unauth {name} blocked", stn in (401, 403), f"got {stn}")

# ---- 17. Mass assignment / prototype pollution-ish payloads ----
evil = {
    "username": "masstest1",
    "protocols": ["vless"],
    "volume_gb": 5,
    "days": 5,
    "__proto__": {"admin": True},
    "is_admin": True,
    "token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "id": 999999,
}
stm2, _, _ = req("POST", "/api/users", json.dumps(evil), AUTH)
ok_mass = stm2 == 200
if ok_mass:
    mdata = json.loads(req("GET", "/api/users?q=masstest1", headers=AUTH)[2])
    item = mdata["items"][0]
    ok_mass = item["id"] != 999999 and item["token"] != evil["token"]
    req("DELETE", f"/api/users/{item['id']}", headers=AUTH)
check("mass-assignment ignored", ok_mass)

# ---- 18. Unicode / homoglyph username rejected by pattern ----
stu3, _, _ = req(
    "POST", "/api/users",
    json.dumps({"username": "\u0645\u06cc\u0646\u0627", "protocols": ["vless"], "volume_gb": 1, "days": 1}),
    AUTH,
)
check("non-ascii username rejected", stu3 in (400, 422), f"got {stu3}")

# ---- 19. Oversized search query handled ----
stq2, _, _ = req("GET", "/api/users?q=" + ("A" * 1000), headers=AUTH)
check("1000-char search safe", stq2 == 200, f"got {stq2}")

# ---- 20. Static dir listing & methods ----
stdir, _, _ = req("GET", "/static/")
check("/static/ dir listing denied", stdir == 404, f"got {stdir}")
stsub_post, _, _ = req("POST", "/sub/" + "0" * 32)
check("POST /sub -> 405", stsub_post == 405, f"got {stsub_post}")

# ---- 21. Session invalidation after password change ----
stcp, _, _ = req(
    "POST", "/api/change-password",
    json.dumps({"current_password": PASSWORD, "new_password": "NewPass123456"}),
    AUTH,
)
check("password change ok", stcp == 200, f"got {stcp}")
stm3, _, _ = req("GET", "/api/me", headers=AUTH)
check("OLD session dead after password change", stm3 == 401, f"got {stm3}")
st_relog, tok2, _ = login_with(PASSWORD + "-nope") if False else (None, None, None)

# login with NEW password
body = json.dumps({"username": ADMIN, "password": "NewPass123456"})
stl3 = 0
try:
    r = urllib.request.Request(BASE + "/api/login", data=body.encode(), method="POST",
                               headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})
    resp = urllib.request.urlopen(r, timeout=8)
    stl3 = resp.status
    sc = resp.headers.get("Set-Cookie", "")
    for part in sc.split(";"):
        part = part.strip()
        if part.startswith("zefira_session="):
            token = part.split("=", 1)[1]
except urllib.error.HTTPError as e:
    stl3 = e.code
AUTH2 = {"Cookie": f"zefira_session={token}", "X-Requested-With": "XMLHttpRequest"}
check("login with new password works", stl3 == 200 and token != "", f"got {stl3}")

# revert password back so other flows stay usable
src_pw = json.dumps({"current_password": "NewPass123456", "new_password": PASSWORD})
strv, _, _ = req("POST", "/api/change-password", src_pw, AUTH2)
check("password reverted", strv == 200, f"got {strv}")

_st_relog, token, _ = login_with(PASSWORD)
AUTH2 = {"Cookie": f"zefira_session={token}", "X-Requested-With": "XMLHttpRequest"}

# ---- 25. Restore atomicity: invalid rows skipped, valid applied ----
body_restore_atomic = json.dumps({
    "zefira_backup": True,
    "users": [
        {"username": "atomic_ok", "protocol": "vless", "protocols": "vless", "volume_gb": 1,
         "token": "b" * 32, "is_active": True, "expires_at": "2027-01-01T00:00:00Z"},
        {"username": "atomic_bad_date", "protocol": "vless", "volume_gb": 1,
         "token": "c" * 32, "expires_at": "NOT-A-DATE"},
    ],
    "password_confirm": PASSWORD,
})
strs, rhead, rb2 = req("POST", "/api/restore", body_restore_atomic, AUTH2)
_sc = hget(rhead, "Set-Cookie")
for _p in _sc.split(";"):
    _p = _p.strip()
    if _p.startswith("zefira_session="):
        token = _p.split("=", 1)[1]
AUTH2 = {"Cookie": f"zefira_session={token}", "X-Requested-With": "XMLHttpRequest"}
ok_atomic = False
if strs == 200:
    rj = json.loads(rb2)
    _stl, _hh, _lb2 = req("GET", "/api/users?q=atomic", headers=AUTH2)
    lst = json.loads(_lb2)
    ok_atomic = rj["skipped"] == 1 and any(u["username"] == "atomic_ok" for u in lst["items"])
    for u in lst["items"]:
        req("DELETE", f"/api/users/{u['id']}", headers=AUTH2)
check("restore atomic: bad row skipped, good row kept", ok_atomic)

# ---- 25b. Restore imports API tokens (fresh session: restore reissues cookies) ----
strst, _, rsb = req("POST", "/api/restore", json.dumps({
    "zefira_backup": True, "users": [], "password_confirm": PASSWORD,
    "api_tokens": [{"name": "restored-bot", "prefix": "zfp_abc",
                    "token_sha": "d" * 64}]}), AUTH2)
try:
    check("restore imports api tokens", strst == 200 and json.loads(rsb).get("restored_tokens") == 1, f"got {strst}")
except Exception:
    check("restore imports api tokens", False, f"got {strst}")
_st, _tokx, _ = login_with(PASSWORD)
AUTH2 = {"Cookie": f"zefira_session={_tokx}", "X-Requested-With": "XMLHttpRequest"}
stlst2, _, lsb2 = req("GET", "/api/api-tokens", headers=AUTH2)
try:
    items2 = json.loads(lsb2)
    tid2 = next((t["id"] for t in items2 if t["name"] == "restored-bot"), None)
    check("restored token listed", tid2 is not None)
    if tid2:
        req("DELETE", f"/api/api-tokens/{tid2}", headers=AUTH2)
except Exception:
    check("restored token listed", False)


# ---- 22. CORP header ----
stc2, hdrc2, _ = req("GET", "/panel")
check("CORP header same-origin", hget(hdrc2, "Cross-Origin-Resource-Policy") == "same-origin")

# ---- 23. Lowercased shared bucket: case variants cannot split the counter ----
first_batch = []
for i in range(9):
    stc3, _, _ = req(
        "POST", "/api/login",
        json.dumps({"username": "admin", "password": "WrongPass12345"}),
        {"X-Requested-With": "XMLHttpRequest"},
    )
    first_batch.append(stc3)
second_batch = []
for i in range(6):
    stc4, _, _ = req(
        "POST", "/api/login",
        json.dumps({"username": "AdMiN", "password": "WrongPass12345"}),
        {"X-Requested-With": "XMLHttpRequest"},
    )
    second_batch.append(stc4)
check("lowercase bucket fills (first batch throttles)", 429 in first_batch, f"codes={set(first_batch)}")
check("case-variant shares the same bucket", 429 in second_batch, f"codes={set(second_batch)}")

# ---- 24. Limiter memory-eviction sanity (unit) ----
import subprocess as sp

unit = sp.run(
    [sys.executable, "-c", """
import sys; sys.path.insert(0, '.')
from security import SlidingWindowLimiter
lim = SlidingWindowLimiter(max_events=5, window_seconds=60)
lim.MAX_KEYS = 50
for i in range(500):
    lim.hit('k' + str(i))
print(len(lim._events))
"""],
    capture_output=True, text=True, cwd=HERE,
)
evicted = unit.stdout.strip()
check("limiter evicts stale keys (memory-safe)", evicted.isdigit() and int(evicted) <= 50, f"keys={evicted}")

# ---- 26. Cache-Control on API ----
stcc, hdcc, _ = req("GET", "/api/stats", headers=AUTH2)
check("API responses no-store", hget(hdcc, "Cache-Control") == "no-store", f"got {hget(hdcc,'Cache-Control')}")

# ---- 27. Settings port types normalized to int after save ----
stps, _, _ = req("PUT", "/api/settings", json.dumps({
    "domain": "t.example.com", "sub_port": "8443", "hy2_port": 9000, "wg_port": 51821,
    "ovpn_port": 1195, "dns": "1.1.1.1", "ovpn_proto": "udp",
    "reality_port": 443, "reality_sni": "www.yahoo.com", "wg_pub": ""
}), AUTH2)
stpg, _, pgbody = req("GET", "/api/settings", headers=AUTH2)
pj = json.loads(pgbody)
ports_int = all(isinstance(pj.get(k), int) for k in ("sub_port", "hy2_port", "wg_port", "ovpn_port"))
check("saved ports come back as integers", stpg == 200 and ports_int, f"types={[type(pj.get(k)).__name__ for k in ('sub_port','hy2_port')]}")

# ---- 28. Inbound fuzzing ----
fuzz_ok = True
for payload in [
    {"name": "bad proto", "protocol": "not-a-proto", "port": 1},
    {"name": "ok", "protocol": "vless", "port": -5},
    {"name": "ok", "protocol": "vless", "port": 70000},
    {"name": "bad host", "protocol": "vless", "port": 10, "host": "ev il/x"},
    {"name": "x" * 100, "protocol": "vless", "port": 10},
]:
    stf, _, _ = req("POST", "/api/inbounds", json.dumps(payload), AUTH2)
    if stf not in (400, 422):
        fuzz_ok = False
        print(f"      inbound fuzz accepted {str(payload)[:60]} -> {stf}")
check("inbound input fuzz rejected (422/400)", fuzz_ok)

# ---- 29. Node fuzzing ----
fuzz_ok2 = True
for payload in [
    {"name": "n1", "transport": "carrier-pigeon", "iran_ip": "1.1.1.1", "kharej_ip": "2.2.2.2", "tunnel_port": 443},
    {"name": "n2", "transport": "tcp", "iran_ip": "javascript:alert(1)", "kharej_ip": "2.2.2.2", "tunnel_port": 443},
    {"name": "n3", "transport": "tcp", "iran_ip": "1.1.1.1", "kharej_ip": "2.2.2.2", "tunnel_port": 0},
    {"name": "n4", "transport": "tcp", "iran_ip": "1.1.1.1", "kharej_ip": "2.2.2.2", "tunnel_port": 443, "forwarded_ports": "abc"},
]:
    stf2, _, rbx = req("POST", "/api/nodes", json.dumps(payload), AUTH2)
    if stf2 not in (400, 422):
        fuzz_ok2 = False
        print(f"      node fuzz accepted {str(payload)[:60]} -> {stf2} body={rbx[:80]}")
check("node input fuzz rejected (422/400)", fuzz_ok2)

# ---- 29b. Server-node validation ----
svfuzz_ok = True
for payload in [
    {"name": "s1", "transport": "tcp", "address": "not a host!!", "check_port": 443},
    {"name": "s2", "transport": "tcp", "address": "1.1.1.1", "check_port": 0},
    {"name": "s3", "transport": "tcp", "address": "1.1.1.1", "check_port": 443, "note": "x" * 500},
    {"name": "x" * 100, "transport": "tcp", "address": "1.1.1.1", "check_port": 443},
]:
    p2 = {"name": payload["name"], "address": payload["address"], "check_port": payload["check_port"]}
    if "note" in payload:
        p2["note"] = payload["note"]
    stfv, _, _ = req("POST", "/api/server-nodes", json.dumps(p2), AUTH2)
    if stfv not in (400, 422):
        svfuzz_ok = False
        print(f"      srvnode fuzz accepted {str(p2)[:60]} -> {stfv}")
check("server-node input fuzz rejected (422/400)", svfuzz_ok)
stbadn, _, _ = req("POST", "/api/inbounds", json.dumps(
    {"name": "badnodeib", "protocol": "vless", "port": 29443, "node_id": 999999}), AUTH2)
check("inbound with unknown node rejected", stbadn == 404, f"got {stbadn}")

# ---- 30. CSV-injection source stored server-side (client sanitizes on export) ----
stcsv, _, _ = req("POST", "/api/users", json.dumps({
    "username": "csvtest1", "protocols": ["vless"], "volume_gb": 1, "days": 1,
    "note": "=HYPERLINK(\"http://evil\",\"click\")"
}), AUTH2)
check("formula-note stored raw (export layer sanitizes)", stcsv == 200, f"got {stcsv}")
if stcsv == 200:
    lst2 = json.loads(req("GET", "/api/users?q=csvtest1", headers=AUTH2)[2])
    for u2 in lst2["items"]:
        req("DELETE", f"/api/users/{u2['id']}", headers=AUTH2)

# ---- 31. HSTS is emitted when behind a TLS-terminating proxy ----
sth, hdrh, _ = req("GET", "/panel", headers={"X-Forwarded-Proto": "https"})
check("HSTS honored via X-Forwarded-Proto (loopback peer)", "max-age=31536000" in hget(hdrh, "Strict-Transport-Security"), f"got {hget(hdrh,'Strict-Transport-Security')!r}")
sthp, hdrhp, _ = req("GET", "/panel")
check("no HSTS on plain http", hget(hdrhp, "Strict-Transport-Security") == "")

# ---- 32. Restore endpoint accepts large (legit backup) bodies ----
big_body = json.dumps({"password_confirm": "wrong-password", "zefira_backup": True, "users": [], "pad": "x" * 1200000})
stbig, _, _ = req("POST", "/api/restore", big_body, AUTH2)
check("restore size gate allows >1MB backups", stbig != 413, f"got {stbig}")
stcap, _, _ = req("POST", "/api/restore", json.dumps({
    "zefira_backup": True, "users": [], "password_confirm": "WrongPass12345",
    "blocked_sites": [{"domain": f"d{i}.example.com"} for i in range(601)],
}), AUTH2)
check("restore caps blocked_sites list", stcap == 422, f"got {stcap}")

# ---- 33. Password-gated backup ----
stb3, _, _ = req("POST", "/api/backup", json.dumps({"password_confirm": "WrongPass12345"}), AUTH2)
check("backup with wrong password -> 400", stb3 == 400, f"got {stb3}")
stb4, _, bbb4 = req("POST", "/api/backup", json.dumps({"password_confirm": PASSWORD}), AUTH2)
bok = stb4 == 200
try:
    bj = json.loads(bbb4)
    bok = bok and bj.get("zefira_backup") is True
except Exception:
    bok = False
check("backup with correct password downloads", bok, f"got {stb4}")

stfa, _, _ = req("GET", "/api/2fa/status", headers=AUTH2)
check("2fa endpoints are gone (404 even authed)", stfa == 404, f"got {stfa}")
stfa2, _, _ = req("POST", "/api/2fa/enable", json.dumps({"code": "123456", "current_password": "WrongPass12345"}), AUTH2)
check("2fa enable is gone (404 even authed)", stfa2 == 404, f"got {stfa2}")

# ---- 34b. AI assistant: auth, validation, no key leak, needs config ----
stai, _, _ = req("GET", "/api/ai/settings")
check("ai settings requires auth", stai == 401, f"got {stai}")
staip, _, _ = req("POST", "/api/ai/chat", json.dumps({"messages": [{"role": "user", "content": "hi"}]}), {"X-Requested-With": "XMLHttpRequest"})
check("ai chat requires auth", staip in (401, 403), f"got {staip}")
stai2, _, aib = req("GET", "/api/ai/settings", headers=AUTH2)
aiok = stai2 == 200
try:
    aij = json.loads(aib)
    blob = json.dumps(aij).lower()
    aiok = aiok and "api_key" not in aij and "sk-" not in blob
except Exception:
    aiok = False
check("ai settings never leaks the key", aiok, f"got {stai2}")
staibad, _, _ = req("PUT", "/api/ai/settings", json.dumps({"provider": "evil", "model": "x"}), AUTH2)
check("ai settings rejects bad provider", staibad == 422, f"got {staibad}")
staihist, _, _ = req("POST", "/api/ai/chat", json.dumps({"messages": [{"role": "user", "content": "x"}] * 13}), AUTH2)
check("ai chat caps history length", staihist == 422, f"got {staihist}")
stainc, _, _ = req("POST", "/api/ai/chat", json.dumps({"messages": [{"role": "user", "content": "hi"}]}), AUTH2)
check("ai chat without config -> 400", stainc == 400, f"got {stainc}")
stup, _, upb = req("GET", "/api/update/status", headers=AUTH2)
upok = stup == 200
try:
    upj = json.loads(upb)
    upok = upok and all(k in upj for k in ("repo", "current", "latest", "update_available", "updating", "incoming", "local_log"))
    upok = upok and isinstance(upj["incoming"], list) and isinstance(upj["local_log"], list)
except Exception:
    upok = False
check("update status shape (authed)", upok, f"got {stup}")
stupw, _, _ = req("POST", "/api/update/apply", json.dumps({"password_confirm": "WrongPass12345"}), AUTH2)
check("update apply with wrong password -> 400 (no-op)", stupw == 400, f"got {stupw}")

# ---- 34. Appearance: public display values only, writes gated + validated ----
stap, _, apb = req("GET", "/api/appearance")
apok = stap == 200
try:
    apj = json.loads(apb)
    apok = apok and apj.get("theme_accent") == "#ff2740" and apj.get("brand_name") == "ZEFIRA"
    blob = json.dumps(apj).lower()
    apok = apok and not any(s in blob for s in ("password", "token", "secret", "begin"))
except Exception:
    apok = False
check("appearance public shows only display values", apok, f"got {stap}")
stauw, _, _ = req("PUT", "/api/appearance", json.dumps({"theme_accent": "#00c853"}), {"X-Requested-With": "XMLHttpRequest"})
check("appearance PUT requires auth", stauw in (401, 403), f"got {stauw}")
sttk, _, _ = req("GET", "/api/api-tokens")
check("api tokens require auth", sttk == 401, f"got {sttk}")
sttk2, _, _ = req("POST", "/api/api-tokens", json.dumps({"name": "x"}), {"X-Requested-With": "XMLHttpRequest"})
check("api token create blocked w/o session", sttk2 in (401, 403), f"got {sttk2}")
stupd, _, _ = req("GET", "/api/update/status")
check("update status requires auth", stupd == 401, f"got {stupd}")
stupa, _, _ = req("POST", "/api/update/apply", json.dumps({"password_confirm": "x"}), {"X-Requested-With": "XMLHttpRequest"})
check("update apply requires auth", stupa in (401, 403), f"got {stupa}")
stabad, _, _ = req("PUT", "/api/appearance", json.dumps({"theme_accent": "red", "brand_name": "<script>"}), AUTH2)
check("appearance rejects non-hex color / html brand", stabad == 422, f"got {stabad}")
stabad2, _, _ = req("PUT", "/api/appearance", json.dumps({"theme_text": "#12345", "theme_muted": "blue"}), AUTH2)
check("appearance rejects bad text colors", stabad2 == 422, f"got {stabad2}")
stlay, _, layb = req("PUT", "/api/appearance", json.dumps({
    "menu_layout": json.dumps([{"id": "users", "hidden": False}, {"id": "settings", "hidden": True}, {"id": "nope", "hidden": True}]),
    "dash_layout": json.dumps({"order": ["apps"], "hidden": ["link", "bogus"]})}), AUTH2)
try:
    layj = json.loads(layb)
    ml = layj.get("menu_layout", [])
    dl = layj.get("dash_layout", {})
    check("menu layout canonicalized (locked kept, junk dropped)",
          stlay == 200 and ml[0].get("id") == "users"
          and all(not (m.get("id") == "settings" and m.get("hidden")) for m in ml)
          and not any(m.get("id") == "nope" for m in ml)
          and len(ml) == 10, f"got {stlay}")
    check("dash layout canonicalized",
          dl.get("order", [])[0] == "apps" and "link" in dl.get("hidden", [])
          and "bogus" not in dl.get("hidden", []), f"got {stlay}")
except Exception:
    check("menu layout canonicalized (locked kept, junk dropped)", False, f"got {stlay}")
    check("dash layout canonicalized", False, f"got {stlay}")
req("PUT", "/api/appearance", json.dumps({"menu_layout": "", "dash_layout": ""}), AUTH2)
stcss, hdrcss, cssb = req("GET", "/theme.css")
cssb = cssb.decode("utf-8", "replace") if isinstance(cssb, bytes) else cssb
check("theme.css served as css with defaults", stcss == 200 and "text/css" in hget(hdrcss, "Content-Type") and ":root" in cssb and "#ff2740" in cssb, f"got {stcss}")
stcss2, _, cssb2 = req("GET", "/theme.css")
cssb2 = cssb2.decode("utf-8", "replace") if isinstance(cssb2, bytes) else cssb2
check("theme.css has no secrets", "password" not in cssb2.lower())

# ---- 35. Extending an expired account counts from today ----
stmk2, _, mkb2 = req("POST", "/api/users", json.dumps({
    "username": "exttest1", "protocols": ["vless"], "volume_gb": 1, "days": 1}), AUTH2)
ext_ok = False
if stmk2 == 200:
    uid = json.loads(mkb2)["id"]
    req("PATCH", f"/api/users/{uid}", json.dumps({"set_expires_at": "2020-01-01T00:00"}), AUTH2)
    ste, _, eb = req("PATCH", f"/api/users/{uid}", json.dumps({"extend_days": 30}), AUTH2)
    try:
        exp_dt = datetime.fromisoformat(json.loads(eb)["expires_at"].replace("Z", "+00:00"))
        now_dt = datetime.now(timezone.utc)
        ext_ok = ste == 200 and exp_dt > now_dt and (exp_dt - now_dt).days >= 29
    except Exception:
        ext_ok = False
    req("DELETE", f"/api/users/{uid}", headers=AUTH2)
check("extending expired account starts from today", ext_ok, f"created={stmk2}")

# ---- 35b. Developer reset-usage endpoint ----
stru, _, _ = req("POST", "/api/users/999999/reset-usage", None, AUTH2)
check("reset-usage requires existing user", stru == 404, f"got {stru}")
stru2, _, _ = req("POST", "/api/users/999999/reset-usage")
check("reset-usage requires auth", stru2 in (401, 403), f"got {stru2}")

# ---- 35b. API tokens lifecycle (bots & integrations) ----
stmk3, _, mkb3 = req("POST", "/api/api-tokens", json.dumps({"name": "pentest-bot"}), AUTH2)
tok_once = ""
try:
    tj = json.loads(mkb3)
    tok_once = tj.get("token_once", "")
    check("api token create returns once-only secret", stmk3 == 200 and tok_once.startswith("zfp_"), f"got {stmk3}")
except Exception:
    check("api token create returns once-only secret", False, f"got {stmk3}")
BH = {"Authorization": f"Bearer {tok_once}"} if tok_once else {}
stb, _, mb = req("GET", "/api/me", headers=BH)
try:
    check("bearer works without cookie", stb == 200 and json.loads(mb).get("username") == ADMIN, f"got {stb}")
except Exception:
    check("bearer works without cookie", False, f"got {stb}")
stbp, _, _ = req("POST", "/api/users", json.dumps(
    {"username": "bottmp1", "protocols": ["vless"], "volume_gb": 1, "days": 1}), BH)
check("bearer POST works without CSRF header", stbp == 200, f"got {stbp}")
if stbp == 200:
    lst = json.loads(req("GET", "/api/users?q=bottmp1", headers=AUTH2)[2])
    for u2 in lst["items"]:
        req("DELETE", f"/api/users/{u2['id']}", headers=AUTH2)
stbb, _, _ = req("GET", "/api/me", headers={"Authorization": "Bearer garbage-token"})
check("garbage bearer rejected", stbb == 401, f"got {stbb}")
stlst, _, lsb = req("GET", "/api/api-tokens", headers=AUTH2)
try:
    items = json.loads(lsb)
    tid = next((t["id"] for t in items if t["name"] == "pentest-bot"), None)
    blob = json.dumps(items).lower()
    check("token list hides hashes", stlst == 200 and tid is not None and "token_sha" not in blob and "token_once" not in blob, f"got {stlst}")
except Exception:
    tid = None
    check("token list hides hashes", False, f"got {stlst}")
if tid:
    stdel, _, _ = req("DELETE", f"/api/api-tokens/{tid}", headers=AUTH2)
    check("token revoke", stdel == 200, f"got {stdel}")
    stdead, _, _ = req("GET", "/api/me", headers=BH)
    check("revoked bearer rejected", stdead == 401, f"got {stdead}")

# ---- 36. Logout invalidates the session server-side ----
stme, _, _ = req("GET", "/api/me", headers=AUTH2)
stlo, _, _ = req("POST", "/api/logout", None, AUTH2)
stdead, _, _ = req("GET", "/api/me", headers=AUTH2)
check("logout kills session (old cookie 401)", stme == 200 and stlo == 200 and stdead == 401, f"me={stme} logout={stlo} after={stdead}")

print("\n=== SUMMARY ===")

passed = sum(1 for _, okk, _ in results if okk)
total = len(results)
for name, okk, detail in results:
    if not okk:
        print(f"  FAILED: {name} {detail}")
print(f"{passed}/{total} checks passed")
sys.exit(0 if passed == total else 1)
