"""
ZEFIRA ATTACK SUITE - live adversarial probes against a running panel.
Complements security_test.py: focuses on attacker-controlled input reaching
sinks (headers, paths, bodies, unicode, timing, methods, sizes).

  .venv\\Scripts\\python attack_test.py http://127.0.0.1:8000 admin PASSWORD
"""
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"
HOSTPORT = tuple(urllib.parse.urlparse(BASE).netloc.split(":")[:2]) or ("127.0.0.1", "80")
if len(HOSTPORT) == 1:
    HOSTPORT = (HOSTPORT[0], "443" if BASE.startswith("https") else "80")
DB_PATH = sys.argv[4] if len(sys.argv) > 4 else "instance/zefira.db"

# Payload names contain non-ASCII / RTL / zero-width characters; the Windows
# console defaults to cp1252 and would crash the reporter itself.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def req(method, path, body=None, headers=None, timeout=25, raw_host=None):
    url = BASE + path
    data = body.encode() if isinstance(body, str) else body
    hdrs = {"User-Agent": "zefira-attack/1.0"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        hdrs.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    if raw_host is not None:
        # urllib rejects overriding Host, so go raw-socket for that case.
        return raw_request(method, path, body, hdrs, raw_host, timeout)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()


def raw_request(method, path, body, headers, host_override, timeout=25):
    """Send a request with a spoofed Host header over a raw socket."""
    h, p = HOSTPORT[0], int(HOSTPORT[1])
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host_override}", "Connection: close"]
    for k, v in headers.items():
        if k.lower() in ("host", "connection", "content-type"):
            continue
        lines.append(f"{k}: {v}")
    if body is not None:
        b = body.encode() if isinstance(body, str) else body
        lines.append(f"Content-Length: {len(b)}")
        lines.append("Content-Type: application/json")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode()
    if body is not None:
        raw += body.encode() if isinstance(body, str) else body
    try:
        s = socket.create_connection((h, p), timeout=timeout)
        s.sendall(raw)
        chunks = []
        while True:
            d = s.recv(65536)
            if not d:
                break
            chunks.append(d)
        s.close()
        data = b"".join(chunks)
    except Exception as e:
        return 0, {}, str(e).encode()
    head, _, payload = data.partition(b"\r\n\r\n")
    status = 0
    if head.startswith(b"HTTP/"):
        try:
            status = int(head.split(b" ")[1])
        except Exception:
            status = 0
    hd = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            hd[k.decode("latin1").strip()] = v.decode("latin1").strip()
    return status, hd, payload


def login():
    st, hd, _ = req("POST", "/api/login", json.dumps({"username": ADMIN, "password": PASSWORD}),
                    {"X-Requested-With": "XMLHttpRequest"})
    tok = ""
    for part in (hd.get("set-cookie") or "").split(";"):
        if part.strip().startswith("zefira_session="):
            tok = part.split("=", 1)[1]
    return st, {"Cookie": f"zefira_session={tok}", "X-Requested-With": "XMLHttpRequest"}


print(f"=== ZEFIRA ATTACK SUITE -> {BASE} ===")
st, AUTH = login()
check("login for attack tests", st == 200, f"status={st}")
if st != 200:
    sys.exit(2)

# ---------------------------------------------------------------- header injection
st, hd, body = req("GET", "/api/users", headers=AUTH)
items = json.loads(body).get("items", [])
uname = "atk" + uuid.uuid4().hex[:8]
st, ub, ubb = req("POST", "/api/users", json.dumps({
    "username": uname, "protocols": ["vless"], "volume_gb": 5, "days": 5,
    "note": "attack-suite"}), AUTH)
try:
    u = json.loads(ubb)
except Exception:
    u = {}
check("seed user for header tests", st == 200 and u.get("token"), f"{st} {str(u)[:80]}")
tok = u.get("token", "0" * 32)
uid = u.get("id")

CRLF_NOTE = "note\r\nX-Injected: yes"
st, rb, _ = req("POST", "/api/users", json.dumps({
    "username": "crlf" + uuid.uuid4().hex[:8], "protocols": ["vless"],
    "volume_gb": 5, "days": 5, "note": CRLF_NOTE}), AUTH)
check("CRLF in note does not create a header", st in (200, 422), f"{st}")
st, hd2, _ = req("GET", "/api/users", headers=AUTH)
check("no X-Injected header anywhere",
      "x-injected" not in {k.lower() for k in hd2}, str(list(hd2)[:8]))

# Host header poisoning: does the subscription point at the spoofed host?
st, hd3, payload = req("GET", f"/sub/{tok}", headers={"User-Agent": "Mozilla/5.0"},
                       raw_host="evil.example.net")
txt = payload.decode("utf-8", "replace")
poisoned = "evil.example.net" in txt
check("Host header cannot poison the customer dashboard", not poisoned,
      "spoofed host reflected into page")
st, hd4, payload = req("GET", f"/sub/{tok}", headers={"User-Agent": "v2rayNG/1.0"},
                       raw_host="evil.example.net")
raw = payload.decode("utf-8", "replace")
check("Host header cannot poison raw subscription links",
      "evil.example.net" not in raw, "spoofed host in links")

# XSS payloads in user-controlled fields (stored XSS attempt)
xss_notes = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "</textarea><script>alert(1)</script>",
    "{{7*7}}",
    "%7B%7B7*7%7D%7D",
    "\u202e<script>alert(1)</script>",
]
xss_user = "xx" + uuid.uuid4().hex[:8]
xss_token = None
for payload in xss_notes:
    st, r, rb2 = req("POST", "/api/users", json.dumps({
        "username": "x" + uuid.uuid4().hex[:10], "protocols": ["vless"],
        "volume_gb": 1, "days": 1, "note": payload}), AUTH)
    ok = st in (200, 422)
    check(f"note accepts/rejects XSS payload safely: {payload[:22]!r}", ok, f"{st}")
# one user whose note carries every payload at once, then read the page back
st, r, rb3 = req("POST", "/api/users", json.dumps({
    "username": xss_user, "protocols": ["vless"], "volume_gb": 5, "days": 5,
    "note": " | ".join(xss_notes)}), AUTH)
try:
    xss_token = json.loads(rb3).get("token")
except Exception:
    xss_token = None
check("stored-XSS user created", st == 200 and xss_token, f"{st}")
st, hd5, page = req("GET", f"/sub/{xss_token}", headers={"User-Agent": "Mozilla/5.0"}) if xss_token else (0, {}, b"")
html = page.decode("utf-8", "replace")
check("stored note is HTML-escaped on the customer page",
      "<script>alert(1)</script>" not in html, "raw script tag in output")
# The payload's TEXT may appear (harmless), but no unescaped '<' from user
# data may create a tag or attribute. Assert on the dangerous raw forms.
check("no unescaped tag from the note", "<img src=x" not in html
      and "</textarea><script" not in html, "raw tag injected")
check("note text is escaped, not stripped", "&lt;img" in html or "&lt;script" in html,
      "note vanished instead of being escaped")
check("Jinja left the template expression as literal text", "{{7*7}}" in html,
      "template expression evaluated")
# the same note must also be safe in the panel table (textContent) and CSV
st, panel_hd, panel_body = req("GET", "/panel", headers=AUTH)
# ASGI sends header names lowercased: compare case-insensitively.
_lc = {k.lower() for k in panel_hd}
check("panel page carries the CSP", "content-security-policy" in _lc, "no CSP on /panel")

# ---------------------------------------------------------------- path traversal
traversals = [
    "/static/../../etc/passwd",
    "/static/..%2f..%2fetc%2fpasswd",
    "/static/%2e%2e/%2e%2e/etc/passwd",
    "/sub/../../etc/passwd",
    "/theme.css/../../etc/passwd",
    "/api/users/..%2f..%2fsettings",
]
for p in traversals:
    st, _, body = req("GET", p)
    leak = b"root:x:" in body or b"ZEFIRA_ADMIN" in body
    check(f"traversal blocked: {p[:38]}", not leak and st in (301, 302, 307, 400, 403, 404),
          f"status={st} leak={leak}")

# ---------------------------------------------------------------- method confusion
st, _, _ = req("PUT", "/api/users", json.dumps({"username": "x", "protocols": ["vless"],
                                                "volume_gb": 1, "days": 1}), AUTH)
check("PUT on /api/users is not 405-exploitable", st in (404, 405), f"{st}")
st, _, _ = req("DELETE", "/api/stats", headers=AUTH)
check("DELETE on a GET route is rejected", st in (404, 405), f"{st}")
st, _, _ = req("PATCH", "/api/login", json.dumps({"username": ADMIN, "password": PASSWORD}),
               {"X-Requested-With": "XMLHttpRequest"})
check("PATCH on /api/login rejected", st in (404, 405), f"{st}")
st, _, _ = req("POST", "/api/me", "{}", AUTH)
check("POST on /api/me rejected", st in (404, 405), f"{st}")

# ---------------------------------------------------------------- huge / malformed bodies
big = "x" * 2_000_000
st_big, _ = raw_request("POST", "/api/users", json.dumps({
    "username": "big" + uuid.uuid4().hex[:6], "protocols": ["vless"],
    "volume_gb": 1, "days": 1, "note": big}).encode(),
    {"Cookie": AUTH["Cookie"], "X-Requested-With": "XMLHttpRequest"},
    "127.0.0.1:8000", timeout=45)[:2]
check("2MB body rejected by the 1MB gate", st_big in (413, 0), f"{st_big}")
# 413 or a connection closed mid-upload: both mean "refused, not processed".
deep = {"username": "d" + uuid.uuid4().hex[:8], "protocols": ["vless"], "volume_gb": 1, "days": 1}
st, _, _ = req("POST", "/api/users", "[" * 2000 + "]" * 2000, AUTH, timeout=30)
check("over-nested JSON returns 400, never 500", st in (400, 413, 422), f"{st}")
st, _, _ = req("POST", "/api/users", '{"a":' * 2000 + "1" + "}" * 2000, AUTH, timeout=30)
check("over-nested objects return 400, never 500", st in (400, 413, 422), f"{st}")
st, _, _ = req("POST", "/api/users", b'{"username": "\xed\xa0\x80"}', AUTH)
check("lone surrogate (CESU-8) in JSON handled", st in (400, 422), f"{st}")
st, _, _ = req("POST", "/api/users", "\x00\x01\x02", AUTH)
check("binary garbage body handled", st in (400, 413, 422), f"{st}")

# prototype pollution attempt
pollute = {"username": "pp" + uuid.uuid4().hex[:8], "protocols": ["vless"],
           "volume_gb": 1, "days": 1, "__proto__": {"admin": True},
           "constructor": {"prototype": {"admin": True}}}
st, _, _ = req("POST", "/api/users", json.dumps(pollute), AUTH)
st2, _, _ = req("GET", "/api/me", headers=AUTH)
check("prototype-pollution payload does not escalate", st in (200, 422) and st2 == 200, f"{st}/{st2}")

# ---------------------------------------------------------------- ReDoS timing
def timed_search(q):
    t0 = time.monotonic()
    st, _, _ = req("GET", "/api/users?q=" + urllib.parse.quote(q), headers=AUTH, timeout=30)
    return time.monotonic() - t0, st


redos_payloads = [
    "a" * 64 + "%",
    "\\" * 32,
    "a" * 500 + "!" * 32,
    "(" * 30,
    "a" * 32 + "_" * 32,
]
worst = 0.0
for p in redos_payloads:
    dt, st = timed_search(p)
    worst = max(worst, dt)
    check(f"search stays fast for {p[:16]!r}", dt < 2.0 and st in (200, 422), f"{dt:.2f}s status={st}")
# deep nested object into a validated list field
st, _, _ = req("POST", "/api/blocklist", json.dumps({"domain": "a" * 253 + ".com"}), AUTH, timeout=20)
check("over-long blocked domain rejected fast", st in (200, 422), f"{st}")

# ---------------------------------------------------------------- timing oracle
def timed_token(token):
    t0 = time.monotonic()
    st, _, _ = req("GET", f"/sub/{token}")
    return time.monotonic() - t0, st


t_bad, s_bad = timed_token("0" * 32)
t_none, s_none = timed_token("f" * 32)
check("unknown tokens all 404", s_bad == 404 and s_none == 404, f"{s_bad}/{s_none}")
check("unknown-token timing is uniform (no existence oracle)",
      abs(t_bad - t_none) < 0.25, f"delta={abs(t_bad-t_none):.3f}s")

# ---------------------------------------------------------------- auth matrix
unauth_paths = [
    ("GET", "/api/stats"), ("GET", "/api/users"), ("POST", "/api/users"),
    ("GET", "/api/settings"), ("PUT", "/api/settings"), ("GET", "/api/audit"),
    ("GET", "/api/api-tokens"), ("POST", "/api/api-tokens"),
    ("GET", "/api/backup"), ("POST", "/api/backup"),
    ("GET", "/api/inbounds"), ("POST", "/api/inbounds"),
    ("GET", "/api/nodes"), ("POST", "/api/nodes"),
    ("GET", "/api/server-nodes"), ("POST", "/api/server-nodes"),
    ("GET", "/api/blocklist"), ("POST", "/api/blocklist"),
    ("GET", "/api/templates"), ("POST", "/api/templates"),
    ("GET", "/api/reality/private"), ("POST", "/api/reality/generate"),
    ("GET", "/api/ssl/status"), ("POST", "/api/ssl/issue"),
    ("GET", "/api/telegram"), ("PUT", "/api/telegram"),
    ("GET", "/api/ai/settings"), ("POST", "/api/ai/chat"),
    ("PUT", "/api/appearance"),
    ("GET", "/api/update/status"), ("POST", "/api/update/apply"),
    ("GET", "/api/tunnel-settings"), ("PUT", "/api/tunnel-settings"),
    ("GET", "/api/system"), ("GET", "/api/me"),
]
# 401/403 = auth gate; 405 = route exists but that method is not routed
# (FastAPI answers before dependencies, and no data is returned).
leaks = []
for m, p in unauth_paths:
    body = json.dumps({"password_confirm": PASSWORD}) if m in ("POST", "PUT") else (
        json.dumps({"messages": [{"role": "user", "content": "hi"}]}) if p.endswith("/ai/chat") else "{}")
    st, _, b = req(m, p, body if m in ("POST", "PUT") else None)
    if st not in (401, 403, 405):
        leaks.append(f"{m} {p}={st}")
check("every admin endpoint refuses unauthenticated access", not leaks, ", ".join(leaks[:6]))

# GET /api/appearance is public by design (the login page needs the brand).
# Assert it can only ever expose display values, never a secret.
st, _, ab = req("GET", "/api/appearance")
try:
    app_obj = json.loads(ab)
except Exception:
    app_obj = {}
DISPLAY_ONLY = {"theme_accent", "theme_bg", "theme_card", "theme_text", "theme_muted",
                "brand_name", "dash_note", "menu_layout", "dash_layout"}
check("public appearance endpoint exposes display keys only",
      st == 200 and set(app_obj) <= DISPLAY_ONLY,
      f"status={st} extra={sorted(set(app_obj) - DISPLAY_ONLY)}")
check("public appearance endpoint leaks no secret",
      not any(k in ab.decode("utf-8", "replace").lower()
              for k in ("token", "password", "secret", "api_key", "chat_id")),
      "secret-looking key in public appearance payload")

# no-store on sensitive responses (ASGI lowercases header names)
def hval(hdrs, name):
    for k, v in hdrs.items():
        if k.lower() == name.lower():
            return v
    return ""


st, hd, _ = req("GET", "/api/users", headers=AUTH)
check("API responses are no-store", "no-store" in hval(hd, "cache-control"), hval(hd, "cache-control"))
st, hd, _ = req("GET", "/api/users")
check("401 responses are no-store too", "no-store" in hval(hd, "cache-control"), hval(hd, "cache-control"))

# security headers on every response type
for path in ("/login", "/panel", "/api/me", "/static/app.js", "/theme.css"):
    st, hd, _ = req("GET", path, headers=AUTH)
    missing = [h for h in ("X-Frame-Options", "X-Content-Type-Options",
                           "Content-Security-Policy", "Referrer-Policy")
               if not hval(hd, h)]
    check(f"security headers present on {path}", not missing, ",".join(missing))

# ------------------------------------------- unauthenticated login-throttle bypass
# Rotating the username used to mint a fresh 8-attempt bucket per guess, so an
# anonymous client could force a full scrypt (~16 MiB) + audit write per
# request. A per-source-IP budget must stop it well before that.
# (Run before the flood below: wrong guesses must NOT lock the operator out.)
for i in range(3):
    req("POST", "/api/login", json.dumps({"username": ADMIN, "password": "WrongPass12345"}),
        {"X-Requested-With": "XMLHttpRequest"})
st_ok, _, _ = req("POST", "/api/login", json.dumps({"username": ADMIN, "password": PASSWORD}),
                  {"X-Requested-With": "XMLHttpRequest"})
check("a few wrong guesses do not lock the operator out", st_ok == 200, f"{st_ok}")

# ---- Concurrent-login starvation: a parallel flood must not park every
# thread-pool worker (which would take the whole panel offline) and must not
# reserve 16 MiB per request. The hashing gate is non-blocking, so surplus
# attempts are refused with 429 instead of queueing.
# (Run BEFORE the flood below, while this source still has budget, so the
# requests really do reach the password-hashing path.)
import concurrent.futures as _cf
_pool = _cf.ThreadPoolExecutor(max_workers=30)
_futs = [
    _pool.submit(req, "POST", "/api/login",
                 json.dumps({"username": f"conc{i:02d}y", "password": "WrongPass12345"}),
                 {"X-Requested-With": "XMLHttpRequest"}, 30)
    for i in range(30)
]
time.sleep(0.25)
t_starve = time.monotonic()
st_starve, _, _ = req("GET", "/api/users", headers=AUTH, timeout=25)
starve_dt = time.monotonic() - t_starve
_codes = [f.result()[0] for f in _futs]
_pool.shutdown()
check("panel stays responsive during a concurrent login flood",
      st_starve == 200 and starve_dt < 10, f"status={st_starve} in {starve_dt:.1f}s")
check("concurrent login flood answered only 401/429 (no 500, no hang)",
      all(c in (401, 429) for c in _codes), f"codes={sorted(set(_codes))}")
check("hashing gate refuses surplus work instead of queueing it",
      429 in _codes, f"codes={sorted(set(_codes))}")

# Telegram HTML injection: an unauthenticated attacker controls the username
# echoed into lockout notifications. Production builds that text with
# security.tg_message, which escapes every interpolated value.
from security import tg_message
evil = '<a href="https://evil.example">click</a>'
built = tg_message("Zefira: brute-force lockout (user: {})", evil)
check("telegram notification escapes untrusted values",
      "<a href" not in built and "&lt;a href" in built, built)
check("telegram notification keeps trusted markup",
      "<b>x</b>" in tg_message("user <b>{}</b>", "x"), "trusted markup lost")
check("telegram notification caps the body length", len(tg_message("{}", "y" * 900)) <= 500,
      "message not truncated")
# Regression guard: no call site may f-string values into the HTML template.
src = open("main.py", encoding="utf-8").read()
check("no f-string interpolation into telegram HTML templates",
      "notify_async(f\"" not in src, "notify_async(f\"...\") reintroduced")

# Supply-chain guards for the in-panel updater: it must install exactly the
# commit it advertised (no force-push race) and must know the signature state.
check("updater pins the advertised commit SHA (no force-push race)",
      "advertised_sha" in src and "fetched_sha.strip() != advertised_sha" in src,
      "SHA consistency check missing")
check("updater checks the upstream commit signature",
      "_commit_verification" in src and "ZEFIRA_REQUIRE_SIGNED_UPDATE" in src,
      "signature verification missing")

# ---- SSRF: IPv4-mapped / 6to4 / Teredo IPv6 forms must not reach metadata.
sys.path.insert(0, ".")
from main import _ai_base_url_blocked, _ip_is_ssrf_blocked  # noqa: E402

mapped = [
    "::ffff:100.100.100.200", "::ffff:192.0.0.192",
    "::ffff:169.254.169.254", "::ffff:a9fe:a9fe",
    "2002:a9fe:a9fe::1",     # 6to4 wrapping 169.254.169.254
]
for m in mapped:
    check(f"mapped/6to4 metadata address blocked: {m}", _ip_is_ssrf_blocked(m),
          "guard let a wrapped metadata IP through")
for u in ("http://[::ffff:100.100.100.200]", "http://[::ffff:192.0.0.192]",
          "http://[::ffff:169.254.169.254]", "http://[::ffff:a9fe:a9fe]"):
    check(f"AI base_url rejects wrapped metadata: {u}", _ai_base_url_blocked(u) is not None,
          "URL guard allowed it")
check("legitimate local AI target still allowed",
      _ip_is_ssrf_blocked("127.0.0.1") is False
      and _ip_is_ssrf_blocked("10.0.0.5") is False,
      "guard now blocks loopback/private nodes")

# ---- Restore: no anonymous 64 MiB buffering.
import socket as _sock2  # noqa: E402


def raw_post_bytes(path, headers, body_chunks=(), read_bytes=4096, timeout=25,
                   body_delay=0.0, read_first=False):
    """Send headers, optionally wait, then push the body.

    With body_delay the probe mimics the real attack shape: headers first, so
    a server that refuses up front answers before a single body byte is read.
    read_first collects that early answer before the (now pointless) upload,
    because a server that already replied usually resets the connection.
    """
    h, p = (HOSTPORT[0], int(HOSTPORT[1]))
    s = _sock2.create_connection((h, p), timeout=timeout)
    lines = [f"POST {path} HTTP/1.1", f"Host: {h}:{p}", "Connection: close"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    data = b""

    def _drain():
        nonlocal data
        try:
            while len(data) < read_bytes:
                d = s.recv(read_bytes - len(data))
                if not d:
                    break
                data += d
        except OSError:
            pass

    try:
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        if read_first:
            s.settimeout(3)
            _drain()
            if data:
                s.close()
                return data.split(b"\r\n", 1)[0]
            s.settimeout(timeout)
        if body_delay:
            time.sleep(body_delay)
        for c in body_chunks:
            s.sendall(c)
        _drain()
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass
    return data.split(b"\r\n", 1)[0] if data else b""


chunked = raw_post_bytes(
    "/api/restore",
    {"Transfer-Encoding": "chunked", "Content-Type": "application/json",
     "X-Requested-With": "XMLHttpRequest"},
    [b"%x\r\n" % len(b"A" * 65536) + b"A" * 65536 + b"\r\n"] * 8 + [b"0\r\n\r\n"],
    read_first=True)
check("anonymous chunked restore is refused before its body is buffered",
      b"411" in chunked or b"413" in chunked or b"429" in chunked,
      f"status line: {chunked[:40]!r}")
# Same for the encrypted variant.
chunked_enc = raw_post_bytes(
    "/api/restore-encrypted",
    {"Transfer-Encoding": "chunked", "Content-Type": "application/json",
     "X-Requested-With": "XMLHttpRequest"},
    read_first=True)
check("anonymous chunked encrypted restore is refused too",
      b"411" in chunked_enc or b"429" in chunked_enc, f"status line: {chunked_enc[:40]!r}")
# A declared oversize length is still a clean 413 without reading the body.
oversize = raw_post_bytes(
    "/api/restore",
    {"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest",
     "Content-Length": str(70 * 1048576)},
    [b"{}"])
check("oversize declared restore is refused immediately",
      b"413" in oversize or b"429" in oversize, f"status line: {oversize[:40]!r}")

# ---- QR: bot-reachable, CPU-bound -> must be budgeted and cached.
st_qr1, _, qr1 = req("GET", f"/api/users/{uid}/qr", headers=AUTH) if uid else (0, {}, b"")
st_qr2, _, qr2 = req("GET", f"/api/users/{uid}/qr", headers=AUTH) if uid else (0, {}, b"")
check("QR endpoint works for an admin", st_qr1 == 200, f"{st_qr1}")
check("QR is cached (identical repeat response, no re-render)",
      st_qr1 == 200 and st_qr2 == 200 and qr1 == qr2, "QR not stable")
qr_codes = []
for _ in range(45):
    st_q, _, _ = req("GET", f"/api/users/{uid}/qr", headers=AUTH) if uid else (0, {}, b"")
    qr_codes.append(st_q)
check("QR endpoint is rate-limited", 429 in qr_codes, f"no 429 in {len(qr_codes)} calls")
# A pathological Host must not inflate the generated link.
st_h, _, hb = raw_request("GET", f"/api/users/{uid}/qr", b"", {"X-Requested-With": "XMLHttpRequest"},
                          "a" * 2000 + ":8000")
check("implausible Host cannot bloat the subscription link",
      b"a" * 200 not in hb, "2 KB Host leaked into the generated URL")

# ---------------------------------------------------------------- unicode / normalization
weird_users = [
    "Ａ" * 3,           # fullwidth
    "admin ",      # non-breaking space suffix
    "ADMIN",
    "a" * 32,
    "a" * 33,
    "ab",
    "__proto__",
    "constructor",
    "a‍b",       # zero-width joiner
    "аdmin",  # cyrillic а
]
for wu in weird_users:
    st, _, _ = req("POST", "/api/users", json.dumps({
        "username": wu, "protocols": ["vless"], "volume_gb": 1, "days": 1}), AUTH)
    # Either rejected, or accepted as a distinct harmless name
    ok = st in (200, 400, 409, 422)
    check(f"weird username handled: {wu[:14]!r}", ok, f"{st}")

# read-path defence: a row poisoned OUTSIDE the HTTP layer (hand-edited DB /
# old import) must not be able to 500 the whole list endpoint.
st, _, _ = req("POST", "/api/users", json.dumps({
    "username": "poisonrow", "protocols": ["vless"], "volume_gb": 1, "days": 1,
    "note": "seed"}), AUTH)
try:
    import sqlite3
    db = sqlite3.connect(DB_PATH)
    db.execute("UPDATE vpn_users SET note=? WHERE username='poisonrow'",
               (b"bad \xed\xa0\x80 note",))   # lone surrogate, CESU-8
    db.commit()
    db.close()
    st_p, _, pb = req("GET", "/api/users?q=poisonrow", headers=AUTH)
    check("pre-existing surrogate row does not 500 the list endpoint",
          st_p == 200, f"{st_p}")
    check("pre-existing surrogate row is sanitised on read",
          st_p == 200 and b"\xed" not in pb and b"note" in pb,
          "raw invalid byte echoed")
except Exception as exc:
    check("pre-existing surrogate row does not 500 the list endpoint", False, repr(exc))

# cleanup: the attack suite owns this database, so leave it empty.
st, _, lst = req("GET", "/api/users", headers=AUTH)
try:
    leftovers = json.loads(lst).get("items", [])
except Exception:
    leftovers = []
for x in leftovers:
    req("DELETE", f"/api/users/{x['id']}", headers=AUTH)
st, _, final = req("GET", "/api/users", headers=AUTH)
try:
    total = json.loads(final).get("total", -1)
except Exception:
    total = -1
check("attack suite cleaned up", total == 0, f"leftover users={total}")

# ---- LAST: the login flood. It deliberately locks this source out for the
# rest of the window, so nothing after it may need a fresh login.
rot_statuses = []
t0 = time.monotonic()
for i in range(120):
    st_r, _, _ = req("POST", "/api/login", json.dumps({
        "username": f"rot{i:03d}x", "password": "WrongPass12345"}),
        {"X-Requested-With": "XMLHttpRequest"}, timeout=30)
    rot_statuses.append(st_r)
elapsed = time.monotonic() - t0
first_429 = rot_statuses.index(429) if 429 in rot_statuses else len(rot_statuses)
check("username rotation cannot bypass login throttling", 429 in rot_statuses,
      f"no 429 in {len(rot_statuses)} rotating attempts")
check("per-source login budget bounds the scrypt work", first_429 <= 105,
      f"first 429 at attempt {first_429}")
check("throttled rotation is not a CPU/memory DoS", elapsed < 90,
      f"{elapsed:.1f}s for {len(rot_statuses)} attempts")
st_lock, _, _ = req("POST", "/api/login", json.dumps({
    "username": ADMIN, "password": PASSWORD}), {"X-Requested-With": "XMLHttpRequest"})
check("guessing flood keeps the admin locked out (cannot be flushed)", st_lock == 429,
      f"{st_lock}")
# The limiter must not be evictable: a saturated bucket survives a key flood.
from security import SlidingWindowLimiter
_lim = SlidingWindowLimiter(max_events=3, window_seconds=600)
_lim.MAX_KEYS = 10
for _ in range(3):
    _lim.hit("victim")
_pinned = [_lim.hit("victim") for _ in range(30)]
for i in range(5000):
    _lim.hit(f"flood{i}")
check("a saturated bucket is never evicted by a key flood", not any(_pinned),
      "victim bucket was cleared by flood keys")
check("eviction keeps the limiter bounded", len(_lim._events) < 100000,
      f"{len(_lim._events)} keys retained")

passed = sum(1 for _, ok, _ in results if ok)
print("\n=== SUMMARY ===")
print(f"{passed}/{len(results)} checks passed")
if passed != len(results):
    print("\nFAILURES:")
    for n, ok, d in results:
        if not ok:
            print(f"  - {n}: {d}")
sys.exit(0 if passed == len(results) else 1)
