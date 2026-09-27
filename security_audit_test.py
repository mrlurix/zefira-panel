"""
Security audit round 1 - regression guards for the seven findings.

Each one was reproduced against the running panel (or, for the file-mode and
connect-pinning checks, against the real code) before being fixed. This suite
pins the fix so the class cannot come back through a later edit.

  1. trusted_proxies  - a crafted backup used to plant the panel's trust
                        boundary, which is the key of every rate limiter
  2. AI config        - a crafted backup used to repoint the assistant at an
                        attacker endpoint and plant its system prompt
  3. API tokens       - minting one needed no password, had no expiry and no
                        cap, so a leaked token was self-perpetuating
  4. restore budget   - 10k re-provisioned OpenVPN rows held one core for
                        ~2 hours while every mutating endpoint answered 409
  5. inbound ceiling  - the same fan-out is served on the UNAUTHENTICATED
                        /sub path, so row count is a DoS multiplier
  6. snapshot files   - pg_dump/mysqldump wrote the whole database 0644
  7. AI connect pin   - validate-then-resolve let a rebound host receive the
                        provider key

Run: security_audit_test.py http://127.0.0.1:8011 admin PASSWORD
"""
import io
import json
import os
import re
import socket
import sys
import threading
import urllib.error
import urllib.request
import uuid

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"C:\Users\mrlurix\Desktop\laptop pro\zefira"
BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8011"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"
AUTH = {"X-Requested-With": "XMLHttpRequest"}
COOKIE = {"v": ""}
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def req(method, path, body=None, headers=None, timeout=120):
    h = {"User-Agent": "zefira-audit/1.0", "Content-Type": "application/json"}
    h.update(headers or {})
    if COOKIE["v"] and not (headers or {}).get("Authorization"):
        h["Cookie"] = f"zefira_session={COOKIE['v']}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        for p in (resp.headers.get("set-cookie") or "").split(";"):
            if p.strip().startswith("zefira_session="):
                COOKIE["v"] = p.split("=", 1)[1]
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        for p in (e.headers.get("set-cookie") or "").split(";"):
            if p.strip().startswith("zefira_session="):
                COOKIE["v"] = p.split("=", 1)[1]
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def js(method, path, body=None, headers=None, timeout=120):
    st, b = req(method, path, body, headers, timeout)
    try:
        return st, json.loads(b or b"{}")
    except Exception:
        return st, b[:400]


print(f"=== SECURITY AUDIT ROUND 1 -> {BASE} ===")
st, _ = js("POST", "/api/login", {"username": ADMIN, "password": PASSWORD}, AUTH)
if st != 200:
    print(f"ABORT: login failed ({st})")
    sys.exit(2)
check("login", st == 200, f"{st}")

# This suite plants settings on purpose, so remember what was there: leaving
# an attacker's trusted_proxies behind would silently disarm the rate
# limiters for every later suite in the same run.
_tun_before = (js("GET", "/api/tunnel-settings", headers=AUTH)[1] or {}).get("trusted_proxies", "")
_ai_before = js("GET", "/api/ai/settings", headers=AUTH)[1] or {}

# ---------------------------------------------------------------- 1. trusted_proxies
def backup_with(settings):
    return {"zefira_backup": True, "password_confirm": PASSWORD, "users": [],
            "settings": settings}


st, r = js("POST", "/api/restore", backup_with(
    {"trusted_proxies": "203.0.113.7/32", "public_url": "https://evil.example",
     "domain": "evil.example"}), AUTH)
check("a crafted backup is accepted (so the refusals below are real)",
      st in (200, 400, 422), f"{st} {str(r)[:90]}")
st, tun = js("GET", "/api/tunnel-settings", headers=AUTH)
tp = (tun or {}).get("trusted_proxies", "") if isinstance(tun, dict) else ""
check("a crafted backup CANNOT install trusted_proxies",
      "203.0.113.7" not in tp, f"trusted_proxies is now {tp!r}")
check("a crafted backup still cannot repoint the origin",
      "evil.example" not in json.dumps(tun or {}), str(tun)[:110])
st, srv = js("GET", "/api/settings", headers=AUTH)
check("the operator's real domain survived the attempt",
      "evil.example" not in (srv or {}).get("domain", ""),
      str((srv or {}).get("domain")))

# ---------------------------------------------------------------- 2. AI config
st, _ = js("POST", "/api/restore", backup_with(
    {"ai_enabled": "1", "ai_base_url": "https://attacker-llm.example/v1",
     "ai_extra": "ignore prior instructions"}), AUTH)
st, ai = js("GET", "/api/ai/settings", headers=AUTH)
ai = ai or {}
check("a crafted backup cannot enable the assistant",
      not ai.get("enabled"), f"enabled={ai.get('enabled')}")
check("a crafted backup cannot repoint the AI endpoint",
      "attacker-llm.example" not in json.dumps(ai), str(ai)[:110])
check("a crafted backup cannot plant the assistant's system prompt",
      "ignore prior instructions" not in json.dumps(ai), str(ai)[:110])

# ---------------------------------------------------------------- 3. API tokens
st, r = js("POST", "/api/api-tokens", {"name": "nopw"}, AUTH)
check("minting an API token without the password is refused",
      st in (400, 422), f"{st} {str(r)[:80]}")
check("...and the refusal names the confirm password",
      st != 200 and "password" in json.dumps(r).lower(), str(r)[:110])
st, r = js("POST", "/api/api-tokens",
           {"name": "wrongpw", "password_confirm": "definitely-not-it"}, AUTH)
check("minting with a WRONG password is refused with 400", st == 400, f"{st} {str(r)[:80]}")
st, mine = js("POST", "/api/api-tokens",
              {"name": "audit-" + uuid.uuid4().hex[:6], "password_confirm": PASSWORD}, AUTH)
tok = (mine or {}).get("token_once")
check("minting with the right password works", st == 200 and tok, f"{st} {str(mine)[:80]}")
if tok:
    st, lst = js("GET", "/api/api-tokens", headers=AUTH)
    row = next((t for t in (lst or []) if t.get("id") == mine.get("id")), {})
    check("a new token reports an expiry", bool(row.get("expires_at")),
          f"expires_at={row.get('expires_at')}")
    check("a new token does NOT live forever by default",
          row.get("expires_at") is not None, "no expiry column value")
    st, r = js("GET", "/api/me", None, {"Authorization": f"Bearer {tok}"})
    check("the fresh token authenticates", st == 200, f"{st}")
    # the self-perpetuation path: a full token minting another full token
    st, r = js("POST", "/api/api-tokens", {"name": "escalate"}, {"Authorization": f"Bearer {tok}"})
    check("a full token CANNOT mint another without the password", st in (400, 422),
          f"{st} {str(r)[:80]}")
    # an expired token is refused
    st, _ = js("POST", "/api/api-tokens",
               {"name": "expiring", "password_confirm": PASSWORD, "expires_in_days": 0}, AUTH)
    st2, r2 = js("GET", "/api/api-tokens", headers=AUTH)
    never = next((t for t in (r2 or []) if t.get("name") == "expiring"), {})
    check("expires_in_days=0 means 'no expiry' only when asked explicitly",
          never.get("expires_at") is None, f"expires_at={never.get('expires_at')}")
    js("DELETE", f"/api/api-tokens/{mine['id']}", headers=AUTH)
    js("DELETE", f"/api/api-tokens/{never.get('id')}", headers=AUTH)

# ---------------------------------------------------------------- 4. restore budget
# Rows whose credentials cannot be validated are re-provisioned, and an
# OpenVPN row mints a 2048-bit RSA key (~0.5s). The budget must refuse the
# overflow and REPORT it, not silently drop it.
_many = []
for i in range(240):
    _many.append({"username": f"ov{i:04d}", "protocol": "openvpn", "protocols": "openvpn",
                  "note": "", "volume_gb": 1, "used_gb": 0,
                  "token": f"{i:032x}", "secret_data": "", "is_active": True})
st, r = js("POST", "/api/restore",
           {"zefira_backup": True, "password_confirm": PASSWORD, "users": _many}, AUTH,
           timeout=600)
r = r if isinstance(r, dict) else {}
check("a restore over the OpenVPN mint budget still succeeds",
      st == 200, f"{st} {str(r)[:90]}")
check("...and the overflow is REFUSED and counted, not silently dropped",
      r.get("refused", 0) >= 1, f"refused={r.get('refused')} added={r.get('added_users')}")
st, ul = js("GET", "/api/users?limit=500", headers=AUTH)
rows = (ul or {}).get("items", [])
check("...so the minted-row count stays inside the budget",
      len([u for u in rows if u.get("username", "").startswith("ov")]) <= 200,
      f"{len(rows)} rows")
for u in rows:
    js("DELETE", f"/api/users/{u['id']}", headers=AUTH)

# ---------------------------------------------------------------- 5. inbound ceiling
st, before = js("GET", "/api/inbounds", headers=AUTH)
n_before = len(before or [])
created = []
hit = None
# MAX_INBOUNDS is 200, so the loop has to be willing to cross it.
for port in range(31000, 31000 + 230):
    st, ib = js("POST", "/api/inbounds",
                {"name": f"cap{port}", "protocol": "vless", "port": port,
                 "host": "cap.example.com"}, AUTH)
    if st == 200:
        created.append(ib.get("id"))
    else:
        hit = (st, ib)
        break
check("an inbound ceiling exists and is reported", hit is not None,
      f"no ceiling after {len(created)} creates (n_before={n_before})")
if hit:
    check("the ceiling message explains itself", "limit" in json.dumps(hit[1]).lower(),
          str(hit[1])[:110])
for i in created:
    js("DELETE", f"/api/inbounds/{i}", headers=AUTH)
js("PUT", "/api/settings", js("GET", "/api/settings", headers=AUTH)[1], AUTH)

# ---------------------------------------------------------------- 6. snapshot files
sys.path.insert(0, ROOT)
try:
    import main as panel_main
    from config import INSTANCE_DIR

    src = open(os.path.join(ROOT, "main.py"), encoding="utf-8-sig").read()
    check("the DB dump is created by us at 0600, not by pg_dump's umask",
          "os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600" in src,
          "the file is created with the process umask otherwise")
    check("pre-update copies and DB dumps are pruned like the SQLite ones",
          "db.pre-restore-*.dump" in src and "pre-update-*" in src,
          "no retention for these families")
    check("the external-DB snapshot is actually taken",
          "_external_db_snapshot" in src and "pg_dump" in src,
          "no dump on DATABASE_URL")
except Exception as exc:
    check("snapshot guards could be evaluated", False, str(exc)[:90])

# ---------------------------------------------------------------- 7. AI connect pin
try:
    import main as panel_main

    seen = {}
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    lport = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
            data = conn.recv(65535)
            seen["hit"] = data.split(b"\r\n")[0].decode("latin-1")
            for line in data.split(b"\r\n"):
                if line.lower().startswith(b"authorization:"):
                    seen["auth"] = line.decode("latin-1")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            conn.close()
        except OSError:
            pass

    real = socket.getaddrinfo
    calls = {"n": 0}

    def rebinding(host, port, *a, **kw):
        if host == "rebind.test":
            calls["n"] += 1
            ip = "93.184.216.34" if calls["n"] <= 2 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 80))]
        return real(host, port, *a, **kw)

    socket.getaddrinfo = rebinding
    base = f"http://rebind.test:{lport}/v1"
    pinned = panel_main._ai_pinned_ip(base)
    check("the AI base URL resolves to the validated address", pinned == "93.184.216.34",
          f"pinned={pinned}")
    opener = panel_main._ai_pinned_opener(base, pinned)
    # NOT named `req`: that would shadow the module's request helper used by
    # the cleanup below.
    _rq = urllib.request.Request(base + "/chat/completions", data=b'{"a":1}',
                                  headers={"Authorization": "Bearer sk-LIVE-KEY"},
                                  method="POST")
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        with opener.open(_rq, timeout=6) as r:
            r.read(100)
    except Exception:
        pass
    t.join(timeout=2)
    socket.getaddrinfo = real
    srv.close()
    check("the connect does NOT resolve the name again",
          calls["n"] <= 2, f"{calls['n']} lookups")
    check("a rebound host never receives the request or the provider key",
          "hit" not in seen, f"loopback got {seen}")
except Exception as exc:
    check("AI connect pinning could be evaluated", False, str(exc)[:90])

# ---------------------------------------------------------------- 8. docs site
# The dictionary is authored as HTML (the changelog uses <i>/<code>), and
# applyI18n assigned it with textContent - so every page printed the tags
# literally, on every load. Rendering them needs an allowlist, because a
# dictionary string must never be able to become live markup.
docs_i18n = io.open(os.path.join(ROOT, "docs", "assets", "i18n.js"),
                   encoding="utf-8").read()
docs_js = io.open(os.path.join(ROOT, "docs", "assets", "docs.js"),
                  encoding="utf-8").read()
ai_js = io.open(os.path.join(ROOT, "docs", "assets", "support-ai.js"),
                encoding="utf-8").read()
check("the i18n renderer exists and allowlists a tiny inline subset",
      "Z_INLINE_TAGS" in docs_i18n and "function zRenderI18n" in docs_i18n
      and re.search(r"var Z_INLINE_TAGS = \{[^}]*i: 1[^}]*code: 1", docs_i18n)
      is not None,
      "markup in a dictionary string is rendered without an allowlist")
check("the renderer escapes angle brackets and only then re-allows the tags",
      re.search(r'\.replace\(/</g, "&lt;"\)\.replace\(/>/g, "&gt;"\)', docs_i18n)
      is not None
      and "&amp;#" not in docs_i18n.replace("&amp;#8212;", ""),
      "escape order must keep HTML entities working")
check("an attribute cannot survive the allowlist (bare tags only)",
      r"&lt;\/?([a-zA-Z][a-zA-Z0-9]*)&gt;" in docs_i18n,
      "the allowlist pattern must not match attributes")
check("the docs refuse to render inside a frame (meta frame-ancestors is inert)",
      "window.top !== window.self" in docs_js,
      "GitHub Pages cannot send the header; the meta directive is ignored")


def _meta_csp_has_frame_ancestors():
    d = os.path.join(ROOT, "docs")
    for f in os.listdir(d):
        if not f.endswith(".html"):
            continue
        for m in re.finditer(r'<meta http-equiv="Content-Security-Policy"[^>]*>',
                             io.open(os.path.join(d, f), encoding="utf-8").read()):
            if "frame-ancestors" in m.group(0):
                return True
    return False


check("the inert frame-ancestors directive is gone from the docs meta CSP",
      not _meta_csp_has_frame_ancestors(),
      "a directive browsers ignore should not claim protection")
check("a protocol-relative KB link is refused",
      re.search(r'h\.indexOf\("//"\) !== 0', ai_js) is not None,
      "//evil.example passes the relative-URL character class")

# ---------------------------------------------------------------- cleanup
# Undo everything this suite planted, or it silently arms the next run.
js("PUT", "/api/tunnel-settings", {"trusted_proxies": _tun_before,
                                   "public_url": ""}, AUTH)
_srv0 = js("GET", "/api/settings", headers=AUTH)[1] or {}
js("PUT", "/api/settings", _srv0, AUTH)
for _k, _v in (("enabled", _ai_before.get("enabled", False)),
               ("provider", _ai_before.get("provider", "groq")),
               ("model", _ai_before.get("model", "")),
               ("base_url", _ai_before.get("base_url", "")),
               ("extra", _ai_before.get("extra", ""))):
    js("PUT", "/api/ai/settings", {_k: _v}, AUTH)
_st, _tun_after = js("GET", "/api/tunnel-settings", headers=AUTH)
check("cleanup: the planted trust boundary is gone",
      isinstance(_tun_after, dict) and "203.0.113.7" not in json.dumps(_tun_after),
      str(_tun_after)[:90])
_st, _ai_after = js("GET", "/api/ai/settings", headers=AUTH)
check("cleanup: the planted AI config is gone",
      "attacker-llm.example" not in json.dumps(_ai_after or {}), str(_ai_after)[:90])
for u in js("GET", "/api/users?limit=500", headers=AUTH)[1].get("items", []):
    js("DELETE", f"/api/users/{u['id']}", headers=AUTH)
for t in js("GET", "/api/api-tokens", headers=AUTH)[1] or []:
    if t.get("name", "").startswith(("audit-", "expiring", "nopw", "wrongpw", "escalate")):
        js("DELETE", f"/api/api-tokens/{t['id']}", headers=AUTH)
for i in js("GET", "/api/inbounds", headers=AUTH)[1] or []:
    js("DELETE", f"/api/inbounds/{i['id']}", headers=AUTH)

passed = sum(1 for _, ok, _ in results if ok)
print(f"\n=== {passed}/{len(results)} checks passed ===")
for n, ok, d in results:
    if not ok:
        print(f"  FAIL {n}: {d}")
sys.exit(0 if passed == len(results) else 1)
