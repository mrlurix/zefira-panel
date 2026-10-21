"""An MCP tool call must be attributed to the caller who made it.

The MCP transport forwards a tool call into the panel's own API, in-process.
It forwards the CALLER'S TOKEN, so the scope check is the panel's own and the
blast radius is right. But the forwarded request's client address used to be
hard-coded to 127.0.0.1 in the ASGI scope.

Two things followed, and both were measured on a running panel:

  - the audit trail could not attribute the action. One MCP call that created
    a customer wrote MCP_CALL ip=203.0.113.9 and USER_CREATE ip=127.0.0.1 -
    the same operation, two addresses, one trail.
  - the per-IP rate limiters of the FORWARDED routes keyed on that single
    address, so every MCP client shared one bucket, together with the
    operator's own same-host requests.

This suite makes the caller visible to the panel - the panel trusts
X-Forwarded-For from the loopback, which is the same-host nginx case and the
installer's default - and then checks that ONE operation leaves ONE address in
the trail.
"""

import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:190])
                         if (detail and not cond) else ""))


WORK = tempfile.mkdtemp(prefix="zefira_mcpip_")
APP = os.path.join(WORK, "app")
os.makedirs(APP, exist_ok=True)
for name in ("main.py", "config.py", "database.py", "security.py",
             "protocols.py", "schemas.py", "VERSION", "templates", "static",
             "mcp_tools.py", "mcp_protocol.py", "mcp_exec.py", "mcp_server.py"):
    src = os.path.join(ROOT, name)
    dst = os.path.join(APP, name)
    if os.path.isdir(src):
        shutil.copytree(src, dst, dirs_exist_ok=True)
    elif os.path.exists(src):
        shutil.copy2(src, dst)
shutil.copytree(os.path.join(ROOT, "instance"), os.path.join(APP, "instance"),
                dirs_exist_ok=True)

PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
PORT = 8224
BASE = "http://127.0.0.1:%d" % PORT
PW = "kf0MrM3rm0GLg47x"
FAKE = "203.0.113.9"
OPENER = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(__import__("http.cookiejar",
                                                  fromlist=["x"]).CookieJar()))


def call(method, path, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    h = dict(headers or {})
    h.setdefault("X-Requested-With", "XMLHttpRequest")
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=h,
                                 method=method)
    try:
        with OPENER.open(req, timeout=90) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode("utf-8", "replace")


proc = subprocess.Popen(
    [PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port",
     str(PORT), "--no-server-header", "--no-proxy-headers"],
    cwd=APP, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    # the panel must trust this peer before it reads the header
    con = sqlite3.connect(os.path.join(APP, "instance", "zefira.db"))
    con.execute("INSERT OR REPLACE INTO settings (key, value) VALUES "
                "('trusted_proxies', '127.0.0.1')")
    con.commit()
    con.close()

    for _ in range(280):
        time.sleep(0.25)
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2).read()
            break
        except urllib.error.HTTPError:
            break
        except Exception:
            continue
    CSRF = {"X-Requested-With": "XMLHttpRequest"}
    call("POST", "/api/login", {"username": "admin", "password": PW}, CSRF)
    CH = dict(CSRF)
    for h in OPENER.handlers:
        jar = getattr(h, "cookiejar", None)
        if jar:
            for c in jar:
                if c.name == "zefira_session":
                    CH["Cookie"] = "zefira_session=" + c.value

    st, tok = call("POST", "/api/api-tokens",
                   {"name": "mcpip guard", "scopes": "full",
                    "password_confirm": PW}, CH)
    token = (tok or {}).get("token_once")
    check("a full-scope token for the MCP transport", bool(token), st)

    uname = "mcpip_%d" % os.getpid()
    st, out = call("POST", "/api/mcp",
                   {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "create_user",
                               "arguments": {"username": uname,
                                             "protocols": ["vless"],
                                             "volume_gb": 10, "days": 30}}},
                   {"Authorization": "Bearer " + (token or ""),
                    "X-Forwarded-For": FAKE, **CSRF})
    check("the MCP call succeeds", st == 200, st)
    res = (out or {}).get("result", {}) if isinstance(out, dict) else {}
    check("...and the customer was created", bool(res), str(out)[:140])

    st, audit = call("GET", "/api/audit?limit=25",
                     headers=dict(CH, **{"X-Forwarded-For": FAKE}))
    items = audit.get("items") if isinstance(audit, dict) else audit
    mcp_rows = [a for a in (items or []) if a.get("event") == "MCP_CALL"]
    user_rows = [a for a in (items or []) if a.get("event") == "USER_CREATE"]
    check("the trail has the MCP call", bool(mcp_rows))
    check("...and the forwarded customer creation", bool(user_rows))
    check("the MCP call is attributed to the caller",
          bool(mcp_rows) and mcp_rows[0].get("ip") == FAKE,
          "ip=%r" % (mcp_rows[0].get("ip") if mcp_rows else None))
    check("...and so is the FORWARDED call, which used to claim 127.0.0.1",
          bool(user_rows) and user_rows[0].get("ip") == FAKE,
          "ip=%r" % (user_rows[0].get("ip") if user_rows else None))
    check("one operation leaves ONE address in the trail",
          bool(mcp_rows) and bool(user_rows)
          and mcp_rows[0].get("ip") == user_rows[0].get("ip"),
          "%r vs %r" % (mcp_rows[0].get("ip") if mcp_rows else None,
                        user_rows[0].get("ip") if user_rows else None))

    # and the scope is still the caller's own
    st, bot = call("POST", "/api/api-tokens",
                   {"name": "mcpip bot", "scopes": "bot",
                    "password_confirm": PW}, CH)
    bot_tok = (bot or {}).get("token_once")
    st, out2 = call("POST", "/api/mcp",
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "create_user",
                                "arguments": {"username": uname + "_bot",
                                              "protocols": ["vless"],
                                              "volume_gb": 10, "days": 30}}},
                    {"Authorization": "Bearer " + (bot_tok or ""),
                     "X-Forwarded-For": FAKE, **CSRF})
    check("a bot-scoped token still cannot use MCP",
          st == 403, "status=%s" % st)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=25)
    except Exception:
        proc.kill()
    shutil.rmtree(WORK, ignore_errors=True)

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)