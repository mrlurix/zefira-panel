"""Argument mapping, and one real HTTP round trip against a live panel.

The mapping tests are pure. The round trip is not: it proves the executor
really speaks the panel's HTTP, with a bearer token and the header the panel
wants on a non-GET.

One detail here is measured rather than assumed. The panel's CSRF guard skips
any request carrying a bearer, so the executor sends `X-Requested-With`
anyway - it costs nothing and it means the executor keeps working if that
rule is ever tightened.
"""
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from mcp_exec import build_call, HttpExecutor, ToolError
import mcp_tools as T

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


# ------------------------------------------------------------ path params
m, p, b, q = build_call(T.TOOL_INDEX["find_user"], {"username": "alice"})
check("a path parameter is substituted", p == "/api/users/by-username/alice", p)
check("a GET sends no body", b is None)
check("and no query", q == {})

m, p, b, q = build_call(T.TOOL_INDEX["reset_usage"], {"user_id": 7})
check("an int path parameter is substituted",
      p == "/api/users/7/reset-usage", p)

try:
    build_call(T.TOOL_INDEX["find_user"], {})
    check("a missing path parameter is refused", False, "no exception")
except ToolError as exc:
    check("a missing path parameter is refused", "username" in str(exc),
          str(exc))

# a path parameter must never fall back to the body, or a caller could smuggle
# one in and point the request somewhere else
try:
    build_call(T.TOOL_INDEX["find_user"], {"name": "alice"})
    check("a path parameter cannot come from another argument", False)
except ToolError:
    check("a path parameter cannot come from another argument", True)

# and the substitution is escaped, not pasted
m, p, b, q = build_call(T.TOOL_INDEX["find_user"],
                        {"username": "../../api/settings"})
check("a path parameter is URL-escaped, so it cannot escape its route",
      "..%2F" in p or "%2F" in p, p)

# ------------------------------------------------------------- body forms
m, p, b, q = build_call(T.TOOL_INDEX["create_user"],
                        {"username": "zed", "protocols": "vless",
                         "volume_gb": 5, "days": 30})
check("a flat body carries the mapped keys",
      b == {"username": "zed", "protocols": "vless", "volume_gb": 5,
            "days": 30}, json.dumps(b))

m, p, b, q = build_call(T.TOOL_INDEX["create_user"],
                        {"username": "zed", "volume_gb": 5})
check("an omitted optional argument is left out, not sent as null",
      set(b) == {"username", "volume_gb"}, json.dumps(b))

m, p, b, q = build_call(T.TOOL_INDEX["update_settings"],
                        {"settings": {"domain": "x", "sub_port": 443},
                         "confirm": "REPLACE"})
check("__all__ sends the object the caller passed",
      b == {"domain": "x", "sub_port": 443}, json.dumps(b))

m, p, b, q = build_call(T.TOOL_INDEX["restore_backup"],
                        {"backup": {"users": [{}], "zefira_backup": True},
                         "password_confirm": "pw"})
check("__merge__ spreads beside the other keys",
      b == {"users": [{}], "zefira_backup": True, "password_confirm": "pw"},
      json.dumps(b))

try:
    build_call(T.TOOL_INDEX["update_settings"], {"settings": "nope"})
    check("__all__ refuses a non-object", False)
except ToolError:
    check("__all__ refuses a non-object", True)

# ---------------------------------------------------------------- query
m, p, b, q = build_call(T.TOOL_INDEX["list_users"], {"limit": 5})
# the value keeps its type rather than being stringified: urlencode does that
# at send time, and stringifying here would make a falsy value indistinguishable
# from an absent one further down
check("a query parameter is mapped, keeping its type",
      q == {"limit": 5}, json.dumps(q))
m, p, b, q = build_call(T.TOOL_INDEX["list_users"], {"limit": 0})
check("a zero query value is still sent, because 0 is a real limit",
      q == {"limit": 0}, json.dumps(q))
m, p, b, q = build_call(T.TOOL_INDEX["list_users"], {})
check("an omitted query argument is absent, not null", q == {}, json.dumps(q))

# ----------------------------------------------------------------- live
PORT = 8171
BASE = "http://127.0.0.1:%d" % PORT
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
     "--port", str(PORT), "--no-server-header", "--no-proxy-headers"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(200):
        time.sleep(0.25)
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2).read()
            break
        except Exception:
            continue

    cred = io.open(os.path.join(ROOT, "instance", "first-run-credentials.txt"),
                   encoding="utf-8", errors="replace").read()
    U = re.search(r"(?im)^\s*(?:username|user|admin)\s*[:=]\s*(\S+)",
                  cred).group(1)
    P = re.search(r"(?im)^\s*(?:password|pass)\s*[:=]\s*(\S+)",
                  cred).group(1)

    # urllib keeps no cookies, and the panel authenticates this login with
    # one - so the opener has to, or the token mint below answers 401.
    import http.cookiejar
    OPENER = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def post(path, body, headers=None):
        req = urllib.request.Request(
            BASE + path, data=json.dumps(body).encode(),
            headers=dict({"Content-Type": "application/json",
                          "X-Requested-With": "XMLHttpRequest"},
                         **(headers or {})))
        with OPENER.open(req, timeout=30) as r:
            return json.loads(r.read())

    post("/api/login", {"username": U, "password": P})
    # ApiToken.name is unique, so minting blindly answers 409 on the second
    # run and this suite would only ever be runnable once. Revoke any probe
    # token a previous run left, then mint a fresh raw value - the panel stores
    # only a digest, so the old raw token is unrecoverable and cannot be reused.
    lst = json.loads(OPENER.open(urllib.request.Request(
        BASE + "/api/api-tokens"), timeout=30).read())
    items = lst if isinstance(lst, list) else lst.get("items", [])
    for row in items:
        if row.get("name") == "mcp-exec-probe":
            OPENER.open(urllib.request.Request(
                BASE + "/api/api-tokens/%d" % row["id"], method="DELETE",
                headers={"X-Requested-With": "XMLHttpRequest"}),
                timeout=30).read()
            break
    tok = post("/api/api-tokens", {"name": "mcp-exec-probe",
                                   "scopes": "full",
                                   "password_confirm": P})["token_once"]
    import asyncio

    ex = HttpExecutor(BASE, tok)
    res = asyncio.run(ex.call(T.TOOL_INDEX["panel_stats"], {}))
    check("the executor authenticates with a bearer and gets real data",
          isinstance(res.get("data"), dict) and "total_users" in res["data"],
          json.dumps(res)[:120])

    res = asyncio.run(ex.call(T.TOOL_INDEX["list_users"], {"limit": 3}))
    check("a query parameter survives the round trip",
          isinstance(res.get("data"), dict) and "items" in res["data"],
          json.dumps(res)[:120])

    res = asyncio.run(ex.call(T.TOOL_INDEX["find_user"], {"username": "nope"}))
    check("a 404 comes back as a result, not an exception",
          res.get("error") is not None, json.dumps(res)[:120])
    check("and it keeps the panel's own status", res.get("status") == 404,
          json.dumps(res)[:120])
    check("and the panel's own detail",
          "not found" in json.dumps(res.get("error")).lower(),
          json.dumps(res.get("error"))[:110])

    res = asyncio.run(ex.call(T.TOOL_INDEX["get_settings"], {}))
    check("a full settings read works", isinstance(res.get("data"), dict),
          json.dumps(res)[:100])

    bad = HttpExecutor(BASE, "zfp_not_a_real_token")
    res = asyncio.run(bad.call(T.TOOL_INDEX["panel_stats"], {}))
    check("a bad token yields 401, not a crash", res.get("status") == 401,
          json.dumps(res)[:120])

    dead = HttpExecutor("http://127.0.0.1:9", tok)
    res = asyncio.run(dead.call(T.TOOL_INDEX["panel_stats"], {}))
    check("an unreachable panel is an error result, not an exception",
          "error" in res and "cannot reach" in str(res.get("error")).lower(),
          json.dumps(res)[:120])
finally:
    proc.terminate()
    try:
        proc.wait(timeout=20)
    except Exception:
        proc.kill()

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)