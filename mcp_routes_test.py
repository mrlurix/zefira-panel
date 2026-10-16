"""The four MCP routes, against a live panel with a real bearer token.

Every check is a round trip, and the three that matter most are:
the transport accepts a bearer and refuses a cookie, the limiter is
charged only after authentication, and settings GET never contains a
token.

The limiter check orders itself deliberately. A budget charged before
authentication would let an anonymous caller burn an operator's whole MCP
allowance with a loop of 401s, so the test drives the limiter with a BAD
token first and then a good one: if the bad token had charged it, the good
one would be refused.
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

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


PORT = 8173
BASE = "http://127.0.0.1:%d" % PORT
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
     "--port", str(PORT), "--no-server-header", "--no-proxy-headers"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(220):
        time.sleep(0.25)
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2).read()
            break
        except Exception:
            continue

    import http.cookiejar
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    COOKIE = {}

    def call(method, path, body=None, headers=None, cookie=False):
        data = None if body is None else json.dumps(body).encode()
        h = dict(headers or {})
        if data is not None:
            h["Content-Type"] = "application/json"
        if cookie and COOKIE.get("v"):
            h["Cookie"] = COOKIE["v"]
        req = urllib.request.Request(BASE + path, data=data, headers=h,
                                     method=method)
        try:
            with opener.open(req, timeout=40) as r:
                raw = r.read()
                for c in (r.headers.get_all("Set-Cookie") or []):
                    if c.startswith("zefira_session="):
                        COOKIE["v"] = c.split(";")[0]
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw.decode("utf-8", "replace")

    CSRF = {"X-Requested-With": "XMLHttpRequest"}
    cred = io.open(os.path.join(ROOT, "instance", "first-run-credentials.txt"),
                   encoding="utf-8", errors="replace").read()
    U = re.search(r"(?im)^\s*(?:username|user|admin)\s*[:=]\s*(\S+)",
                  cred).group(1)
    P = re.search(r"(?im)^\s*(?:password|pass)\s*[:=]\s*(\S+)",
                  cred).group(1)

    st, _ = call("POST", "/api/login", {"username": U, "password": P}, CSRF)
    check("login works", st == 200, str(st))
    for row in (call("GET", "/api/api-tokens", cookie=True)[1] or []):
        if isinstance(row, dict) and row.get("name", "").startswith("mcp-rt-"):
            call("DELETE", "/api/api-tokens/%d" % row["id"], cookie=True,
                 headers=CSRF)
    tok = call("POST", "/api/api-tokens",
               {"name": "mcp-rt-probe", "scopes": "full",
                "password_confirm": P}, dict(CSRF), cookie=True)[1]["token_once"]
    A = {"Authorization": "Bearer " + tok, "X-Requested-With": "XMLHttpRequest"}

    # ------------------------------------------------------- settings GET
    st, j = call("GET", "/api/mcp/settings", headers=A)
    check("GET /api/mcp/settings is 200", st == 200, str(st))
    check("it reports the tool count", j.get("tool_count", 0) > 10,
          str(j.get("tool_count")))
    check("and the protocol version, read from the SDK",
          j.get("protocol_version") == "2026-07-28", str(j.get("protocol_version")))
    blob = json.dumps(j).lower()
    check("it never contains a token",
          tok.lower() not in blob and '"token":' not in blob
          and "zfp_" not in blob, blob[:130])
    check("it hints which identity to use, without its value",
          isinstance(j.get("token_hint"), str) and "mcp-rt-probe" in j["token_hint"],
          str(j.get("token_hint")))
    # A cookie session DOES read these routes, and that is correct: the panel
    # is cookie-authenticated throughout and the MCP card Task 7 adds reads
    # this route with the session cookie. Insisting on 401 here would mean the
    # card could never load in the panel that documents it.
    check("a cookie session can read the settings, so the MCP card can load",
          call("GET", "/api/mcp/settings", cookie=True)[0] == 200)
    # A brand-new opener with NO cookie processor. cookie=False is not
    # enough: it only stops this test from adding the cookie header, while
    # the shared opener keeps sending it - measured answering 200, so the
    # check was green while measuring nothing.
    def _bare_status(path):
        import urllib.request as _u
        plain = _u.build_opener()          # no cookie processor at all
        try:
            with plain.open(BASE + path, timeout=30) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    _bare = _bare_status("/api/mcp/settings")
    check("and a bare request with nothing at all is refused",
          _bare in (401, 403), "status %s" % _bare)

    # ------------------------------------------------------- settings PUT
    st, j = call("PUT", "/api/mcp/settings", {"enabled": False}, headers=A)
    check("PUT /api/mcp/settings is 200", st == 200, str(st))
    check("and the write reads back immediately, so the cache was popped",
          call("GET", "/api/mcp/settings", headers=A)[1].get("enabled") is False)
    call("PUT", "/api/mcp/settings", {"enabled": True}, headers=A)

    st, j = call("PUT", "/api/mcp/settings", {"max_calls_per_min": 99999},
                 headers=A)
    check("an absurd rate limit is refused", st == 422, str(st))
    st, j = call("PUT", "/api/mcp/settings", {"enabled": "yes"}, headers=A)
    check("a non-boolean enabled is refused: StrictBool", st == 422, str(st))
    st, j = call("PUT", "/api/mcp/settings", {"http_enabled": 1}, headers=A)
    check("a numeric http_enabled is refused too", st == 422, str(st))
    check("and a refused write changed nothing",
          call("GET", "/api/mcp/settings", headers=A)[1].get("enabled") is True)

    # ---------------------------------------------------------- transport
    st, j = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {}}, headers=A)
    check("POST /api/mcp answers initialize", st == 200, str(st))
    check("with the protocol version",
          j.get("result", {}).get("protocolVersion") == "2026-07-28",
          json.dumps(j)[:130])

    st, j = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                 headers=A)
    check("tools/list is offered", len(j.get("result", {}).get("tools", [])) > 10,
          str(len(j.get("result", {}).get("tools", []))))
    check("and the composed tool IS offered here, not just in-process",
          any(t["name"] == "subscription_link"
              for t in j.get("result", {}).get("tools", [])))

    st, j = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "panel_stats", "arguments": {}}},
                 headers=A)
    check("a tool call reaches the panel", st == 200, str(st))
    check("and returns real data",
          "total_users" in j.get("result", {}).get("content", [{}])[0].get("text", ""),
          json.dumps(j)[:140])

    st, j = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                  "params": {"name": "delete_user",
                             "arguments": {"user_id": 1}}}, headers=A)
    check("an unconfirmed destructive call is refused",
          j.get("result", {}).get("isError") is True, json.dumps(j)[:140])
    check("and the refusal names the exact string",
          'confirm: "1"' in j["result"]["content"][0]["text"],
          json.dumps(j["result"])[:140])
    check("and customer 1 is still there",
          call("GET", "/api/users?limit=1", headers=A)[1].get("items") is not None)

    # ------------------------------------------------------- the auth rules
    # 403 from the CSRF guard, which refuses before the route runs; 401 if it
    # ever reaches the route's own check. Either way it is refused, and which
    # of the two says nothing extra about safety.
    st, _ = call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 5,
                                      "method": "ping"})
    check("no credentials at all is refused", st in (401, 403), str(st))

    # A cookie is different: it reaches the route, and the route refuses it.
    # A cookie session may read /api/mcp/settings (above, on purpose) but may
    # not DRIVE the transport - it already works everywhere else with one, and
    # an MCP client has no business carrying a browser cookie.
    st, j = call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 5,
                                      "method": "ping"}, CSRF, cookie=True)
    check("a COOKIE on the transport is refused: bearer only", st == 401, str(st))
    check("and the route says why, by name", "bearer" in str(j).lower(),
          str(j)[:90])

    st, _ = call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 5, "method": "ping"},
                 headers={"Authorization": "Bearer zfp_bogus",
                          "X-Requested-With": "XMLHttpRequest"})
    check("a bogus bearer is 401", st == 401, str(st))
    st, _ = call("GET", "/api/mcp", headers=A)
    check("GET /api/mcp is 405, and it is not a routed GET", st == 405, str(st))

    # ------------------------------------------- the limiter, in the right order
    call("PUT", "/api/mcp/settings", {"max_calls_per_min": 5}, headers=A)
    # 40 bad-token calls first: if they charged the limiter, the good token
    # below would be refused.
    for i in range(40):
        call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 900 + i,
                                  "method": "ping"},
             headers={"Authorization": "Bearer zfp_bogus",
                      "X-Requested-With": "XMLHttpRequest"})
    st, _ = call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 6, "method": "ping"},
                 headers=A)
    check("an unauthenticated caller does NOT spend the operator's budget",
          st == 200, str(st))
    # The window is shared with every earlier call in this run, so this
    # measures the CHANGE across a burst rather than expecting a specific
    # count on the first 429.
    codes = []
    for i in range(40):
        codes.append(call("POST", "/api/mcp",
                          {"jsonrpc": "2.0", "id": 1000 + i, "method": "ping"},
                          headers=A)[0])
    check("the limiter does fire for an authenticated caller",
          codes.count(429) > 0, "codes seen: %s" % sorted(set(codes)))
    check("and it refuses the later calls in the burst", codes[-1] == 429,
          "last was %s" % codes[-1])
    # NOT "the first call is allowed": the window is shared with every
    # earlier call in this run under the same token, so the budget may
    # already be spent by the time the burst starts. Measured output
    # was "first was 429". What matters is that it fires and STAYS
    # fired - a limiter that lets one through every N would defeat
    # itself.
    check("and once it fires it stays fired for the rest of the window",
          codes[-5:] == [429] * 5, "tail was %s" % codes[-5:])

    # ---- the order of the limiter and the authentication ----
    # The 40 bad-token calls above prove an UNAUTHENTICATED caller spends
    # nothing, but they are refused by the CSRF guard before reaching the
    # limiter at all, so they cannot tell "limiter runs first" apart from
    # "limiter runs second". A token that resolves to no admin does reach
    # it: that is the case the ordering comment is about.
    orphan_codes = []
    for i in range(12):
        orphan_codes.append(call(
            "POST", "/api/mcp",
            {"jsonrpc": "2.0", "id": 700 + i, "method": "ping"},
            headers={"Authorization": "Bearer zfp_orphan_token_value",
                     "X-Requested-With": "XMLHttpRequest"})[0])
    check("a bearer that resolves to no admin is 401 every time",
          set(orphan_codes) == {401},
          "codes seen: " + repr(sorted(set(orphan_codes))))
    check("and it never reaches the limiter: a 429 here would mean the limiter ran before authentication",
          429 not in orphan_codes,
          "saw " + repr(sorted(set(orphan_codes))))

    # ---- a zero ceiling must refuse, not fall back ----
    # Driven directly rather than through the route: cached_setting
    # memoises for 15 seconds, so writing 0 into the settings table left
    # the route reading its own cached value. Measured - the first version
    # of this check passed while exercising nothing but the cache.
    from security import SlidingWindowLimiter as _SWL
    _zero = _SWL(max_events=60, window_seconds=60)
    _zero.max_override = 0
    _zc = [_zero.hit("k") for _ in range(3)]
    check("a ceiling of 0 refuses everything rather than falling back",
          _zc == [False, False, False], "got " + repr(_zc))
    _unset = _SWL(max_events=2, window_seconds=60)
    _uc = [_unset.hit("k") for _ in range(3)]
    check("and an unset ceiling uses the one it was built with",
          _uc == [True, True, False], "got " + repr(_uc))

    # ------------------------------------------------------------- the switch
    call("PUT", "/api/mcp/settings", {"max_calls_per_min": 600}, headers=A)
    call("PUT", "/api/mcp/settings", {"http_enabled": False}, headers=A)
    st, j = call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 7,
                                      "method": "ping"}, headers=A)
    check("with http_enabled off the transport is 405", st == 405, str(st))
    check("and it says why", "switched off" in str(j).lower(), str(j)[:90])
    call("PUT", "/api/mcp/settings", {"http_enabled": True}, headers=A)
    check("and it comes back when switched on",
          call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 8,
                                     "method": "ping"}, headers=A)[0] == 200)
    call("PUT", "/api/mcp/settings", {"enabled": False}, headers=A)
    st, j = call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 9,
                                      "method": "ping"}, headers=A)
    check("with the master switch off the transport is 405 too", st == 405, str(st))
    call("PUT", "/api/mcp/settings", {"enabled": True}, headers=A)

    # ----------------------------------------------------------------- test
    st, j = call("POST", "/api/mcp/test", {}, headers=A)
    check("POST /api/mcp/test is 200", st == 200, str(st))
    check("it reports the tool count", j.get("tool_count", 0) > 10,
          json.dumps(j)[:140])
    check("and can actually reach the transport", j.get("ok") is True,
          json.dumps(j)[:140])
    check("it never returns a token", tok.lower() not in json.dumps(j).lower(),
          json.dumps(j)[:140])

    # --------------------------------------------------------- audit trail
    st, j = call("GET", "/api/audit?limit=40", headers=A)
    check("an MCP call left an audit row", "MCP_CALL" in json.dumps(j),
          json.dumps(j)[:160])

    # --------------------------------------------------- the compose path
    uname = "mcp_rt_probe_user"
    for row in (call("GET", "/api/users?limit=200", headers=A)[1].get("items") or []):
        if row.get("username") == uname:
            call("DELETE", "/api/users/%d" % row["id"], headers=A)
    call("POST", "/api/users",
         {"username": uname, "protocols": ["vless"], "volume_gb": 5, "days": 30},
         headers=A)
    st, j = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 20, "method": "tools/call",
                  "params": {"name": "subscription_link",
                             "arguments": {"username": uname}}}, headers=A)
    txt = j.get("result", {}).get("content", [{}])[0].get("text", "")
    check("subscription_link is served, composed in-process",
          j.get("result", {}).get("isError") is not True, json.dumps(j)[:150])
    check("and carries a URL", "/sub/" in txt, txt[:110])
    st, j = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 21, "method": "tools/call",
                  "params": {"name": "subscription_link",
                             "arguments": {"username": "nobody_at_all"}}},
                 headers=A)
    check("and refuses for a customer that does not exist",
          j.get("result", {}).get("isError") is True, json.dumps(j)[:140])
    for row in (call("GET", "/api/users?limit=200", headers=A)[1].get("items") or []):
        if row.get("username") == uname:
            call("DELETE", "/api/users/%d" % row["id"], headers=A)
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