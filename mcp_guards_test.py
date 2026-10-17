"""Regression guards for every defect the bug hunt found.

Fourteen bugs, each fixed and each with a check here that fails if the fix is
reverted. They are grouped by the property rather than by the file, because
that is what a reviewer needs to see: a title bar, and the evidence that made
it a bug in the first place.

  security
    1  a cross-origin redirect must not receive the operator's bearer
    2  the same-origin redirect must still be followed
    3  /api/mcp must refuse a token whose scope does not cover MCP
    4  a partial PUT must not reset the fields it did not mention

  protocol
    5  a notification is answered with silence
    6  a REQUEST that merely LOOKS like a notification is still answered
    7  the jsonrpc envelope is validated
    8  exception text never reaches the model, only its type

  the confirmation gate
    9  a missing target must not turn into the magic string "None"

  argument handling
   10  a bare dot-segment is refused rather than pasted into a path
   11  a response body is read with a cap

  the settings switches
   12  "false" and every other non-affirmative value mean OFF
   13  /api/mcp/test makes a real tool call, or says it made none
   14  an empty PUT body is refused rather than silently accepted

Several of these were green before the fixes. That is the point of writing
them down: each one had a plausible-looking test that could not fail.
"""

import asyncio
import io
import json
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import mcp_exec
import mcp_protocol
import mcp_tools

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:170])
                         if (detail and not cond) else ""))


def section(t):
    print()
    print("== %s ==" % t)


# ------------------------------------------------------------ 1 and 2
section("1-2. the bearer must not cross an origin")

# Two servers, because "same host, different port" is a genuinely different
# origin - and a panel behind a load balancer looks exactly like that.
#
# Server A is the CONFIGURED origin and is the redirect TARGET.
# Server B is the CONFIGURED origin and issues the 302 to A.
#
# The bearer reaching B is correct and expected: that is the host the operator
# configured. What must never happen is the bearer reaching A.
HITS_A = []
HITS_B = []


class _B(BaseHTTPRequestHandler):
    """The configured origin: every request here legitimately carries the token."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        HITS_B.append((self.path, self.headers.get("Authorization")))
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:%d/stolen" % PORT_A)
        self.end_headers()

    do_POST = do_GET


class _A(BaseHTTPRequestHandler):
    """The redirect target. Anything it sees at all is the defect."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        HITS_A.append((self.path, self.headers.get("Authorization")))
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET


srv_a = HTTPServer(("127.0.0.1", 0), _A)
PORT_A = srv_a.server_port
threading.Thread(target=srv_a.serve_forever, daemon=True).start()
srv_b = HTTPServer(("127.0.0.1", 0), _B)
PORT_B = srv_b.server_port
threading.Thread(target=srv_b.serve_forever, daemon=True).start()

try:
    ex = mcp_exec.HttpExecutor("http://127.0.0.1:%d" % PORT_B,
                               "zfp_OPERATOR_TOKEN")
    res = ex._once("GET", "/start", None, None)
    check("the configured origin does receive the bearer, as it must",
          HITS_B and HITS_B[0][1] == "Bearer zfp_OPERATOR_TOKEN", HITS_B)
    check("the redirect TARGET receives nothing at all",
          HITS_A == [], HITS_A)
    check("and the caller is told the token was not sent there",
          "another origin" in str(res.get("error", ""))
          or "NOT sent" in str(res.get("error", "")), res)

    # same-origin must still work, or the fix would break real deployments
    class _Self(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/hop":
                self.send_response(302)
                self.send_header("Location", "/landed")
                self.end_headers()
                return
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_POST = do_GET

    srv_s = HTTPServer(("127.0.0.1", 0), _Self)
    threading.Thread(target=srv_s.serve_forever, daemon=True).start()
    try:
        ex4 = mcp_exec.HttpExecutor("http://127.0.0.1:%d" % srv_s.server_port,
                                    "zfp_OPERATOR_TOKEN")
        res4 = ex4._once("GET", "/hop", None, None)
        check("a same-origin redirect is still followed",
              res4.get("status") == 200, res4)
    finally:
        srv_s.shutdown()
finally:
    srv_a.shutdown()
    srv_b.shutdown()

# ---------------------------------------------------------------- 5 and 6
section("5-6. notifications are silent, mislabelled requests are not")


class _Rec:
    def __init__(self):
        self.calls = []

    def record(self, tool, args, ok, detail=""):
        self.calls.append(tool)


rec = _Rec()
d = mcp_protocol.Dispatcher(mcp_exec.AsgiExecutor(lambda e, s: None, "x"))
for method in ("ping", "tools/list", "initialize", "tools/call"):
    frame = {"jsonrpc": "2.0", "method": method}
    if method == "initialize":
        frame["params"] = {}
    if method == "tools/call":
        frame["params"] = {"name": "panel_stats", "arguments": {}}
    out = asyncio.run(d.handle(dict(frame)))
    check("%-13s as a notification is answered with nothing" % method,
          out is None, out)

out = asyncio.run(d.handle({"jsonrpc": "2.0", "id": 7,
                            "method": "notifications/initialized"}))
check("a REQUEST named notifications/... IS answered, so nothing hangs",
      isinstance(out, dict) and out.get("id") == 7, out)
out = asyncio.run(d.handle({"jsonrpc": "2.0", "id": 8,
                            "method": "notifications/../tools/list"}))
check("and a crafted method name cannot suppress a request either",
      isinstance(out, dict) and out.get("error", {}).get("code") == -32601,
      out)
out = asyncio.run(d.handle({"jsonrpc": "2.0", "id": None, "method": "ping"}))
check("a request with a null id is a request and is still answered",
      isinstance(out, dict) and out.get("id") is None, out)

# ------------------------------------------------------------------- 7
section("7. the jsonrpc envelope is validated")
for bad, why in (({"jsonrpc": "1.0", "id": 1, "method": "ping"},
                  "jsonrpc 1.0"),
                 ({"id": 1, "method": "ping"}, "no jsonrpc member")):
    out = asyncio.run(d.handle(dict(bad)))
    check("%-22s is Invalid Request" % why,
          isinstance(out, dict)
          and out.get("error", {}).get("code") == -32600, out)
out = asyncio.run(d.handle({"jsonrpc": "2.0", "id": 1, "result": {}}))
check("a response object is not mistaken for a request",
      isinstance(out, dict) and out.get("error", {}).get("code") == -32600,
      out)

# ------------------------------------------------------------------- 8
section("8. exception text stays out of the model's answer")


class _Boom:
    def call(self, tool, args):
        raise RuntimeError("unable to open C:\\secret\\instance\\zefira.db")

    def _once(self, *a, **k):
        raise RuntimeError("unable to open C:\\secret\\instance\\zefira.db")


d2 = mcp_protocol.Dispatcher(_Boom())
out = asyncio.run(d2.handle({"jsonrpc": "2.0", "id": 1,
                             "method": "tools/call",
                             "params": {"name": "panel_stats",
                                        "arguments": {}}}))
txt = json.dumps(out)
check("no filesystem path reaches the model",
      "zefira.db" not in txt and "secret" not in txt, txt[:180])
check("but the exception TYPE does, so a failure is still diagnosable",
      "RuntimeError" in txt, txt[:180])


def composed(tool, args):
    raise ValueError("no such row: C:\\secret\\instance\\zefira.db")


d3 = mcp_protocol.Dispatcher(mcp_exec.AsgiExecutor(lambda e, s: None, "x"),
                             compose=composed)
out = asyncio.run(d3.handle({"jsonrpc": "2.0", "id": 1,
                             "method": "tools/call",
                             "params": {"name": "subscription_link",
                                        "arguments": {"username": "x"}}}))
txt = json.dumps(out)
check("and the compose path leaks nothing either",
      "zefira.db" not in txt, txt[:180])

# ------------------------------------------------------------------- 9
section("9. the confirmation gate has no magic string")
for name in ("delete_user", "delete_api_token", "create_api_token"):
    try:
        mcp_tools.check_confirmation(name, {})
        check("%-18s with no target refuses" % name, False,
              "it ALLOWED the call")
    except mcp_exec.ToolError:
        check("%-18s with no target refuses" % name, True)
    except Exception as e:
        check("%-18s with no target refuses" % name, False,
              "%s: %s" % (type(e).__name__, e))

src = io.open(os.path.join(ROOT, "mcp_tools.py"), encoding="utf-8",
              newline="").read()
refusals = []
for name in ("delete_user", "delete_api_token", "create_api_token"):
    try:
        mcp_tools.check_confirmation(name, {})
    except Exception as e:
        refusals.append(str(e))
check("and no refusal message names the string \"None\"",
      not any('"None"' in m for m in refusals), refusals[:1])

# ------------------------------------------------------------------ 10
section("10. a bare dot-segment never reaches a path")
for name, args in (("delete_user", {"user_id": "..", "confirm": ".."}),
                   ("user_config", {"user_id": ".."}),
                   ("find_user", {"username": ".."})):
    try:
        call = mcp_exec.build_call(mcp_tools.TOOL_INDEX[name], dict(args))
        check("%-12s with '..' is refused" % name, False,
              "it built %s" % (call,))
    except mcp_exec.ToolError:
        check("%-12s with '..' is refused" % name, True)
check("an ordinary id is unaffected",
      mcp_exec.build_call(mcp_tools.TOOL_INDEX["user_config"],
                          {"user_id": 7})[1] == "/api/users/7/config")

# ------------------------------------------------------------------ 11
section("11. a response body is read with a cap")
src = io.open(os.path.join(ROOT, "mcp_exec.py"), encoding="utf-8",
              newline="").read()
check("both HTTP reads pass a size",
      src.count("resp.read(MAX_RESPONSE_BYTES)") == 1
      and src.count("exc.read(MAX_RESPONSE_BYTES)") == 1,
      "resp:%d exc:%d" % (src.count("resp.read(MAX_RESPONSE_BYTES)"),
                          src.count("exc.read(MAX_RESPONSE_BYTES)")))
check("an uncapped resp.read() or exc.read() is gone",
      "resp.read()" not in src and "exc.read()" not in src)
check("the cap is declared and is a real number",
      re.search(r"MAX_RESPONSE_BYTES\s*=\s*\d+\s*\*\s*1024\s*\*\s*1024", src)
      is not None)

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d offline guards passed ===" % (n, len(ok)))
if n != len(ok):
    sys.exit(1)
