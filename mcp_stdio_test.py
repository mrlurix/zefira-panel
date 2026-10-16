"""The stdio transport, driven over pipes.

No SDK, no panel: this feeds newline-delimited JSON-RPC at the loop and reads
what comes back, which is exactly what an MCP client does over a pipe. The
SDK's own client is the conformance check in Task 8.

The check that matters most here is the quietest: a line that is not JSON
must not stop the loop. One bad frame from a client ends the session
otherwise, and the client sees a dead pipe with no explanation.
"""
import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import mcp_server
from mcp_server import run_stdio, read_env_config, main
from mcp_protocol import PROTOCOL_VERSION

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


class FakeExec:
    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply if reply is not None else {"status": 200,
                                                      "data": {"total_users": 11}}

    async def call(self, tool, args):
        self.calls.append(tool["name"])
        return self.reply


def drive(lines, exec_obj=None):
    with tempfile.TemporaryFile("w+", encoding="utf-8") as fin, \
         tempfile.TemporaryFile("w+", encoding="utf-8") as fout:
        for l in lines:
            fin.write(l + "\n")
        fin.seek(0)
        rc = run_stdio("http://127.0.0.1:9", "zfp_x", stdin=fin, stdout=fout,
                       executor=exec_obj or FakeExec())
        fout.seek(0)
        body = fout.read()
        return rc, [json.loads(l) for l in body.splitlines() if l.strip()], body


# ------------------------------------------------- one request, one response
rc, out, raw = drive([
    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {}}),
    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "panel_stats", "arguments": {}}}),
    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
])
check("the loop exits cleanly at end of input", rc == 0, str(rc))
check("it answers the three requests and not the notification",
      len(out) == 3, str(len(out)))
check("initialize is first", out[0]["result"]["protocolVersion"]
      == PROTOCOL_VERSION)
check("tools/list answers the table", len(out[1]["result"]["tools"]) > 10,
      str(len(out[1]["result"]["tools"])))
check("tools/call reaches the executor",
      "total_users" in out[2]["result"]["content"][0]["text"])
check("ids come back in order", [r["id"] for r in out] == [1, 2, 3],
      str([r["id"] for r in out]))
check("every line is a complete JSON object", raw.count("\n") == 3,
      "%d newlines in %d bytes" % (raw.count("\n"), len(raw)))
check("the output is flushed line by line, so a client sees it as it comes",
      all(l.strip() for l in raw.splitlines()))

# ------------------------------------------------------- a garbage frame
rc, out, _ = drive([
    "this is not json at all",
    json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"}),
])
check("a non-JSON line does not stop the loop", rc == 0, str(rc))
check("and the next request is still answered", len(out) == 2, str(len(out)))
check("the bad line gets parse error -32700",
      out[0].get("error", {}).get("code") == -32700, json.dumps(out[0])[:120])
check("the parse error carries a null id",
      out[0].get("id") is None, json.dumps(out[0])[:90])

# several bad frames in a row, then a good one
rc, out, _ = drive([
    "{", "]", "null", "[]", json.dumps({"jsonrpc": "2.0", "id": 9,
                                       "method": "ping"})])
check("four bad frames in a row still leave the loop working",
      rc == 0 and len(out) == 5, "rc=%d out=%d" % (rc, len(out)))
check("and only the last one is a result",
      "result" in out[-1] and "error" in out[-2], json.dumps(out[-2])[:90])

# ------------------------------------------------------------ blank lines
rc, out, _ = drive(["", json.dumps({"jsonrpc": "2.0", "id": 6,
                                    "method": "ping"}), ""])
check("blank lines are ignored, not answered", len(out) == 1,
      json.dumps(out)[:110])
rc, out, _ = drive(["   ", "\t", json.dumps({"jsonrpc": "2.0", "id": 7,
                                             "method": "ping"})])
check("whitespace-only lines are ignored too", len(out) == 1,
      json.dumps(out)[:110])

# ------------------------------------------------- stdout is the channel
# Anything else written to stdout corrupts the stream and the client
# disconnects with no useful message. Captured here, because it is the one
# defect that would be invisible until a real client tried it.
rc, out, raw = drive([json.dumps({"jsonrpc": "2.0", "id": 8,
                                  "method": "tools/call",
                                  "params": {"name": "no_such_tool",
                                             "arguments": {}}})])
check("stdout carries JSON-RPC and nothing else",
      all(l.strip().startswith("{") for l in raw.splitlines() if l.strip()),
      raw[:120])
check("an unknown tool answers, it does not print a traceback",
      len(out) == 1 and out[0]["result"].get("isError") is True,
      json.dumps(out)[:120])

# a request that makes the dispatcher raise must still answer the frame
class Exploding:
    async def call(self, tool, args):
        raise RuntimeError("boom")

# Read the RAW bytes, not json.dumps(out): dumps re-wraps the objects across
# lines, so "every line starts with {" would be false for the wrong reason.
# What is actually guarded against is a non-JSON line on the wire.
rc, out, raw = drive([json.dumps({"jsonrpc": "2.0", "id": 10,
                                  "method": "tools/call",
                                  "params": {"name": "panel_stats"}})],
                     exec_obj=Exploding())
check("an executor that raises still answers the frame", len(out) == 1,
      json.dumps(out)[:120])
check("and it is reported, not printed",
      "isError" in out[0].get("result", {}), json.dumps(out)[:120])
lines = [l for l in raw.splitlines() if l.strip()]
check("stdout is exactly one whole JSON object per line",
      len(lines) == 1 and lines[0].startswith("{") and lines[0].endswith("}"),
      repr(raw[:140]))
check("and it parses back to a JSON-RPC frame",
      json.loads(lines[0]).get("jsonrpc") == "2.0")


class _WatchedOut:
    """Records WHEN a flush happened relative to the loop finishing."""

    def __init__(self, inner):
        self.inner = inner
        self.flushed = 0
        self.loop_done = False
        self.flush_while_running = 0

    def write(self, s):
        return self.inner.write(s)

    def flush(self):
        self.flushed += 1
        if not self.loop_done:
            self.flush_while_running += 1
        return self.inner.flush()


def _flushed_per_line():
    """Was there a flush before the loop returned?"""
    buf = io.StringIO()
    out = _WatchedOut(buf)
    with tempfile.TemporaryFile("w+", encoding="utf-8") as fin:
        for req in ({"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    {"jsonrpc": "2.0", "id": 2, "method": "ping"}):
            fin.write(json.dumps(req) + "\n")
        fin.seek(0)
        rc = run_stdio("http://127.0.0.1:9", "zfp_x", stdin=fin, stdout=out,
                       executor=FakeExec())
    return out.flush_while_running, rc, buf.getvalue()


_while, _rc, _txt = _flushed_per_line()
check("the loop exits cleanly", _rc == 0, str(_rc))
check("both pings were answered", _txt.count("\n") == 2, repr(_txt[:90]))
check("each reply is flushed while the loop is still running",
      _while == 2, "%d flush(es) before the loop returned" % _while)


check("a reply reaches a pipe as it is written, not at close",
      _while == 2,
      "a client on a pipe would block reading forever until the loop ended")

# ----------------------------------------------------------- the env contract
old = dict(os.environ)
try:
    os.environ["ZEFIRA_URL"] = "https://panel.example"
    os.environ["ZEFIRA_TOKEN"] = "zfp_secret"
    url, tok = read_env_config()
    check("the base URL comes from ZEFIRA_URL", url == "https://panel.example", url)
    check("the token comes from ZEFIRA_TOKEN", tok == "zfp_secret")
    del os.environ["ZEFIRA_TOKEN"]
    check("a missing token yields an empty string, not a crash",
          read_env_config()[1] == "")
    os.environ["ZEFIRA_URL"] = "  https://spaced.example  "
    check("the values are stripped", read_env_config()[0] == "https://spaced.example")
    del os.environ["ZEFIRA_URL"]
    check("with neither variable set it returns empties, still no crash",
          read_env_config() == ("", ""))

    # a token is never echoed, in any code path. The refusal text is what a
    # client ends up pasting into an issue, so a live credential in it is how
    # a bearer token ends up in a bug report.
    os.environ["ZEFIRA_URL"] = ""
    os.environ["ZEFIRA_TOKEN"] = "zfp_supersecret_value"
    err = io.StringIO()
    old_err = sys.stderr
    old_run = mcp_server.run_stdio
    sys.stderr = err
    try:
        rc = main([])
        rc2 = main(["--base-url", ""])
        # With run_stdio stubbed out, main()'s own guard is the only thing
        # left that can refuse. Without the stub, run_stdio's identical check
        # masks a mutation that removes main()'s.
        calls = []
        mcp_server.run_stdio = lambda *a, **k: calls.append(a) or 0
        rc3 = main(["--base-url", "", "--token", "zfp_x"])
        rc4 = main([])
    finally:
        mcp_server.run_stdio = old_run
        sys.stderr = old_err
    check("refusing to start exits 2", rc == 2, str(rc))
    check("and so does an empty --base-url", rc2 == 2, str(rc2))
    check("with run_stdio stubbed, main() still refuses an empty URL",
          rc3 == 2, str(rc3))
    check("so the refusal is main()'s, not borrowed from run_stdio",
          rc4 == 2 and not calls, "rc=%d calls=%d" % (rc4, len(calls)))
    # and run_stdio refuses for itself when called as a library
    err2 = io.StringIO()
    old_err = sys.stderr
    sys.stderr = err2
    try:
        rc5 = run_stdio("", "", stdin=io.StringIO(""))
    finally:
        sys.stderr = old_err
    check("run_stdio refuses for itself too, with no URL or token",
          rc5 == 2, str(rc5))
    check("and the usage message never contains the token",
          "zfp_supersecret_value" not in err.getvalue(),
          repr(err.getvalue()[:110]))
    check("but it does say what to set",
          "ZEFIRA_URL" in err.getvalue(), repr(err.getvalue()[:110]))
    # --help goes to stderr and must not print it either
    err3 = io.StringIO()
    sys.stderr = err3
    try:
        check("--help exits 0", main(["--help"]) == 0)
    finally:
        sys.stderr = old_err
    check("and --help does not print the token either",
          "zfp_supersecret_value" not in err3.getvalue(),
          repr(err3.getvalue()[:110]))
finally:
    os.environ.clear()
    os.environ.update(old)

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)