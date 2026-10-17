"""MCP conformance: the real SDK as a real client, over both transports.

The panel ships no MCP dependency, deliberately - `mcp==2.3.0` drags httpx2,
opentelemetry-api, jsonschema, python-multipart and pywin32 into the panel's
runtime, and install.sh installs hash-locked from requirements.lock while the
in-panel updater reinstalls requirements.txt on every update. So the SDK is used
the only way it can be used without changing what the panel installs: as a TEST
CLIENT in a throwaway virtualenv outside the repository, driving the panel
exactly the way an operator's AI client would.

  transport 1  stdio  - the SDK launches mcp_server.py as a subprocess and
                        speaks MCP over its stdin/stdout
  transport 2  http   - the SDK's Streamable HTTP client against POST /api/mcp

Four things measured here rather than assumed, each of which cost a run:

  - the SDK's transport yields a TWO-tuple, not the three older docs show. An
    early version unpacked three and died with "not enough values to unpack",
    which reads like the transport refusing the panel when nothing had been
    sent yet.

  - 2.3.0 spells everything snake_case: server_info, protocol_version,
    input_schema, is_error. The wire-format names are gone.

  - the panel answers Streamable HTTP in its stateless form: application/json
    with no Mcp-Session-Id. The SDK accepts that, and a full session -
    initialize, tools/list, tools/call - completes over it.

  - the SDK sends LATEST_HANDSHAKE_VERSION, 2025-11-25, and raises RuntimeError
    unless the answer is in its handshake set. The panel used to echo any
    version string it was sent, which is why the SDK connected at all - and
    also why it answered "1999-01-01" with "1999-01-01". Negotiation is now
    validated against the versions the panel implements.

Exit codes are load-bearing:

  0  every check passed
  1  a check failed - the server is wrong
  2  the environment could not be prepared - nothing was proven EITHER way, and
     a suite that cannot run must never be reported as a pass
"""

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SDK_VERSION = "2.3.0"
# The versions ClientSession.initialize() will accept an answer from. It sends
# LATEST_HANDSHAKE_VERSION and raises RuntimeError for anything outside this
# set, so membership is the property worth asserting - not an exact string,
# which would rot on the next SDK release.
HANDSHAKE = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")

TMP = tempfile.gettempdir()
VENV = os.path.join(TMP, "mcpclient")
SDK_PY = os.path.join(VENV, "Scripts", "python.exe")
PANEL_PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:150])
                         if (detail and not cond) else ""))


def bail_environment(why, detail=""):
    print()
    print("=== ENVIRONMENT UNAVAILABLE ===")
    print("  %s" % why)
    if detail:
        print("  %s" % detail)
    print()
    print("  Nothing was proven either way. Exiting 2, not 0: a suite that")
    print("  could not run must never be reported as a pass.")
    sys.exit(2)


def sdk_run(argv, timeout, why):
    """Run something in the SDK venv, or exit 2 explaining why it could not.

    Without this, a venv that exists but cannot execute raises OSError straight
    out of subprocess - measured on Windows as WinError 193 - and the suite dies
    with a traceback and rc=1. A traceback is not a verdict on conformance and
    is indistinguishable from a failed check. Anything that stops the client
    running means nothing was proven, so every launch into the venv goes here.
    """
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, encoding="utf-8",
                              errors="replace")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        bail_environment(why, "%s: %s" % (type(exc).__name__, exc))


# ------------------------------------------------------ 1. the SDK, or exit 2
print("== 1. the SDK client ==")
if not os.path.exists(SDK_PY):
    print("  no virtualenv at %s - building one" % VENV)
    r = sdk_run([PANEL_PY, "-m", "venv", VENV], 900,
                "could not create the throwaway virtualenv")
    if r.returncode != 0 or not os.path.exists(SDK_PY):
        bail_environment("could not create the throwaway virtualenv",
                         (r.stderr or r.stdout or "")[-400:])
    print("  installing mcp==%s (the only thing in this venv)" % SDK_VERSION)
    r = sdk_run([SDK_PY, "-m", "pip", "install", "--quiet",
                 "--disable-pip-version-check", "mcp==" + SDK_VERSION],
                1800, "could not install mcp==" + SDK_VERSION)
    if r.returncode != 0:
        bail_environment("could not install mcp==" + SDK_VERSION,
                         (r.stderr or r.stdout or "")[-400:])

r = sdk_run([SDK_PY, "-c", "import importlib.metadata as m; print(m.version('mcp'))"],
            300, "the SDK interpreter could not be launched")
if r.returncode != 0:
    bail_environment("the virtualenv cannot import mcp",
                     (r.stderr or "")[-400:])
have = (r.stdout or "").strip()
if have != SDK_VERSION:
    # exit 1 would say "the server is wrong". The server is fine: the client is
    # not the one this suite was written against, so nothing was proven.
    bail_environment("the venv has mcp %r, not %r"
                     % (have or "nothing importable", SDK_VERSION))
check("the SDK is importable in a throwaway venv", True, have)
check("and it lives outside the repository, so the panel installs nothing new",
      os.path.abspath(VENV).startswith(os.path.abspath(TMP))
      and not os.path.abspath(VENV).startswith(os.path.abspath(ROOT)))

r = sdk_run([PANEL_PY, "-c", "import mcp"], 300,
            "the panel interpreter could not be launched")
check("the panel's own runtime still has no mcp in it", r.returncode != 0)

req = io.open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8",
              newline="").read()
lock = io.open(os.path.join(ROOT, "requirements.lock"), encoding="utf-8",
               newline="").read()
check("and requirements.txt and the lock are untouched by it",
      not re.search(r"^mcp", req, re.M | re.I) and "mcp" not in lock.lower())

# ------------------------------------------------------------ 2. the probes
def probe_source(stdio):
    """The client body. `stdio` picks the transport; the checks are identical.

    The checks are deliberately the same on both transports so that any
    difference between them shows up as a difference in the OUTPUT rather than
    as two test bodies that drifted apart.
    """
    open_call = (
        "        async with stdio_client(params) as (r, w):"
        if stdio else
        "        async with streamable_http_client(base + \"/api/mcp\",\n"
        "                                              http_client=hc) as (r, w):")
    imports = (
        "    from mcp.client.stdio import StdioServerParameters, stdio_client"
        if stdio else
        "    import httpx2\n"
        "    from mcp.client.streamable_http import streamable_http_client")
    prelude = (
        "    params = StdioServerParameters(\n"
        "        command=sys.argv[1], args=[sys.argv[2]],\n"
        "        env={\"ZEFIRA_URL\": sys.argv[3], \"ZEFIRA_TOKEN\": sys.argv[4],\n"
        "             \"PATH\": os.environ.get(\"PATH\", \"\"),\n"
        "             \"SYSTEMROOT\": os.environ.get(\"SYSTEMROOT\", \"\"),\n"
        "             \"PYTHONIOENCODING\": \"utf-8\"})\n"
        "    async def _cleanup():\n"
        "        # stdio_client owns the subprocess and closes it itself, so\n"
        "        # there is nothing to tear down here.\n"
        "        return None\n"
        if stdio else
        "    base, tok = sys.argv[1], sys.argv[2]\n"
        "    headers = {\"Authorization\": \"Bearer \" + tok,\n"
        "               \"MCP-Protocol-Version\": \"2025-06-18\"}\n"
        "    hc = httpx2.AsyncClient(headers=headers, timeout=40)\n"
        "    await hc.__aenter__()\n"
        "    async def _cleanup():\n"
        "        await hc.__aexit__(None, None, None)\n")

    return '''"""Drive the panel's %s transport with the real SDK client."""
import asyncio
import contextlib
import json
import os
import sys

OUT = {}


async def main():
    from mcp import ClientSession
%s
%s
    try:
%s
            async with ClientSession(r, w) as s:
                init = await s.initialize()
                OUT["server"] = init.server_info.name
                OUT["protocol"] = init.protocol_version
                OUT["caps"] = sorted(init.capabilities.model_dump().keys())
                tools = await s.list_tools()
                OUT["tools"] = len(tools.tools)
                OUT["names"] = sorted(t.name for t in tools.tools)
                OUT["schemas_ok"] = all(
                    isinstance(t.input_schema, dict)
                    and t.input_schema.get("type") == "object"
                    for t in tools.tools)
                OUT["described"] = all(bool(t.description)
                                        for t in tools.tools)
                got = await s.call_tool("panel_stats", {})
                OUT["stats_error"] = bool(got.is_error)
                OUT["stats_text"] = (got.content[0].text[:120]
                                     if got.content else "")
                bad = await s.call_tool("no_such_tool", {})
                OUT["unknown_is_error"] = bool(bad.is_error)
                out = await s.call_tool("delete_user", {"user_id": 999999})
                OUT["destructive_is_error"] = bool(out.is_error)
                OUT["confirm_named"] = "confirm:" in (
                    out.content[0].text if out.content else "")
                OUT["has_subscription_link"] = (
                    "subscription_link" in OUT["names"])
    finally:
        await _cleanup()


asyncio.run(main())
print("@@JSON@@" + json.dumps(OUT))
''' % ("stdio" if stdio else "http", imports, prelude, open_call)


def run_probe(stdio, argv, label):
    path = os.path.join(TMP, "opencode", "mcp_probe_%s.py" % label)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, "w", encoding="utf-8", newline="\n").write(
        probe_source(stdio))
    r = sdk_run([SDK_PY, path] + list(argv), 600,
                "the SDK could not be launched for the %s probe" % label)
    out = r.stdout or ""
    m = re.search(r"@@JSON@@(.*)", out, re.S)
    if not m:
        return None, ((out + (r.stderr or ""))[-700:])
    try:
        return json.loads(m.group(1).strip()), None
    except Exception as e:
        return None, "unparseable result: %s" % e


def shared_checks(got, where):
    check("%s: initialize completes" % where, got.get("server") == "zefira",
          got.get("server"))
    check("%s: the negotiated version is one the SDK itself accepts" % where,
          got.get("protocol") in HANDSHAKE, got.get("protocol"))
    check("%s: the server advertises the tools capability" % where,
          "tools" in (got.get("caps") or []), got.get("caps"))
    check("%s: tools/list returns the whole table" % where,
          got.get("tools", 0) > 20, got.get("tools"))
    check("%s: every tool carries a JSON-Schema object input" % where,
          bool(got.get("schemas_ok")))
    check("%s: every tool carries a description" % where,
          bool(got.get("described")))
    check("%s: a read-only tool returns real panel data" % where,
          got.get("stats_error") is False
          and "total_users" in (got.get("stats_text") or ""),
          (got.get("stats_text") or "")[:80])
    check("%s: an unknown tool is an error, not a crash" % where,
          bool(got.get("unknown_is_error")))
    check("%s: a destructive tool refuses without its confirmation" % where,
          bool(got.get("destructive_is_error")))
    check("%s: and the refusal names the exact string to send" % where,
          bool(got.get("confirm_named")))


# --------------------------------------------------------------- the panel
PORT = 8183
BASE = "http://127.0.0.1:%d" % PORT
print()
print("== 2. both transports, driven by the SDK ==")
proc = subprocess.Popen(
    [PANEL_PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
     "--port", str(PORT), "--no-server-header", "--no-proxy-headers"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    up = False
    for _ in range(280):
        time.sleep(0.25)
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2).read()
            up = True
            break
        except Exception:
            continue
    if not up:
        bail_environment("the panel did not start on port %d" % PORT)

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
            with opener.open(req, timeout=60) as r:
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
    check("the panel accepts an admin login", st == 200, st)
    for row in (call("GET", "/api/api-tokens", cookie=True)[1] or []):
        if isinstance(row, dict) and row.get("name", "").startswith("mcp-cf-"):
            call("DELETE", "/api/api-tokens/%d" % row["id"], cookie=True,
                 headers=CSRF)
    tok = call("POST", "/api/api-tokens",
               {"name": "mcp-cf-probe", "scopes": "full",
                "password_confirm": P}, CSRF,
               cookie=True)[1].get("token_once")
    check("a full-scope bearer token was minted for the client", bool(tok))
    if not tok:
        raise SystemExit("no token; the rest cannot run")

    print()
    print("  -- transport 1: stdio --")
    got, err = run_probe(True, [PANEL_PY, os.path.join(ROOT, "mcp_server.py"),
                                BASE, tok], "stdio")
    if got is None:
        bail_environment("the SDK could not drive the stdio transport", err)
    shared_checks(got, "stdio")
    check("stdio does NOT offer the composed tool, as designed",
          got.get("has_subscription_link") is False)
    stdio_tools = got.get("tools", 0)
    stdio_names = got.get("names", [])

    print()
    print("  -- transport 2: http --")
    got, err = run_probe(False, [BASE, tok], "http")
    if got is None:
        bail_environment("the SDK could not drive the HTTP transport", err)
    shared_checks(got, "http")
    check("http DOES offer the composed tool",
          got.get("has_subscription_link") is True)
    http_tools = got.get("tools", 0)

    print()
    print("  -- the two transports --")
    check("HTTP offers exactly one tool more than stdio, and it is the "
          "composed one",
          http_tools == stdio_tools + 1
          and got.get("has_subscription_link") is True,
          "http %s vs stdio %s" % (http_tools, stdio_tools))
    check("and they agree on every tool but the composed one",
          [x for x in got.get("names", []) if x != "subscription_link"]
          == stdio_names)
    again, err2 = run_probe(False, [BASE, tok], "http2")
    check("a second, independent session over the same endpoint also completes",
          isinstance(again, dict) and again.get("server") == "zefira",
          err2 or type(again).__name__)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=25)
    except Exception:
        proc.kill()

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d checks passed ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
