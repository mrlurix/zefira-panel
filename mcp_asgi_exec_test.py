"""The in-panel executor. This task carries the spike's finding.

The spike measured, against a live panel, that a request forwarded through
the app is indistinguishable from one over the wire: same 200, same keys,
and a missing bearer still yields 401, so the real auth stack runs. That is
what lets one tool table serve both transports instead of two.

It also found the defect this whole task exists to avoid. ASGI splits
`path` from `query_string`; leaving `?limit=1` inside `path` made the router
match nothing - a 404 for a call that answers 200 over the wire. A tool
passing a query would have reported "not found" for every listed call,
silently, with nothing pointing at the cause.

Two halves here:

  - a fake app, so the scope the executor builds is checked field by field,
    with no server and no network;
  - one real forwarded call through the real panel, because a scope that
    looks right can still be rejected by a middleware that reads something
    this test did not think of.
"""
import asyncio
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from mcp_exec import AsgiExecutor, build_call, split_path_and_query
import mcp_tools as T

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


print("  == the split, on its own ==")
check("a query string is split out of the path",
      split_path_and_query("/api/users?limit=5") == ("/api/users", b"limit=5"),
      repr(split_path_and_query("/api/users?limit=5")))
check("a path with no query is left whole",
      split_path_and_query("/api/stats") == ("/api/stats", b""))
check("a path ending in ? is not a query",
      split_path_and_query("/api/stats?") == ("/api/stats", b""),
      repr(split_path_and_query("/api/stats?")))
check("a ? inside an encoded value is not a split point",
      split_path_and_query("/api/users/a%3Fb") == ("/api/users/a%3Fb", b""),
      repr(split_path_and_query("/api/users/a%3Fb")))


print("\n  == the scope, field by field ==")


class FakeApp:
    def __init__(self):
        self.seen = []
        self.receives = 0

    async def __call__(self, scope, receive, send):
        self.seen.append(scope)
        # a body read, like the panel's own size middleware does
        got = b""
        for _ in range(5):
            msg = await receive()
            self.receives += 1
            if msg["type"] == "http.disconnect":
                break
            got += msg.get("body", b"")
            if not msg.get("more_body"):
                break
        body = json.dumps({"echo_path": scope["path"],
                           "echo_q": scope["query_string"].decode(),
                           "echo_body": got.decode("utf-8", "replace")}).encode()

        async def sd(m):
            if m["type"] == "http.response.start":
                self.status = m["status"]
            elif m["type"] == "http.response.body":
                self.chunks = getattr(self, "chunks", []) + [m.get("body", b"")]

        await sd({"type": "http.response.start", "status": 200, "headers": []})
        await sd({"type": "http.response.body", "body": body})


async def go():
    app = FakeApp()
    ex = AsgiExecutor(app, token="zfp_example")

    await ex.call(T.TOOL_INDEX["list_users"], {"limit": 5})
    sc = app.seen[-1]
    check("the scope path carries no query string",
          sc["path"] == "/api/users", sc["path"])
    check("the query lives in query_string",
          sc["query_string"] == b"limit=5", sc["query_string"])
    check("raw_path matches path, as the router reads it",
          sc["raw_path"] == b"/api/users", sc["raw_path"])
    check("the bearer reaches the forwarded call",
          (b"authorization", b"Bearer zfp_example") in sc["headers"],
          repr(sc["headers"]))
    check("X-Requested-With is sent, so CSRF never applies",
          (b"x-requested-with", b"XMLHttpRequest") in sc["headers"])
    check("content-type is application/json",
          (b"content-type", b"application/json") in sc["headers"])
    check("the scope declares an http type", sc["type"] == "http")
    check("and an ASGI version", sc["asgi"]["version"] == "3.0")
    check("a GET carries content-length 0",
          (b"content-length", b"0") in sc["headers"], repr(sc["headers"]))
    check("the client is loopback", sc["client"][0] == "127.0.0.1")
    check("root_path is empty", sc["root_path"] == "")
    check("and scope state exists for the middleware to write into",
          isinstance(sc.get("state"), dict))

    # ------------------------------------------------------ a POST body
    await ex.call(T.TOOL_INDEX["create_user"],
                  {"username": "zed", "volume_gb": 5, "days": 30})
    sc = app.seen[-1]
    check("a POST forwards as POST", sc["method"] == "POST", sc["method"])
    sent = json.loads(json.dumps({}))
    hdr_len = dict(sc["headers"]).get(b"content-length")
    # content-length must equal the real body or a size guard would reject it
    expect = len(json.dumps({"username": "zed", "volume_gb": 5,
                             "days": 30}).encode())
    check("content-length matches the body actually sent",
          int(hdr_len) == expect, "%s vs %d" % (hdr_len, expect))

    # receive must be safe to call more than once AND keep returning the body:
    # the panel's size middleware streams the body, then replaces
    # request._receive with its own replay. A receive that answers
    # http.disconnect on the second call breaks exactly that path.
    #
    # Checking only that it is callable was not enough - a disconnect-on-second
    # call IS callable repeatedly. It just answers the wrong thing, which is
    # the defect. So the second read's CONTENT is what is checked.
    await ex.call(T.TOOL_INDEX["create_user"],
                  {"username": "zed", "volume_gb": 5, "days": 30})
    probe = {"n": 0, "reads": []}
    sc = app.seen[-1]

    async def reader(_probe):
        for _ in range(3):
            msg = await _probe_receive()
            _probe["reads"].append(
                (msg["type"], msg.get("body", b"").decode("utf-8", "replace")))
            if msg["type"] == "http.disconnect" or not msg.get("more_body"):
                break

    async def _probe_receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    # read the real receive out of the executor by running a tiny app
    class ReplayApp:
        def __init__(self):
            self.rc = None

        async def __call__(self, scope, receive, send):
            self.rc = receive
            await send({"type": "http.response.start", "status": 200,
                        "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

    ra = ReplayApp()
    await AsgiExecutor(ra, token="t").call(
        T.TOOL_INDEX["create_user"],
        {"username": "zed", "volume_gb": 5, "days": 30})
    got = []
    # Unconditionally, not breaking on more_body: that break is what a
    # well-behaved consumer does, and here it would hide the very read this
    # check is about.
    for _ in range(3):
        got.append((await ra.rc())["type"])
    check("receive answers the body on every call, never http.disconnect",
          got == ["http.request"] * 3, str(got))
    check("a repeated read is not silently empty",
          (await ra.rc()).get("type") == "http.request",
          "the panel replays the body, so a second read must too")

    # ------------------------------------------------------ isolation
    await ex.call(T.TOOL_INDEX["panel_stats"], {})
    a = app.seen[-1]
    await ex.call(T.TOOL_INDEX["panel_stats"], {})
    b = app.seen[-1]
    check("each forwarded call gets a fresh scope object", a is not b)
    check("and a fresh state dict", a["state"] is not b["state"])

    # ------------------------------------------------------ error shape
    class FailApp:
        # Must forward to the executor's real send(). A stub that kept the
        # status on itself leaves the executor reading 0, and the checks
        # below would then be testing a shape rather than the error path.
        async def __call__(self, scope, receive, send):
            await send({"type": "http.response.start", "status": 403,
                        "headers": []})
            await send({"type": "http.response.body",
                        "body": json.dumps({"detail": "nope"}).encode()})

    ex2 = AsgiExecutor(FailApp(), token="zfp_x")
    res = await ex2.call(T.TOOL_INDEX["panel_stats"], {})
    check("a 403 comes back as an error result",
          res.get("error") is not None, json.dumps(res)[:110])
    check("with the panel's own status", res.get("status") == 403,
          json.dumps(res)[:110])
    check("and the panel's own detail", "nope" in json.dumps(res.get("error")),
          json.dumps(res.get("error"))[:110])


asyncio.run(go())

# --------------------------------------------------------- the real panel
print("\n  == one real forwarded call through the real panel ==")
PORT = 8172
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

    import http.cookiejar
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def jcall(path, body=None, method=None):
        data = None if body is None else json.dumps(body).encode()
        h = {"X-Requested-With": "XMLHttpRequest"}
        if data is not None:
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(BASE + path, data=data, headers=h,
                                     method=method or ("POST" if data else "GET"))
        with opener.open(req, timeout=30) as r:
            return json.loads(r.read())

    cred = io.open(os.path.join(ROOT, "instance", "first-run-credentials.txt"),
                   encoding="utf-8", errors="replace").read()
    U = re.search(r"(?im)^\s*(?:username|user|admin)\s*[:=]\s*(\S+)",
                  cred).group(1)
    P = re.search(r"(?im)^\s*(?:password|pass)\s*[:=]\s*(\S+)",
                  cred).group(1)
    jcall("/api/login", {"username": U, "password": P})
    # ApiToken.name is unique, so a leftover from a previous run answers 409
    # and this suite would only ever be runnable once. Revoke it first: the
    # panel keeps only a digest, so the old raw value is unrecoverable.
    for row in (jcall("/api/api-tokens") or []):
        if isinstance(row, dict) and row.get("name") == "mcp-asgi-probe":
            jcall("/api/api-tokens/%d" % row["id"], method="DELETE")
    tok = jcall("/api/api-tokens", {"name": "mcp-asgi-probe", "scopes": "full",
                                    "password_confirm": P})["token_once"]

    import main as M
    ex = AsgiExecutor(M.app, token=tok)

    res = asyncio.run(ex.call(T.TOOL_INDEX["panel_stats"], {}))
    check("a forwarded stats call is 200", res.get("status") == 200,
          json.dumps(res)[:120])
    check("and returns real data", isinstance(res.get("data"), dict)
          and "total_users" in res["data"], json.dumps(res)[:120])

    res = asyncio.run(ex.call(T.TOOL_INDEX["list_users"], {"limit": 2}))
    check("a forwarded call WITH a query works - the spike's 404",
          res.get("status") == 200 and "items" in res.get("data", {}),
          json.dumps(res)[:140])

    res = asyncio.run(ex.call(T.TOOL_INDEX["find_user"],
                              {"username": "definitely_not_here"}))
    check("a forwarded 404 keeps the panel's status",
          res.get("status") == 404, json.dumps(res)[:110])

    res = asyncio.run(AsgiExecutor(M.app, token="zfp_bogus").call(
        T.TOOL_INDEX["panel_stats"], {}))
    check("a bogus bearer gives 401, so the real auth stack ran",
          res.get("status") == 401, json.dumps(res)[:110])

    uname = "mcp_asgi_probe_user"
    for row in (jcall("/api/users?limit=200").get("items") or []):
        if row.get("username") == uname:
            jcall("/api/users/%d" % row["id"], method="DELETE")
    res = asyncio.run(ex.call(T.TOOL_INDEX["create_user"],
                              {"username": uname, "protocols": ["vless"],
                               "volume_gb": 5, "days": 30}))
    check("a forwarded POST with a body reaches the handler",
          res.get("status") in (200, 201), json.dumps(res)[:160])
    for row in (jcall("/api/users?limit=200").get("items") or []):
        if row.get("username") == uname:
            jcall("/api/users/%d" % row["id"], method="DELETE")
            break

    # The shape the panel actually accepts, proved rather than assumed:
    # protocols is a list, and days=0 is a 422 (ge=1) - the sentinel is
    # start_on_first_use. The first draft of the tool table sent a
    # comma-separated string and documented days=0, so every create_user it
    # asked for was refused.
    res = asyncio.run(ex.call(T.TOOL_INDEX["create_user"],
                              {"username": uname + "2",
                               "protocols": "vless", "volume_gb": 5,
                               "days": 30}))
    check("a comma-separated protocols string is refused, as the panel does",
          res.get("status") == 422, json.dumps(res)[:140])
    res = asyncio.run(ex.call(T.TOOL_INDEX["create_user"],
                              {"username": uname + "3", "protocols": ["vless"],
                               "volume_gb": 5, "days": 0}))
    check("days=0 is refused: the schema is ge=1", res.get("status") == 422,
          json.dumps(res)[:140])
    for row in (jcall("/api/users?limit=200").get("items") or []):
        if row.get("username", "").startswith(uname):
            jcall("/api/users/%d" % row["id"], method="DELETE")
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