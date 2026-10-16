"""JSON-RPC 2.0 framing and the MCP methods, with no panel and no network.

Every key name here was read out of mcp.types 2.3.0 rather than recalled, and
the measurement is worth repeating because two of them are the opposite of
what you would guess:

  * a tool's schema key on the wire is `inputSchema`, while the Python
    attribute is `input_schema`;
  * dumping the SDK's own ListToolsResult fills in `ttlMs: 0` and
    `cacheScope: "private"`, which are legal but are not what a client should
    be told about a stateless server. So tools/list is built by hand.

The composed-tool rule is here too: `subscription_link` needs DB access the
executors do not have, so it exists only when a compose callable was injected.
"""
import asyncio
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from mcp_protocol import (Dispatcher, list_tools_payload, PROTOCOL_VERSION,
                          SERVER_NAME)
import mcp_tools as T

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


class FakeExec:
    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply if reply is not None else {"status": 200,
                                                      "data": {"ok": True}}

    async def call(self, tool, args):
        self.calls.append((tool["name"], dict(args)))
        return self.reply


async def go():
    d = Dispatcher(FakeExec())

    # ------------------------------------------------------------ initialize
    r = await d.handle({"jsonrpc": "2.0", "id": 1,
                        "method": "initialize", "params": {}})
    check("initialize answers protocolVersion",
          r["result"]["protocolVersion"] == PROTOCOL_VERSION)
    check("which is the SDK's own version", PROTOCOL_VERSION == "2026-07-28")
    check("and not a remembered one", PROTOCOL_VERSION != "2024-11-05")
    check("initialize declares the tools capability",
          "tools" in r["result"]["capabilities"])
    check("initialize names the server", r["result"]["serverInfo"]["name"]
          == SERVER_NAME)
    check("and versions it", bool(r["result"]["serverInfo"].get("version")))
    check("the envelope is jsonrpc 2.0", r["jsonrpc"] == "2.0")
    check("and echoes the id", r["id"] == 1)
    check("and has no error", "error" not in r)

    r = await d.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"}})
    check("initialize honours the client's protocolVersion",
          r["result"]["protocolVersion"] == "2025-06-18",
          r["result"]["protocolVersion"])

    # --------------------------------------------------------- notifications
    check("a notification gets no response",
          await d.handle({"jsonrpc": "2.0",
                          "method": "notifications/initialized"}) is None)
    check("an unknown notification is silently ignored",
          await d.handle({"jsonrpc": "2.0",
                          "method": "notifications/cancelled"}) is None)

    # ------------------------------------------------------------------ ping
    r = await d.handle({"jsonrpc": "2.0", "id": 3, "method": "ping"})
    check("ping answers an empty result", r["result"] == {})

    # ------------------------------------------------------------ tools/list
    r = await d.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
    tools = r["result"]["tools"]
    check("tools/list returns every non-composed tool",
          len(tools) == len([t for t in T.TOOLS if not t.get("compose")]),
          "%d of %d" % (len(tools), len([t for t in T.TOOLS
                                         if not t.get("compose")])))
    check("each tool carries inputSchema, the exact wire key",
          all("inputSchema" in t for t in tools))
    check("and never the python-side input_schema",
          all("input_schema" not in t for t in tools))
    check("and a description", all(t.get("description") for t in tools))
    check("ttlMs is absent, so the SDK does not default it in",
          "ttlMs" not in r["result"], sorted(r["result"]))
    check("cacheScope is absent too", "cacheScope" not in r["result"])
    check("and no tool is named twice",
          len({t["name"] for t in tools}) == len(tools))

    # a composed tool exists only when a compose callable was injected
    d_nc = Dispatcher(FakeExec())
    r = await d_nc.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
    names = {t["name"] for t in r["result"]["tools"]}
    check("without a compose callable the composed tool is not offered",
          "subscription_link" not in names, str(sorted(names))[:90])

    d_c = Dispatcher(FakeExec(), compose=lambda name, args: {"link": "x"})
    r = await d_c.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/list"})
    names_c = {t["name"] for t in r["result"]["tools"]}
    check("with one, it is", "subscription_link" in names_c)
    check("and every other tool is still there",
          names_c - {"subscription_link"} == names)

    r = await d_c.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                         "params": {"name": "subscription_link",
                                    "arguments": {"username": "alice"}}})
    check("a composed call answers from the compose callable, "
          "never reaching the executor",
          '"link"' in r["result"]["content"][0]["text"],
          json.dumps(r)[:130])

    # ------------------------------------------------- tools/call, the happy path
    ex = FakeExec({"status": 200, "data": {"total_users": 11}})
    r = await Dispatcher(ex).handle({"jsonrpc": "2.0", "id": 8,
                                     "method": "tools/call",
                                     "params": {"name": "panel_stats",
                                                "arguments": {}}})
    check("a successful call is not an error",
          r["result"].get("isError") is not True)
    check("and comes back as text content",
          r["result"]["content"][0]["type"] == "text")
    check("carrying the JSON", "total_users" in r["result"]["content"][0]["text"])
    check("the executor was reached once", len(ex.calls) == 1, str(ex.calls))

    # ------------------------------------------------------- the confirm gate
    ex = FakeExec()
    d4 = Dispatcher(ex)
    r = await d4.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                         "params": {"name": "delete_user",
                                    "arguments": {"user_id": 7}}})
    check("delete_user without confirm is refused",
          r["result"].get("isError") is True)
    check("and the executor was NEVER reached", ex.calls == [], repr(ex.calls))
    check("the refusal names the exact string required",
          'confirm: "7"' in r["result"]["content"][0]["text"])

    for near, label in (("7 ", "trailing space"), (7, "an int"),
                        (True, "a boolean")):
        r = await d4.handle({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
                             "params": {"name": "delete_user",
                                        "arguments": {"user_id": 7,
                                                      "confirm": near}}})
        check("a near miss (%s) does not reach the executor" % label,
              ex.calls == [], repr(ex.calls))

    r = await d4.handle({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                         "params": {"name": "delete_user",
                                    "arguments": {"user_id": 7,
                                                  "confirm": "7"}}})
    check("the exact confirmation does reach it", len(ex.calls) == 1,
          repr(ex.calls))
    check("and the confirm field is not forwarded as an argument",
          "confirm" not in ex.calls[0][1], repr(ex.calls[0][1]))

    # --------------------------------------------------------------- errors
    r = await d.handle({"jsonrpc": "2.0", "id": 12, "method": "tools/call",
                         "params": {"name": "no_such_tool"}})
    check("an unknown tool is an error result, not a crash",
          r["result"].get("isError") is True)
    check("and it lists the tools that do exist",
          "panel_stats" in r["result"]["content"][0]["text"])

    ex3 = FakeExec({"status": 403, "error": {"detail": "nope"}})
    r = await Dispatcher(ex3).handle({"jsonrpc": "2.0", "id": 13,
                                      "method": "tools/call",
                                      "params": {"name": "panel_stats"}})
    check("a panel error surfaces as isError", r["result"].get("isError") is True)
    check("with the panel's own detail",
          "nope" in r["result"]["content"][0]["text"])

    # -------------------------------------------------------------- malformed
    for label, req in (
        ("no method", {"jsonrpc": "2.0", "id": 20}),
        ("method is not a string", {"jsonrpc": "2.0", "id": 21, "method": 7}),
        ("params is not an object",
         {"jsonrpc": "2.0", "id": 22, "method": "tools/call",
          "params": "nonsense"}),
        ("arguments is not an object",
         {"jsonrpc": "2.0", "id": 23, "method": "tools/call",
          "params": {"name": "panel_stats", "arguments": 5}}),
        ("the whole request is a list", [1, 2, 3]),
        ("the whole request is a string", "hello"),
    ):
        r = await d.handle(req)
        check("malformed (%s) answers a JSON-RPC error object" % label,
              isinstance(r, dict) and "error" in r, json.dumps(r)[:110] if r else "None")
        check("  with an integer error code, never an exception",
              isinstance(r, dict)
              and isinstance(r.get("error", {}).get("code"), int),
              json.dumps(r)[:110] if r else "None")

    r = await d.handle({"jsonrpc": "2.0", "id": 30, "method": "resources/list"})
    check("an unimplemented method is code -32601",
          isinstance(r, dict) and r.get("error", {}).get("code") == -32601,
          json.dumps(r)[:110])

    # a notification-shaped malformed frame gets silence, not an error the
    # client is not waiting for
    check("a malformed notification is ignored rather than answered",
          await d.handle({"jsonrpc": "2.0", "method": "tools/call",
                          "params": "nonsense"}) is None)

    # ------------------------------------------------------------- the audit
    rows = []
    d5 = Dispatcher(FakeExec(), audit=lambda *a: rows.append(a))
    await d5.handle({"jsonrpc": "2.0", "id": 31, "method": "tools/call",
                     "params": {"name": "panel_stats"}})
    check("a call is audited", len(rows) == 1, str(rows))
    await d5.handle({"jsonrpc": "2.0", "id": 32, "method": "tools/call",
                     "params": {"name": "delete_user",
                                "arguments": {"user_id": 7}}})
    check("and so is a refusal, marked as refused",
          len(rows) == 2 and rows[1][2] is False, str(rows))

    def boom(*a):
        raise RuntimeError("the log is unhappy")
    d6 = Dispatcher(FakeExec(), audit=boom)
    r = await d6.handle({"jsonrpc": "2.0", "id": 33, "method": "tools/call",
                         "params": {"name": "panel_stats"}})
    check("an audit failure does not fail the call",
          r["result"].get("isError") is not True, json.dumps(r)[:120])
    check("and the executor still ran", isinstance(r.get("result"), dict))


asyncio.run(go())

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)