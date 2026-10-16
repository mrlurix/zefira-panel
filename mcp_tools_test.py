"""The tool table is data, so its properties are testable without a panel.

Two checks here exist because the table drifted once already:

  - `input_schema`, not `inputSchema`. The MCP wire format uses the camelCase
    key (read out of mcp.types 2.3.0, not recalled); the Python attribute is
    snake_case. Storing the wire name here and converting later is how a tool
    ends up invisible to a client.
  - every route the table names must be registered in main.py. Two of the
    twenty-five tools in the first draft of the design pointed at routes that
    do not exist, and nothing would have said so until a client called them.
"""
import ast
import io
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import mcp_tools as T

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


print("  %d tools in the table\n" % len(T.TOOLS))

names = [t["name"] for t in T.TOOLS]
check("every tool has a unique name", len(names) == len(set(names)),
      str([n for n in names if names.count(n) > 1]))
check("every tool has a description over 20 chars",
      all(len(t.get("description", "")) > 20 for t in T.TOOLS))
check("every tool declares a JSON Schema object",
      all(t["input_schema"].get("type") == "object" for t in T.TOOLS))
check("every tool declares a known method",
      all(t["method"] in ("GET", "POST", "PATCH", "PUT", "DELETE")
          for t in T.TOOLS))
check("every tool's path starts with /api",
      all(t["path"].startswith("/api") for t in T.TOOLS))
check("PROTOCOL_VERSION is the SDK's own, not a remembered one",
      T.PROTOCOL_VERSION == "2026-07-28", T.PROTOCOL_VERSION)
check("the table uses input_schema, never the wire name inputSchema",
      all("inputSchema" not in t and "input_schema" in t for t in T.TOOLS))

# ------------------------------------------------------------ confirmation
for name in ("delete_user", "restore_backup", "update_settings",
             "apply_update", "delete_api_token", "create_api_token"):
    check("%s is destructive" % name, name in T.DESTRUCTIVE)

msg = T.check_confirmation("delete_user", {"user_id": 7})
check("delete_user without confirm is refused", msg is not None)
check("and the refusal names the exact string required",
      msg is not None and 'confirm: "7"' in msg, repr(msg)[:90])

check("delete_user with the exact id proceeds",
      T.check_confirmation("delete_user", {"user_id": 7, "confirm": "7"}) is None)
check("delete_user with the wrong string is still refused",
      T.check_confirmation("delete_user", {"user_id": 7,
                                            "confirm": "alice"}) is not None)
check("a read-only tool needs no confirmation",
      T.check_confirmation("panel_stats", {}) is None)

# a sloppy comparison here would be the hole the gate exists to close
check("trailing whitespace does not satisfy the confirmation",
      T.check_confirmation("delete_user", {"user_id": 7,
                                            "confirm": "7 "}) is not None)
check("a non-string confirmation does not satisfy it",
      T.check_confirmation("delete_user", {"user_id": 7,
                                            "confirm": 7}) is not None)
check("confirm=true does not satisfy it",
      T.check_confirmation("delete_user", {"user_id": 7,
                                            "confirm": True}) is not None)
check("confirm with a unicode lookalike does not satisfy it",
      T.check_confirmation("delete_user", {"user_id": 7,
                                            "confirm": "７"}) is not None)

# the keyword confirmations
for name, args, want in (("update_settings", {"settings": {}}, "REPLACE"),
                         ("restore_backup", {"backup": {}}, "RESTORE"),
                         ("apply_update", {}, "APPLY"),
                         ("delete_api_token", {"token_id": 3}, "3"),
                         ("create_api_token", {"name": "bot"}, "bot")):
    check("%s requires confirm %r" % (name, want),
          T.check_confirmation(name, args) is not None
          and ('confirm: "%s"' % want) in T.check_confirmation(name, args),
          repr(T.check_confirmation(name, args))[:90])
    got = dict(args)
    got["confirm"] = want
    check("%s proceeds with it" % name,
          T.check_confirmation(name, got) is None)

# --------------------------------------------- the routes really are routed
src = io.open(os.path.join(ROOT, "main.py"), encoding="utf-8", errors="replace").read()
registered = set()
for n in ast.walk(ast.parse(src)):
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for d in n.decorator_list:
            if (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                    and d.func.attr in ("get", "post", "put", "patch", "delete")
                    and d.args and isinstance(d.args[0], ast.Constant)):
                registered.add((d.func.attr.upper(), d.args[0].value))
print("  %d routes registered in main.py\n" % len(registered))

for t in T.TOOLS:
    if t.get("compose"):
        check("%s is composed in-process, so it needs no route" % t["name"],
              bool(t["compose"]))
        # A composed tool still CARRIES a path, and the first draft of this
        # table named one that does not exist. Skipping the route check for
        # composed tools - which is what this did originally - meant that
        # route went unchecked entirely, and the mutation pointed it at a
        # 404 while the suite stayed green. Check it anyway: the compose
        # callback is what makes it work, not the absence of a check.
        check("%s's carried path is a real route too" % t["name"],
              (t["method"], t["path"]) in registered,
              "%s %s" % (t["method"], t["path"]))
        continue
    check("%s -> %s %s is a real route" % (t["name"], t["method"], t["path"]),
          (t["method"], t["path"]) in registered)

# a destructive tool that points nowhere would be a trap, not a guard
for name in T.DESTRUCTIVE:
    t = T.TOOL_INDEX.get(name)
    check("destructive %s is in the table" % name, t is not None)

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)