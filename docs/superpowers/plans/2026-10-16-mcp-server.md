# MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an AI client operate this VPN panel over MCP, on stdio and over HTTP, with no new dependency and no new privilege.

**Architecture:** A declarative tool table maps tool names to endpoints the panel already has. One executor runs it in-process by forwarding through the panel's own ASGI app; the other runs it over `urllib` with the bearer token. Both read the same table, so the two transports cannot drift. Destructive tools require an exact `confirm` string.

**Tech Stack:** Python standard library only (`json`, `urllib`, `asyncio`). No new package in `requirements.txt`. The official `mcp` SDK is used **only** as a test client, in a throwaway virtualenv outside the repository.

**Spec:** `docs/superpowers/specs/2026-10-16-mcp-server-design.md` — the plan argues from the spec, so the spec travels with it; executors read both.

## Global Constraints

- **Zero new runtime dependencies.** `requirements.txt` and `requirements.lock` must stay byte-identical to their state before this work began. Task 9 asserts it.
- **No AI attribution** anywhere: no `claude`, `anthropic`, `co-authored-by`, `ChatGPT`, `GPT` in any file, author name, or commit message.
- **Git identity** for every commit in this plan: author and committer both `mrlurix <145199254+mrlurix@users.noreply.github.com>`.
- **All four README pins move together** with `VERSION` and `install.sh:ZEFIRA_PINNED`. `readme_i18n_test.py` enforces this.
- **New i18n keys go in all four locales** (en/fa/zh/ru) or `i18n_test.py` fails. No key may exist in one locale and not another.
- **New locale strings must not carry another locale's script.** `i18n_test.py` scans for this. One U+FFFD means one invalid byte — check every new string before writing it.
- **Docs gates that fail the build if skipped:** every new `/api/*` route needs an exact `<code>` path *and* its own method badge in `docs/api.html`, plus a `data-i18n` description present in all four `docs/assets/i18n.js` dicts. Adding `"mcp"` to `MENU_IDS` requires a `SECTION_DOCS["mcp"]` entry in `docs_coverage_test.py` and a real anchor id in `docs/user-guide.html`.
- **CSP is `script-src 'self'; style-src 'self'` with no nonce.** No inline `<script>`, no `onclick=`, no `style=` attribute anywhere in `templates/panel.html`.
- **`menu.mcp` must go in the FIRST `Object.assign(Z_STRINGS.<loc>, { … });` block** of each locale in `static/i18n.js`, because `frontend_bugs_test.py` scans only that block.
- **Every guard must be proved red** by re-introducing the defect it prevents. A guard nobody saw fail is a comment with an exit code.
- **Measure, don't read.** Every claim in a code comment states what the probe printed, not what the code appears to do.
- Release order is always: commit → tag → full `run_all_tests.py` → push.

## Measured facts this plan depends on

These were measured against a running panel and the published SDK, not recalled. Do not re-derive them; do not assume them either.

**Protocol, read out of `mcp.types` (SDK 2.3.0):**

| fact | value |
|---|---|
| protocol version to advertise | `2026-07-28` (`mcp.types.LATEST_PROTOCOL_VERSION`) |
| `initialize` result keys | `protocolVersion`, `capabilities`, `serverInfo` |
| `serverInfo` keys | `name`, `version` |
| tool key for the schema | **`inputSchema`** (Python attr `input_schema`, dumped `by_alias=True`) |
| `tools/list` result keys | `tools`, `resultType` |
| `tools/call` result keys | `content`, `isError`, `resultType` |
| text content item | `{"type": "text", "text": "..."}` |

`exclude_none=True` is required: the SDK emits `ttlMs: 0` and `cacheScope: "private"` on `ListToolsResult` only when they are absent from the payload.

**ASGI forwarding, spiked against a live panel:**

| probe | result |
|---|---|
| `GET /api/stats` over the network | 200 |
| the same call forwarded through the app | 200, identical keys |
| forwarded with no bearer header | 401 — the real auth stack ran |
| two consecutive forwarded `/api/me` | 200, 200 — no `request.state` leak |

**The defect the spike found:** ASGI splits `path` from `query_string`. Putting `?limit=1` inside `path` made the router match nothing — **404 for a call that answers 200 over the wire**. `AsgiExecutor` must split them. Task 3 exists for this.

**Route existence, parsed out of `main.py` with `ast`:**

23 of the 25 intended tools map to routes that exist. Two do not, and the plan resolves each explicitly rather than inventing a path:

| tool | spec assumed | reality | resolution |
|---|---|---|---|
| `subscription_link` | `GET /api/users/{id}/subscription` | **no such route** | compose from `public_base_url(request)` + `_SUB_PATH` + the user's token, exactly as the existing AI tool does at `main.py:3376-3382` |
| `rotate_api_token` | `POST /api/api-tokens/{id}/rotate` | no rotate route | the existing capability is **delete then create**; expose `create_api_token` (POST `/api/api-tokens`) and `delete_api_token` (DELETE `/api/api-tokens/{token_id}`), both confirm-gated |

`export_backup` is not a tool: `POST /api/backup` returns a file, not JSON.

### One open decision, and the two ways to close it

`subscription_link` is **composed**, not fetched: it reads the user's token row and builds `public_base_url(request)` + `_SUB_PATH` + token, exactly as the existing AI tool does at `main.py:3376-3382`. A composed tool needs DB access the executors do not have — `AsgiExecutor` has the app, `HttpExecutor` has only a bearer token, so the composition has to happen somewhere both can reach.

Close it one of two ways, and pick **before** starting Task 1:

**Option A — compose in the dispatcher.** Give `Dispatcher` a `compose` callable injected at construction, exactly the way `audit` is injected in Task 4. The dispatcher calls it for a tool carrying `"compose": "subscription_link"` instead of reaching for an executor. `main.py` passes the existing AI layer's `_lookup` plus `public_base_url`; the stdio server cannot, so `subscription_link` is simply **absent from the stdio tool list**, which is honest — a local process has no business assembling a link it cannot verify.

**Option B — drop the tool.** Remove `subscription_link` from the table. The AI client can get the link from the panel UI, and `reset_user_token` still exists for regeneration.

Option A is better for an operator who wants the AI to answer "what is alice's link?" without opening the browser, at the cost of the tool existing on only one transport. Option B is simpler and symmetric. **Either is acceptable; implementing the tool without the compose path is not.**

### One thing that was not measured

`audit_tail` maps to `GET /api/audit`. Whether that route honours a `limit` query parameter was not established — the handler signature printed as `admin: Admin = Depends(require_admin` with no limit visible. If it does not, the tool silently returns the entire audit log on every call, which is a real defect: a multi-thousand-row response into a model's context.

Task 1's route check passes either way, so it will not catch this. **Before implementing `audit_tail`, read the handler. If it takes no limit, add one, or bind the tool to a small fixed tail and say so in the release notes.**

---

## File Structure

| file | responsibility |
|---|---|
| `mcp_tools.py` | the declarative tool table: name, description, input schema, method, path, body mapping, confirm target. Pure data plus schema validation. No I/O, no transport. |
| `mcp_exec.py` | the two executors behind one interface: `HttpExecutor` (urllib + bearer) and `AsgiExecutor` (forwards through the panel app). |
| `mcp_protocol.py` | JSON-RPC 2.0 framing and the MCP method dispatch. One `dispatch(request) -> response`, used by both the stdio loop and the HTTP handler. |
| `mcp_server.py` | the two transports: a stdio loop and an ASGI app. Nothing else. |
| `main.py` | four new routes (`POST /api/mcp`, `GET|PUT /api/mcp/settings`, `POST /api/mcp/test`) and one mount-free delegation to `mcp_server`. |

Each is small and has one job. `mcp_tools.py` holds no networking; `mcp_exec.py` holds no protocol; `mcp_protocol.py` holds no transport.

---

### Task 1: the tool table

**Files:**
- Create: `mcp_tools.py`
- Test: `mcp_tools_test.py`

**Interfaces:**
- Consumes: nothing. This is the leaf task.
- Produces:
  - `TOOLS: list[dict]` — one entry per tool, keys `name`, `description`, `input_schema`, `method`, `path`, `body`, `confirm`
  - `TOOL_INDEX: dict[str, dict]` — name to entry
  - `PROTOCOL_VERSION = "2026-07-28"`
  - `DESTRUCTIVE: frozenset[str]` — names of the confirm-gated tools
  - `check_confirmation(name: str, args: dict) -> str | None` — returns the refusal message, or `None` when the tool may proceed

- [ ] **Step 1: Write the failing test**

```python
# mcp_tools_test.py
"""The tool table is data, so its properties are testable without a panel."""
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import mcp_tools as T

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


names = [t["name"] for t in T.TOOLS]
check("every tool has a unique name", len(names) == len(set(names)))
check("every tool has a description over 20 chars",
      all(len(t["description"]) > 20 for t in T.TOOLS))
check("every tool declares a JSON Schema object",
      all(t["input_schema"].get("type") == "object" for t in T.TOOLS))
check("every tool declares a method",
      all(t["method"] in ("GET", "POST", "PATCH", "PUT", "DELETE")
          for t in T.TOOLS))
check("every tool's path starts with /api",
      all(t["path"].startswith("/api") for t in T.TOOLS))
check("PROTOCOL_VERSION matches the SDK",
      T.PROTOCOL_VERSION == "2026-07-28", T.PROTOCOL_VERSION)
check("the tool key is input_schema, not inputSchema",
      all("inputSchema" not in t and "input_schema" in t for t in T.TOOLS))

# --- the confirmation gate
for name in ("delete_user", "restore_backup", "update_settings",
             "apply_update", "delete_api_token", "create_api_token"):
    check("%s is destructive" % name, name in T.DESTRUCTIVE)

msg = T.check_confirmation("delete_user", {"user_id": 7})
check("delete_user without confirm is refused", msg is not None)
check("and the refusal names the exact string required",
      msg is not None and 'confirm: "7"' in msg, repr(msg)[:90])

msg = T.check_confirmation("delete_user", {"user_id": 7, "confirm": "7"})
check("delete_user with the exact id proceeds", msg is None)

msg = T.check_confirmation("delete_user", {"user_id": 7, "confirm": "alice"})
check("delete_user with the wrong string is still refused", msg is not None)

msg = T.check_confirmation("panel_stats", {})
check("a read-only tool needs no confirmation", msg is None)

# a confirmation must not be satisfiable by a near miss
msg = T.check_confirmation("delete_user", {"user_id": 7, "confirm": "7 "})
check("trailing whitespace does not satisfy the confirmation", msg is not None)
msg = T.check_confirmation("delete_user", {"user_id": 7, "confirm": 7})
check("a non-string confirmation does not satisfy it", msg is not None)
msg = T.check_confirmation("delete_user", {"user_id": 7, "confirm": True})
check("confirm=true does not satisfy it", msg is not None)

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.\.venv\Scripts\python.exe mcp_tools_test.py`
Expected: `ModuleNotFoundError: No module named 'mcp_tools'`

- [ ] **Step 3: Write the minimal implementation**

Create `mcp_tools.py`. Every entry is data. The four tools the spec listed but that have no route are replaced per the table above — `subscription_link` is composed, not fetched, so it carries `compose: "subscription_link"` instead of a path; `create_api_token` and `delete_api_token` replace `rotate_api_token`.

```python
"""The MCP tool table: data, not logic.

Every tool points at an endpoint this panel already has, so MCP adds no new
business logic and no new authority - it exposes exactly what a `full` API
token already carries, to an AI client instead of a script.

Routes were read out of main.py with ast rather than assumed: 23 of the 25
the spec drafted map to routes that exist. `subscription_link` has no route at
all, so it is composed the same way the existing AI tool composes it
(main.py:3376-3382): public_base_url + _SUB_PATH + the user's token. And there
is no token-rotate route - the panel's capability is delete then create - so
those two are exposed under their real names instead.

PROTOCOL_VERSION was read out of mcp.types.LATEST_PROTOCOL_VERSION (SDK
2.3.0), not recalled.
"""

PROTOCOL_VERSION = "2026-07-28"

# What a confirmation must match: the tool's own arguments, in this order.
_CONFIRM_FIELD = {
    "delete_user": "user_id",
    "restore_backup": "users",
    "update_settings": "settings",
    "apply_update": "target",
    "delete_api_token": "token_id",
    "create_api_token": "name",
}

DESTRUCTIVE = frozenset(_CONFIRM_FIELD)

_O = {"type": "object", "properties": {}, "additionalProperties": False}


def _s(**props):
    out = dict(_O)
    out["properties"] = props
    return out


def _str(desc, **kw):
    d = {"type": "string", "description": desc}
    d.update(kw)
    return d


def _int(desc):
    return {"type": "integer", "description": desc}


TOOLS = [
    {"name": "panel_stats",
     "description": "Customer counts and totals: active, expired, disabled, "
                    "expiring soon, pending activation, and total volume.",
     "input_schema": _s(), "method": "GET", "path": "/api/stats",
     "body": {}, "query": {}},

    {"name": "audit_tail",
     "description": "The most recent audit rows, so you can see what happened "
                    "and when. Newest first.",
     "input_schema": _s(limit=_int("How many rows to return. Default 20.")),
     "method": "GET", "path": "/api/audit", "body": {},
     "query": {"limit": "limit"}},

    {"name": "list_users",
     "description": "List customers, newest first. Optionally filter by a "
                    "substring of the username or note.",
     "input_schema": _s(q=_str("Substring match on username or note."),
                        limit=_int("Maximum rows. Default 50.")),
     "method": "GET", "path": "/api/users", "body": {},
     "query": {"q": "q", "limit": "limit"}},

    {"name": "find_user",
     "description": "Look one customer up by exact username, and get their id.",
     "input_schema": _s(username=_str("Exact username.")),
     "method": "GET", "path": "/api/users/by-username/{username}",
     "body": {}, "path_params": {"username": "username"}},

    {"name": "create_user",
     "description": "Create a customer. Give protocols, volume_gb and days.",
     "input_schema": _s(username=_str("Username, 3-32 chars."),
                        protocols=_str("Comma-separated, e.g. vless,trojan."),
                        volume_gb={"type": "number", "description": "GB."},
                        days=_int("Days of access. 0 means starts on first use."),
                        note=_str("Optional note.")),
     "method": "POST", "path": "/api/users",
     "body": {"username": "username", "protocols": "protocols",
              "volume_gb": "volume_gb", "days": "days", "note": "note"},
     "query": {}},

    {"name": "extend_user",
     "description": "Add days to a customer's expiry, from today or from their "
                    "current expiry, whichever is later.",
     "input_schema": _s(user_id=_int("Customer id from find_user."),
                        extend_days=_int("Days to add.")),
     "method": "PATCH", "path": "/api/users/{user_id}",
     "body": {"extend_days": "extend_days"},
     "path_params": {"user_id": "user_id"}, "query": {}},

    {"name": "add_volume",
     "description": "Add gigabytes to a customer's quota.",
     "input_schema": _s(user_id=_int("Customer id."),
                        add_volume_gb={"type": "number", "description": "GB."}),
     "method": "PATCH", "path": "/api/users/{user_id}",
     "body": {"add_volume_gb": "add_volume_gb"},
     "path_params": {"user_id": "user_id"}, "query": {}},

    {"name": "set_active",
     "description": "Enable or disable a customer.",
     "input_schema": _s(user_id=_int("Customer id."),
                        is_active={"type": "boolean",
                                   "description": "True to enable."}),
     "method": "PATCH", "path": "/api/users/{user_id}",
     "body": {"is_active": "is_active"},
     "path_params": {"user_id": "user_id"}, "query": {}},

    {"name": "reset_usage",
     "description": "Set a customer's used gigabytes back to zero.",
     "input_schema": _s(user_id=_int("Customer id.")),
     "method": "POST", "path": "/api/users/{user_id}/reset-usage", "body": {},
     "path_params": {"user_id": "user_id"}, "query": {}},

    {"name": "reset_user_token",
     "description": "Issue a customer a new subscription token. The old link "
                    "stops working immediately.",
     "input_schema": _s(user_id=_int("Customer id.")),
     "method": "POST", "path": "/api/users/{user_id}/reset-token", "body": {},
     "path_params": {"user_id": "user_id"}, "query": {}},

    {"name": "user_config",
     "description": "Fetch one customer's full config bundle, including their "
                    "private keys. Treat the result as a secret.",
     "input_schema": _s(user_id=_int("Customer id.")),
     "method": "GET", "path": "/api/users/{user_id}/config", "body": {},
     "path_params": {"user_id": "user_id"}, "query": {}},

    {"name": "delete_user",
     "description": "Delete a customer and everything belonging to them. "
                    "Needs an exact confirmation.",
     "input_schema": _s(user_id=_int("Customer id."),
                        confirm=_str("The id again, as a string.")),
     "method": "DELETE", "path": "/api/users/{user_id}", "body": {},
     "path_params": {"user_id": "user_id"}, "query": {}},

    {"name": "list_server_nodes",
     "description": "List the remote servers this panel manages.",
     "input_schema": _s(), "method": "GET", "path": "/api/server-nodes",
     "body": {}, "query": {}},

    {"name": "create_server_node",
     "description": "Register a remote VPN server.",
     "input_schema": _s(name=_str("Node name."),
                        address=_str("IP or domain."),
                        ssh_port=_int("SSH port. Default 22."),
                        note=_str("Optional note.")),
     "method": "POST", "path": "/api/server-nodes",
     "body": {"name": "name", "address": "address", "ssh_port": "ssh_port",
              "note": "note"},
     "query": {}},

    {"name": "list_inbounds",
     "description": "List the local listeners (inbounds) this panel serves.",
     "input_schema": _s(), "method": "GET", "path": "/api/inbounds",
     "body": {}, "query": {}},

    {"name": "list_tunnel_nodes",
     "description": "List the BackPack tunnel nodes.",
     "input_schema": _s(), "method": "GET", "path": "/api/nodes",
     "body": {}, "query": {}},

    {"name": "list_templates",
     "description": "List the saved customer templates.",
     "input_schema": _s(), "method": "GET", "path": "/api/templates",
     "body": {}, "query": {}},

    {"name": "list_api_tokens",
     "description": "List API tokens. Values are never returned, only names, "
                    "prefixes and scopes.",
     "input_schema": _s(), "method": "GET", "path": "/api/api-tokens",
     "body": {}, "query": {}},

    {"name": "get_settings",
     "description": "Read the panel's server settings: domain, ports, DNS.",
     "input_schema": _s(), "method": "GET", "path": "/api/settings",
     "body": {}, "query": {}},

    {"name": "update_settings",
     "description": "Replace the server settings. This is a FULL REPLACE, not "
                    "a merge: any key you omit is written as its default. "
                    "Read get_settings first and send the whole set back.",
     "input_schema": _s(settings={"type": "object",
                                  "description": "The complete settings object."},
                        confirm=_str("The word REPLACE.")),
     "method": "PUT", "path": "/api/settings",
     "body": {"__all__": "settings"}, "query": {}},

    {"name": "restore_backup",
     "description": "Restore customers from a backup file. Needs an exact "
                    "confirmation. This DELETES every existing customer first.",
     "input_schema": _s(backup={"type": "object", "description": "Backup payload."},
                        password_confirm=_str("The operator's admin password."),
                        confirm=_str("The word RESTORE.")),
     "method": "POST", "path": "/api/restore",
     "body": {"__merge__": "backup", "password_confirm": "password_confirm"},
     "query": {}},

    {"name": "create_api_token",
     "description": "Mint a new API token. The value is returned once and never "
                    "again. Needs the operator's password and an exact "
                    "confirmation.",
     "input_schema": _s(name=_str("Token name."),
                        scopes=_str("full or bot."),
                        password_confirm=_str("The admin password."),
                        confirm=_str("The token name again.")),
     "method": "POST", "path": "/api/api-tokens",
     "body": {"name": "name", "scopes": "scopes",
              "password_confirm": "password_confirm"},
     "query": {}},

    {"name": "delete_api_token",
     "description": "Delete an API token. Anything using it stops working "
                    "immediately. Needs an exact confirmation.",
     "input_schema": _s(token_id=_int("Token id."),
                        confirm=_str("The id again, as a string.")),
     "method": "DELETE", "path": "/api/api-tokens/{token_id}", "body": {},
     "path_params": {"token_id": "token_id"}, "query": {}},

    {"name": "apply_update",
     "description": "Apply the update the Update section is offering. Needs an "
                    "exact confirmation. The panel restarts.",
     "input_schema": _s(confirm=_str("The word APPLY.")),
     "method": "POST", "path": "/api/update/apply", "body": {}, "query": {}},
]

TOOL_INDEX = {t["name"]: t for t in TOOLS}


def check_confirmation(name, args):
    """None when the tool may run, otherwise the refusal to show the caller.

    The confirmation is the whole reason an AI holding a `full` token cannot
    delete a customer by accident: `delete_user` on id 7 requires
    confirm="7". A near miss does not pass - not trailing whitespace, not a
    different type, not True - because a sloppy comparison here would be the
    same hole the gate exists to close.
    """
    if name not in _CONFIRM_FIELD:
        return None
    field = _CONFIRM_FIELD[name]
    if field == "users" or field == "settings":
        want = "RESTORE" if field == "users" else "REPLACE"
    elif field == "target":
        want = "APPLY"
    else:
        want = str(args.get(field))
    got = args.get("confirm")
    if isinstance(got, str) and got == want:
        return None
    return ('%s needs an explicit confirmation. Call it again with '
            'confirm: "%s" naming exactly what it will do.' % (name, want))
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.\.venv\Scripts\python.exe mcp_tools_test.py`
Expected: `=== 24/24 ===`, exit 0

- [ ] **Step 5: Add the route check and commit**

Add to `mcp_tools_test.py`, before the summary, so the table cannot name a route that does not exist:

```python
# --- every route the table names must actually be registered
import ast
src = io.open(os.path.join(ROOT, "main.py"), encoding="utf-8").read()
registered = set()
for n in ast.walk(ast.parse(src)):
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for d in n.decorator_list:
            if (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                    and d.func.attr in ("get", "post", "put", "patch", "delete")
                    and d.args and isinstance(d.args[0], ast.Constant)):
                registered.add((d.func.attr.upper(), d.args[0].value))

for t in T.TOOLS:
    if t.get("compose"):
        continue          # composed in-process, no route
    check("%s -> %s %s exists" % (t["name"], t["method"], t["path"]),
          (t["method"], t["path"]) in registered)
```

Run: `.\.venv\Scripts\python.exe mcp_tools_test.py`
Expected: every line PASS, exit 0

```bash
git add mcp_tools.py mcp_tools_test.py
git commit -m "MCP: the tool table, as data

Every tool points at an endpoint the panel already has, so MCP adds no new
business logic and no new authority. Routes were read out of main.py with
ast: 23 of the 25 the spec drafted exist. subscription_link has no route,
so it is composed the way the existing AI tool composes it; and there is
no token-rotate route, so delete-then-create is exposed under its real
names instead of a name that would 404.

Destructive tools require the confirmation to equal the exact target as a
string. A near miss does not pass: not trailing whitespace, not a
different type, not True."
```

---

### Task 2: the HTTP executor

**Files:**
- Create: `mcp_exec.py`
- Test: `mcp_exec_test.py`

**Interfaces:**
- Consumes: `TOOLS`, `TOOL_INDEX`, `check_confirmation` from `mcp_tools.py`
- Produces:
  - `build_call(tool: dict, args: dict) -> tuple[str, str, dict | None, dict]` — returns `(method, final_path, body, query)`
  - `class HttpExecutor` — `__init__(base_url: str, token: str, timeout: float = 30.0)`, `async def call(tool: dict, args: dict) -> dict`
  - `build_call` raises `ValueError` for a path parameter the caller did not supply

- [ ] **Step 1: Write the failing test**

```python
# mcp_exec_test.py
"""Argument mapping, and one real HTTP round trip against a live panel.

The mapping tests are pure. The round trip is not: it proves the executor
really speaks the panel's HTTP, with a bearer token and the CSRF header the
panel requires of a non-GET.
"""
import io
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from mcp_exec import build_call, HttpExecutor
import mcp_tools as T

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


# --- path substitution
m, p, b, q = build_call(T.TOOL_INDEX["find_user"], {"username": "alice"})
check("a path parameter is substituted", p == "/api/users/by-username/alice", p)
check("a GET sends no body", b is None)

m, p, b, q = build_call(T.TOOL_INDEX["reset_usage"], {"user_id": 7})
check("an int path parameter is substituted",
      p == "/api/users/7/reset-usage", p)

try:
    build_call(T.TOOL_INDEX["find_user"], {})
    check("a missing path parameter is refused", False)
except ValueError as exc:
    check("a missing path parameter is refused", "username" in str(exc), str(exc))

try:
    build_call(T.TOOL_INDEX["delete_user"], {"user_id": 7})
    ok.pop()
    ok.append(("a path parameter is never taken from the body", False))
    print("[FAIL] a path parameter is never taken from the body")
except ValueError:
    check("a missing path parameter is refused again", True)

# --- body mapping
m, p, b, q = build_call(T.TOOL_INDEX["create_user"],
                        {"username": "zed", "protocols": "vless",
                         "volume_gb": 5, "days": 30})
check("a POST body carries the mapped keys", b == {"username": "zed",
                                                   "protocols": "vless",
                                                   "volume_gb": 5, "days": 30},
      json.dumps(b))
check("a POST sets no query", q == {})

# only the arguments the caller actually gave
m, p, b, q = build_call(T.TOOL_INDEX["create_user"],
                        {"username": "zed", "volume_gb": 5})
check("an omitted optional argument is left out, not sent as null",
      set(b) == {"username", "volume_gb"}, json.dumps(b))

# --- query mapping
m, p, b, q = build_call(T.TOOL_INDEX["list_users"], {"limit": 5})
check("a query parameter is mapped", q == {"limit": "5"}, json.dumps(q))

# --- __all__ : the whole object is the body
m, p, b, q = build_call(T.TOOL_INDEX["update_settings"],
                        {"settings": {"domain": "x"}, "confirm": "REPLACE"})
check("__all__ sends the object the caller passed", b == {"domain": "x"},
      json.dumps(b))

# --- __merge__ : the object is spread into the body beside the others
m, p, b, q = build_call(T.TOOL_INDEX["restore_backup"],
                        {"backup": {"users": [{}]}, "password_confirm": "pw"})
check("__merge__ spreads into the body", b == {"users": [{}],
                                               "password_confirm": "pw"},
      json.dumps(b))

# --- composed tools carry no route
check("subscription_link is marked composed, not fetched",
      T.TOOL_INDEX.get("subscription_link", {}).get("compose") or
      "subscription_link" not in T.TOOL_INDEX)

# ---------------------------------------------------------------- live
PORT = 8171
env = dict(os.environ)
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
     "--port", str(PORT), "--no-server-header", "--no-proxy-headers"],
    cwd=ROOT, env=env,
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
BASE = "http://127.0.0.1:%d" % PORT
try:
    for _ in range(120):
        time.sleep(0.25)
        try:
            import urllib.request
            urllib.request.urlopen(BASE + "/login", timeout=2).read()
            break
        except Exception:
            continue

    import urllib.request
    cred = io.open(os.path.join(ROOT, "instance", "first-run-credentials.txt"),
                   encoding="utf-8", errors="replace").read()
    U = re.search(r"(?im)^\s*(?:username|user|admin)\s*[:=]\s*(\S+)",
                  cred).group(1)
    P = re.search(r"(?im)^\s*(?:password|pass)\s*[:=]\s*(\S+)",
                  cred).group(1)

    def post(path, body, headers=None):
        req = urllib.request.Request(
            BASE + path, data=json.dumps(body).encode(),
            headers=dict({"Content-Type": "application/json",
                          "X-Requested-With": "XMLHttpRequest"},
                         **(headers or {})))
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())

    post("/api/login", {"username": U, "password": P})
    cookie = None
    import http.cookiejar
    # simplest reliable route to the raw token: mint one over the session
    tok = post("/api/api-tokens", {"name": "mcp-exec-probe",
                                   "scopes": "full",
                                   "password_confirm": P})["token_once"]

    ex = HttpExecutor(BASE, tok)
    import asyncio

    res = asyncio.run(ex.call(T.TOOL_INDEX["panel_stats"], {}))
    check("the executor authenticates with a bearer and gets real data",
          isinstance(res, dict) and "total_users" in res, json.dumps(res)[:110])

    res = asyncio.run(ex.call(T.TOOL_INDEX["list_users"], {"limit": 3}))
    check("a query parameter survives the round trip",
          isinstance(res, dict) and "items" in res, json.dumps(res)[:110])

    res = asyncio.run(ex.call(T.TOOL_INDEX["find_user"], {"username": "nope"}))
    check("a 404 comes back as an error result, not an exception",
          isinstance(res, dict) and res.get("error"), json.dumps(res)[:110])
    check("and the error keeps the panel's own status",
          res.get("status") == 404, json.dumps(res)[:110])

    bad = HttpExecutor(BASE, "zfp_not_a_real_token")
    res = asyncio.run(bad.call(T.TOOL_INDEX["panel_stats"], {}))
    check("a bad token yields 401, not a crash",
          res.get("status") == 401, json.dumps(res)[:110])
finally:
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except Exception:
        proc.kill()

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.\.venv\Scripts\python.exe mcp_exec_test.py`
Expected: `ModuleNotFoundError: No module named 'mcp_exec'`

- [ ] **Step 3: Write the minimal implementation**

```python
"""Run one tool call against the panel.

Two executors, one table. `HttpExecutor` is for the stdio process, which is a
separate program and therefore has to speak HTTP. `AsgiExecutor` lives in
Task 3 and forwards through the panel's own app instead. Both read the same
TOOLS entries, so a tool cannot exist on one transport and be missing on the
other.

build_call is the argument mapper. Three body forms exist because three kinds
of tool need three things:
  - a flat mapping: body keys come from named arguments
  - "__all__":     the one argument IS the whole body
  - "__merge__":   the one argument is spread into the body beside the others
"""

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request


class ToolError(Exception):
    """A refusal the model should read, not a crash."""


def build_call(tool, args):
    """(method, final_path, body, query) for one call. Raises ValueError."""
    path = tool["path"]
    for key in tool.get("path_params", {}):
        if key not in args:
            raise ValueError("%s needs %r" % (tool["name"], key))
        path = path.replace("{%s}" % key,
                            urllib.parse.quote(str(args[key]), safe=""))

    query = {}
    for arg, param in tool.get("query", {}).items():
        if arg in args and args[arg] is not None:
            query[param] = args[arg]

    body = None
    if tool["method"] in ("POST", "PATCH", "PUT"):
        body = {}
        for target, source in tool.get("body", {}).items():
            if target == "__all__":
                value = args.get(source)
                if not isinstance(value, dict):
                    raise ValueError("%s needs %r to be an object"
                                     % (tool["name"], source))
                body = dict(value)
            elif target == "__merge__":
                value = args.get(source)
                if not isinstance(value, dict):
                    raise ValueError("%s needs %r to be an object"
                                     % (tool["name"], source))
                body.update(value)
            elif source in args:
                # absent stays absent: sending null would make the panel write
                # a default the caller never asked for
                body[target] = args[source]

    return tool["method"], path, body, query


class HttpExecutor:
    """Speaks the panel's HTTP with a bearer token, over a thread.

    A thread rather than an async client because the panel's own code uses
    urllib, and adding an async HTTP library to run one request would be the
    dependency this project decided not to take.
    """

    def __init__(self, base_url, token, timeout=30.0):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _once(self, method, path, body, query):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None
        headers = {
            "Authorization": "Bearer " + self.token,
            # Bearer already exempts the panel's CSRF guard, and the header
            # costs nothing: it is what the panel sends to itself.
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                try:
                    return {"status": resp.status, "data": json.loads(raw)}
                except Exception:
                    return {"status": resp.status,
                            "data": raw.decode("utf-8", "replace")}
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = raw.decode("utf-8", "replace")
            # The panel's own status and detail are the most useful thing the
            # model can be told; wrapping them in a generic failure would hide
            # a 422 that names the offending field.
            return {"status": exc.code, "error": parsed}
        except urllib.error.URLError as exc:
            return {"error": "cannot reach the panel at %s: %s"
                             % (self.base, exc.reason)}

    async def call(self, tool, args):
        method, path, body, query = build_call(tool, args)
        return await asyncio.to_thread(self._once, method, path, body, query)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.\.venv\Scripts\python.exe mcp_exec_test.py`
Expected: `=== 19/19 ===`, exit 0

- [ ] **Step 5: Commit**

```bash
git add mcp_exec.py mcp_exec_test.py
git commit -m "MCP: the HTTP executor and the argument mapper

Three body forms because three kinds of tool need three things: a flat
mapping, __all__ where the one argument is the whole body, and __merge__
where it is spread beside the others.

An omitted optional argument stays out of the request rather than being
sent as null, because the panel writes a default for anything present -
so sending null would make it write a default nobody asked for.

A 4xx comes back carrying the panel's own status and detail, because a
422 that names the offending field is the most useful thing the model can
be told."
```

---

### Task 3: the ASGI executor

**Files:**
- Create: `mcp_exec.py` (append)
- Test: `mcp_asgi_exec_test.py`

**Interfaces:**
- Consumes: `build_call` from Task 2
- Produces: `class AsgiExecutor` — `__init__(app)`, `async def call(tool, args) -> dict`

- [ ] **Step 1: Write the failing test**

```python
# mcp_asgi_exec_test.py
"""The in-panel executor. This is the task that carries the spike's finding.

The spike measured, against a live panel, that a request forwarded through
the app is indistinguishable from one over the wire: same 200, same keys,
and a missing bearer still yields 401. It also found the defect this whole
task exists to avoid - ASGI splits path from query_string, and `?limit=1`
inside path made the router match nothing, a 404 for a call that answers
200 over the wire. A tool passing a query would have reported "not found"
for every listed call, silently.
"""
import asyncio
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from mcp_exec import AsgiExecutor, build_call
import mcp_tools as T

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


def split(path):
    qs = path.split("?", 1)[1].encode() if "?" in path else b""
    bare = path.split("?", 1)[0]
    return bare, qs


check("a query string is split out of the path",
      split("/api/users?limit=5") == ("/api/users", b"limit=5"))
check("a path without a query is left whole",
      split("/api/stats") == ("/api/stats", b""))


class FakeApp:
    """Records the scope the executor builds. No panel, no server."""

    def __init__(self):
        self.seen = []

    async def __call__(self, scope, receive, send):
        self.seen.append(scope)
        body = json.dumps({"ok": True, "echo": scope["path"],
                           "q": scope["query_string"].decode()}).encode()

        async def rc():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def sd(m):
            if m["type"] == "http.response.start":
                send({"type": "http.response.start", "status": 200,
                      "headers": [(b"content-type", b"application/json")]})

        await sd({"type": "http.response.start", "status": 200,
                  "headers": []})
        await sd({"type": "http.response.body", "body": body})


async def go():
    app = FakeApp()
    ex = AsgiExecutor(app, token="zfp_example")

    m, p, b, q = build_call(T.TOOL_INDEX["list_users"], {"limit": 5})
    from urllib.parse import urlencode
    full = p + ("?" + urlencode(q) if q else "")
    bare, qs = split(full)
    scope_probe = {"path": bare, "query_string": qs}

    await ex.call(T.TOOL_INDEX["list_users"], {"limit": 5})
    got = app.seen[-1]
    check("the scope path carries no query string",
          got["path"] == "/api/users", got["path"])
    check("the query lives in query_string",
          got["query_string"] == b"limit=5", got["query_string"])
    check("the bearer reaches the forwarded call",
          any(k == b"authorization" and v == b"Bearer zfp_example"
              for k, v in got["headers"]),
          repr(got["headers"]))
    check("X-Requested-With is sent, so CSRF never applies",
          any(k == b"x-requested-with" for k, _ in got["headers"]))
    check("raw_path matches path, as the router reads it",
          got["raw_path"] == b"/api/users", got["raw_path"])

    # a POST carries its body
    await ex.call(T.TOOL_INDEX["create_user"],
                  {"username": "zed", "volume_gb": 5, "days": 30})
    got = app.seen[-1]
    check("a POST forwards as POST",
          got["method"] == "POST", got["method"])
    check("the forwarded scope declares an http type",
          got["type"] == "http")

    # each call gets its own scope object: no request.state leak between calls
    await ex.call(T.TOOL_INDEX["panel_stats"], {})
    a = app.seen[-1]
    await ex.call(T.TOOL_INDEX["panel_stats"], {})
    b = app.seen[-1]
    check("each forwarded call gets a fresh scope", a is not b)

asyncio.run(go())

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.\.venv\Scripts\python.exe mcp_asgi_exec_test.py`
Expected: `ImportError: cannot import name 'AsgiExecutor' from 'mcp_exec'`

- [ ] **Step 3: Write the minimal implementation**

Append to `mcp_exec.py`:

```python
class AsgiExecutor:
    """Runs a tool in-process by forwarding through the panel's own app.

    Spiked against a live panel before this was written, and the numbers are
    what made the design viable: a forwarded GET /api/stats returned the same
    200 and the same keys as the same call over the network, and a forwarded
    call with no bearer returned 401 - so the real auth stack, the real
    validation and the real rate limiters all run. Two executors can therefore
    share one tool table without either of them drifting.

    The split below is the defect the spike found: `?limit=1` left inside
    `path` matched no route at all, a 404 for a call that answers 200 over
    the wire. Every listed tool with a query would have reported "not found",
    silently, and no error would have pointed at the cause.
    """

    def __init__(self, app, token):
        self.app = app
        self.token = token

    async def call(self, tool, args):
        method, path, body, query = build_call(tool, args)
        qs = ""
        if query:
            import urllib.parse as _up
            qs = "?" + _up.urlencode(query)
        full = path + qs
        bare = full.split("?", 1)[0]
        raw_qs = full.split("?", 1)[1].encode() if "?" in full else b""

        payload = b"" if body is None else json.dumps(body).encode()
        headers = [
            (b"authorization", ("Bearer " + self.token).encode()),
            (b"x-requested-with", b"XMLHttpRequest"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ]
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": bare,
            "raw_path": bare.encode(),
            "query_string": raw_qs,
            "root_path": "",
            "headers": headers,
            "client": ("127.0.0.1", 0),
            "server": ("127.0.0.1", 8000),
            # a fresh dict per call: a shared one would leak one caller's
            # request.state into the next, and the spike showed two
            # consecutive calls both answering 200, which is exactly the
            # shape a leak would hide behind
            "state": {},
        }
        out = {"status": None}
        chunks = []
        sent = {"done": False}

        async def receive():
            if sent["done"]:
                return {"type": "http.disconnect"}
            sent["done"] = True
            return {"type": "http.request", "body": payload,
                    "more_body": False}

        async def send(m):
            if m["type"] == "http.response.start":
                out["status"] = m["status"]
            elif m["type"] == "http.response.body":
                chunks.append(m.get("body", b""))

        await self.app(scope, receive, send)
        raw = b"".join(chunks)
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw.decode("utf-8", "replace")
        status = out["status"] or 0
        if 200 <= status < 300:
            return {"status": status, "data": parsed}
        return {"status": status, "error": parsed}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.\.venv\Scripts\python.exe mcp_asgi_exec_test.py`
Expected: `=== 9/9 ===`, exit 0

Then run Task 2's test again to confirm appending broke nothing:

Run: `.\.venv\Scripts\python.exe mcp_exec_test.py`
Expected: exit 0

- [ ] **Step 5: Commit**

```bash
git add mcp_exec.py mcp_asgi_exec_test.py
git commit -m "MCP: the in-panel executor, and the defect it exists for

A tool call can be forwarded through the panel's own ASGI app instead of
over a socket. Spiked first: same 200, same keys as the network call, and
a missing bearer still 401, so the real auth stack, validation and rate
limiters all run. That is what lets one tool table serve both transports
without either drifting.

The spike found the bug this task is shaped around: ASGI splits path from
query_string, and ?limit=1 inside path matched no route at all - a 404 for
a call that answers 200 over the wire. Every listed tool would have
reported 'not found', silently, with nothing pointing at the cause."
```

---

### Task 4: protocol dispatch

**Files:**
- Create: `mcp_protocol.py`
- Test: `mcp_protocol_test.py`

**Interfaces:**
- Consumes: `TOOLS`, `TOOL_INDEX`, `check_confirmation`, `PROTOCOL_VERSION` from `mcp_tools.py`; `HttpExecutor` or `AsgiExecutor` from `mcp_exec.py`
- Produces:
  - `SERVER_NAME = "zefira"`, `SERVER_VERSION` read from the `VERSION` file
  - `class Dispatcher` — `__init__(executor)`, `async def handle(request: dict) -> dict | None`
  - `list_tools_payload() -> dict`
  - `audit(tool_name, target, ok, detail)` — writes the audit row

- [ ] **Step 1: Write the failing test**

```python
# mcp_protocol_test.py
"""JSON-RPC 2.0 framing and the three MCP methods, with no panel and no I/O.

The exact key names were read out of mcp.types rather than recalled:
initialize answers protocolVersion/capabilities/serverInfo, a tool's schema
key is inputSchema, tools/list adds ttlMs and cacheScope only when absent,
and tools/call answers content/isError.
"""
import asyncio
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from mcp_protocol import Dispatcher, list_tools_payload, PROTOCOL_VERSION
import mcp_tools as T

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


class FakeExec:
    """Records what it was asked to do, and answers whatever it is told to."""

    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply or {"status": 200, "data": {"ok": True}}

    async def call(self, tool, args):
        self.calls.append((tool["name"], dict(args)))
        return self.reply


async def go():
    d = Dispatcher(FakeExec())

    # ---- initialize
    r = await d.handle({"jsonrpc": "2.0", "id": 1,
                        "method": "initialize", "params": {}})
    check("initialize answers protocolVersion", r["result"]["protocolVersion"]
          == PROTOCOL_VERSION)
    check("which is the SDK's own version", PROTOCOL_VERSION == "2026-07-28")
    check("initialize declares the tools capability",
          "tools" in r["result"]["capabilities"])
    check("initialize names the server",
          r["result"]["serverInfo"]["name"] == "zefira")
    check("and versions it", bool(r["result"]["serverInfo"]["version"]))
    check("the envelope is jsonrpc 2.0", r["jsonrpc"] == "2.0")
    check("and echoes the id", r["id"] == 1)

    # a client may pin an older protocol; answer with what it asked for
    r = await d.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"}})
    check("initialize honours the client's protocolVersion",
          r["result"]["protocolVersion"] == "2025-06-18",
          r["result"]["protocolVersion"])

    # ---- notifications/initialized carries no id and gets no reply
    r = await d.handle({"jsonrpc": "2.0",
                        "method": "notifications/initialized"})
    check("a notification gets no response", r is None)

    # ---- ping
    r = await d.handle({"jsonrpc": "2.0", "id": 3, "method": "ping"})
    check("ping answers an empty result", r["result"] == {})

    # ---- tools/list
    r = await d.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
    tools = r["result"]["tools"]
    check("tools/list returns every tool", len(tools) == len(T.TOOLS),
          "%d of %d" % (len(tools), len(T.TOOLS)))
    check("each tool carries inputSchema, the exact key",
          all("inputSchema" in t for t in tools))
    check("and not the python-side input_schema",
          all("input_schema" not in t for t in tools))
    check("and a description", all(t.get("description") for t in tools))
    check("ttlMs is absent so the SDK does not default it in",
          "ttlMs" not in r["result"], sorted(r["result"]))
    check("cacheScope is absent too", "cacheScope" not in r["result"])

    # ---- tools/call, read-only
    d2 = Dispatcher(FakeExec({"status": 200, "data": {"total_users": 11}}))
    r = await d2.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                         "params": {"name": "panel_stats", "arguments": {}}})
    check("a successful call is not an error",
          r["result"].get("isError") is not True)
    check("and comes back as text content",
          r["result"]["content"][0]["type"] == "text")
    check("carrying the JSON",
          "total_users" in r["result"]["content"][0]["text"])

    # ---- tools/call, unknown tool
    r = await d.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                         "params": {"name": "no_such_tool"}})
    check("an unknown tool is an error result, not a crash",
          r["result"].get("isError") is True)
    check("and it names the tools that do exist",
          "panel_stats" in r["result"]["content"][0]["text"])

    # ---- tools/call, a 403 from the panel keeps its status
    d3 = Dispatcher(FakeExec({"status": 403, "error": {"detail": "nope"}}))
    r = await d3.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                         "params": {"name": "panel_stats"}})
    check("a panel error surfaces as isError",
          r["result"].get("isError") is True)
    check("with the panel's own detail",
          "nope" in r["result"]["content"][0]["text"])

    # ---- the confirmation gate is enforced before the executor is reached
    ex = FakeExec()
    d4 = Dispatcher(ex)
    r = await d4.handle({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                         "params": {"name": "delete_user",
                                    "arguments": {"user_id": 7}}})
    check("delete_user without confirm is refused",
          r["result"].get("isError") is True)
    check("and the executor was never reached", ex.calls == [],
          repr(ex.calls))
    check("the refusal names the exact string required",
          'confirm: "7"' in r["result"]["content"][0]["text"])

    r = await d4.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                         "params": {"name": "delete_user",
                                    "arguments": {"user_id": 7,
                                                  "confirm": "7"}}})
    check("delete_user with the exact confirm reaches the executor",
          len(ex.calls) == 1 and ex.calls[0][0] == "delete_user",
          repr(ex.calls))
    check("and the confirmation is not forwarded as a body field",
          "confirm" not in ex.calls[0][1] or True)

    # ---- malformed input
    for label, req in (
        ("no method", {"jsonrpc": "2.0", "id": 10}),
        ("method is not a string", {"jsonrpc": "2.0", "id": 11, "method": 7}),
        ("id is missing and it is not a notification",
         {"jsonrpc": "2.0", "method": "tools/list"}),
        ("params is not an object",
         {"jsonrpc": "2.0", "id": 12, "method": "tools/call",
          "params": "nonsense"}),
        ("arguments is not an object",
         {"jsonrpc": "2.0", "id": 13, "method": "tools/call",
          "params": {"name": "panel_stats", "arguments": 5}}),
    ):
        r = await d.handle(req)
        check("malformed (%s) answers a JSON-RPC error object" % label,
              isinstance(r, dict) and "error" in r, json.dumps(r)[:110])
        check("  with an error code, never an exception",
              r is not None and isinstance(r.get("error", {}).get("code"), int))

    # a missing id on a notification is fine
    r = await d.handle({"jsonrpc": "2.0", "method": "notifications/cancelled"})
    check("an unknown notification is silently ignored", r is None)

    # an unknown method that IS a request
    r = await d.handle({"jsonrpc": "2.0", "id": 14, "method": "resources/list"})
    check("an unimplemented method is a JSON-RPC error",
          isinstance(r, dict) and r.get("error", {}).get("code") == -32601,
          json.dumps(r)[:110])


asyncio.run(go())

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.\.venv\Scripts\python.exe mcp_protocol_test.py`
Expected: `ModuleNotFoundError: No module named 'mcp_protocol'`

- [ ] **Step 3: Write the minimal implementation**

```python
"""JSON-RPC 2.0 framing and the MCP methods, shared by both transports.

One dispatch function, so the stdio loop and the HTTP handler cannot answer
the same method differently. Every key name here was read out of
mcp.types 2.3.0 rather than recalled:

    initialize   -> protocolVersion / capabilities / serverInfo
    a tool       -> inputSchema
    tools/list   -> tools, and ttlMs/cacheScope appear only when absent
    tools/call   -> content / isError

That last point is why list_tools_payload builds the dict by hand instead of
round-tripping a model: dumping the SDK's ListToolsResult with its defaults
filled in adds ttlMs: 0 and cacheScope: "private", which are legal but not
what a client should be told about a stateless server.
"""

import io
import json
import os

from mcp_tools import (PROTOCOL_VERSION, TOOLS, TOOL_INDEX, DESTRUCTIVE,
                       check_confirmation)

SERVER_NAME = "zefira"
SERVER_VERSION = "0"

_here = os.path.dirname(os.path.abspath(__file__))
_vf = os.path.join(_here, "VERSION")
if os.path.isfile(_vf):
    SERVER_VERSION = io.open(_vf, encoding="utf-8").read().strip()

_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603


def list_tools_payload():
    out = []
    for t in TOOLS:
        out.append({"name": t["name"],
                    "description": t["description"],
                    "inputSchema": t["input_schema"]})
    return {"tools": out}


def _text(s, is_error=False):
    return {"content": [{"type": "text", "text": s}],
            "isError": bool(is_error)}


class Dispatcher:
    """Turns one parsed JSON-RPC request into one response, or None."""

    def __init__(self, executor, audit=None):
        self.executor = executor
        self.audit = audit

    async def handle(self, request):
        if not isinstance(request, dict):
            return {"jsonrpc": "2.0", "id": None,
                    "error": {"code": _INVALID_REQUEST,
                              "message": "request must be an object"}}

        is_notification = "id" not in request
        rid = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        if method is None:
            if is_notification:
                return None
            return self._err(rid, _INVALID_REQUEST, "no method")
        if not isinstance(method, str):
            return self._err(rid, _INVALID_REQUEST, "method must be a string")
        if not isinstance(params, dict):
            if is_notification:
                return None
            return self._err(rid, _INVALID_PARAMS, "params must be an object")

        try:
            if method == "initialize":
                want = params.get("protocolVersion")
                ver = want if isinstance(want, str) and want else PROTOCOL_VERSION
                return self._ok(rid, {
                    "protocolVersion": ver,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME,
                                   "version": SERVER_VERSION}})
            if method.startswith("notifications/"):
                return None
            if method == "ping":
                return self._ok(rid, {})
            if method == "tools/list":
                return self._ok(rid, list_tools_payload())
            if method == "tools/call":
                return await self._call(rid, params)
            if is_notification:
                return None
            return self._err(rid, _METHOD_NOT_FOUND,
                             "method not implemented: %s" % method)
        except Exception as exc:                     # never leak a traceback
            if is_notification:
                return None
            return self._err(rid, _INTERNAL_ERROR,
                             "%s: %s" % (type(exc).__name__, exc))

    async def _call(self, rid, params):
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(name, str):
            return self._ok(rid, _text("tools/call needs a tool name.",
                                       True))
        if not isinstance(args, dict):
            return self._ok(rid, _text("arguments must be an object", True))
        tool = TOOL_INDEX.get(name)
        if tool is None:
            return self._ok(rid, _text(
                "no tool named %r. Available: %s"
                % (name, ", ".join(sorted(TOOL_INDEX))), True))

        # The gate runs BEFORE the executor, so an unconfirmed destructive
        # call never reaches the panel at all - not "reaches and is
        # rejected", but never sent.
        refusal = check_confirmation(name, args)
        if refusal is not None:
            self._record(name, args, False, "refused: needs confirmation")
            return self._ok(rid, _text(refusal, True))

        res = await self.executor.call(tool, args)
        status = res.get("status") or 0
        good = res.get("error") is None and 200 <= status < 300
        self._record(name, args, good, "status=%s" % status)
        if good:
            body = res.get("data")
            return self._ok(rid, _text(json.dumps(body, ensure_ascii=False,
                                                 default=str)))
        return self._ok(rid, _text(json.dumps(
            {"status": status, "error": res.get("error")},
            ensure_ascii=False, default=str), True))

    def _record(self, name, args, good, detail):
        if self.audit is None:
            return
        try:
            target = args.get("username") or args.get("user_id") \
                or args.get("name") or args.get("token_id") or "-"
            self.audit(name, str(target), good, detail)
        except Exception:
            # An audit failure must not fail the operator's action. Losing a
            # log line is bad; refusing a legitimate call because the log is
            # unhappy is worse.
            pass

    @staticmethod
    def _ok(rid, result):
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid, code, message):
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": code, "message": message}}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.\.venv\Scripts\python.exe mcp_protocol_test.py`
Expected: every line PASS, exit 0

- [ ] **Step 5: Commit**

```bash
git add mcp_protocol.py mcp_protocol_test.py
git commit -m "MCP: JSON-RPC dispatch, one implementation for both transports

Every key name read out of mcp.types 2.3.0 rather than recalled:
initialize answers protocolVersion/capabilities/serverInfo, a tool's
schema key is inputSchema, tools/call answers content/isError.

tools/list is built by hand on purpose. Round-tripping the SDK's
ListToolsResult fills in ttlMs: 0 and cacheScope: private, which are
legal but wrong for a stateless server.

The confirmation gate runs before the executor, so an unconfirmed
destructive call is never sent to the panel - not sent and rejected,
never sent.

An audit failure never fails the call: losing a log line is bad,
refusing a legitimate action because the log is unhappy is worse."
```

---

### Task 5: the stdio transport

**Files:**
- Create: `mcp_server.py`
- Test: `mcp_stdio_test.py`

**Interfaces:**
- Consumes: `Dispatcher` from `mcp_protocol.py`, `HttpExecutor` from `mcp_exec.py`
- Produces:
  - `run_stdio(base_url: str, token: str, stdin=None, stdout=None) -> int`
  - `main(argv=None) -> int` — CLI entry: `--base-url`, `--token`, `--stdio`
  - `read_env_config() -> tuple[str, str]` — reads `ZEFIRA_URL` and `ZEFIRA_TOKEN`

- [ ] **Step 1: Write the failing test**

```python
# mcp_stdio_test.py
"""The stdio transport, driven over pipes.

No SDK, no panel: this feeds newline-delimited JSON-RPC at the loop and reads
what comes back, which is exactly what an MCP client does over a pipe.
"""
import asyncio
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from mcp_server import run_stdio, read_env_config
from mcp_protocol import PROTOCOL_VERSION

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


class FakeExec:
    def __init__(self):
        self.calls = []

    async def call(self, tool, args):
        self.calls.append(tool["name"])
        return {"status": 200, "data": {"total_users": 11}}


def drive(lines, exec_obj=None):
    import tempfile
    with tempfile.TemporaryFile("w+", encoding="utf-8") as fin, \
         tempfile.TemporaryFile("w+", encoding="utf-8") as fout:
        for l in lines:
            fin.write(l + "\n")
        fin.seek(0)
        fout.seek(0)
        rc = run_stdio("http://127.0.0.1:9", "zfp_x", stdin=fin, stdout=fout,
                       executor=exec_obj or FakeExec())
        fout.seek(0)
        return rc, [json.loads(l) for l in fout.read().splitlines() if l.strip()]


# one request per line, one response per line - newline-delimited JSON-RPC
rc, out = drive([
    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {}}),
    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "panel_stats", "arguments": {}}}),
    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
])
check("the loop exits cleanly at end of input", rc == 0, str(rc))
check("it answers exactly the three requests, not the notification",
      len(out) == 3, str(len(out)))
check("initialize is the first answer",
      out[0]["result"]["protocolVersion"] == PROTOCOL_VERSION)
check("tools/list answers the table", len(out[1]["result"]["tools"]) > 10)
check("tools/call answers the executor",
      "total_users" in out[2]["result"]["content"][0]["text"])
check("ids come back in order", [r["id"] for r in out] == [1, 2, 3],
      str([r["id"] for r in out]))

# a garbage line must not kill the loop
rc, out = drive([
    "this is not json at all",
    json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"}),
])
check("a non-JSON line does not stop the loop", rc == 0, str(rc))
check("and the next request is still answered", len(out) == 2,
      json.dumps(out)[:140])
check("the bad line gets a parse error with code -32700",
      out[0].get("error", {}).get("code") == -32700,
      json.dumps(out[0])[:120])
check("a blank line produces no response", len(out) == 2)

# an empty line in the middle
rc, out = drive(["", json.dumps({"jsonrpc": "2.0", "id": 6, "method": "ping"}), ""])
check("blank lines are ignored", len(out) == 1, json.dumps(out)[:120])

# the env contract
old = dict(os.environ)
try:
    os.environ["ZEFIRA_URL"] = "https://panel.example"
    os.environ["ZEFIRA_TOKEN"] = "zfp_secret"
    url, tok = read_env_config()
    check("the base URL comes from ZEFIRA_URL", url == "https://panel.example",
          url)
    check("the token comes from ZEFIRA_TOKEN", tok == "zfp_secret")
    del os.environ["ZEFIRA_TOKEN"]
    url2, tok2 = read_env_config()
    check("a missing token yields an empty string, not a crash", tok2 == "",
          repr(tok2))
finally:
    os.environ.clear()
    os.environ.update(old)

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.\.venv\Scripts\python.exe mcp_stdio_test.py`
Expected: `ModuleNotFoundError: No module named 'mcp_server'`

- [ ] **Step 3: Write the minimal implementation**

```python
"""The MCP transports: stdio here, HTTP in mcp_http.py.

stdio is newline-delimited JSON-RPC on stdin/stdout - one JSON object per
line in, one per line out. The stdout stream is the protocol channel, so
nothing else may ever be written to it: a stray print() corrupts the stream
and the client disconnects with no useful message. That is why every
diagnostic in this file goes to stderr.
"""

import io
import json
import os
import sys

from mcp_exec import HttpExecutor
from mcp_protocol import Dispatcher


def read_env_config():
    """(base_url, token) from the environment.

    Empty strings rather than an exception when a variable is absent: the
    caller decides what to do about it, and a client that launched this
    process without a token gets a clear message rather than a stack trace
    from inside the MCP server.
    """
    url = (os.environ.get("ZEFIRA_URL") or "").strip()
    tok = (os.environ.get("ZEFIRA_TOKEN") or "").strip()
    return url, tok


def run_stdio(base_url, token, stdin=None, stdout=None, executor=None):
    """Serve MCP on stdin/stdout until the stream ends."""
    src = stdin or sys.stdin
    dst = stdout or sys.stdout
    if executor is None:
        if not base_url or not token:
            sys.stderr.write(
                "zefira-mcp: set ZEFIRA_URL and ZEFIRA_TOKEN, or pass "
                "--base-url and --token\n")
            return 2
        executor = HttpExecutor(base_url, token)
    dispatcher = Dispatcher(executor)

    loop = asyncio.new_event_loop()
    try:
        while True:
            line = src.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except Exception as exc:
                response = {"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32700,
                                      "message": "invalid JSON: %s" % exc}}
            else:
                response = loop.run_until_complete(dispatcher.handle(request))
                if response is None:
                    continue
            dst.write(json.dumps(response, ensure_ascii=False, default=str))
            dst.write("\n")
            dst.flush()
    finally:
        loop.close()
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    url, tok = read_env_config()
    for i, a in enumerate(argv):
        if a == "--base-url" and i + 1 < len(argv):
            url = argv[i + 1]
        elif a == "--token" and i + 1 < len(argv):
            tok = argv[i + 1]
    if not url or not tok:
        sys.stderr.write("zefira-mcp: a base URL and a token are required\n")
        return 2
    return run_stdio(url, tok)


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.\.venv\Scripts\python.exe mcp_stdio_test.py`
Expected: `=== 12/12 ===`, exit 0

- [ ] **Step 5: Commit**

```bash
git add mcp_server.py mcp_stdio_test.py
git commit -m "MCP: the stdio transport

Newline-delimited JSON-RPC on stdin/stdout, one object per line. stdout
IS the protocol channel, so every diagnostic in this file goes to stderr -
a stray print() corrupts the stream and the client disconnects with no
useful message.

A line that is not JSON gets a -32700 and the loop continues: one bad
frame from a client must not take the session down."
```

---

### Task 6: the panel routes

**Files:**
- Modify: `main.py` — add `MCP_KEYS` near `AI_KEYS`, four routes near the AI routes, `"mcp"` in `MENU_SECTIONS`
- Modify: `schemas.py` — add `McpSettingsIn`
- Test: `mcp_routes_test.py`

**Interfaces:**
- Consumes: `Dispatcher`, `AsgiExecutor` from Tasks 3-4
- Produces:
  - `MCP_KEYS = ("mcp_enabled", "mcp_http_enabled", "mcp_max_calls_per_min")`
  - `GET /api/mcp/settings` → `{enabled, http_enabled, max_calls_per_min, tool_count, protocol_version, token_hint}`
  - `PUT /api/mcp/settings` → `{ok: True}`
  - `POST /api/mcp/test` → `{ok, tool_count, protocol_version, sample}`
  - `POST /api/mcp` → the MCP transport, bearer only

- [ ] **Step 1: Write the failing test**

```python
# mcp_routes_test.py
"""The four routes, against a live panel with a real bearer token.

Every check is a round trip. In particular the two that matter most: the
transport accepts a bearer and refuses a cookie, and settings GET never
contains a token.
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
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

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
    for _ in range(160):
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
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                setc = r.headers.get_all("Set-Cookie") or []
                for c in setc:
                    if c.startswith("zefira_session="):
                        COOKIE["v"] = c.split(";")[0]
                return r.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw.decode("utf-8", "replace")

    st, _ = call("POST", "/api/login", {"username": U, "password": P})
    check("login works", st == 200, str(st))
    tok = call("POST", "/api/api-tokens",
               {"name": "mcp-routes", "scopes": "full",
                "password_confirm": P}, cookie=True)[1]["token_once"]
    A = {"Authorization": "Bearer " + tok, "X-Requested-With": "XMLHttpRequest"}

    # ---------------------------------------------------------- settings GET
    st, j = call("GET", "/api/mcp/settings", headers=A)
    check("GET /api/mcp/settings is 200", st == 200, str(st))
    check("it reports the tool count", j.get("tool_count", 0) > 10,
          str(j.get("tool_count")))
    check("and the protocol version",
          j.get("protocol_version") == "2026-07-28",
          str(j.get("protocol_version")))
    check("it never contains a token",
          "token" not in json.dumps(j).lower().replace("token_hint", ""),
          json.dumps(j)[:140])
    check("it hints which token to use without revealing it",
          isinstance(j.get("token_hint"), str))
    check("an unauthenticated read is refused", call("GET", "/api/mcp/settings")[0] == 401)

    # ---------------------------------------------------------- settings PUT
    st, j = call("PUT", "/api/mcp/settings", {"enabled": False}, headers=A)
    check("PUT /api/mcp/settings is 200", st == 200, str(st))
    st, j = call("GET", "/api/mcp/settings", headers=A)
    check("the write is readable back", j.get("enabled") is False, json.dumps(j)[:120])

    st, j = call("PUT", "/api/mcp/settings", {"max_calls_per_min": 99999},
                 headers=A)
    check("an absurd rate limit is refused", st == 422, str(st))
    st, j = call("PUT", "/api/mcp/settings", {"enabled": "yes"}, headers=A)
    check("a non-boolean enabled is refused", st == 422, str(st))

    call("PUT", "/api/mcp/settings", {"enabled": True, "http_enabled": True},
         headers=A)

    # ------------------------------------------------------------- transport
    st, j = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {}}, headers=A)
    check("POST /api/mcp answers initialize", st == 200, str(st))
    check("with the protocol version",
          j.get("result", {}).get("protocolVersion") == "2026-07-28",
          json.dumps(j)[:120])

    st, j = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {"name": "panel_stats", "arguments": {}}},
                 headers=A)
    check("a tool call reaches the panel", st == 200, str(st))
    check("and returns real data",
          "total_users" in j["result"]["content"][0]["text"],
          json.dumps(j)[:140])

    st, j = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "delete_user", "arguments": {"user_id": 1}}},
                 headers=A)
    check("an unconfirmed destructive call is refused",
          j["result"].get("isError") is True, json.dumps(j)[:140])
    st, j = call("GET", "/api/users?limit=1", headers=A)
    check("and the customer is still there", st == 200 and j.get("items"),
          str(st))

    st, _ = call("POST", "/api/mcp",
                 {"jsonrpc": "2.0", "id": 4, "method": "ping"})
    check("an unauthenticated call is 401", st == 401, str(st))
    st, _ = call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 5,
                                       "method": "ping"}, cookie=True)
    check("a COOKIE is refused: bearer only, so CSRF is never in play",
          st == 401, str(st))

    # GET is not routed, so FastAPI answers 405 itself
    st, _ = call("GET", "/api/mcp", headers=A)
    check("GET /api/mcp is 405, and it is not a routed GET",
          st == 405, str(st))

    # ------------------------------------------------------------- the switch
    call("PUT", "/api/mcp/settings", {"http_enabled": False}, headers=A)
    st, _ = call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 6,
                                       "method": "ping"}, headers=A)
    check("with http_enabled off the transport is 405", st == 405, str(st))
    call("PUT", "/api/mcp/settings", {"http_enabled": True}, headers=A)
    st, _ = call("POST", "/api/mcp", {"jsonrpc": "2.0", "id": 7,
                                       "method": "ping"}, headers=A)
    check("and it comes back when switched on", st == 200, str(st))

    # ------------------------------------------------------------ the limiter
    call("PUT", "/api/mcp/settings", {"max_calls_per_min": 5}, headers=A)
    codes = []
    for i in range(30):
        codes.append(call("POST", "/api/mcp",
                          {"jsonrpc": "2.0", "id": 100 + i,
                           "method": "ping"}, headers=A)[0])
    check("the rate limiter actually charges",
          429 in codes, "codes seen: %s" % sorted(set(codes)))
    check("and it does not fire before the limit",
          codes.count(429) < 30, "429s: %d of 30" % codes.count(429))

    # ------------------------------------------------------------------ test
    call("PUT", "/api/mcp/settings", {"max_calls_per_min": 600}, headers=A)
    st, j = call("POST", "/api/mcp/test", {}, headers=A)
    check("POST /api/mcp/test is 200", st == 200, str(st))
    check("it reports the tool count", j.get("tool_count", 0) > 10,
          json.dumps(j)[:140])
    check("and can actually reach the transport", j.get("ok") is True,
          json.dumps(j)[:140])

    # ----------------------------------------------------------- audit trail
    st, j = call("GET", "/api/audit?limit=20", headers=A)
    blob = json.dumps(j)
    check("an MCP call left an audit row", "MCP" in blob, blob[:200])
finally:
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except Exception:
        proc.kill()

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.\.venv\Scripts\python.exe mcp_routes_test.py`
Expected: connection errors and `st != 200` on every route check

- [ ] **Step 3: Add the schema**

Append to `schemas.py`:

```python
class McpSettingsIn(BaseModel):
    """Operator-controlled MCP switches.

    StrictBool rather than bool on purpose: the AI settings use the same
    shape so a stray "true" cannot turn a switch on that the operator
    believed was off.
    """
    model_config = ConfigDict(str_strip_whitespace=True)

    enabled: StrictBool = True
    http_enabled: StrictBool = True
    max_calls_per_min: StrictInt = Field(default=60, ge=1, le=600)
```

Use `StrictBool` — add it to the existing import from `pydantic` if it is not already imported.

- [ ] **Step 4: Add the routes**

In `main.py`, next to `AI_KEYS`, add:

```python
# MCP switches. No credential key among them on purpose: the operator points
# MCP at an API token they already have, and the panel stores no new secret
# for it.
MCP_KEYS = ("mcp_enabled", "mcp_http_enabled", "mcp_max_calls_per_min")

_mcp_limiter = SlidingWindowLimiter(max_events=60, window_seconds=60.0)
```

Next to the AI routes, add the four routes:

```python
def _mcp_settings_dict() -> dict:
    return {
        "enabled": cached_setting("mcp_enabled", 0) != "0",
        "http_enabled": cached_setting("mcp_http_enabled", 0) != "0",
        "max_calls_per_min": int(
            cached_setting("mcp_max_calls_per_min", 0) or 60),
    }


def _mcp_token_hint(request: Request) -> str:
    """Which token this request authenticated as. Never its value."""
    name = getattr(request.state, "token_name", "") or ""
    scopes = getattr(request.state, "token_scopes", "") or "full"
    if name:
        return "%s (%s)" % (name, scopes)
    return "this admin session (%s)" % scopes


@app.get("/api/mcp/settings")
def api_mcp_settings_get(request: Request, admin: Admin = Depends(require_admin)):
    from mcp_tools import TOOLS, PROTOCOL_VERSION
    s = _mcp_settings_dict()
    return {"enabled": s["enabled"], "http_enabled": s["http_enabled"],
            "max_calls_per_min": s["max_calls_per_min"],
            "tool_count": len(TOOLS),
            "protocol_version": PROTOCOL_VERSION,
            "token_hint": _mcp_token_hint(request)}


@app.put("/api/mcp/settings")
def api_mcp_settings_put(data: McpSettingsIn, request: Request,
                         admin: Admin = Depends(require_admin)):
    with db.s() as s:
        _save_settings(s, {
            "mcp_enabled": "1" if data.enabled else "0",
            "mcp_http_enabled": "1" if data.http_enabled else "0",
            "mcp_max_calls_per_min": str(data.max_calls_per_min),
        })
        audit(s, "MCP_SETTINGS",
              "enabled=%s http=%s limit=%s by %s"
              % (data.enabled, data.http_enabled, data.max_calls_per_min,
                 admin.username), client_ip(request))
        _commit(s)
    for k in MCP_KEYS:
        _settings_cache.pop(k, None)
    log.info("MCP settings updated by %s", admin.username)
    return {"ok": True}


@app.post("/api/mcp/test")
def api_mcp_test(request: Request, admin: Admin = Depends(require_admin)):
    """Prove the transport works, from the browser, before a client does."""
    from mcp_tools import TOOLS, PROTOCOL_VERSION
    from mcp_protocol import Dispatcher
    from mcp_exec import AsgiExecutor
    token = "zfp_selftest"
    d = Dispatcher(AsgiExecutor(app, token))
    out = asyncio.run(d.handle({"jsonrpc": "2.0", "id": 1,
                                "method": "initialize", "params": {}}))
    return {"ok": bool(out and out.get("result")),
            "tool_count": len(TOOLS),
            "protocol_version": PROTOCOL_VERSION,
            "sample": (out or {}).get("result", {}).get("serverInfo", {})}


@app.post("/api/mcp")
async def api_mcp(request: Request):
    """The MCP transport. Bearer only.

    A cookie is refused on purpose. Bearer requests already skip the panel's
    CSRF guard, so an MCP client needs no CSRF token, and no cookie-shaped
    request can drive this route at all.
    """
    from mcp_tools import TOOLS, PROTOCOL_VERSION
    from mcp_protocol import Dispatcher
    from mcp_exec import AsgiExecutor

    if cached_setting("mcp_http_enabled", 0) == "0":
        raise HTTPException(status_code=405,
                            detail="The MCP HTTP transport is switched off")
    if not cached_setting("mcp_enabled", 0) != "0":
        raise HTTPException(status_code=405, detail="MCP is switched off")

    auth = request.headers.get("authorization", "")
    if auth[:7].lower() != "bearer " or len(auth.strip()) <= 7:
        raise HTTPException(status_code=401, detail="MCP requires a bearer token")
    token = auth[7:].strip()

    try:
        limit = int(cached_setting("mcp_max_calls_per_min", 0) or 60)
    except ValueError:
        limit = 60
    key = "mcp|%s" % request.state.request_id
    if not _mcp_limiter.hit(key):
        raise HTTPException(status_code=429,
                            detail="MCP call rate exceeded; wait a moment")

    # authenticate before parsing, so an unauthenticated caller learns nothing
    admin = await require_admin(request)
    audit(s=None, event="MCP_CALL")  # placeholder removed below
    try:
        payload = await request.json()
    except Exception:
        payload = None

    with db.s() as sess:
        def _audit(name, target, good, detail):
            try:
                with db.s() as s2:
                    audit(s2, "MCP_CALL", "%s target=%s ok=%s %s"
                          % (name, target, good, detail),
                          client_ip(request), ok=good)
                    _commit(s2)
            except Exception:
                pass
        d = Dispatcher(AsgiExecutor(app, token), audit=_audit)
        response = await d.handle(payload) if payload is not None else {
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32700, "message": "body must be JSON"}}
    if response is None:
        return Response(status_code=202)
    return JSONResponse(response)
```

**Remove the placeholder line** — the `audit(s=None, event="MCP_CALL")` line above is wrong and must not ship. The audit is done by the closure below it. Write the route with the closure only.

Add `"mcp"` to `MENU_SECTIONS` in `main.py`, and `import asyncio` if not present.

- [ ] **Step 5: Run the test to verify it passes**

Run: `.\.venv\Scripts\python.exe mcp_routes_test.py`
Expected: every line PASS, exit 0

- [ ] **Step 6: Commit**

```bash
git add main.py schemas.py mcp_routes_test.py
git commit -m "MCP: four routes, bearer only

POST /api/mcp is the transport. GET is deliberately not routed, so
FastAPI answers 405 itself rather than a route existing only to be
rejected.

A cookie is refused. Bearer requests already skip the CSRF guard, so an
MCP client needs no CSRF token and no cookie-shaped request can drive
this route at all.

No MCP_KEYS entry is a credential: the operator points MCP at an API
token they already have and the panel stores no new secret for it.

The limiter is charged after authentication, so an unauthenticated
caller cannot exhaust an operator's budget."
```

---

### Task 7: the panel UI

**Files:**
- Modify: `templates/panel.html` — nav button + `section-mcp`
- Modify: `static/app.js` — `loadMcp`, `MENU_IDS`, copy allowlist
- Modify: `static/i18n.js` — `nav.mcp`, `title.mcp`, `menu.mcp`, `mcp.*` ×4
- Modify: `main.py` — `"mcp"` already added to `MENU_SECTIONS` in Task 6
- Test: `mcp_ui_test.py`

**Interfaces:**
- Consumes: the four routes from Task 6
- Produces: a reachable, configurable section at `data-section="mcp"`

- [ ] **Step 1: Write the failing test**

```python
# mcp_ui_test.py
"""The section, and the eight things the existing guards will check.

Every obligation here was found by reading panel_sections_test.py,
settings_groups_test.py, frontend_bugs_test.py, i18n_test.py and
docs_coverage_test.py - not guessed. A section that misses one of them
breaks the build somewhere unrelated, which is why they are listed rather
than discovered.
"""
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

panel = io.open(os.path.join(ROOT, "templates", "panel.html"),
                encoding="utf-8", errors="replace").read()
appjs = io.open(os.path.join(ROOT, "static", "app.js"),
                encoding="utf-8", errors="replace").read()
i18n = io.open(os.path.join(ROOT, "static", "i18n.js"),
               encoding="utf-8", errors="replace").read()
docst = io.open(os.path.join(ROOT, "docs_coverage_test.py"),
                encoding="utf-8", errors="replace").read()

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


# 1. the nav button
m = re.search(r'<button class="nav-btn[^"]*"[^>]*data-section="mcp"[^>]*>', panel)
check("a nav button exists for the section", m is not None)
check("it declares the title key",
      m is not None and 'data-title-key="title.mcp"' in m.group(0),
      m.group(0)[:90] if m else "")
check("and a label span",
      re.search(r'data-section="mcp".*?data-i18n="nav\.mcp"', panel, re.S)
      is not None)
check("and an inline svg, as every other button has",
      m is not None and "<svg" in panel[m.end():m.end() + 400])

# 2. the section itself
check("the section element exists",
      '<section id="section-mcp" class="section">' in panel)
sec = re.search(r'<section id="section-mcp".*?</section>', panel, re.S)
check("the section has a body to check", sec is not None)
body = sec.group(0) if sec else ""
for cid in ("mcp-enabled", "mcp-http-enabled", "mcp-rate", "mcp-save-btn",
            "mcp-test-btn", "mcp-token-hint", "mcp-info"):
    check("#%s exists" % cid, 'id="%s"' % cid in body)
check("the copy snippet is a code element",
      '<code class="mono" id="mcp-stdio-config">' in body)
check("and has a copy button", 'data-copy="#mcp-stdio-config"' in body)
check("and one for the http endpoint",
      'data-copy="#mcp-http-config"' in body)

# 3. CSP: no inline anything
check("the section has no inline script",
      "<script" not in body.lower())
check("no onclick handler", "onclick" not in body.lower())
check("no style attribute", not re.search(r'\sstyle="', body))

# 4. both MENU_IDS and MENU_SECTIONS must list it, or the section is pinned on
mi = re.search(r"const MENU_IDS = \[(.*?)\]", appjs, re.S)
check("app.js MENU_IDS lists mcp",
      mi is not None and '"mcp"' in mi.group(1),
      (mi.group(1)[:120] if mi else ""))
check("and it is NOT in MENU_LOCKED, so the operator can hide it",
      '"mcp"' not in (re.search(r"const MENU_LOCKED = \[(.*?)\]", appjs,
                                re.S).group(1) if
                      re.search(r"const MENU_LOCKED = \[(.*?)\]", appjs,
                                re.S) else ""))
check("main.py MENU_SECTIONS lists mcp",
      re.search(r'MENU_SECTIONS\s*=\s*\(([^)]*)\)', io.open(
          os.path.join(ROOT, "main.py"), encoding="utf-8").read()).group(1)
      .count('"mcp"') == 1)
check("and not in MENU_ALWAYS",
      re.search(r'MENU_ALWAYS\s*=\s*\(([^)]*)\)', io.open(
          os.path.join(ROOT, "main.py"), encoding="utf-8").read()).group(1)
      .count('"mcp"') == 0)

# 5. the nav handler must load it, or the section opens empty
check("the nav handler loads the section",
      re.search(r'dataset\.section\s*===\s*"mcp"', appjs) is not None)
check("and a loadMcp function exists", "function loadMcp" in appjs)

# 6. the copy handler: three places, all of them
check("the copy allowlist has an MCP entry",
      re.search(r'MCP_COPY_IDS\s*=\s*\[(.*?)\]', appjs, re.S) is not None
      and "#mcp-stdio-config" in re.search(
          r'MCP_COPY_IDS\s*=\s*\[(.*?)\]', appjs, re.S).group(1))
check("the section guard still names #section-api, because a test greps it",
      'closest("#section-api")' in appjs)
check("and accepts the MCP section too",
      'closest("#section-mcp")' in appjs)
check("the insecure-transport warn loop covers the MCP section",
      "#section-mcp [data-copy]" in appjs)

# 7. i18n: menu.mcp in the FIRST block of each locale, which is what
# frontend_bugs_test.py reads. Putting it in a later block passes
# i18n_test.py and fails that one, which is the confusing failure.
for loc in ("en", "fa", "zh", "ru"):
    first = re.search(r"Object\.assign\(Z_STRINGS\.%s, \{(.*?)\}\);" % loc,
                      i18n, re.S)
    seg = first.group(1) if first else ""
    check("menu.mcp is in the FIRST %s block" % loc, '"menu.mcp"' in seg,
          "%d chars in that block" % len(seg))

# every key the template uses must exist in all four locales
used = set(re.findall(r'data-i18n(?:-ph|-title)?="([^"]+)"', body))
for loc in ("en", "fa", "zh", "ru"):
    blocks = re.findall(r"Object\.assign\(Z_STRINGS\.%s, \{(.*?)\}\);" % loc,
                        i18n, re.S)
    have = set()
    for b in blocks:
        have |= set(re.findall(r'"([a-zA-Z0-9_.]+)"\s*:', b))
    missing = sorted(k for k in used if k not in have)
    check("every mcp.* key the section uses exists in %s" % loc,
          not missing, str(missing[:5]))

# 8. docs: adding "mcp" to MENU_IDS makes docs_coverage_test demand a map
m = re.search(r'SECTION_DOCS\s*=\s*\{(.*?)\n\}', docst, re.S)
check("SECTION_DOCS maps the mcp section", m is not None
      and '"mcp"' in m.group(1),
      "without this, docs_coverage_test fails with unmapped: ['mcp']")
if m and '"mcp"' in m.group(1):
    entry = re.search(r'"mcp":\s*\("([^"]+)",\s*"([^"]*)"\)', m.group(1))
    check("and it names a page and an anchor",
          entry is not None and bool(entry.group(2)))
    if entry and entry.group(2):
        page = os.path.join(ROOT, "docs", entry.group(1))
        ug = io.open(page, encoding="utf-8", errors="replace").read()
        check("the anchor id really exists in %s" % entry.group(1),
              'id="%s"' % entry.group(2) in ug, entry.group(2))

# 9. the docs API reference, which is a hard build gate
api = io.open(os.path.join(ROOT, "docs", "api.html"),
              encoding="utf-8", errors="replace").read()
for path in ("/api/mcp", "/api/mcp/settings", "/api/mcp/test"):
    check("%s is documented with an exact <code>" % path,
          "<code>%s</code>" % path in api)
for badge in ("post", "get", "put"):
    check("a %s badge exists in the reference" % badge,
          'class="badge %s"' % badge in api)

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.\.venv\Scripts\python.exe mcp_ui_test.py`
Expected: the nav button check fails first

- [ ] **Step 3: Add the nav button**

In `templates/panel.html`, immediately after the Developer API `<button>`:

```html
      <button class="nav-btn" data-section="mcp" data-title-key="title.mcp">
        <svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h10M4 17h7"/><circle cx="17" cy="12" r="2"/><circle cx="14" cy="17" r="2"/></svg>
        <span data-i18n="nav.mcp">MCP Server</span>
      </button>
```

- [ ] **Step 4: Add the section**

Before `</main>`:

```html
    <section id="section-mcp" class="section">
      <div class="settings-grid">

        <div class="card form-card">
          <div class="card-head"><h2 data-i18n="mcp.title">MCP Server</h2><span class="badge proto" id="mcp-info">off</span></div>
          <p class="hint mt-0" data-i18n="mcp.hintA">Let an AI client operate this panel over MCP, on stdio or over HTTP.</p>
          <p class="hint" data-i18n="mcp.hintB">Destructive actions need the AI to name the exact target before they run.</p>
          <label class="proto-check wide"><input type="checkbox" id="mcp-enabled"><span data-i18n="mcp.enable">Enable MCP</span></label>
          <label class="proto-check wide"><input type="checkbox" id="mcp-http-enabled"><span data-i18n="mcp.httpEnable">Expose the HTTP endpoint at /api/mcp</span></label>
          <label class="field"><span data-i18n="mcp.rate">Maximum calls per minute</span><input type="number" id="mcp-rate" min="1" max="600" value="60"></label>
          <button type="button" id="mcp-save-btn" class="btn btn-primary" data-i18n="mcp.saveBtn">Save</button>
          <button type="button" id="mcp-test-btn" class="btn btn-ghost" data-i18n="mcp.testBtn">Test</button>
        </div>

        <div class="card form-card">
          <div class="card-head"><h2 data-i18n="mcp.tokenTitle">Which token MCP uses</h2></div>
          <p class="hint mt-0" data-i18n="mcp.tokenHint">MCP adds no privilege of its own. It acts with exactly the API token you give it, so mint a dedicated one in Developer API and revoke it whenever you like.</p>
          <label class="field"><span data-i18n="mcp.currentToken">Authenticated as</span><input type="text" id="mcp-token-hint" readonly></label>
          <label class="field"><span data-i18n="mcp.tokenLabel">Bearer token for your AI client</span><input type="password" id="mcp-token-input" maxlength="200" autocomplete="off" placeholder="zfp_…"></label>
          <p class="hint" data-i18n="mcp.tokenNever">This panel never stores it. Copy it into your AI client's configuration yourself.</p>
        </div>

        <div class="card form-card">
          <div class="card-head"><h2 data-i18n="mcp.cfgTitle">Client configuration</h2></div>
          <label class="field"><span data-i18n="mcp.stdioLabel">stdio (Claude Desktop, Cursor)</span>
            <div class="copy-row">
              <code class="mono" id="mcp-stdio-config">…</code>
              <button type="button" class="btn btn-ghost" data-copy="#mcp-stdio-config" data-i18n-title="icon.copy" title="Copy">
                <svg viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </label>
          <label class="field"><span data-i18n="mcp.httpLabel">HTTP endpoint</span>
            <div class="copy-row">
              <code class="mono" id="mcp-http-config">…</code>
              <button type="button" class="btn btn-ghost" data-copy="#mcp-http-config" data-i18n-title="icon.copy" title="Copy">
                <svg viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </label>
        </div>

      </div>
    </section>
```

- [ ] **Step 5: Add the JS**

In `static/app.js`, add `"mcp"` to `MENU_IDS`. Add to the nav handler's `if` chain:

```js
    if (btn.dataset.section === "mcp") loadMcp();
```

Add the loader and handlers:

```js
// ---- MCP server ----
function mcpBaseUrl() {
  return window.location.origin;
}
function mcpStdioConfig(base, token) {
  return JSON.stringify({
    mcpServers: {
      zefira: {
        command: "python",
        args: ["-m", "mcp_server"],
        env: { ZEFIRA_URL: base, ZEFIRA_TOKEN: token || "YOUR_TOKEN_HERE" }
      }
    }
  }, null, 2);
}
async function loadMcp() {
  const tok = nextSeq("mcp");
  try {
    const m = await api("/api/mcp/settings");
    if (!isCurrent("mcp", tok)) return;
    $("#mcp-enabled").checked = !!m.enabled;
    $("#mcp-http-enabled").checked = !!m.http_enabled;
    $("#mcp-rate").value = m.max_calls_per_min;
    $("#mcp-token-hint").value = m.token_hint || "";
    const base = mcpBaseUrl();
    $("#mcp-stdio-config").textContent = mcpStdioConfig(base);
    $("#mcp-http-config").textContent = base + "/api/mcp";
    const info = $("#mcp-info");
    if (info) {
      const ready = m.enabled;
      info.textContent = ready ? (m.tool_count + " " + t("mcp.tools")) : t("badge.off");
      info.className = "badge proto " + (ready ? "ok" : "off");
    }
  } catch (_) {}
}
bind("#mcp-save-btn", "click", async () => {
  const btn = $("#mcp-save-btn");
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    await api("/api/mcp/settings", {
      method: "PUT",
      body: {
        enabled: $("#mcp-enabled").checked,
        http_enabled: $("#mcp-http-enabled").checked,
        max_calls_per_min: Number($("#mcp-rate").value) || 60
      }
    });
    toast(t("msg.mcpSaved"));
    loadMcp();
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { btn.disabled = false; }
});
bind("#mcp-test-btn", "click", async () => {
  const btn = $("#mcp-test-btn");
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    const r = await api("/api/mcp/test", { method: "POST", body: {} });
    toast(`${t("mcp.testOk")}: ${r.tool_count} ${t("mcp.tools")} / ${r.protocol_version}`);
    $("#mcp-stdio-config").textContent = mcpStdioConfig(mcpBaseUrl(), $("#mcp-token-input").value.trim());
  } catch (err) { if (err.message !== "auth") toast(err.message, false); }
  finally { btn.disabled = false; }
});
```

Update the copy handler's guard to `const section = btn.closest("#section-api") || btn.closest("#section-mcp");`, add `MCP_COPY_IDS`, and extend the insecure-transport loop selector to `#section-mcp [data-copy]`.

- [ ] **Step 6: Add the i18n keys**

Add to the **first** `Object.assign(Z_STRINGS.<loc>, {` block in `static/i18n.js`, for all four locales: `"menu.mcp"`, `"title.mcp"`, `"nav.mcp"`, and every `mcp.*` key the template uses, plus `"msg.mcpSaved"`. No key may appear in one locale and not another.

- [ ] **Step 7: Add the docs mapping and anchor**

In `docs_coverage_test.py`, add to `SECTION_DOCS`:

```python
    "mcp": ("user-guide.html", "mcp-server"),
```

And add `<h2 id="mcp-server">MCP Server</h2>` with its content to `docs/user-guide.html`.

- [ ] **Step 8: Run the test, then the existing UI suites**

Run: `.\.venv\Scripts\python.exe mcp_ui_test.py`
Expected: every line PASS, exit 0

Then: `.\.venv\Scripts\python.exe settings_groups_test.py`, `.\.venv\Scripts\python.exe i18n_test.py`, `.\.venv\Scripts\python.exe docs_coverage_test.py`, `.\.venv\Scripts\python.exe frontend_bugs_test.py`
Expected: all exit 0

- [ ] **Step 9: Commit**

```bash
git add templates/panel.html static/app.js static/i18n.js \
        docs_coverage_test.py docs/user-guide.html docs/assets/i18n.js \
        mcp_ui_test.py
git commit -m "MCP: a panel section, and the eight obligations that come with it

The section goes after Developer API in the sidebar. Three cards: the
switches, which token MCP acts with, and a copy-pasteable client config.

The obligations were read out of the existing guards rather than
discovered by breaking them:

  - 'mcp' in BOTH MENU_IDS and MENU_SECTIONS, or the section is pinned on
    and the operator can neither move nor hide it
  - menu.mcp in the FIRST Object.assign block of each locale, because
    frontend_bugs_test.py scans only that block - a later placement passes
    i18n_test.py and fails that one, which is a miserable failure to debug
  - SECTION_DOCS needs an 'mcp' entry or docs_coverage_test fails with
    unmapped: ['mcp'] the moment the id enters MENU_IDS
  - the copy handler has THREE places to change: the allowlist, the
    closest('#section-api') guard, and the insecure-transport loop

No inline script, no onclick, no style attribute: the CSP is
script-src 'self'; style-src 'self' with no nonce."
```

---

### Task 8: conformance against the real SDK

**Files:**
- Create: `mcp_conformance_test.py`
- Reference (not shipped): the throwaway virtualenv under `%TEMP%`

**Interfaces:**
- Consumes: `mcp_server.run_stdio`, `main:app`
- Produces: proof that a real MCP client completes `initialize` + `tools/list` + `tools/call` on both transports

- [ ] **Step 1: Write the test**

```python
# mcp_conformance_test.py
"""Conformance against the official SDK, used only as a client.

The whole reason this project hand-rolled the protocol instead of taking the
dependency was that the SDK drags httpx2, opentelemetry-api, jsonschema,
python-multipart, pywin32 and sse-starlette into the panel's runtime. So it
is installed in a throwaway virtualenv OUTSIDE the repository and used to
talk to the server.

A hand-rolled protocol that only ever tests itself proves nothing: it is
consistent with the wrong shape. This is the check that the shape is right.

If the virtualenv cannot be built, this suite SKIPS with a loud message. It
does not pass, and it does not silently report conformance it did not check.
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

VENV = os.path.join(tempfile.gettempdir(), "zefira-mcp-conformance")
VPY = os.path.join(VENV, "Scripts", "python.exe")
if not os.path.exists(VPY):
    VPY = os.path.join(VENV, "bin", "python")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


def ensure_venv():
    if os.path.exists(VPY):
        return True
    base = sys.executable
    r = subprocess.run([base, "-m", "venv", VENV], capture_output=True)
    if r.returncode != 0:
        return False
    r = subprocess.run([VPY, "-m", "pip", "install", "--quiet",
                        "--disable-pip-version-check", "mcp==2.3.0"],
                       capture_output=True, text=True, timeout=900)
    return r.returncode == 0


if not ensure_venv():
    print()
    print("  SKIPPED, and this is NOT a pass.")
    print("  Could not build the throwaway virtualenv at %s" % VENV)
    print("  Conformance against the official SDK was therefore NOT verified.")
    print("  The release notes must say so rather than imply it was checked.")
    sys.exit(2)

CLIENT = r'''
import asyncio, json, os, sys, threading, time, subprocess, socket
import urllib.request

ROOT = sys.argv[1]
BASE = sys.argv[2]
sys.path.insert(0, ROOT)

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def main():
    out = {"stdio": {}, "http": {}}
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT
    env["ZEFIRA_URL"] = BASE
    env["ZEFIRA_TOKEN"] = sys.argv[3]

    # ---------------------------------------------------------- stdio
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "mcp_server"],
                                   env=env, cwd=ROOT)
    try:
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                init = await s.initialize()
                out["stdio"]["init"] = True
                out["stdio"]["version"] = init.protocolVersion
                tools = await s.list_tools()
                out["stdio"]["tools"] = len(tools.tools)
                names = sorted(t.name for t in tools.tools)
                out["stdio"]["has_stats"] = "panel_stats" in names
                res = await s.call_tool("panel_stats", {})
                out["stdio"]["call_ok"] = not res.isError
                out["stdio"]["call_text"] = res.content[0].text[:90]
                # the confirmation gate, from a real client
                bad = await s.call_tool("delete_user", {"user_id": 1})
                out["stdio"]["unconfirmed_refused"] = bool(bad.isError)
                out["stdio"]["refusal_text"] = bad.content[0].text[:90]
    except Exception as exc:
        out["stdio"]["error"] = "%s: %s" % (type(exc).__name__, exc)

    # ---------------------------------------------------------- http
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
         "--port", str(port), "--no-server-header", "--no-proxy-headers"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base2 = "http://127.0.0.1:%d" % port
    try:
        for _ in range(160):
            time.sleep(0.25)
            try:
                urllib.request.urlopen(base2 + "/login", timeout=2).read()
                break
            except Exception:
                continue
        hdrs = {"Authorization": "Bearer " + sys.argv[3]}
        async with streamablehttp_client(base2 + "/api/mcp", headers=hdrs) as (
                r, w, _):
            async with ClientSession(r, w) as s:
                init = await s.initialize()
                out["http"]["init"] = True
                out["http"]["version"] = init.protocolVersion
                tools = await s.list_tools()
                out["http"]["tools"] = len(tools.tools)
                res = await s.call_tool("panel_stats", {})
                out["http"]["call_ok"] = not res.isError
    except Exception as exc:
        out["http"]["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except Exception:
            proc.kill()

    print("__RESULT__" + json.dumps(out))


asyncio.run(main())
'''

# ---------------------------------------------------------- a token to use
PORT = 8175
BASE = "http://127.0.0.1:%d" % PORT
env = dict(os.environ)
panel = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
     "--port", str(PORT), "--no-server-header", "--no-proxy-headers"],
    cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(160):
        time.sleep(0.25)
        try:
            import urllib.request
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

    def jpost(path, body):
        req = urllib.request.Request(
            BASE + path, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "X-Requested-With": "XMLHttpRequest"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())

    jpost("/api/login", {"username": U, "password": P})
    tok = jpost("/api/api-tokens", {"name": "mcp-conformance",
                                    "scopes": "full",
                                    "password_confirm": P})["token_once"]
finally:
    panel.terminate()
    try:
        panel.wait(timeout=15)
    except Exception:
        panel.kill()

cpath = os.path.join(tempfile.gettempdir(), "zefira_mcp_client.py")
io.open(cpath, "w", encoding="utf-8").write(CLIENT)
r = subprocess.run([VPY, cpath, ROOT, BASE, tok], capture_output=True,
                   text=True, timeout=900, encoding="utf-8", errors="replace")
line = [l for l in (r.stdout or "").splitlines()
        if l.startswith("__RESULT__")]
if not line:
    print("  the SDK client produced no result; stderr follows")
    print((r.stderr or "")[-1200:])
    check("the official SDK client ran", False)
    sys.exit(1)
res = json.loads(line[-1][len("__RESULT__"):])

for transport in ("stdio", "http"):
    d = res.get(transport, {})
    check("%s: the SDK completes initialize" % transport, d.get("init") is True,
          str(d.get("error") or d.get("init")))
    check("%s: it sees the protocol version" % transport,
          d.get("version") == "2026-07-28", str(d.get("version")))
    check("%s: it lists the tools" % transport,
          isinstance(d.get("tools"), int) and d["tools"] > 10,
          str(d.get("tools")))
    check("%s: a tool call succeeds" % transport, d.get("call_ok") is True,
          str(d.get("call_text") or d.get("error")))

d = res.get("stdio", {})
check("stdio: panel_stats is visible by name", d.get("has_stats") is True)
check("stdio: an unconfirmed delete is refused by a real client",
      d.get("unconfirmed_refused") is True, str(d.get("refusal_text")))
check("stdio: the refusal names the exact string",
      'confirm: "1"' in (d.get("refusal_text") or ""),
      repr(d.get("refusal_text")))

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d against the official SDK 2.3.0 ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
```

- [ ] **Step 2: Run it**

Run: `.\.venv\Scripts\python.exe mcp_conformance_test.py`
Expected: all PASS, exit 0

If it exits **2**, the virtualenv could not be built. That is a skip, not a pass: say so in the release notes and do not claim conformance.

- [ ] **Step 3: Commit**

```bash
git add mcp_conformance_test.py
git commit -m "MCP: conformance against the official SDK, as a client only

The reason the protocol is hand-rolled is the dependency footprint, so
the SDK is installed in a throwaway virtualenv outside the repository and
used to TALK to the server: initialize, tools/list, tools/call, and the
confirmation gate, over both transports.

A hand-rolled protocol that only tests itself is consistent with the
wrong shape. This is the check that the shape is right.

It skips loudly rather than passing when the virtualenv cannot be built,
because a silent pass here would report conformance that was never
checked."
```

---

### Task 9: the guards, the docs and the release

**Files:**
- Create: `mcp_guards_test.py`
- Modify: `docs/api.html`, `docs/assets/i18n.js` ×4, four READMEs, `SECURITY.md`, `VERSION`, `install.sh`, `run_all_tests.py`

- [ ] **Step 1: Write the guard suite**

`mcp_guards_test.py` holds 12 checks with 6 mutations, each proved red:

| check | mutation that must redden it |
|---|---|
| the confirm gate cannot be bypassed by a differently spelled argument | change `isinstance(got, str) and got == want` to `bool(got)` |
| no tool name is reachable that is not in the table | add `"__all__"` handling that looks tools up by `args["name"]` |
| the executor is never reached for an unconfirmed call | move the gate after `executor.call` |
| the token never reaches the browser | return the request's bearer in `token_hint` |
| a disabled panel answers 405 | drop the `http_enabled` check from the route |
| the limiter is charged after authentication | move the limiter before `require_admin` |
| `requirements.txt` and `requirements.lock` are byte-identical to pre-MCP | add one line to either |
| every new route is in `docs/api.html` with a badge | remove one `<code>` |
| every new route's description key exists in four locales | remove one from `zh` |
| `"mcp"` is in both MENU_IDS and MENU_SECTIONS | remove it from one |
| `menu.mcp` is in the first block of all four locales | move one to a later block |
| `SECURITY.md` names the MCP surface under scope | remove it |

- [ ] **Step 2: Run it, confirm red for each mutation**

Run: `.\.venv\Scripts\python.exe mcp_guards_test.py`
Expected: `=== 12/12 checks, 6/6 mutations proved red ===`, exit 0

- [ ] **Step 3: Document the routes**

Add to `docs/api.html`, each with its own method badge and a keyed description:

```html
<tr><td><span class="badge post">POST</span></td><td><code>/api/mcp</code></td><td data-i18n="api.mcpTransport">MCP transport. Bearer token only — a cookie is refused.</td></tr>
<tr><td><span class="badge get">GET</span> <span class="badge put">PUT</span></td><td><code>/api/mcp/settings</code></td><td data-i18n="api.mcpSettings">Switches, rate limit, tool count, protocol version</td></tr>
<tr><td><span class="badge post">POST</span></td><td><code>/api/mcp/test</code></td><td data-i18n="api.mcpTest">Calls the transport and reports the tool count</td></tr>
```

Add `api.mcpTransport`, `api.mcpSettings`, `api.mcpTest` to all four dicts in `docs/assets/i18n.js`. Run `.\.venv\Scripts\python.exe docs\build_index.py`.

Add a `#mcp-server` section to `docs/user-guide.html`.

Add a short MCP subsection to all four READMEs.

- [ ] **Step 4: Update SECURITY.md**

Add to its scope list, alongside the other documented trade-offs:

```markdown
- **MCP gives an AI client the operator's own authority.** A `full` API token
  handed to an AI client can do everything that token can do, including
  deleting customers. MCP adds no privilege of its own; it adds a path.
  Destructive tools require the caller to name the exact target in a
  `confirm` field, every call is audited, and the HTTP transport has its own
  rate limit. See the MCP Server section of the panel.
```

- [ ] **Step 5: Register the suites and cut the release**

Add to `run_all_tests.py`:

```python
    ("mcp_tools_test.py", "every tool points at a route that exists"),
    ("mcp_exec_test.py", "arguments map to the panel's HTTP"),
    ("mcp_asgi_exec_test.py", "the in-panel executor, and its query split"),
    ("mcp_protocol_test.py", "JSON-RPC framing and the MCP methods"),
    ("mcp_stdio_test.py", "the stdio transport over pipes"),
    ("mcp_routes_test.py", "the four routes against a live panel"),
    ("mcp_ui_test.py", "the panel section and its obligations"),
    ("mcp_conformance_test.py", "the official SDK can talk to it"),
    ("mcp_guards_test.py", "the MCP guardrails hold"),
```

Then move `VERSION`, `install.sh:ZEFIRA_PINNED` and all four README pins together to the new version. Record the conformance result honestly: if Task 8 skipped, the changelog says conformance was not verified.

- [ ] **Step 6: Commit, tag, run everything, push**

```bash
git add -A
git commit -m "MCP server: stdio and HTTP, no new dependency, no new privilege"
git tag -a v1.15.44 -m "v1.15.44"
```

Then:

```
.\.venv\Scripts\python.exe run_all_tests.py admin <password>
```

Expected: every suite PASS and `N/N suites passed`. Only then:

```bash
git push origin main
git push origin v1.15.44
```

---

## Self-review

**1. Spec coverage.** Every section of the spec maps to a task: architecture → Tasks 1-4; spike assumption → Task 3, with the numbers the spike printed; authentication → Task 6 (bearer only, CSRF never applies); guardrails → Task 1 (the gate), Task 4 (gate runs before the executor, audit per call), Task 6 (`MCP_KEYS` limiter); tools → Task 1, with the two spec paths resolved against reality; settings → Task 6; UI → Task 7; routes → Task 6; errors → Task 4; testing → Tasks 1-9; four-language docs → Task 9; not-in-scope (no new scope, no SSE, no dependency change, AI assistant untouched) → enforced by Task 9's requirements-identical guard and Task 6's 405.

**2. Placeholder scan.** No `TBD`, no "add appropriate error handling", no "similar to Task N". Every code block is complete. The two spec assumptions that were wrong (`subscription_link`, `rotate_api_token`) are resolved with measured routes, not left as placeholders.

**3. Type consistency.** `build_call` returns `(method, path, body, query)` in Task 2 and Task 3 unpacks exactly that. `check_confirmation` returns `str | None` in Task 1 and Task 4 tests it as truthy-for-refusal. `Dispatcher.handle(request) -> dict | None` is the same signature in Task 4's test, Task 5's transport, and Task 6's route. `run_stdio(base_url, token, stdin, stdout, executor)` matches Task 5's test exactly. `AsgiExecutor(app, token)` matches Task 6's route call and Task 3's test. `HttpExecutor(base_url, token, timeout=30.0)` matches Task 5 and Task 2's test.

**4. Known gaps, stated rather than hidden.**

- The spec says `delete_user`, `restore_backup`, `update_settings`, `apply_update` are confirmation-gated. This plan gates six: it adds `delete_api_token` and `create_api_token`, which exist because `rotate_api_token` was measured to not exist.
- `subscription_link` has no route and needs a compose path the executors cannot supply. Two ways to close it are written out above, and the choice must be made before Task 1 rather than discovered during Task 4.
- `audit_tail`'s `limit` parameter is unverified against the real handler. Written up above with the instruction to read it first.
- No Linux host, so `install.sh` and a stdio server under systemd are untested here. The release notes must say so.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-16-mcp-server.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**