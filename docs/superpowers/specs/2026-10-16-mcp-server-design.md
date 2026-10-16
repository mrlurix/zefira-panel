# MCP server for the Zefira panel — design

**Date:** 2026-10-16
**Status:** proposed, not implemented
**Target version:** 1.15.43

## What this is

An MCP (Model Context Protocol) server so an AI client can operate this panel.
The operator connects their AI client — Claude Desktop, Cursor, anything that
speaks MCP — and asks it to look after customers, nodes and settings the way
they would ask a human operator.

Two transports, because the operator asked for both:

- **stdio** — the AI client launches a small process locally. Nothing new is
  exposed on the panel.
- **HTTP** — `POST /api/mcp` on the panel itself, for an AI client that runs
  elsewhere.

## The one fact that decides the architecture

There is no MCP SDK in this panel, and adding one is expensive.

`requirements.txt` pins 11 packages exactly. `install.sh` installs from
`requirements.lock` with `--require-hashes`, and the in-panel updater runs
`pip install -r requirements.txt` on **every update**. Adding the official
`mcp` SDK (measured against PyPI: version 2.3.0) drags `httpx2`,
`opentelemetry-api`, `jsonschema`, `python-multipart`, `pywin32`,
`sse-starlette`, `anyio`, `typing-inspection` into the panel's runtime, and
every one of them needs a PyPI-verified hash in the lock file. On a security
sensitive panel that is a large blast radius to buy a JSON-RPC dispatch.

**Decision: implement the protocol directly with the standard library.** No
new dependency, `requirements.lock` untouched, and the install path and every
future update stay byte-identical.

The risk of hand-rolling is spec compliance, so that risk is retired by
measurement rather than assertion: **the official SDK is installed in a
throwaway virtualenv outside the repository and used as a real client** against
both transports. If the SDK cannot talk to it, it is not done. Nothing is
added to `requirements.txt`.

## Architecture

```
                 ┌──────────────────────────────────────────┐
  AI client ─────┤                                          │
  (stdio)        │  mcp_server.py                           │
                 │  · JSON-RPC 2.0 framing                  │
                 │  · stdio loop  /  HTTP handler            │
                 │  · one dispatch, two transports           │
                 └───────────────┬──────────────────────────┘
                                 │  tool call
                 ┌───────────────▼──────────────────────────┐
                 │  mcp_tools.py                            │
                 │  · declarative table: name, description, │
                 │    inputSchema, method, path, body map   │
                 │  · confirmation gate for destructive ops │
                 │  · per-call audit + rate limit           │
                 └───────────────┬──────────────────────────┘
                                 │  Executor interface
                    ┌────────────┴─────────────┐
                    │                          │
        ┌───────────▼──────────┐   ┌───────────▼──────────────────┐
        │  HttpExecutor        │   │  AsgiExecutor                │
        │  urllib + Bearer     │   │  forwards through panel app  │
        │  (stdio process)     │   │  (in-panel HTTP transport)   │
        └───────────┬──────────┘   └───────────┬──────────────────┘
                    │                          │
                    └────────────┬─────────────┘
                                 ▼
                         the panel's own app
```

### The spike that justifies this shape

The whole design rests on one claim: a request forwarded through the panel's own
ASGI app behaves exactly like a request over the network. If false, every tool
needs two implementations and they will drift.

Measured, not reasoned, against a running panel:

| probe | result |
|---|---|
| `GET /api/stats` over the network | 200, keys `active_users, disabled_users, …` |
| the same call forwarded through the app | **200, identical keys** |
| forwarded with **no** bearer header | **401** — the real auth stack ran |
| `GET /api/me` forwarded | 200 |
| two consecutive `/api/me` forwarded | 200, 200 — no `request.state` leak |
| `git status --porcelain` | empty — nothing in the repo was touched |

One real defect surfaced from the spike and is fixed in the design below: ASGI
splits `path` from `query_string`, and putting `?limit=1` inside `path` made
the router match nothing — **404 for a call that answers 200 over the wire**.
A tool that passed a query would have reported "not found" for every listed
call, silently. The executor must split them.

### Why one tool table and two executors

The tools are declared once, as data: name, description, JSON Schema, HTTP
method, path, and how arguments map to a body. `AsgiExecutor` runs them
in-process; `HttpExecutor` runs them over `urllib` with the bearer token. Both
read the same table, so a tool cannot exist on one transport and be missing on
the other.

`HttpExecutor` is also **the same token the operator already has**: MCP grants
no privilege that a `full` API token does not already carry. It adds a
convenience, not an authority.

## Authentication

**No new authentication path.** The MCP layer calls the panel's existing
`require_admin`, so the same token, the same expiry check, the same scope gate
and the same rate limiters apply. A `full` token means exactly what it means
today.

On the HTTP transport **only a bearer token is accepted, never a cookie.** That
is deliberate: bearer requests skip the CSRF middleware, so an MCP client needs
no CSRF token and there is no cookie-shaped attack surface on a public VPN
panel.

The stdio process reads its token from the environment variable
`ZEFIRA_TOKEN` and refuses to start without it.

## Guardrails — stated plainly

The operator chose `full`, which means an AI can delete every customer, restore
a crafted backup, rotate REALITY keys and mint tokens. That is the same
authority the existing Developer API hands to anyone holding the token; this
change does not widen it. What it does is hand it to something that can be
wrong in new ways, so three guardrails apply.

**1. Destructive tools require an exact confirmation.**
`delete_user`, `restore_backup`, `update_settings`, `apply_update` and
`rotate_api_token` are refused unless the arguments carry
`confirm: "<the exact name or id of the target>"`. Deleting `alice` requires
`confirm: "alice"`. A hallucination does not produce that string; a deliberate
action does.

**2. Every call writes an audit row.** Each tool call writes to the existing
`audit` table with the tool name and its target, so an operator can always
answer "what did the AI just do". Secrets are never written.

**3. The HTTP transport has its own rate limit.** `mcp_limiter`, separate from
the per-endpoint limiters, so an AI loop cannot burn the operator's user-create
budget unnoticed.

### Tools

Around twenty-five, declared explicitly. Deliberately **not** a generic HTTP
proxy: a proxy would let the AI reach any endpoint the panel has, including ones
nobody intended to expose, and would make the audit log meaningless.

| group | tools |
|---|---|
| overview | `panel_stats`, `audit_tail` |
| customers | `list_users`, `find_user`, `create_user`, `extend_user`, `add_volume`, `set_active`, `reset_usage`, `subscription_link`, `user_config`, `reset_user_token`, **`delete_user`** |
| infrastructure | `list_server_nodes`, `create_server_node`, `list_inbounds`, `list_tunnel_nodes`, `list_templates` |
| settings | `get_settings`, **`update_settings`** |
| operations | `export_backup`, **`restore_backup`** |
| tokens | `list_api_tokens`, **`rotate_api_token`** |
| panel | **`apply_update`** |

Bold entries are the confirmation-gated ones. Every one maps to an endpoint
that already exists, so no new business logic is introduced.

## Routes

Four new routes, all declared with `@app.<method>` so `api_coverage_test.py`
and `docs_coverage_test.py` see them. None of them is new business logic; the
first dispatches, the other three back the UI card.

| method | path | purpose |
|---|---|---|
| `POST` | `/api/mcp` | the MCP transport. JSON-RPC in, JSON-RPC response out |
| `GET` | `/api/mcp/settings` | what the UI card reads: enabled flags, limits, tool count, protocol version, and **which token name to use — never the token** |
| `PUT` | `/api/mcp/settings` | write the flags and the limit |
| `POST` | `/api/mcp/test` | the Test button: calls `/api/mcp` itself and reports the tool count and protocol version |

`GET /api/mcp` is **not declared**. FastAPI answers 405 for an unrouted method
automatically, and a route that exists only to be rejected would still owe a
documentation row.

### A note on `export_backup`

`POST /api/backup` returns a **file**, not JSON, and an MCP tool whose result
is a download is awkward for a model to reason about. So the tool does not call
it. Instead `export_backup` returns the backup's **JSON payload inline**,
capped, and says plainly that it is a summary rather than a file — the
operator downloads a real backup from the Settings section as they always
have. If this proves too lossy in practice, the honest fix is a JSON endpoint
that returns the same payload, not a tool that smuggles a file.

## Settings

Three keys, stored in the existing `settings` table, following the pattern the
AI settings already use — including the easy-to-miss requirement that
`_settings_cache` is popped after every write or the value serves stale for up
to fifteen seconds.

| key | meaning |
|---|---|
| `mcp_enabled` | master switch. Off means `POST /api/mcp` answers 405 |
| `mcp_max_calls_per_min` | rate limit for the HTTP transport |
| `mcp_http_enabled` | expose `POST /api/mcp` at all |

The token is **not** a setting. The operator picks an existing API token; the
panel never stores a new credential for MCP. The UI shows which token to use
and its scopes, and never the token itself — the same `has_*` boolean the AI
card uses.

## The panel UI

A new section in the left menu, positioned after Developer API and before
Settings.

```html
<button class="nav-btn" data-section="mcp" data-title-key="title.mcp">
  <svg viewBox="0 0 24 24">…</svg>
  <span data-i18n="nav.mcp">MCP Server</span>
</button>
```

Three cards inside `<section id="section-mcp" class="section">`:

1. **Server** — enable toggle, calls-per-minute, and a **Test** button that
   calls the MCP endpoint and reports the tool count and protocol version.
2. **Token** — which API token MCP should use, and its scopes. Read-only; the
   value is never sent to the browser.
3. **Client configuration** — a `.copy-row` with a ready-to-paste
   `claude_desktop_config.json` snippet for the stdio transport and the HTTP
   endpoint URL, each with the existing copy button.

### Test-enforced obligations, found rather than guessed

| # | obligation | enforced by |
|---|---|---|
| 1 | `"mcp"` in `MENU_IDS` (`static/app.js`) **and** `MENU_SECTIONS` (`main.py`) | otherwise the section is pinned on and cannot be reordered or hidden |
| 2 | `menu.mcp` in the **first** `Object.assign(Z_STRINGS.<loc>, …)` block, all four locales | `frontend_bugs_test.py` scans only the first block; a key placed elsewhere reads as present to `i18n_test.py` and missing to this one |
| 3 | `title.mcp`, `nav.mcp` and every `mcp.*` key in all four locales, correct script per locale | `i18n_test.py` |
| 4 | `SECTION_DOCS["mcp"] = ("user-guide.html", "<real anchor id>")` | `docs_coverage_test.py` fails with `unmapped: ['mcp']` the moment `"mcp"` enters `MENU_IDS` |
| 5 | each new route: exact `<code>` path **and** its own method badge in `docs/api.html`, description as a keyed span, key present in all four `docs/assets/i18n.js` dicts | `api_coverage_test.py` |
| 6 | the copy handler: `API_COPY_IDS`, the `closest("#section-api")` guard **and** the `#section-api [data-copy]` warn loop all updated together | `frontend_bugs_test.py` |
| 7 | `if (btn.dataset.section === "mcp") loadMcp();` in the nav handler | a section without it loads empty |
| 8 | no `<script>`, no `onclick=`, no `style=` in the section | CSP is `script-src 'self'; style-src 'self'` with no nonce |

The route is `/api/mcp` and not `/mcp` **on purpose**: `api_coverage_test.py`
and `docs_coverage_test.py` both filter on `/api`, so a bare `/mcp` would slip
past both documentation guards. Choosing `/api/mcp` keeps them doing their job
and obliges the documentation.

## Error handling

- A tool the token's scope forbids returns the panel's own 403 body, unchanged,
  so the AI sees why rather than a generic failure.
- A validation error returns the panel's 422 detail, unchanged.
- A missing confirmation is a clear, tool-level refusal naming the exact
  string required — not a stack trace.
- A rate-limited call returns 429 with the panel's standard message.
- Every failure is audited with `ok=False`, matching how the panel already
  records failures.

## Testing

Nothing here ships on "it parses". Each claim below is measured, and each guard
is shown red by re-introducing the defect it prevents.

| suite | proves | mutations |
|---|---|---|
| `mcp_protocol_test.py` | `initialize`, `tools/list`, `tools/call` frame correctly; a malformed request produces a JSON-RPC error object and never a traceback; the tool list is identical on both transports | each malformed frame |
| `mcp_tools_test.py` | every tool maps to a route that exists; every destructive tool refuses without `confirm` and proceeds with the exact string; the executor splits `?query` out of `path` (the spike's 404) | each unconfirmed destructive call, the query-string split |
| `mcp_conformance_test.py` | the **official SDK, installed in a throwaway virtualenv**, completes `initialize` + `tools/list` + one `tools/call` over stdio and over HTTP | — (it is a conformance check, not a mutation suite) |
| `mcp_guards_test.py` | the confirm gate cannot be bypassed by a differently spelled argument; the token never reaches the browser; a disabled panel answers 405; the rate limiter actually charges | each |

Plus the existing suites, which must all stay green: `panel_sections_test.py`,
`settings_groups_test.py`, `frontend_bugs_test.py`, `i18n_test.py`,
`api_coverage_test.py`, `docs_coverage_test.py`, `security_test.py`,
`menu_order_check.js`, `app_smoke_check.js`.

**Zero new dependencies is itself a guard**: a check asserts
`requirements.txt` and `requirements.lock` are byte-identical to the previous
release. If an implementation "needs one more package", the suite says so
instead of the diff.

## Documentation, in four languages

`docs/user-guide.html` gains an `#mcp-server` section (obligation 4).
`docs/api.html` gains rows for the new routes (obligation 5). The four READMEs
gain a short subsection. All four locales of `static/i18n.js` and
`docs/assets/i18n.js` are updated together — `i18n_test.py` fails on a missing
key **or** an orphan key in either direction.

## Not in scope

- No new API scope. `full` is what MCP uses. A future read-only scope would be
  a separate change; `_token_scope_allowed` fails closed on unknown scope
  strings, so adding one without wiring it in would 403 every such token.
- No SSE or server-initiated streaming. The HTTP transport is **stateless**:
  one POST in, one JSON-RPC response out. No session store, no session
  lifetime, nothing to leak or time out. `GET /api/mcp` returns 405 with a
  message pointing at POST.
- No dependency changes.
- No changes to the existing AI assistant. It keeps its own eight-tool
  allowlist and its own quota; MCP does not touch it.

## Risks, and what happens if one lands

| risk | mitigation |
|---|---|
| an AI deletes a customer by mistake | the `confirm` gate; a mistaken target string does not match |
| an AI loops and burns the operator's quota | a separate `mcp_limiter`, plus the existing per-endpoint limiters which a forwarded call genuinely charges |
| a prompt injection from a customer note makes the AI call a tool | the tool list is fixed; there is no tool that accepts free-form instructions; the confirm gate stands between the model and every destructive effect |
| the spec drifts from what real clients speak | conformance is tested against the official SDK, not against my reading of the spec |
| a new dependency sneaks in | the requirements-identical guard |

## What I could not verify here

- **No Linux host**, so `install.sh`, the systemd unit and the stdio process
  under a real service manager are unexercised.
- **The MCP SDK conformance run needs a virtualenv build**; if the sandbox has
  no route to PyPI at implementation time, that one check cannot run and the
  release notes must say so rather than implying it was verified.