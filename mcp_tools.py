"""The MCP tool table: data, not logic.

Every tool points at an endpoint this panel already has, so MCP adds no new
business logic and no new authority - it exposes exactly what a `full` API
token already carries, to an AI client instead of a script.

Two things about this table were settled by measurement, not by reading the
design:

  - 23 of the 25 tools the design drafted mapped to routes that exist. The
    two that did not are corrected here rather than shipped to 404:
    `subscription_link` has no route at all and is COMPOSED the way the
    existing AI tool composes it (main.py:3376-3382), and there is no
    token-rotate route, so the panel's actual capability - delete then
    create - is exposed under its real names instead.
  - PROTOCOL_VERSION is mcp.types.LATEST_PROTOCOL_VERSION from the official
    SDK 2.3.0. Not a remembered constant.

The confirmation gate is the whole reason an AI holding a `full` token cannot
delete a customer by accident, so the comparison is exact: `isinstance(str)`
and `==`, nothing looser.
"""

# ToolError lives in mcp_exec and mcp_exec does NOT import this module, so
# this is a one-way import with no cycle.
from mcp_exec import ToolError


PROTOCOL_VERSION = "2026-07-28"

# The versions this server will actually speak. Taken from the SDK's own
# KNOWN_PROTOCOL_VERSIONS, read out of the installed 2.3.0 distribution:
#
#     ('2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28')
#
# PROTOCOL_VERSION above is mcp.types.LATEST_PROTOCOL_VERSION. A client is
# answered with the version it asked for ONLY when that version is in this
# tuple. Echoing any string would be a claim to speak a protocol that does not
# exist - and the real SDK, which raises "Unsupported protocol version from the
# server" on anything outside its handshake set, would have no way to tell the
# difference between a version this server implements and one it does not.
PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25",
                     PROTOCOL_VERSION)

# Which argument a confirmation has to name, and what to call that argument
# when there is no single id to quote.
_CONFIRM_FIELD = {
    "delete_user": "user_id",
    "delete_api_token": "token_id",
    "create_api_token": "name",
    "restore_backup": "backup",
    "update_settings": "settings",
    "apply_update": "target",
}

# The three whose confirmation is a keyword rather than an id.
_CONFIRM_WORD = {
    "restore_backup": "RESTORE",
    "update_settings": "REPLACE",
    "apply_update": "APPLY",
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


def _num(desc):
    return {"type": "number", "description": desc}


TOOLS = [
    {"name": "panel_stats",
     "description": "Customer counts and totals: active, expired, disabled, "
                    "expiring soon, pending activation, total volume.",
     "input_schema": _s(), "method": "GET", "path": "/api/stats",
     "body": {}, "query": {}, "path_params": {}},

    {"name": "audit_tail",
     "description": "The 50 most recent audit rows, newest first: what "
                    "happened and when. Fixed length, this panel keeps the "
                    "tail only.",
     "input_schema": _s(), "method": "GET", "path": "/api/audit",
     "body": {}, "query": {}, "path_params": {}},

    {"name": "list_users",
     "description": "List customers, newest first, optionally filtered by a "
                    "substring of the username or note.",
     "input_schema": _s(q=_str("Substring match on username or note."),
                        limit=_int("Maximum rows.")),
     "method": "GET", "path": "/api/users",
     "body": {}, "query": {"q": "q", "limit": "limit"}, "path_params": {}},

    {"name": "find_user",
     "description": "Look one customer up by exact username and get their id.",
     "input_schema": _s(username=_str("Exact username.")),
     "method": "GET", "path": "/api/users/by-username/{username}",
     "body": {}, "query": {}, "path_params": {"username": "username"}},

    # `protocols` is a LIST, not a comma-separated string: UserCreateIn
    # declares List[Protocol]. The first draft of this table sent a string and
    # every create_user answered 422 - found by forwarding a real call
    # through the app, not by reading the schema.
    #
    # `days` is ge=1, so 0 is NOT "starts on first use" - it is a 422. The
    # sentinel is start_on_first_use, and it is what this table sends.
    {"name": "create_user",
     "description": "Create a customer. Give protocols, volume_gb and days.",
     "input_schema": _s(username=_str("Username, 3-32 characters."),
                        protocols={"type": "array",
                                   "description": "Protocols, e.g. "
                                                  "[\"vless\", \"trojan\"].",
                                   "minItems": 1,
                                   "items": {"type": "string"}},
                        volume_gb=_num("Traffic allowance in GB."),
                        days=_int("Days of access. Omit with "
                                  "start_on_first_use instead of passing 0."),
                        start_on_first_use={"type": "boolean",
                                           "description": "Do not count down "
                                                          "until the first "
                                                          "fetch."},
                        note=_str("Optional note.")),
     "method": "POST", "path": "/api/users",
     "body": {"username": "username", "protocols": "protocols",
              "volume_gb": "volume_gb", "days": "days",
              "start_on_first_use": "start_on_first_use", "note": "note"},
     "query": {}, "path_params": {}},

    {"name": "extend_user",
     "description": "Add days to a customer's expiry, measured from today or "
                    "from their current expiry, whichever is later.",
     "input_schema": _s(user_id=_int("Customer id from find_user."),
                        extend_days=_int("Days to add.")),
     "method": "PATCH", "path": "/api/users/{user_id}",
     "body": {"extend_days": "extend_days"},
     "query": {}, "path_params": {"user_id": "user_id"}},

    {"name": "add_volume",
     "description": "Add gigabytes to a customer's quota.",
     "input_schema": _s(user_id=_int("Customer id."),
                        add_volume_gb=_num("GB to add.")),
     "method": "PATCH", "path": "/api/users/{user_id}",
     "body": {"add_volume_gb": "add_volume_gb"},
     "query": {}, "path_params": {"user_id": "user_id"}},

    {"name": "set_active",
     "description": "Enable or disable a customer.",
     "input_schema": _s(user_id=_int("Customer id."),
                        is_active={"type": "boolean",
                                   "description": "True to enable."}),
     "method": "PATCH", "path": "/api/users/{user_id}",
     "body": {"is_active": "is_active"},
     "query": {}, "path_params": {"user_id": "user_id"}},

    {"name": "reset_usage",
     "description": "Set a customer's used gigabytes back to zero.",
     "input_schema": _s(user_id=_int("Customer id.")),
     "method": "POST", "path": "/api/users/{user_id}/reset-usage",
     "body": {}, "query": {}, "path_params": {"user_id": "user_id"}},

    {"name": "reset_user_token",
     "description": "Issue a customer a new subscription token. Their old "
                    "link stops working immediately.",
     "input_schema": _s(user_id=_int("Customer id.")),
     "method": "POST", "path": "/api/users/{user_id}/reset-token",
     "body": {}, "query": {}, "path_params": {"user_id": "user_id"}},

    {"name": "user_config",
     "description": "Fetch one customer's full config bundle, including their "
                    "private keys. Treat the result as a secret.",
     "input_schema": _s(user_id=_int("Customer id.")),
     "method": "GET", "path": "/api/users/{user_id}/config",
     "body": {}, "query": {}, "path_params": {"user_id": "user_id"}},

    {"name": "delete_user",
     "description": "Delete a customer and everything belonging to them. "
                    "Needs an exact confirmation.",
     "input_schema": _s(user_id=_int("Customer id."),
                        confirm=_str("The id again, as a string.")),
     "method": "DELETE", "path": "/api/users/{user_id}",
     "body": {}, "query": {}, "path_params": {"user_id": "user_id"}},

    {"name": "list_server_nodes",
     "description": "List the remote servers this panel manages.",
     "input_schema": _s(), "method": "GET", "path": "/api/server-nodes",
     "body": {}, "query": {}, "path_params": {}},

    {"name": "create_server_node",
     "description": "Register a remote VPN server.",
     "input_schema": _s(name=_str("Node name."),
                        address=_str("IP address or domain."),
                        ssh_port=_int("SSH port. Default 22."),
                        note=_str("Optional note.")),
     "method": "POST", "path": "/api/server-nodes",
     "body": {"name": "name", "address": "address", "ssh_port": "ssh_port",
              "note": "note"},
     "query": {}, "path_params": {}},

    {"name": "list_inbounds",
     "description": "List the local listeners (inbounds) this panel serves.",
     "input_schema": _s(), "method": "GET", "path": "/api/inbounds",
     "body": {}, "query": {}, "path_params": {}},

    {"name": "list_tunnel_nodes",
     "description": "List the BackPack tunnel nodes.",
     "input_schema": _s(), "method": "GET", "path": "/api/nodes",
     "body": {}, "query": {}, "path_params": {}},

    {"name": "list_templates",
     "description": "List the saved customer templates.",
     "input_schema": _s(), "method": "GET", "path": "/api/templates",
     "body": {}, "query": {}, "path_params": {}},

    {"name": "list_api_tokens",
     "description": "List API tokens. Values are never returned - only names, "
                    "prefixes and scopes.",
     "input_schema": _s(), "method": "GET", "path": "/api/api-tokens",
     "body": {}, "query": {}, "path_params": {}},

    {"name": "get_settings",
     "description": "Read the panel's server settings: domain, ports, DNS.",
     "input_schema": _s(), "method": "GET", "path": "/api/settings",
     "body": {}, "query": {}, "path_params": {}},

    {"name": "update_settings",
     "description": "Replace the server settings. This is a FULL REPLACE, not "
                    "a merge: any key you omit is written as its default. Call "
                    "get_settings first and send the whole object back.",
     "input_schema": _s(settings={"type": "object",
                                  "description": "The complete settings "
                                                 "object, unchanged."},
                        confirm=_str("The word REPLACE.")),
     "method": "PUT", "path": "/api/settings",
     "body": {"__all__": "settings"},
     "query": {}, "path_params": {}},

    {"name": "restore_backup",
     "description": "Restore customers from a backup file. This DELETES every "
                    "existing customer before re-creating them. Needs an "
                    "exact confirmation.",
     "input_schema": _s(backup={"type": "object",
                                 "description": "The backup payload."},
                        password_confirm=_str("The operator's admin password."),
                        confirm=_str("The word RESTORE.")),
     "method": "POST", "path": "/api/restore",
     "body": {"__merge__": "backup", "password_confirm": "password_confirm"},
     "query": {}, "path_params": {}},

    {"name": "create_api_token",
     "description": "Mint a new API token. The value is returned once and "
                    "never again. Needs the operator's password and an exact "
                    "confirmation.",
     "input_schema": _s(name=_str("Token name."),
                        scopes=_str("full or bot."),
                        password_confirm=_str("The admin password."),
                        confirm=_str("The token name again.")),
     "method": "POST", "path": "/api/api-tokens",
     "body": {"name": "name", "scopes": "scopes",
              "password_confirm": "password_confirm"},
     "query": {}, "path_params": {}},

    {"name": "delete_api_token",
     "description": "Delete an API token. Anything using it stops working "
                    "immediately. Needs an exact confirmation.",
     "input_schema": _s(token_id=_int("Token id."),
                        confirm=_str("The id again, as a string.")),
     "method": "DELETE", "path": "/api/api-tokens/{token_id}",
     "body": {}, "query": {}, "path_params": {"token_id": "token_id"}},

    {"name": "apply_update",
     "description": "Apply the update the Update section is offering. Needs "
                    "an exact confirmation. The panel restarts.",
     "input_schema": _s(confirm=_str("The word APPLY.")),
     "method": "POST", "path": "/api/update/apply",
     "body": {}, "query": {}, "path_params": {}},

    # Composed rather than fetched. There is no subscription route on this
    # panel; the link is assembled from the user's token row the same way the
    # existing AI assistant assembles it, so there is no URL to name here.
    {"name": "subscription_link",
     "description": "Build a customer's subscription link. Composed inside "
                    "the panel, so it is available on the HTTP transport only.",
     "input_schema": _s(username=_str("Exact username.")),
     "method": "GET", "path": "/api/users/by-username/{username}",
     "body": {}, "query": {}, "path_params": {"username": "username"},
     "compose": "subscription_link"},
]

TOOL_INDEX = {t["name"]: t for t in TOOLS}


def expected_confirmation(name, args):
    """The string a confirmation must equal, or None if this tool is safe.

    None means "no confirmation required", so a MISSING target cannot also
    mean "the confirmation is the four letters None". It did: args.get on an
    absent key returns None, str() of that is "None", and the refusal then
    said `Call it again with confirm: "None"`. A model that obeyed the
    instruction passed the gate - measured for delete_user, delete_api_token
    and create_api_token - so the one check standing between an agent and a
    deleted customer could be opened by following its own error message.

    Nothing destructive happened, because build_call independently requires the
    same field and refused with ToolError: delete_user needs "user_id". But a
    gate that can be opened is not a gate, and the message must never name a
    string that is not the target's.

    So a missing or null target refuses here, with a message that says what is
    wrong instead of handing out a magic word.
    """
    if name not in _CONFIRM_FIELD:
        return None
    if name in _CONFIRM_WORD:
        return _CONFIRM_WORD[name]
    field = _CONFIRM_FIELD[name]
    value = args.get(field) if isinstance(args, dict) else None
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ToolError("%s needs a %s to confirm: you named none, so there "
                        "is nothing to echo back." % (name, field))
    return str(value)


def check_confirmation(name, args):
    """None when the tool may run, otherwise the refusal to show the caller.

    The comparison is exact on purpose. `isinstance(got, str) and got == want`
    rejects a trailing space, an int, True and a unicode lookalike - and a
    looser check here is the exact hole the gate exists to close, because the
    caller is a language model that will happily produce "7 " when it means 7.
    """
    want = expected_confirmation(name, args)
    if want is None:
        return None
    got = args.get("confirm") if isinstance(args, dict) else None
    if isinstance(got, str) and got == want:
        return None
    return ('%s needs an explicit confirmation. Call it again with '
            'confirm: "%s" - exactly that, to say you mean it.' % (name, want))