"""JSON-RPC 2.0 framing and the MCP methods, shared by both transports.

One dispatch function, so the stdio loop and the HTTP handler cannot answer
the same method differently.

Every key name here was read out of mcp.types 2.3.0 rather than recalled,
and two of them are the opposite of what you would guess:

    initialize   -> protocolVersion / capabilities / serverInfo
    a tool       -> inputSchema   (the Python attribute is input_schema)
    tools/list   -> tools, and ttlMs/cacheScope appear only when ABSENT
    tools/call   -> content / isError

That last point is why list_tools_payload builds the dict by hand. Dumping
the SDK's own ListToolsResult with its defaults filled in adds `ttlMs: 0` and
`cacheScope: "private"` - legal, but not what a client should be told about a
stateless server.
"""

import io
import json
import os

from mcp_tools import (PROTOCOL_VERSION, TOOLS, TOOL_INDEX,
                       check_confirmation)

SERVER_NAME = "zefira"
SERVER_VERSION = "0"

_here = os.path.dirname(os.path.abspath(__file__))
_vf = os.path.join(_here, "VERSION")
if os.path.isfile(_vf):
    SERVER_VERSION = io.open(_vf, encoding="utf-8").read().strip()

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def available_tools(has_compose):
    """The table, minus any composed tool this process cannot serve."""
    return [t for t in TOOLS if not t.get("compose") or has_compose]


def list_tools_payload(has_compose=False):
    return {"tools": [{"name": t["name"],
                       "description": t["description"],
                       "inputSchema": t["input_schema"]}
                      for t in available_tools(has_compose)]}


def _text(s, is_error=False):
    return {"content": [{"type": "text", "text": s}], "isError": bool(is_error)}


def _json(payload):
    return json.dumps(payload, ensure_ascii=False, default=str)


class Dispatcher:
    """Turns one parsed JSON-RPC request into one response, or None.

    `compose` is optional. A composed tool needs DB access the executors do
    not have - subscription_link assembles a URL from the user's token row -
    so without a compose callable the tool is simply not offered, rather than
    offered and failing when called. A stdio process has no business
    assembling a link it cannot verify, so it runs without one.
    """

    def __init__(self, executor, audit=None, compose=None):
        self.executor = executor
        self.audit = audit
        self.compose = compose

    # ------------------------------------------------------------------ core
    async def handle(self, request):
        if not isinstance(request, dict):
            return self._err(None, INVALID_REQUEST,
                             "request must be an object")

        # A notification is any frame with no id: JSON-RPC says answer it
        # with silence, and a client that sent one is not waiting.
        is_notification = "id" not in request
        rid = request.get("id")
        method = request.get("method")
        params = request.get("params")
        if params is None:
            params = {}

        if method is None:
            return (None if is_notification
                    else self._err(rid, INVALID_REQUEST, "no method"))
        if not isinstance(method, str):
            return (None if is_notification
                    else self._err(rid, INVALID_REQUEST,
                                   "method must be a string"))
        if not isinstance(params, dict):
            return (None if is_notification
                    else self._err(rid, INVALID_PARAMS,
                                   "params must be an object"))

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
                return self._ok(rid,
                                list_tools_payload(self.compose is not None))
            if method == "tools/call":
                return await self._call(rid, params)
            if is_notification:
                return None
            return self._err(rid, METHOD_NOT_FOUND,
                             "method not implemented: %s" % method)
        except Exception as exc:
            # Never let a traceback reach a client: a stack trace in a tool
            # result is noise the model has to read past, and it can name
            # server paths it has no business knowing.
            if is_notification:
                return None
            return self._err(rid, INTERNAL_ERROR,
                             "%s: %s" % (type(exc).__name__, exc))

    # ------------------------------------------------------------- tools/call
    async def _call(self, rid, params):
        name = params.get("name")
        args = params.get("arguments")
        if args is None:
            args = {}
        # A frame whose `arguments` is not an object is a MALFORMED REQUEST,
        # not a failed tool call, so it gets a JSON-RPC error rather than an
        # isError result. Returning isError here would say "the tool ran and
        # failed", which is a different thing and a client branching on
        # isError would treat it as the tool's fault.
        if not isinstance(args, dict):
            return self._err(rid, INVALID_PARAMS,
                             "arguments must be an object")
        if not isinstance(name, str):
            return self._err(rid, INVALID_PARAMS,
                             "tools/call needs a string tool name")

        tool = TOOL_INDEX.get(name)
        if tool is None:
            # sorted() over the dicts themselves raises TypeError, which the
            # outer handler would turn into a -32603: an unknown tool name
            # would look like a server fault instead of a caller mistake.
            names = sorted(t["name"] for t in
                           available_tools(self.compose is not None))
            return self._ok(rid, _text(
                "no tool named %r. Available: %s" % (name, ", ".join(names)),
                True))

        # The gate runs BEFORE anything else reaches out, so an unconfirmed
        # destructive call is never sent - not sent and rejected, never sent.
        refusal = check_confirmation(name, args)
        if refusal is not None:
            self._record(name, args, False, "refused: needs confirmation")
            return self._ok(rid, _text(refusal, True))

        if tool.get("compose"):
            if self.compose is None:
                return self._ok(rid, _text(
                    "%s is only available on the HTTP transport" % name, True))
            try:
                data = self.compose(name, args)
            except Exception as exc:
                self._record(name, args, False, "compose failed")
                return self._ok(rid, _text(
                    "%s could not be built: %s: %s"
                    % (name, type(exc).__name__, exc), True))
            self._record(name, args, True, "composed")
            return self._ok(rid, _text(_json(data)))

        # `confirm` is a gate argument, not a request field. Stripping it here
        # means a tool's own body mapping never has to know about it.
        clean = {k: v for k, v in args.items() if k != "confirm"}

        try:
            res = await self.executor.call(tool, clean)
        except Exception as exc:
            self._record(name, args, False, "%s" % type(exc).__name__)
            return self._ok(rid, _text("%s: %s" % (type(exc).__name__, exc), True))

        if not isinstance(res, dict):
            self._record(name, args, False, "executor returned nonsense")
            return self._ok(rid, _text("the tool returned nothing usable", True))

        status = res.get("status") or 0
        good = res.get("error") is None and 200 <= status < 300
        self._record(name, args, good, "status=%s" % status)
        if good:
            return self._ok(rid, _text(_json(res.get("data"))))
        # The panel's own status and detail survive to the model: a 422 that
        # names the offending field is the most useful thing it can be told.
        return self._ok(rid, _text(_json({"status": status,
                                         "error": res.get("error")}), True))

    # ----------------------------------------------------------------- audit
    def _record(self, name, args, good, detail):
        if self.audit is None:
            return
        try:
            target = (args.get("username") or args.get("user_id")
                      or args.get("name") or args.get("token_id") or "-")
            self.audit(name, str(target), bool(good), detail)
        except Exception:
            # An audit failure must not fail the operator's action. Losing a
            # log line is bad; refusing a legitimate call because the log is
            # unhappy is worse.
            pass

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _ok(rid, result):
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid, code, message):
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": code, "message": message}}