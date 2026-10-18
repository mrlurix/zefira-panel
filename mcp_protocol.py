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

from mcp_tools import (PROTOCOL_VERSION, PROTOCOL_VERSIONS, TOOLS, TOOL_INDEX,
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


def available_tools(
        has_compose: bool) -> List[Dict[str, Any]]:
    """The table, minus any composed tool this process cannot serve."""
    return [t for t in TOOLS if not t.get("compose") or has_compose]


def list_tools_payload(
        has_compose: bool = False) -> Dict[str, Any]:
    return {"tools": [{"name": t["name"],
                       "description": t["description"],
                       "inputSchema": t["input_schema"]}
                      for t in available_tools(has_compose)]}


def _text(s: str, is_error: bool = False) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": s}], "isError": bool(is_error)}


def _json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


class Dispatcher:
    """Turns one parsed JSON-RPC request into one response, or None.

    `compose` is optional. A composed tool needs DB access the executors do
    not have - subscription_link assembles a URL from the user's token row -
    so without a compose callable the tool is simply not offered, rather than
    offered and failing when called. A stdio process has no business
    assembling a link it cannot verify, so it runs without one.
    """

    def __init__(self, executor: Any,
                 audit: Optional[Any] = None,
                 compose: Optional[Any] = None) -> None:
        self.executor = executor
        self.audit = audit
        self.compose = compose

    # ------------------------------------------------------------------ core
    async def handle(
            self, request: Any
) -> Optional[Dict[str, Any]]:
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

        # The envelope, which was never read at all: measured, jsonrpc "1.0"
        # and a missing jsonrpc were both accepted, and a Response object
        # ("result" with no "method") was treated as a Request. JSON-RPC 2.0
        # requires the member and requires its value to be exactly "2.0".
        if request.get("jsonrpc") != "2.0":
            return (None if is_notification
                    else self._err(rid, INVALID_REQUEST,
                                   'jsonrpc must be "2.0"'))
        if method is None:
            if "result" in request or "error" in request:
                return (None if is_notification
                        else self._err(rid, INVALID_REQUEST,
                                       "that is a response, not a request"))
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
            response = await self._dispatch(method, params, rid,
                                                is_notification)
        except Exception as exc:
            # Never let a traceback reach a client: a stack trace in a tool
            # result is noise the model has to read past, and it can name
            # server paths it has no business knowing.
            response = self._err(rid, INTERNAL_ERROR,
                                 "%s: the panel hit an internal error;"
                                 " the detail is in the audit log"
                                 % type(exc).__name__)
        # The one place a notification is silenced. It used to live only in the
        # malformed-frame branches and the unknown-method fallback, so the four
        # implemented methods answered unconditionally: {"jsonrpc":"2.0",
        # "method":"ping"} came back as {"id":null,"result":{}}, against "The
        # Server MUST NOT reply to a Notification". Over HTTP that also made
        # main.py answer 200-with-a-body where it answers 202 for the same
        # method, so the two transports disagreed - the exact thing this
        # shared dispatcher exists to prevent. One choke point rather than a
        # flag on four call sites, so a method added later inherits the rule.
        #
        # Note a notification of tools/call still EXECUTES; only the reply is
        # dropped. JSON-RPC calls those fire-and-forget, not "do not happen",
        # and the audit row is the point of the whole thing.
        return None if is_notification else response

    async def _dispatch(
            self, method: Any, params: Any, rid: Any,
            is_notification: bool
) -> Optional[Dict[str, Any]]:
        if method == "initialize":
            # Answer with the version the client asked for ONLY if this server
            # implements it. The handshake makes the server name the version it
            # will use, and a client told about an unknown version will send
            # features nothing here understands and read the replies as if it
            # did. Anything unsupported gets our own latest, which is what the
            # spec asks for and what the SDK accepts - measured: it raises
            # "Unsupported protocol version from the server" for anything
            # outside its handshake set.
            want = params.get("protocolVersion")
            ver = (want if isinstance(want, str) and want in PROTOCOL_VERSIONS
                   else PROTOCOL_VERSION)
            return self._ok(rid, {
                "protocolVersion": ver,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME,
                               "version": SERVER_VERSION}})
        if method.startswith("notifications/"):
            # Silent only for a real notification. A frame that CARRIES an id
            # is a Request, and a Request that is never answered hangs the
            # client: measured, {"id":7,"method":"notifications/initialized"}
            # used to stop right here and nothing more. It also swallowed
            # anything like "notifications/../tools/list" instead of answering
            # -32601, so a crafted method name could suppress a request.
            if is_notification:
                return None
            return self._err(rid, METHOD_NOT_FOUND,
                             "no such method: %s" % method)
        if method == "ping":
            return self._ok(rid, {})
        if method == "tools/list":
            return self._ok(rid, list_tools_payload(self.compose is not None))
        if method == "tools/call":
            return await self._call(rid, params)
        return self._err(rid, METHOD_NOT_FOUND,
                         "method not implemented: %s" % method)

    # ------------------------------------------------------------- tools/call
    async def _call(
            self, rid: Any, params: Mapping[str, Any]
) -> Dict[str, Any]:
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
                # Same split as the executor's catch-all below: the type goes
                # to the model, the text goes to the audit row. Compose runs
                # the panel's own database calls in-process, so str(exc) can
                # carry a filesystem path.
                self._record(name, args, False,
                             "compose failed: %s: %s"
                             % (type(exc).__name__, exc))
                return self._ok(rid, _text(
                    "%s could not be built: %s" % (name, type(exc).__name__),
                    True))
            self._record(name, args, True, "composed")
            return self._ok(rid, _text(_json(data)))

        # `confirm` is a gate argument, not a request field. Stripping it here
        # means a tool's own body mapping never has to know about it.
        clean = {k: v for k, v in args.items() if k != "confirm"}

        try:
            res = await self.executor.call(tool, clean)
        except Exception as exc:
            # The TYPE names no path and no secret; the TEXT does, because
            # AsgiExecutor runs the panel in-process and str(exc) is the
            # server's own text - measured carrying an absolute database
            # path. The model gets the type, the audit row gets the detail:
            # the row is written for every failed call and nobody reads it,
            # while the model's answer is read on every single request.
            self._record(name, args, False,
                         "%s: %s" % (type(exc).__name__, exc))
            return self._ok(rid, _text(
                "%s failed inside the panel; the detail is in the audit log."
                % type(exc).__name__, True))

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
    def _record(self, name: str,
               args: Mapping[str, Any],
               good: bool, detail: str) -> None:
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
    def _ok(rid: Any, result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid: Any, code: int,
            message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": code, "message": message}}