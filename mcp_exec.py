"""Run one tool call against the panel.

Two executors, one table. `HttpExecutor` is for the stdio process, which is a
separate program and therefore has to speak HTTP. `AsgiExecutor` lives below
and forwards through the panel's own app instead. Both read the same TOOLS
entries, so a tool cannot exist on one transport and be missing on the other.

build_call is the argument mapper. Three body forms exist because three kinds
of tool need three things:
  - a flat mapping: body keys come from named arguments
  - "__all__":     the one argument IS the whole body
  - "__merge__":   the one argument is spread in beside the others

Nothing here decides whether a tool is allowed to run. That is
`mcp_tools.check_confirmation`, and the dispatcher calls it before it ever
reaches this file - an unconfirmed destructive call is not sent and rejected,
it is never sent.
"""

import asyncio
import json
import urllib.error
import urllib.parse
import urllib.request

# A value this long in a path segment is not an id. The panel bounds every
# id itself; this only stops a caller pasting an entire backup into a URL.
_MAX_PATH_SEGMENT = 64


class ToolError(Exception):
    """A refusal the caller should read, not a crash."""


def _quote(value, name, arg):
    s = str(value)
    if len(s) > _MAX_PATH_SEGMENT:
        raise ToolError("%s: %r is too long to be a %s" % (name, arg, arg))
    return urllib.parse.quote(s, safe="")


def build_call(tool, args):
    """(method, final_path, body, query) for one call. Raises ToolError.

    A missing path parameter is an error rather than a blank, because
    `/api/users//reset-usage` matches no route and would come back as a 404
    that says nothing about which argument was missing.
    """
    if not isinstance(args, dict):
        raise ToolError("%s: arguments must be an object" % tool["name"])
    name = tool["name"]

    path = tool["path"]
    for key in tool.get("path_params", {}):
        if key not in args:
            raise ToolError('%s needs "%s"' % (name, key))
        if args[key] is None:
            raise ToolError('%s: "%s" must not be null' % (name, key))
        path = path.replace("{%s}" % key, _quote(args[key], name, key))

    query = {}
    for arg, param in tool.get("query", {}).items():
        # `is not None`, not truthiness: limit=0 is a real limit and limit=""
        # is a real search, and dropping either would quietly widen the result.
        if arg in args and args[arg] is not None:
            query[param] = args[arg]

    body = None
    if tool["method"] in ("POST", "PATCH", "PUT"):
        body = {}
        for target, source in tool.get("body", {}).items():
            if target == "__all__":
                value = args.get(source)
                if not isinstance(value, dict):
                    raise ToolError('%s: "%s" must be an object' % (name, source))
                body = dict(value)
            elif target == "__merge__":
                value = args.get(source)
                if not isinstance(value, dict):
                    raise ToolError('%s: "%s" must be an object' % (name, source))
                body.update(value)
            elif source in args:
                # absent stays absent. The panel writes a default for any key
                # present in the body, so sending null would make it write a
                # default nobody asked for.
                body[target] = args[source]

    return tool["method"], path, body, query


class HttpExecutor:
    """Speaks the panel's HTTP with a bearer token, on a worker thread.

    A thread rather than an async client because the panel's own code uses
    urllib, and taking on an async HTTP library to make one request would be
    the dependency this project decided not to take.
    """

    def __init__(self, base_url, token, timeout=30.0):
        self.base = (base_url or "").rstrip("/")
        self.token = token
        self.timeout = timeout

    def _once(self, method, path, body, query):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in query.items() if v != ""})
        headers = {
            "Authorization": "Bearer " + self.token,
            # A bearer already exempts the panel's CSRF guard. Sending the
            # header anyway costs nothing and keeps this working if that rule
            # is ever tightened.
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
        }
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False, default=str).encode()
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
            # The panel's own status and detail are the most useful thing a
            # model can be told. Wrapping them in a generic failure would hide
            # a 422 that names the offending field.
            return {"status": exc.code, "error": parsed}
        except urllib.error.URLError as exc:
            return {"error": "cannot reach the panel at %s: %s"
                             % (self.base, exc.reason)}
        except Exception as exc:
            return {"error": "%s: %s" % (type(exc).__name__, exc)}

    async def call(self, tool, args):
        method, path, body, query = build_call(tool, args)
        return await asyncio.to_thread(self._once, method, path, body, query)


import json as _json
import urllib.parse as _up


def split_path_and_query(full):
    """(path, query_string_bytes) from a joined path.

    Split on the FIRST ? only, and never on an encoded %3F: a username
    containing a literal question mark arrives percent-encoded and must stay
    inside the path.
    """
    if "?" not in full:
        return full, b""
    head, tail = full.split("?", 1)
    return head, tail.encode()


class AsgiExecutor:
    """Runs a tool in-process by forwarding through the panel's own app."""

    def __init__(self, app, token):
        self.app = app
        self.token = token

    async def call(self, tool, args):
        method, path, body, query = _build(tool, args)
        url = path
        if query:
            url += "?" + _up.urlencode(
                {k: v for k, v in query.items() if v != ""})
        bare, raw_qs = split_path_and_query(url)

        payload = b"" if body is None else _json.dumps(
            body, ensure_ascii=False, default=str).encode()
        headers = [
            (b"host", b"127.0.0.1:8000"),
            (b"authorization", ("Bearer " + self.token).encode()),
            # A bearer already exempts the CSRF guard; sending this anyway
            # keeps the forwarded call working if that rule is tightened.
            (b"x-requested-with", b"XMLHttpRequest"),
            (b"accept", b"application/json"),
            (b"content-type", b"application/json"),
            # The panel's size middleware compares against this, so it has to
            # be the real length or a POST is rejected as oversized.
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
            # A fresh dict per call. A shared one would leak one caller's
            # request.state into the next, and the spike's two consecutive
            # 200s are exactly the shape a leak would hide behind.
            "state": {},
        }

        out = {"status": 0}
        chunks = []

        async def receive():
            # Idempotent on purpose: the panel's size middleware reads the
            # body, then swaps in its own replay, so a receive that answered
            # http.disconnect the second time would break the POST path.
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
            parsed = _json.loads(raw) if raw else None
        except Exception:
            parsed = raw.decode("utf-8", "replace")
        status = out["status"]
        if 200 <= status < 300:
            return {"status": status, "data": parsed}
        return {"status": status, "error": parsed}


def _build(tool, args):
    """build_call under a private name, so importing this half alone works."""
    from mcp_exec import build_call
    return build_call(tool, args)