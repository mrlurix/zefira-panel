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
from typing import Any, Dict, List, Mapping, Optional, Tuple
import json
import urllib.error
import urllib.parse
import urllib.request

# A value this long in a path segment is not an id. The panel bounds every
# id itself; this only stops a caller pasting an entire backup into a URL.
_MAX_PATH_SEGMENT = 64


# A response the panel produced is small; a response from something that is
# not the panel can be anything at all. 32 MiB is far above any real endpoint
# here and low enough that a hostile or broken peer cannot exhaust memory
# through one tool call. Measured before the cap: a single call buffered 50 MB.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


class ToolError(Exception):
    """A refusal the caller should read, not a crash."""


def _quote_segment(value: Any, name: str, arg: str) -> str:
    """_quote, then refuse a value that is only a dot-segment.

    quote() never encodes ".", because RFC 3986 calls it unreserved - right for
    a value, wrong here, because a bare ".." then survives into the path whole.
    Measured: `delete_user` with user_id=".." built `DELETE /api/users/..`,
    and `user_config` built `GET /api/users/../config`. Against the panel
    directly both are refused - 422 from a route parameter typed int - so
    nothing destructive happens, but behind a normalising reverse proxy, which
    the documented install has, the request that arrives is /api/ or
    /api/config instead. The path a tool DECLARES has to be the path that gets
    REQUESTED.

    No legitimate argument is "." or "..", so this refuses rather than escapes.
    """
    out = _quote(value, name, arg)
    if out in (".", ".."):
        raise ToolError("%s: %r is not a usable %s" % (name, value, arg))
    return out


def _quote(value: Any, name: str, arg: str) -> str:
    s = str(value)
    if len(s) > _MAX_PATH_SEGMENT:
        raise ToolError("%s: %r is too long to be a %s" % (name, arg, arg))
    return urllib.parse.quote(s, safe="")


def build_call(tool: Mapping[str, Any],
              args: Mapping[str, Any]
) -> Tuple[str, str, Any, Dict[str, Any]]:
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
        path = path.replace("{%s}" % key,
                           _quote_segment(args[key], name, key))

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


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never carry the bearer to another origin.

    urllib's default handler replays every header it is not explicitly told to
    strip, and Authorization is not on its list. Measured against two loopback
    servers: a 302 from the configured host sent
    `Authorization: Bearer <token>` to a different port, and the tool call
    still came back as a 200 success. A `full`-scope token can delete
    customers and read their private keys, so that is the whole credential
    handing itself to whatever a Location header names.

    urllib cannot follow a redirect without the new request's headers, so
    redirect_request returning None is what refuses the hop. The alternative -
    following it and then checking resp.url - is too late: the header has
    already been sent.
    """

    def __init__(self, base: str) -> None:
        parts = urllib.parse.urlsplit(base)
        self.origin = (parts.scheme.lower(), parts.netloc.lower())
        self.blocked = None

    def redirect_request(self, req: Any, fp: Any, code: int,
                          msg: str, headers: Any,
                          newurl: str) -> Optional[Any]:
        parts = urllib.parse.urlsplit(newurl)
        target = (parts.scheme.lower(), parts.netloc.lower())
        if target != self.origin:
            self.blocked = newurl
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpExecutor:
    """Speaks the panel's HTTP with a bearer token, on a worker thread.

    A thread rather than an async client because the panel's own code uses
    urllib, and taking on an async HTTP library to make one request would be
    the dependency this project decided not to take.
    """

    def __init__(self, base_url: str, token: str,
                 timeout: float = 30.0) -> None:
        self.base = (base_url or "").rstrip("/")
        self.token = token
        self.timeout = timeout
        # One opener, built once: rebuilding a handler per request would leak a
        # connection pool's worth of state for nothing, and the no-redirect
        # guard has to be the same object the request actually goes through.
        self._redirect = _SameOriginRedirect(self.base)
        self._opener = urllib.request.build_opener(self._redirect)

    def _once(self, method: str, path: str, body: Any,
              query: Mapping[str, Any]) -> Dict[str, Any]:
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
            with self._opener.open(req, timeout=self.timeout) as resp:
                # A refused cross-origin hop raises HTTPError below; this is
                # here so the reason can name the host rather than just "401".
                if self._redirect.blocked:
                    return {"error":
                            "the panel redirected to another origin and the "
                            "token was NOT sent there: %s"
                            % self._redirect.blocked}
                raw = resp.read(MAX_RESPONSE_BYTES)
                try:
                    return {"status": resp.status, "data": json.loads(raw)}
                except Exception:
                    return {"status": resp.status,
                            "data": raw.decode("utf-8", "replace")}
        except urllib.error.HTTPError as exc:
            # A refused cross-origin hop arrives here as a 3xx, not as a
            # response body, so `raw` is empty and the panel's own status would
            # read as a silent failure. Say what happened instead - and say it
            # here, because the `with` block above never runs on this path.
            if self._redirect.blocked:
                return {"error":
                        "the panel redirected to another origin and the token "
                        "was NOT sent there: %s" % self._redirect.blocked}
            raw = exc.read(MAX_RESPONSE_BYTES)
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

    async def call(
            self, tool: Mapping[str, Any],
            args: Mapping[str, Any]) -> Dict[str, Any]:
        method, path, body, query = build_call(tool, args)
        return await asyncio.to_thread(self._once, method, path, body, query)


import json as _json
import urllib.parse as _up


def split_path_and_query(full: str) -> Tuple[str, bytes]:
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

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.token = token

    async def call(
            self, tool: Mapping[str, Any],
            args: Mapping[str, Any]) -> Dict[str, Any]:
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

        async def receive() -> Dict[str, Any]:
            # Idempotent on purpose: the panel's size middleware reads the
            # body, then swaps in its own replay, so a receive that answered
            # http.disconnect the second time would break the POST path.
            return {"type": "http.request", "body": payload,
                    "more_body": False}

        async def send(m: Mapping[str, Any]) -> None:
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


def _build(tool: Mapping[str, Any],
          args: Mapping[str, Any]
) -> Tuple[str, str, Any, Dict[str, Any]]:
    """build_call under a private name, so importing this half alone works."""
    from mcp_exec import build_call
    return build_call(tool, args)