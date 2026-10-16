"""The MCP transports. stdio here; the HTTP transport lives in main.py.

stdio is newline-delimited JSON-RPC on stdin/stdout: one JSON object per line
in, one per line out.

stdout IS the protocol channel. A single stray print() puts a non-JSON line on
the wire and the client disconnects with no useful message - so every
diagnostic in this file goes to stderr, and the test asserts stdout carries
nothing but frames.

A line that is not JSON gets a -32700 and the loop continues. One bad frame
from a client must not end the session.
"""

import asyncio
import json
import os
import sys

from mcp_exec import HttpExecutor
from mcp_protocol import Dispatcher

USAGE = ("zefira-mcp: set ZEFIRA_URL and ZEFIRA_TOKEN, or pass --base-url "
         "and --token\n")


def read_env_config():
    """(base_url, token) from the environment.

    Empty strings rather than an exception when a variable is absent: the
    caller decides what to do about it, and a client that launched this
    process without a token gets a clear message rather than a stack trace
    from inside an MCP server.
    """
    url = (os.environ.get("ZEFIRA_URL") or "").strip()
    tok = (os.environ.get("ZEFIRA_TOKEN") or "").strip()
    return url, tok


def run_stdio(base_url, token, stdin=None, stdout=None, executor=None):
    """Serve MCP on stdin/stdout until the stream ends.

    `executor` exists so the test can drive this without a panel; the real
    path builds an HttpExecutor over the operator's bearer token.
    """
    src = stdin if stdin is not None else sys.stdin
    dst = stdout if stdout is not None else sys.stdout

    if executor is None:
        if not base_url or not token:
            sys.stderr.write(USAGE)
            return 2
        executor = HttpExecutor(base_url, token)
    dispatcher = Dispatcher(executor)

    loop = asyncio.new_event_loop()
    try:
        while True:
            try:
                line = src.readline()
            except (KeyboardInterrupt, EOFError):
                break
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
                try:
                    response = loop.run_until_complete(
                        dispatcher.handle(request))
                except Exception as exc:
                    # The dispatcher already catches its own errors; this is
                    # the last line of defence, so a frame always gets an
                    # answer rather than the session dying mid-stream.
                    response = {"jsonrpc": "2.0",
                                "id": (request.get("id")
                                       if isinstance(request, dict) else None),
                                "error": {"code": -32603,
                                          "message": "%s: %s"
                                                     % (type(exc).__name__, exc)}}
                if response is None:
                    continue
            try:
                dst.write(json.dumps(response, ensure_ascii=False, default=str))
                dst.write("\n")
                dst.flush()
            except (BrokenPipeError, ValueError):
                # The client went away. That is a normal end of session, not
                # an error to shout about on a pipe nobody is reading.
                return 0
    finally:
        try:
            loop.close()
        except Exception:
            pass
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    url, tok = read_env_config()
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--base-url" and i + 1 < len(argv):
            url = argv[i + 1].strip()
            i += 2
            continue
        if a == "--token" and i + 1 < len(argv):
            tok = argv[i + 1].strip()
            i += 2
            continue
        if a in ("-h", "--help"):
            sys.stderr.write(USAGE)
            return 0
        i += 1
    if not url or not tok:
        sys.stderr.write(USAGE)
        return 2
    return run_stdio(url, tok)


if __name__ == "__main__":
    raise SystemExit(main())