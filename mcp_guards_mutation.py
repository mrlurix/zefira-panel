"""Every guard added for the bug hunt can fail.

A regression test that has never been seen red is a test that might not be
testing anything. Each mutation below re-introduces exactly one of the fourteen
defects into the real shipped file, runs the suite that is supposed to catch
it, and restores the file byte for byte.

Two mutations were deliberately written the way the ORIGINAL defects were, not
in a way that trivially trips a check. In particular the redirect one targets
the guard's own guard: if the origin check were reverted to urllib's default,
the far origin would receive the operator's token again.
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

EXEC = os.path.join(ROOT, "mcp_exec.py")
PROTO = os.path.join(ROOT, "mcp_protocol.py")
TOOLS = os.path.join(ROOT, "mcp_tools.py")
MAIN = os.path.join(ROOT, "main.py")
SCHEMAS = os.path.join(ROOT, "schemas.py")

OFFLINE = os.path.join(ROOT, "mcp_guards_test.py")
LIVE = os.path.join(ROOT, "mcp_routes_test.py")

print()
print("== each of these can fail ==")
MUTATIONS = [
    (EXEC, OFFLINE, "follow a redirect to any origin and replay the bearer",
     ("        if target != self.origin:\n"
      "            self.blocked = newurl\n"
      "            return None",
      "        if False:\n            pass")),

    (PROTO, OFFLINE, "answer a notification with a result",
     ("        return None if is_notification else response",
      "        return response")),

    (PROTO, OFFLINE, "hang a request that looks like a notification",
     ("            if is_notification:\n"
      "                return None\n"
      "            return self._err(rid, METHOD_NOT_FOUND,\n"
      "                             \"no such method: %s\" % method)",
      "            return None")),

    (PROTO, OFFLINE, "accept a jsonrpc version that is not 2.0",
     ('        if request.get("jsonrpc") != "2.0":',
      '        if False:')),

    (PROTO, OFFLINE, "put the exception text back into the answer",
     ('                "%s failed inside the panel; the detail is in the'
      ' audit log."\n'
      '                % type(exc).__name__, True))',
      '                "%s: %s" % (type(exc).__name__, exc), True))')),

    (TOOLS, OFFLINE, "turn a missing target into the magic string None",
     ('    if value is None or (isinstance(value, str)'
      ' and not value.strip()):\n'
      '        raise ToolError("%s needs a %s to confirm: you named none,'
      ' so there "\n'
      '                        "is nothing to echo back." % (name, field))\n'
      '    return str(value)',
      '    return str(args.get(_CONFIRM_FIELD[name]))')),

    (EXEC, OFFLINE, "paste a bare dot-segment into the request path",
     ('    out = _quote(value, name, arg)\n'
      '    if out in (".", ".."):\n'
      '        raise ToolError("%s: %r is not a usable %s" % (name, value, arg))\n'
      '    return out',
      "    return _quote(value, name, arg)")),

    (EXEC, OFFLINE, "read a response body with no cap",
     ("                raw = resp.read(MAX_RESPONSE_BYTES)",
      "                raw = resp.read()")),

    (MAIN, LIVE, "make a partial PUT overwrite the fields it was not given",
     ("    given = data.model_dump(exclude_unset=True, exclude_none=True)",
      '    given = {"enabled": data.enabled, "http_enabled": data.http_enabled,\n'
      '             "max_calls_per_min": data.max_calls_per_min}')),

    (SCHEMAS, LIVE, "default every MCP setting back to on",
     ("    enabled: Optional[StrictBool] = None\n"
      "    http_enabled: Optional[StrictBool] = None\n"
      '    max_calls_per_min: Optional[StrictInt] = Field(default=None, ge=1,'
      " le=600)",
      "    enabled: Optional[StrictBool] = True\n"
      "    http_enabled: Optional[StrictBool] = True\n"
      '    max_calls_per_min: Optional[StrictInt] = Field(default=60, ge=1,'
      " le=600)")),

    (MAIN, LIVE, "skip the token-scope check on /api/mcp",
     ("    if not _token_scope_allowed(scopes, \"POST\", \"/api/mcp\"):",
      "    if False:")),

    (MAIN, LIVE, "read the switches fail-open again",
     ('    return {"enabled": _on("mcp_enabled"),\n'
      '            "http_enabled": _on("mcp_http_enabled"),',
      '    return {"enabled": _on("mcp_enabled") or True,\n'
      '            "http_enabled": _on("mcp_http_enabled") or True,')),

    (MAIN, LIVE, "make the self-test answer from a literal again",
     ('"method": "tools/call",\n'
      '              "params": {"name": "panel_stats", "arguments": {}}}',
      '"method": "initialize", params: {})')),
]

passed = 0
saved = {}
for path, suite, label, (old, new) in MUTATIONS:
    raw = saved.setdefault(path, io.open(path, "rb").read())
    t = raw.decode("utf-8")
    if old not in t:
        print("[FAIL] goes red: %s  -> the mutation did not apply" % label)
        continue
    io.open(path, "wb").write(t.replace(old, new, 1).encode("utf-8"))
    reds = []
    try:
        r = subprocess.run([sys.executable, suite], capture_output=True,
                           text=True, timeout=5400, encoding="utf-8",
                           errors="replace")
        reds = [l.strip() for l in (r.stdout or "").splitlines()
                if l.startswith("[FAIL]")]
        went_red = r.returncode != 0
        print("[%s] goes red: %s%s"
              % ("PASS" if went_red else "FAIL", label,
                 "" if went_red else "  -> rc=0 and printed %s"
                 % (reds[:2] or "nothing")))
        if went_red:
            passed += 1
    finally:
        io.open(path, "wb").write(saved[path])
        assert io.open(path, "rb").read() == saved[path], \
            "%s was not restored" % path

print()
print("=== %d/%d proved red; every file restored byte-for-byte ==="
      % (passed, len(MUTATIONS)))
sys.exit(0 if passed == len(MUTATIONS) else 1)
