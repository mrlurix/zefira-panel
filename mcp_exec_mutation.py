"""Prove the argument mapper and the HTTP executor can fail.

The live checks need a panel on a spare port and a token, so each mutation
costs a full server start. They are worth it: the interesting failures in this
file are behavioural, and a source-only check would not see any of them.
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

print()
print("== each of these can fail ==")
MUTATIONS = [
    # The omitted-argument rule exists because the panel writes a default for
    # any key present in the body: sending null writes a default nobody asked
    # for, silently.
    ("send an omitted optional argument as null",
     ("            elif source in args:",
      "            elif source in args or source not in args:")),
    # The path parameter is the only thing standing between a caller and a
    # different route.
    ("stop escaping a path parameter",
     ('return urllib.parse.quote(s, safe="")', "return s")),
    ("accept a missing path parameter as blank",
     ('        if key not in args:\n'
      '            raise ToolError(\'%s needs "%s"\' % (name, key))',
      '        if key not in args:\n'
      '            args = dict(args, **{key: ""})')),
    # `is not None` rather than truthiness: limit=0 is a real limit.
    ("drop a falsy query value",
     ("        if arg in args and args[arg] is not None:",
      "        if args.get(arg):")),
    # An HTTPError carries the panel's own status and detail, which is the
    # most useful thing a model can be told about a failure.
    ("swallow the panel's status and detail",
     ('            return {"status": exc.code, "error": parsed}',
      '            return {"error": "request failed"}')),
    # An unreachable panel must not take the session down.
    ("let an unreachable panel raise",
     ('        except urllib.error.URLError as exc:\n'
      '            return {"error": "cannot reach the panel at %s: %s"\n'
      '                             % (self.base, exc.reason)}',
      '        except urllib.error.URLError:\n            raise')),
]

raw = io.open(EXEC, "rb").read()
passed = 0
for label, (old, new) in MUTATIONS:
    t = raw.decode("utf-8")
    if old not in t:
        print("[FAIL] goes red: %s  -> the mutation did not apply" % label)
        continue
    io.open(EXEC, "wb").write(t.replace(old, new, 1).encode("utf-8"))
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, "mcp_exec_test.py")],
            capture_output=True, text=True, timeout=900,
            encoding="utf-8", errors="replace")
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
        io.open(EXEC, "wb").write(raw)
        assert io.open(EXEC, "rb").read() == raw, "mcp_exec.py was not restored"

print()
print("=== %d/%d mutations proved red ===" % (passed, len(MUTATIONS)))
sys.exit(0 if passed == len(MUTATIONS) else 1)