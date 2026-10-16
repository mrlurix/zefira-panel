"""Prove the dispatch layer can fail.

The first two are the gate and the wire format, which are the only two places
in this project where a mistake hands an AI destructive authority or makes a
tool invisible to every client.
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

P = os.path.join(ROOT, "mcp_protocol.py")

print()
print("== each of these can fail ==")
MUTATIONS = [
    # The gate moving after the executor is the one defect that would let a
    # hallucinated delete_user through.
    ("run the confirmation gate after the executor",
     ("""        refusal = check_confirmation(name, args)
        if refusal is not None:
            self._record(name, args, False, "refused: needs confirmation")
            return self._ok(rid, _text(refusal, True))

""",
      """        refusal = None

""")),
    # inputSchema is the wire key. input_schema here makes every tool
    # invisible to a real client while tools/list still answers.
    ("emit the python key instead of the wire key",
     ('                       "inputSchema": t["input_schema"]}',
      '                       "input_schema": t["input_schema"]}')),
    # ttlMs/cacheScope are what dumping the SDK's model would add.
    ("let the SDK's default fields into tools/list",
     ('    return {"tools": [{"name": t["name"],',
      '    return {"ttlMs": 0, "cacheScope": "private",\n'
      '            "tools": [{"name": t["name"],')),
    # The one that turned an unknown tool name into a -32603 server fault.
    ("sort the tool dicts instead of their names",
     ('            names = sorted(t["name"] for t in\n'
      '                           available_tools(self.compose is not None))',
      '            names = sorted(available_tools(self.compose is not None))')),
    # A malformed frame answered as an isError result says "the tool ran and
    # failed", which is a different thing.
    ("answer a malformed arguments frame as a tool failure",
     ('        if not isinstance(args, dict):\n'
      '            return self._err(rid, INVALID_PARAMS,\n'
      '                             "arguments must be an object")',
      '        if not isinstance(args, dict):\n'
      '            return self._ok(rid, _text("arguments must be an object",\n'
      '                                        True))')),
    # A composed tool needs DB access the executors lack; offering it anyway
    # means every call fails.
    ("offer composed tools with no compose callable",
     ('    return [t for t in TOOLS if not t.get("compose") or has_compose]',
      '    return list(TOOLS)')),
]

raw = io.open(P, "rb").read()
passed = 0
for label, (old, new) in MUTATIONS:
    t = raw.decode("utf-8")
    if old not in t:
        print("[FAIL] goes red: %s  -> the mutation did not apply" % label)
        continue
    io.open(P, "wb").write(t.replace(old, new, 1).encode("utf-8"))
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, "mcp_protocol_test.py")],
            capture_output=True, text=True, timeout=600,
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
        io.open(P, "wb").write(raw)
        assert io.open(P, "rb").read() == raw, "mcp_protocol.py was not restored"

print()
print("=== %d/%d mutations proved red ===" % (passed, len(MUTATIONS)))
sys.exit(0 if passed == len(MUTATIONS) else 1)