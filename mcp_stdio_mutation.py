"""Prove the stdio loop can fail.

The first two are the ones that kill a real client session: a print() on
stdout, and a bad frame taking the loop down with it.
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

P = os.path.join(ROOT, "mcp_server.py")

print()
print("== each of these can fail ==")
MUTATIONS = [
    # stdout IS the wire. One print puts a non-JSON line on it and the client
    # disconnects with no useful message.
    ("write a diagnostic to stdout",
     ('                dst.write(json.dumps(response, ensure_ascii=False,'
      ' default=str))\n                dst.write("\\n")',
      '                print("handling", request)\n'
      '                dst.write(json.dumps(response, ensure_ascii=False,'
      ' default=str))\n                dst.write("\\n")')),
    # One malformed frame ends the session otherwise.
    ("let a bad frame stop the loop",
     ('                response = {"jsonrpc": "2.0", "id": None,\n'
      '                            "error": {"code": -32700,\n'
      '                                      "message": "invalid JSON: %s" % exc}}',
      '                raise')),
    # Answering a notification means answering a frame the client is not
    # waiting for, which desynchronises a strict client.
    ("answer notifications instead of ignoring them",
     ('                if response is None:\n                    continue',
      '                if response is None:\n'
      '                    response = {"jsonrpc": "2.0", "id": None,\n'
      '                                "result": {}}')),
    # Not flushing per line leaves a client reading a pipe that never
    # produces, which looks like a hang rather than a response.
    ("stop flushing after each line",
     ('                dst.write("\\n")\n                dst.flush()',
      '                dst.write("\\n")')),
    # Refusing to start without a token: a client that launched this without
    # one gets a usage message on stderr, which is the whole difference
    # between a fixable config error and a mystery.
    ("start anyway with no token",
     ('    if not url or not tok:\n        sys.stderr.write(USAGE)\n        return 2',
      '    if not tok:\n        sys.stderr.write(USAGE)\n        return 2')),
    ("echo the token in the refusal",
     ('        sys.stderr.write(USAGE)\n        return 2',
      '        sys.stderr.write(USAGE + "token=" + tok)\n        return 2')),
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
            [sys.executable, os.path.join(ROOT, "mcp_stdio_test.py")],
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
        assert io.open(P, "rb").read() == raw, "mcp_server.py was not restored"

print()
print("=== %d/%d mutations proved red ===" % (passed, len(MUTATIONS)))
sys.exit(0 if passed == len(MUTATIONS) else 1)