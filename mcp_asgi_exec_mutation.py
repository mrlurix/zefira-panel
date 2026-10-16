"""Prove the ASGI executor can fail.

The first three are the spike's finding put back: if any of them returns, the
executor answers 404 for a call that answers 200 over the wire, and no error
says why.
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
    # THE spike finding. Leaving ?limit=1 in path made the router match
    # nothing: a 404 for a call that answers 200 over the wire.
    ("stop splitting the query out of the path",
     ('    if "?" not in full:\n        return full, b""\n'
      '    head, tail = full.split("?", 1)\n    return head, tail.encode()',
      '    return full, b""')),
    # NOT `rsplit`. A path-plus-query has exactly one real `?` because every
    # argument value is percent-encoded by build_call, so rsplit and split
    # agree on every string this executor can produce. Adding it as a
    # "mutation" would be inventing a failure that cannot happen - the first
    # version of this list did exactly that, and the suite going green proved
    # the mutation was unreachable rather than that the code was safe.
    #
    # The panel's size middleware compares content-length. A wrong one is a
    # 413 on every forwarded POST.
    ("send a content-length of zero always",
     ('            (b"content-length", str(len(payload)).encode()),',
      '            (b"content-length", b"0"),')),
    # A receive that answers disconnect on the second call breaks the panel's
    # own body read, which streams then replaces _receive with a replay.
    # Disconnect after the first read. This is a REAL failure and the
    # original check missed it, because the check asserted only that
    # `receive can be called repeatedly` - and a disconnect-on-second-call
    # receive IS callable repeatedly. It answers, it just answers the wrong
    # thing, which is the defect. The fix was to the check, not to the code.
    ("answer http.disconnect after the first body read",
     ('            return {"type": "http.request", "body": payload,\n'
      '                    "more_body": False}',
      '            if seen["n"]:\n'
      '                return {"type": "http.disconnect"}\n'
      '            seen["n"] = 1\n'
      '            return {"type": "http.request", "body": payload,\n'
      '                    "more_body": False}')),
    # A shared state dict leaks one caller's request.state into the next.
    ("share one scope state dict across calls",
     ('            "state": {},', '            "state": _SHARED_STATE,')),
]

raw = io.open(EXEC, "rb").read()
passed = 0
for label, (old, new) in MUTATIONS:
    t = raw.decode("utf-8")
    if label.startswith("answer http.disconnect"):
        # that one needs a counter declared alongside it
        t = t.replace("        out = {\"status\": 0}\n        chunks = []",
                      "        seen = {\"n\": 0}\n"
                      "        out = {\"status\": 0}\n        chunks = []", 1)
    if label.startswith("share one scope"):
        t = t.replace("class AsgiExecutor:",
                      "_SHARED_STATE = {}\n\n\nclass AsgiExecutor:", 1)
    if old not in t:
        print("[FAIL] goes red: %s  -> the mutation did not apply" % label)
        continue
    io.open(EXEC, "wb").write(t.replace(old, new, 1).encode("utf-8"))
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, "mcp_asgi_exec_test.py")],
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