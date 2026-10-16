"""Prove each part of the tool table can fail.

A guard nobody saw fail is a comment with an exit code. Every mutation below
restores a defect this table actually had during design, or the shape one it
would take, so the red is a real failure and not an invented one.
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

TOOLS = os.path.join(ROOT, "mcp_tools.py")
CHILD = os.environ.get("ZEFIRA_MCP_TOOLS_CHILD") == "1"

if CHILD:
    # a normal run; the parent reads the exit code
    raise SystemExit(subprocess.run(
        [sys.executable, os.path.join(ROOT, "mcp_tools_test.py")],
        capture_output=True).returncode)

print()
print("== each of these can fail ==")
MUTATIONS = [
    # the first draft of the design named a subscription route that does not
    # exist; nothing said so until a client called it
    ("point subscription_link at a route that does not exist",
     ('"path": "/api/users/by-username/{username}",\n     "body": {}, '
      '"query": {}, "path_params": {"username": "username"},\n'
      '     "compose": "subscription_link"',
      '"path": "/api/users/{user_id}/subscription",\n     "body": {}, '
      '"query": {}, "path_params": {"user_id": "user_id"},\n'
      '     "compose": "subscription_link"')),
    # and a rotate route that does not exist either
    ("name a token-rotate route the panel does not have",
     ('"method": "DELETE", "path": "/api/api-tokens/{token_id}",',
      '"method": "POST", "path": "/api/api-tokens/{token_id}/rotate",')),
    # the comparison the gate exists for
    ("loosen the confirmation comparison",
     ('    if isinstance(got, str) and got == want:',
      '    if got is not None and str(got).strip() == want:')),
    # and the version, which was a remembered constant until it was read
    ("hard-code a stale protocol version",
     ('PROTOCOL_VERSION = "2026-07-28"', 'PROTOCOL_VERSION = "2024-11-05"')),
    # the wire name leaking into the table
    ("store the wire key instead of the python one",
     ('     "input_schema": _s(user_id=_int("Customer id.")),\n'
      '     "method": "POST", "path": "/api/users/{user_id}/reset-usage",',
      '     "inputSchema": _s(user_id=_int("Customer id.")),\n'
      '     "method": "POST", "path": "/api/users/{user_id}/reset-usage",')),
    # a destructive tool quietly dropping out of the gate
    ("leave delete_user out of the destructive set",
     ('    "delete_user": "user_id",\n    "delete_api_token": "token_id",',
      '    "delete_api_token": "token_id",')),
]

raw = io.open(TOOLS, "rb").read()
passed = 0
for label, (old, new) in MUTATIONS:
    t = raw.decode("utf-8")
    if old not in t:
        print("[FAIL] goes red: %s  -> the mutation did not apply" % label)
        continue
    io.open(TOOLS, "wb").write(t.replace(old, new, 1).encode("utf-8"))
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, "mcp_tools_test.py")],
            capture_output=True, text=True, timeout=300,
            encoding="utf-8", errors="replace",
            env=dict(os.environ, ZEFIRA_MCP_TOOLS_CHILD="1"))
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
        io.open(TOOLS, "wb").write(raw)
        assert io.open(TOOLS, "rb").read() == raw, "mcp_tools.py was not restored"

print()
print("=== %d/%d mutations proved red ===" % (passed, len(MUTATIONS)))
sys.exit(0 if passed == len(MUTATIONS) else 1)