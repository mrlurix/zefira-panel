"""Prove the MCP routes can fail.

Six mutations, in the order they would matter if one were wrong. Each is
applied to the real shipped file, the suite is run against the mutated code,
and the file is then restored byte for byte.

Two of the six were written badly at first and stayed green, which is worth
recording because a green mutation is the quietest broken test there is:

  - "charge the limiter before authenticating" originally keyed the extra hit
    on the first 16 characters of the Authorization header. That is a
    DIFFERENT bucket from "mcp|<token_id>", so it charged something no check
    looked at. It now charges the caller's own bucket, which is the actual
    defect: a rejected caller still spends the operator's budget.

  - "treat a zero ceiling as unset" used `self.max_override or self.max`. With
    a ceiling of 5 that evaluates to 5, so the mutation was a no-op. The
    guard is `is not None` precisely because 0 must refuse rather than fall
    back, and the check now reaches 0 by driving the limiter directly -
    cached_setting memoises for fifteen seconds, so writing 0 into the
    settings table left the route reading its own cached value and the check
    was measuring a cache instead of the limiter.
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

MAIN = os.path.join(ROOT, "main.py")
SEC = os.path.join(ROOT, "security.py")
SUITE = os.path.join(ROOT, "mcp_routes_test.py")

print()
print("== each of these can fail ==")
MUTATIONS = [
    (MAIN, "accept a cookie on the transport",
     ('    if auth[:7].lower() != "bearer " or len(auth.strip()) <= 7:',
      '    if auth[:7].lower() != "bearer " and len(auth.strip()) > 7:')),
    (MAIN, "drop the master switch",
     ('    if not cfg["enabled"]:\n'
      '        raise HTTPException(status_code=405, detail="MCP is switched off")',
      '    if False:\n        pass')),
    (MAIN, "freeze the ceiling and ignore the operator's setting",
     ('    mcp_limiter.max_override = _mcp_settings_dict()["max_calls_per_min"]',
      '    pass  # the limiter keeps its constructor ceiling')),
    (MAIN, "let the settings GET return the token",
     ('            "token_hint": _mcp_token_hint(request)}',
      '"token_hint": request.headers.get("authorization", "")}')),
    (MAIN, "charge the CALLER's limiter before authenticating",
     ('    key = "mcp|%s" % (token_id or admin_id)\n'
      '    if not mcp_limiter.hit(key):',
      '    mcp_limiter.hit("mcp|%s" % (request.headers.get("authorization", "")[:12]))\n'
      '    if not mcp_limiter.hit(key):')),
    (SEC, "treat a zero ceiling as unset",
     ('            max_events = (self.max_override\n'
      '                           if self.max_override is not None\n'
      '                           else self.max)',
      '            max_events = self.max_override or self.max')),
]

passed = 0
saved = {}
for path, label, (old, new) in MUTATIONS:
    raw = saved.setdefault(path, io.open(path, "rb").read())
    t = raw.decode("utf-8")
    if old not in t:
        print("[FAIL] goes red: %s  -> the mutation did not apply" % label)
        continue
    io.open(path, "wb").write(t.replace(old, new, 1).encode("utf-8"))
    try:
        r = subprocess.run([sys.executable, SUITE], capture_output=True,
                           text=True, timeout=1800, encoding="utf-8",
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
print("=== %d/%d mutations proved red; both files restored byte-for-byte ==="
      % (passed, len(MUTATIONS)))
sys.exit(0 if passed == len(MUTATIONS) else 1)
