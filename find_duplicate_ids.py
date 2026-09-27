"""Every id in panel.html must be unique.

`$("#x")` returns the FIRST match, so a duplicated id makes one copy of the
markup dead - the panel's own comment about the moved token card says exactly
that. The existing guard only checked the three apitoken ids, and a duplicate
elsewhere would be invisible.
"""
import collections
import io
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

for name in ("panel.html", "login.html", "sub.html"):
    s = io.open("templates/" + name, encoding="utf-8").read()
    ids = re.findall(r'\bid="([^"]+)"', s)
    dup = {k: v for k, v in collections.Counter(ids).items() if v > 1}
    print(f"{name}: {len(ids)} ids, {len(set(ids))} unique"
          + (f"  DUPLICATES: {dup}" if dup else "  ok"))
    if dup:
        for d in dup:
            for m in re.finditer(r'\bid="' + re.escape(d) + r'"', s):
                line = s.count("\n", 0, m.start()) + 1
                ctx = s[max(0, m.start() - 70):m.start() + 40].replace("\n", " ")
                print(f"    {d} at line {line}: ...{ctx}...")
sys.exit(0)
