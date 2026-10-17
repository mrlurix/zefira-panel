"""The audit-retention figures in SECURITY.md must match the code.

Measured on a running panel, then written down:

    600 tool calls accepted at the 600/min ceiling
    -> both canary rows (an operator's settings change, and a refused
       destructive call) gone
    -> MCP_CALL was 100% of the retained 2000 rows

So "about 3 minutes" is a measurement and "about 33 minutes" is the same
arithmetic at the default budget. A number in a document that drifts from the
code is worse than no number, and the whole reason this file exists is that
earlier releases shipped figures nobody re-checked.

This guard therefore reads the three things that determine the answer - the
prune threshold, the default budget and the schema's maximum - computes the
two durations, and fails if the document says anything else. It also fails if
the retention changes without the document following, which is the case that
matters: someone raising the cap and leaving the prose alone.
"""

import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:150])
                         if (detail and not cond) else ""))


main = io.open(os.path.join(ROOT, "main.py"), encoding="utf-8").read()
schemas = io.open(os.path.join(ROOT, "schemas.py"), encoding="utf-8").read()
sec = io.open(os.path.join(ROOT, "SECURITY.md"), encoding="utf-8").read()

# ---- read the numbers out of the code, not out of the document
m = re.search(r"MAX\(id\),\s*0\)\s*-\s*(\d+)\s+FROM audit_logs", main)
check("the prune threshold is readable from main.py", m is not None,
      "the DELETE statement did not match")
KEEP = int(m.group(1)) if m else 0
print("  the code keeps the newest %d audit rows" % KEEP)

# The default does NOT live in schemas.py any more: max_calls_per_min became
# Optional with default=None so a partial PUT cannot reset it (that was one of
# the fourteen defects), so the fallback an unset row actually gets is the one
# in _mcp_settings_dict. Reading the schema would have read None.
d = re.search(r'int\(cached_setting\("mcp_max_calls_per_min"\)\s*or\s*(\d+)\)',
              main)
check("the default MCP budget is readable from the code that applies it",
      d is not None, "the fallback in _mcp_settings_dict did not match")
DEFAULT = int(d.group(1)) if d else 0
mx = re.search(r"max_calls_per_min:[^\n]*le=(\d+)", schemas)
check("the maximum MCP budget is readable from schemas.py", mx is not None)
MAXIMUM = int(mx.group(1)) if mx else 0
print("  the MCP budget runs from %d/min (default) to %d/min (maximum)"
      % (DEFAULT, MAXIMUM))

check("KEEP, DEFAULT and MAXIMUM are all sane",
      KEEP > 0 and 0 < DEFAULT <= MAXIMUM,
      "%d / %d / %d" % (KEEP, DEFAULT, MAXIMUM))

# ---- the arithmetic the document has to agree with
at_default = KEEP / float(DEFAULT)
at_maximum = KEEP / float(MAXIMUM)


def as_text(minutes):
    """33.3 -> 'about 33 minutes', 3.3 -> 'about 3 minutes'."""
    return "about %d minutes" % round(minutes)


check("at the default budget the window is about %d minutes"
      % round(at_default), 30 <= at_default <= 40, at_default)
check("at the maximum budget it is about %d minute(s)"
      % round(at_maximum), 2.5 <= at_maximum <= 4.0, at_maximum)

# ---- and the document must say exactly that
check("SECURITY.md names the retention figure the code uses",
      re.search(r"newest\s+%d\s+rows" % KEEP, sec) is not None,
      "looking for 'newest %d rows'" % KEEP)
# Also: it must not name a DIFFERENT one. Checking only for the right figure
# would pass a document that says both "2000 rows" and "2500 rows", which is
# exactly what an edit-in-place produces.
stated = sorted(set(int(x) for x in re.findall(r"newest\s+(\d+)\s+rows", sec)))
check("...and does not also name a different retention figure",
      stated in ([], [KEEP]), "the document names %s" % stated)
check("...and quotes the default budget the schema sets",
      re.search(r"%d/min" % DEFAULT, sec) is not None,
      "looking for '%d/min'" % DEFAULT)
check("...and quotes the maximum the schema allows",
      re.search(r"%d/min" % MAXIMUM, sec) is not None,
      "looking for '%d/min'" % MAXIMUM)
check("...and states the window it implies at the default budget",
      as_text(at_default) in sec, as_text(at_default))
check("...and at the maximum budget",
      as_text(at_maximum) in sec, as_text(at_maximum))

# ---- and the trade-off must be filed as a trade-off, not as a defect
check("it is listed among the known trade-offs, not as a defect",
      "### Known trade-offs, not defects" in sec
      and sec.index("### Known trade-offs, not defects")
      < sec.index("newest %d rows" % KEEP))
check("and it points at the knob that changes the answer",
      "max_calls_per_min" in sec)

# ---- no stale numbers of the old kind anywhere in the file
check("SECURITY.md still states no suite total in words",
      not re.search(r"\b(?:thirty|forty|fifty|sixty|seventy)\w*\s+test suites",
                    sec, re.I))
check("and no per-suite check counts that can go stale",
      not re.search(r"\b\d+\s*/\s*\d+\s+(?:checks|passing)", sec))

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)
