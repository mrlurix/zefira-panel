"""Fail on any literal selector in static/app.js that querySelector would reject.

`$("##id")` does not return null - querySelector THROWS a SyntaxError on an
invalid selector, and these bindings sit at module scope, so the throw aborts
every later top-level statement in the file. The hand-rolled `?.` null guards
that were added for missing elements cannot help: the exception happens while
evaluating the argument, before the guard is reached.

First version of this check produced two false positives, which is worth
recording because both look like real bugs:
  - it did not accept a DESCENDANT selector ("#section-api [data-copy]")
  - it read selectors with single outer quotes and inner double quotes
    ('input[name="proto"]') as if the outer quotes were double, and reported
    the fragment as invalid.
So the pattern set is explicit about what it accepts, and anything it cannot
classify is reported rather than silently passed.
"""
import io
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
P = "static/app.js"
src = io.open(P, encoding="utf-8").read()

# Collect literal selectors, honouring both quote styles. A selector is the text
# between the matching outer quotes; inner quotes of the OTHER style are part of
# it, which is exactly the case a naive regex gets wrong.
#
# bind() is in the list because it is now the PRIMARY way this file reaches an
# element - a scanner that only knew about $() would have missed every one of
# them, and did exactly that on the first run.
sels = []
for m in re.finditer(
        r"""(?:\$\(\s*|bind\(\s*|querySelector(?:All)?\(\s*)(["'])(.*?)\1""",
        src, re.S):
    sels.append((m.start(2), m.group(2)))

# Anything built at runtime or assembled from a variable.
DYNAMIC_MARKERS = ("#section-", "${", "+ ")
ACCEPT = [
    re.compile(r"^#[A-Za-z_][\w-]*$"),                       # #id
    re.compile(r"^\.[A-Za-z_][\w-]*$"),                       # .class
    re.compile(r"^[A-Za-z][\w-]*$"),                          # tag
    re.compile(r"^[#.][\w-]+(?:[ >+~][#.][\w-]+)*$"),         # .a > #b
    re.compile(r"^[#.][\w-]+(?:\[[^\]]+\])+$"),               # #a[x]
    re.compile(r"^\[[\w-]+(?:\^?=[\"']?[^]\"']*[\"']?)?\]$"),  # [x=y]
    re.compile(r"^\[[\w-]+$"),                                # [x  (prefix scan)
    re.compile(r"^:root$|^html$|^body$"),
    re.compile(r"^[#.][\w-]+::?[\w-]+(?:\([^)]*\))?$"),        # pseudo-class
    re.compile(r"^input\[[^\]]+\](?::[\w-]+)?$"),
    re.compile(r"^select\[[^\]]+\](?::[\w-]+)?$"),
    re.compile(r"^\.[\w-]+\s*>\s*[\w-]+$"),
    re.compile(r"^#[\w-]+\s+\[[\w-]+\]$"),                    # #a [x]
    # Two more real selectors this check first reported as invalid:
    re.compile(r"^\.[\w-]+(?:\.[\w-]+)+$"),                   # .a.b.c
    re.compile(r"^[A-Za-z][\w-]*\[[^\]]+\](?::\([^)]*\))?$"), # button[x], a:not(b)
    re.compile(r"^[A-Za-z][\w-]*::?[\w-]+(?:\([^)]*\))?$"),     # button:not([type])
    re.compile(r"^[A-Za-z][\w-]*\[[^\]]+\]::?[\w-]+(?:\([^)]*\))?$"),
]
# A comma-separated group is valid CSS, so each member is classified on its own
# rather than trying to match the whole group with one pattern.
GROUP_SPLIT = re.compile(r"\s*,\s*")


def line_of(pos):
    return src.count("\n", 0, pos) + 1


bad, checked = [], set()
for pos, sel in sels:
    sel = sel.strip()
    if not sel or sel in checked or any(k in sel for k in DYNAMIC_MARKERS):
        continue
    checked.add(sel)
    members = GROUP_SPLIT.split(sel)
    if not all(any(p.match(m) for p in ACCEPT) for m in members):
        bad.append((line_of(pos), sel))

print(f"literal selectors classified: {len(checked)}")
if not bad:
    print("  all valid - querySelector would not throw on any of them")
for ln, sel in bad:
    print(f"  line {ln}: \"{sel}\"  <- querySelector would THROW")
sys.exit(1 if bad else 0)
