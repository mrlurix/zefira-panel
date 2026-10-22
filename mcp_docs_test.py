"""The MCP tool table in the reference must be the one the code produces.

The reference promises that "every tool, its arguments and the confirmation
strings are in the endpoint reference", and it was not: none of the
twenty-five tool names appeared in docs/api.html. A bot author following that
sentence found nothing.

The table is now GENERATED from mcp_tools.TOOLS, so the fix is not just the
text - it is the impossibility of the text falling behind. This suite
regenerates the table and compares it with what the page carries, byte for
byte, so:

  - a tool added without a doc line fails the suite
  - a tool whose arguments changed updates the page or fails the suite
  - a destructive tool that lost its confirmation marker fails the suite

A generated table with no check is just a second copy to maintain. This is the
check.
"""

import io
import os
import re
import sys

# THIS file lives at the repository root, so HERE is the repository and
# not its parent - which is what the first version used, and it looked for
# docs/mcp_tools_table.py one directory too high.
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "docs"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:190])
                         if (detail and not cond) else ""))


from mcp_tools_table import (BEGIN, END, current_block,  # noqa: E402
                             render_tools_table)
from mcp_tools import DESTRUCTIVE, TOOLS  # noqa: E402

API = os.path.join(ROOT, "docs", "api.html")
doc = io.open(API, encoding="utf-8", errors="replace").read()

block = current_block(API)
check("the reference carries a generated MCP tool table", block is not None,
      "the markers are not in docs/api.html")
if block is None:
    print()
    print("=== %d/%d ===" % (sum(1 for _k, v in ok if v), len(ok)))
    raise SystemExit(1)

fresh = render_tools_table()
if doc.count("\r\n"):
    fresh = fresh.replace("\n", "\r\n")
check("the table in the page is exactly what the code produces",
      block == fresh,
      "it is stale - run docs/gen_mcp_tools.py")

# every tool is named in the table
missing = [t["name"] for t in TOOLS if ("<code>%s</code>" % t["name"]) not in block]
check("every tool is named in the table", not missing, missing[:5])

# and the destructive ones say so
unmarked = [n for n in sorted(DESTRUCTIVE)
             if not re.search(r"<code>%s</code>.*?needs the exact confirmation" % n,
                              block, re.S)]
check("every destructive tool is marked as needing a confirmation",
      not unmarked, unmarked[:5])

# the tool count in the page is the tool count in the code
rows = len(re.findall(r"<tr><td><code>", block))
check("the table has one row per tool", rows == len(TOOLS),
      "%d rows for %d tools" % (rows, len(TOOLS)))

# each tool's arguments are in the table, so the page cannot promise the
# arguments and then not list them
noargs = []
for t in TOOLS:
    for prop in ((t.get("input_schema") or {}).get("properties") or {}):
        if ("<code>%s</code>" % prop) not in block:
            noargs.append("%s.%s" % (t["name"], prop))
check("every tool's arguments are in the table", not noargs, noargs[:5])

# and the endpoint each tool calls is in the table
notarget = []
for t in TOOLS:
    path = t.get("path") or ""
    if path and ("<code>%s</code>" % path) not in block:
        notarget.append("%s -> %s" % (t["name"], path))
check("the endpoint each tool calls is in the table", not notarget,
      notarget[:5])

n = sum(1 for _k, v in ok if v)
print()
print("  the table carries %d tools, %d of them destructive"
      % (len(TOOLS), len(DESTRUCTIVE)))
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)