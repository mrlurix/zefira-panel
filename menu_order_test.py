"""The three menu orders must be the SAME sequence.

There are three places that decide where a sidebar section sits, and for one
release they did not agree:

    main.py            MENU_SECTIONS   - the server's canonical order
    static/app.js      MENU_IDS        - the front end's canonical order
    templates/panel.html  the nav buttons, in the order they are written

panel.html and app.js both put "mcp" directly above "settings". main.py had it
at the END, after "settings". And the server's tuple is the one that gets
STORED: _canon_menu_layout merges the sections missing from a saved layout
into the canonical order, so a layout saved through the API put the MCP section
below Settings - while the front end drew it above. The saved layout on a live
install read [... "api", "settings", "mcp"], and the section rendered where the
operator did not want it.

The comment above MENU_SECTIONS in main.py already said "Must stay in step
with MENU_IDS in static/app.js". Nothing checked it. This does.

Why a guard rather than a one-off fix: a disagreement between the tuple that
is stored and the template that is drawn is invisible in a screenshot and in
a test that only looks at one of them. It is exactly the kind of drift that
comes back with the next section somebody adds.
"""

import ast
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
                         ("  -> " + str(detail)[:190])
                         if (detail and not cond) else ""))


# ---------------------------------------------------------- main.py: the tuple
main = io.open(os.path.join(ROOT, "main.py"), encoding="utf-8").read()
m = re.search(r"^MENU_SECTIONS\s*=\s*\((.*?)\)\s*$", main, re.M | re.S)
check("MENU_SECTIONS is readable from main.py", m is not None)
SERVER = re.findall(r'"([a-z_]+)"', m.group(1)) if m else []

# ------------------------------------------------ static/app.js: the JS array
js = io.open(os.path.join(ROOT, "static", "app.js"), encoding="utf-8").read()
mj = re.search(r"const\s+MENU_IDS\s*=\s*\[(.*?)\];", js, re.S)
check("MENU_IDS is readable from static/app.js", mj is not None)
FRONT = re.findall(r'"([a-z_]+)"', mj.group(1)) if mj else []

# ------------------------------------------- panel.html: the nav buttons
html = io.open(os.path.join(ROOT, "templates", "panel.html"),
               encoding="utf-8").read()
TEMPLATE = re.findall(r'class="nav-btn[^"]*"\s+data-section="([a-z_]+)"',
                       html)
check("the nav buttons are readable from panel.html", len(TEMPLATE) >= 10,
      "found %d" % len(TEMPLATE))

# ------------------------------------------------------------- the invariant
check("main.py's MENU_SECTIONS and app.js's MENU_IDS are the same sequence",
      SERVER == FRONT,
      "server=%s\n          front =%s" % (SERVER, FRONT))
check("...and panel.html draws them in that same order",
      TEMPLATE == FRONT,
      "template=%s\n          front  =%s" % (TEMPLATE, FRONT))

check("no section appears twice in the canonical order",
      len(set(FRONT)) == len(FRONT),
      "duplicates: %s" % sorted({x for x in FRONT if FRONT.count(x) > 1}))

# --------------------------------------------- the dashboard's block list
# The same class of bug, one level down: the dashboard's blocks are named in
# the front end (DASH_IDS) and in the server (DASH_BLOCKS), and the server's
# copy is the one that decides what may be reordered or hidden.
md = re.search(r"^DASH_BLOCKS\s*=\s*\(([^)]*)\)\s*$", main, re.M)
check("DASH_BLOCKS is readable from main.py", md is not None)
SERVER_DASH = re.findall(r'"([a-z_]+)"', md.group(1)) if md else []
mdj = re.search(r"const\s+DASH_IDS\s*=\s*\[(.*?)\];", js, re.S)
FRONT_DASH = re.findall(r'"([a-z_]+)"', mdj.group(1)) if mdj else []
check("DASH_IDS is readable from static/app.js", mdj is not None)
check("the server's DASH_BLOCKS and the front end's DASH_IDS agree",
      SERVER_DASH == FRONT_DASH,
      "server=%s front=%s" % (SERVER_DASH, FRONT_DASH))

# --------------------------------------------------- the section the user wants
check("the MCP section sits directly above Settings",
      "mcp" in FRONT and "settings" in FRONT
      and FRONT.index("mcp") == FRONT.index("settings") - 1,
      "the order is %s" % FRONT)

# --------------------------------------------------------- the server agrees
# The server's tuple is the one that is STORED, so it is the one that decides
# where a section lands in a saved layout. Check the merge agrees too, by
# asking the server's own function what order a layout saved before MCP
# existed would get.
sys.path.insert(0, ROOT)
import main as _main  # noqa: E402

old_layout = [{"id": i, "hidden": False} for i in FRONT if i != "mcp"]
merged = _main._canon_menu_layout(__import__("json").dumps(old_layout))
ids = [m["id"] for m in merged]
check("a layout saved before the MCP section existed gets MCP above Settings",
      ids.index("mcp") == ids.index("settings") - 1,
      "the merged order is %s" % ids)

# and a layout that already has MCP keeps the operator's own position
custom = [{"id": i, "hidden": False} for i in
          ["dashboard", "users", "mcp", "settings", "inbounds", "tunnels",
           "nodes", "reality", "blocker", "update", "customize", "api"]]
merged2 = [m["id"] for m in
           _main._canon_menu_layout(__import__("json").dumps(custom))]
check("a layout that already names MCP keeps the operator's own position",
      merged2.index("mcp") == 2, "the merged order is %s" % merged2)

n = sum(1 for _k, v in ok if v)
print()
print("  the canonical order is: %s" % " ".join(FRONT))
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)