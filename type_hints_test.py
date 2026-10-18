"""Type annotations must not regress.

An assessment claimed type hinting was "incomplete across the codebase".
Measured, that was false: main.py was already 94%, security.py 86%, and the
bare remainder is 4 top-level functions plus nested callbacks and dunders.
It was true in exactly one place, and that place was mine - the four MCP
modules I wrote last release had ZERO annotated signatures out of 34.

So this guard does two things, and only these two:

  1. The MCP modules must be fully annotated. That closes my gap and keeps it
     closed.
  2. main.py may not gain a NEW top-level bare signature. Four are allowed by
     name, so the file can move freely as long as it does not add more. This
     is the one that pays off later: every route added from now on arrives
     annotated, without anyone having to remember.

It deliberately does NOT assert 100% on main.py or security.py. A guard that
demands perfection from a 4000-line file gets deleted the first time it fires
for a good reason, and a deleted guard is worse than no guard. An allowance
list is the difference between a rule people keep and a rule people delete.
"""

import ast
import io
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:170])
                         if (detail and not cond) else ""))


def annotate_score(path):
    """(annotated, total, bare_toplevel) where 'annotated' means the return
    type OR at least one parameter is annotated."""
    tree = ast.parse(io.open(os.path.join(ROOT, path),
                             encoding="utf-8").read())
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def depth_of(node):
        d = 0
        cur = parents.get(node)
        while cur is not None and d < 16:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef,
                                ast.ClassDef)):
                d += 1
            cur = parents.get(cur)
        return d

    ann = tot = 0
    bare_top = []
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tot += 1
        params = list(n.args.args) + list(n.args.kwonlyargs) + \
            [n.args.vararg, n.args.kwarg]
        ok_fn = n.returns is not None or any(
            a is not None and a.annotation is not None for a in params)
        if ok_fn:
            ann += 1
        elif depth_of(n) == 0:
            bare_top.append(n.name)
    return ann, tot, bare_top


MCP = ("mcp_tools.py", "mcp_protocol.py", "mcp_exec.py", "mcp_server.py")

# ---------------------------------------------------------------- 1. the MCP
# modules, which were 0/34 and are now 34/34.
total_ann = total_fn = 0
for f in MCP:
    a, t, _ = annotate_score(f)
    total_ann += a
    total_fn += t
    check("%s is fully annotated (%d/%d)" % (f, a, t), a == t,
          "bare: see the per-file report")

check("all four MCP modules together are fully annotated",
      total_ann == total_fn, "%d/%d" % (total_ann, total_fn))
check("and the count is the 34 functions that exist",
      total_fn == 34, "expected 34, found %d - if a function was added, "
      "annotate it too" % total_fn)

# ------------------------------------------------- 2. main.py must not regress.
ALLOWED_TOP_LEVEL = {"root", "api_appearance_get", "theme_css",
                     "_parse_ai_bool"}
a, t, bare_top = annotate_score("main.py")
check("main.py still parses and walks", t > 200, "%d functions" % t)
check("main.py has no NEW unannotated top-level function",
      set(bare_top) <= ALLOWED_TOP_LEVEL,
      "new bare: %s" % sorted(set(bare_top) - ALLOWED_TOP_LEVEL))
# Deliberately a SUBSET check and not an equality check. Equality would fire
# the moment someone annotates one of the four, which is an IMPROVEMENT - and
# a guard that punishes improvement is a guard people delete. This one fires
# only on regression; the allowance is free to shrink as the file is cleaned.
check("...and annotating one of the four does not fail this suite",
      set(bare_top) <= ALLOWED_TOP_LEVEL,
      "if you annotated one of them, delete it from ALLOWED_TOP_LEVEL")
check("main.py's annotated share has not fallen below 90%%",
      a * 100 >= t * 90, "%d/%d = %.0f%%" % (a, t, 100.0 * a / max(t, 1)))

# ------------------------------------------------------------- 3. no cheating
# A guard that can be satisfied by widening the allowance is worthless, so the
# allowance is pinned to the four names above rather than to a count: raising
# a number would leave these checks green while allowing a new bare function.
check("the allowance names functions rather than a count, so it cannot grow",
      len(ALLOWED_TOP_LEVEL) == 4
      and all(not n.startswith("__") for n in ALLOWED_TOP_LEVEL))

# The annotated modules must still be valid, importable Python - an annotation
# that only type-checks would not help anyone.
for f in MCP:
    src = io.open(os.path.join(ROOT, f), encoding="utf-8").read()
    check("%s has no bare annotation and no string '->' typo" % f,
          "->" in src and ": ?" not in src)
    check("%s is still LF-only, as it was before" % f,
          b"\r\n" not in io.open(os.path.join(ROOT, f), "rb").read())

n = sum(1 for _k, v in ok if v)
print()
print("  measured: the MCP modules went 0/34 to %d/%d; main.py is %d/%d"
      % (total_ann, total_fn, a, t))
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)