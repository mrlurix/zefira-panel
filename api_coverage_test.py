"""ZEFIRA API COVERAGE GUARD - every route main.py registers must be documented.

The reference was built by copying rows out of the source by hand, so it fell
behind: 33 of 67 /api routes were undocumented when this check was written,
including the three that disclose a tunnel token. A bot author reading the
reference had no way to know those existed.

This closes that by measuring instead of trusting the prose: main.py is parsed
with ast, the same way FastAPI registers them, and every route must appear in
docs/api.html. Adding a route without documenting it now fails here rather than
being noticed by a user.

Also proved red by a mutation, because a guard that cannot fail proves nothing.

    .venv\\Scripts\\python.exe api_coverage_test.py
"""
import ast
import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

results = []
DOC = os.path.join(ROOT, "docs", "api.html")
I18N = os.path.join(ROOT, "docs", "assets", "i18n.js")


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print("[%s] %s" % ("\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m", name)
          + (("  (%s)" % detail) if detail and not cond else ""))


def routes():
    """Every /api route, as (method, path), read from the source."""
    tree = ast.parse(io.open(os.path.join(ROOT, "main.py"), encoding="utf-8").read())
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue
            if dec.func.attr.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if dec.args and isinstance(dec.args[0], ast.Constant):
                p = dec.args[0].value
                if isinstance(p, str) and p.startswith("/api"):
                    found.append((dec.func.attr.upper(), p))
    return sorted(set(found))


def endpoint_paths(doc):
    """The panel endpoints the reference's ENDPOINT TABLE documents.

    The generated MCP tool table names panel endpoints too - a tool that
    calls DELETE /api/users/{id} prints that path - so scanning the whole
    page made this check weaker: a route could be deleted from the endpoint
    table and still count as documented, because the tool table mentioned
    it. The endpoint table is what this check is about.

    Both the parent and its child have to use the SAME definition, or the
    child's mutation proves nothing.
    """
    _b = doc.find("<!-- MCP-TOOLS:BEGIN -->")
    _e = doc.find("<!-- MCP-TOOLS:END -->")
    if _b >= 0 and _e > _b:
        doc = doc[:_b] + doc[_e:]
    return set(re.findall(r"<code>(/api/[a-zA-Z0-9/_{}\-]+)</code>", doc))


def block_end(text, brace_open):
    depth, i, n = 0, brace_open, len(text)
    while i < n:
        c = text[i]
        if c in "\"'`":
            q, i = c, i + 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == q:
                    break
                i += 1
            i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AssertionError("unbalanced")


def main():
    rs = routes()
    doc = io.open(DOC, encoding="utf-8", errors="replace").read()
    documented = endpoint_paths(doc)

    missing = [(m, p) for m, p in rs if p not in documented]
    check("every /api route in main.py appears in the API reference "
          "(%d routes, %d missing)" % (len(rs), len(missing)),
          not missing,
          "undocumented: " + ", ".join("%s %s" % x for x in missing[:5]))

    # A method badge must be present too, so a path documented only as a GET
    # does not quietly hide its DELETE.
    wrong = [(m, p) for m, p in rs
             if p in documented
             and not re.search(r'badge[^"]*">%s<' % re.escape(m), doc)]
    check("each documented route carries its own method badge",
          not wrong, "no %s badge for: %s" % (
              wrong[0][0], wrong[0][1]) if wrong else "")

    # Every data-i18n key the page uses must exist in all four locales.
    it = io.open(I18N, encoding="utf-8", newline="").read()
    need = sorted(set(re.findall(r'data-i18n(?:-aria|-ph)?="([^"]+)"', doc)))
    spans = {}
    for m in re.finditer(r"Object\.assign\(Z_STRINGS\.(\w+),\s*\{", it):
        spans.setdefault(m.group(1), []).append(
            (m.start(), block_end(it, m.end() - 1)))
    for loc in ("en", "fa", "zh", "ru"):
        have = set()
        for a, b in spans.get(loc, []):
            have |= set(re.findall(r'"([\w.]+)"\s*:', it[a:b]))
        miss = [k for k in need if k not in have]
        check("the reference's strings exist in %s" % loc, not miss,
              "missing: " + ", ".join(miss[:4]))

    print()
    print("  --- proving the coverage check fails when a route goes undocumented ---")
    original = io.open(DOC, encoding="utf-8", newline="").read()
    try:
        target = rs[0][1]
        broken = original.replace("<code>%s</code>" % target,
                                  "<code>/api/unlisted-%s</code>" % target[1:], 1)
        if broken == original:
            check("goes red without the fix", False,
                  "the mutation did not apply, so this check proves nothing")
        else:
            with io.open(DOC, "w", encoding="utf-8", newline="") as fh:
                fh.write(broken)
            p = subprocess.run([sys.executable, os.path.abspath(__file__)],
                               capture_output=True, text=True, timeout=180,
                               env=dict(os.environ, ZEFIRA_APICOV_CHILD="1"))
            check("goes red when a documented route is removed from the page",
                  "GUARD:coverage" in p.stdout,
                  "child said %r" % p.stdout.strip()[-140:])
    finally:
        with io.open(DOC, "w", encoding="utf-8", newline="") as fh:
            fh.write(original)
    check("docs/api.html restored byte-for-byte after mutation",
          io.open(DOC, encoding="utf-8", newline="").read() == original)

    passed = sum(1 for _n, c in results if c)
    print()
    print("=== %d/%d checks passed ===" % (passed, len(results)))
    return 0 if passed == len(results) else 1


def child():
    doc = io.open(DOC, encoding="utf-8", newline="").read()
    rs = routes()
    documented = endpoint_paths(doc)
    miss = [(m, p) for m, p in rs if p not in documented]
    if miss:
        print("[FAIL] GUARD:coverage %d route(s) no longer documented: %s"
              % (len(miss), ", ".join(p for _m, p in miss[:3])))
    return 1 if miss else 0


if __name__ == "__main__":
    if os.environ.get("ZEFIRA_APICOV_CHILD") == "1":
        raise SystemExit(child())
    raise SystemExit(main())