"""Bump ?v=N on local asset URLs so browsers drop stale cache after updates.

Covers stylesheets, scripts AND the versioned fetch() URLs inside the JS
(search-index.json, site-knowledge.json): content updates used to ship
stale to cached browsers because only style.css/docs.js were bumped.

Usage:  python docs/bump_assets.py [VERSION] [docs_dir]

With no VERSION the script derives the next number from what the files
already carry. The old hard-coded default ("4") silently rewrote every
URL to ?v=4 when someone forgot the argument, which un-did the bump and
left the search index / knowledge base permanently cached.
"""
import pathlib
import re
import sys

docs = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else pathlib.Path(__file__).resolve().parent
html_pat = re.compile(r"(assets/(?:style\.css|docs\.js|i18n\.js|support-ai\.js))(\?v=\d+)?")
fetch_pat = re.compile(r"((?:search-index|site-knowledge)\.json\?v=)\d+")

if len(sys.argv) > 1:
    VER = sys.argv[1]
else:
    seen = [0]
    for f in sorted(docs.glob("*.html")):
        seen += [int(m) for m in re.findall(r"assets/[\w.-]+\?v=(\d+)", f.read_text(encoding="utf-8"))]
    for js in ("assets/docs.js", "assets/support-ai.js"):
        p = docs / js
        if p.exists():
            seen += [int(m) for m in re.findall(r"\.json\?v=(\d+)", p.read_text(encoding="utf-8"))]
    VER = str(max(seen) + 1 if seen else 1)
    print("no version given, using next:", VER)
print("setting every local asset URL to ?v=" + VER)

for f in sorted(docs.glob("*.html")):
    html = f.read_text(encoding="utf-8")
    new = html_pat.sub(r"\1?v=" + VER, html)
    if new != html:
        f.write_text(new, encoding="utf-8")
        print("bumped", f.name)
for js in ("assets/docs.js", "assets/support-ai.js"):
    p = docs / js
    if not p.exists():
        continue
    src = p.read_text(encoding="utf-8")
    new = fetch_pat.sub(r"\g<1>" + VER, src)
    if new != src:
        p.write_text(new, encoding="utf-8")
        print("bumped", js)
