"""Bump ?v=N on local asset URLs so browsers drop stale cache after updates.

Covers stylesheets, scripts AND the versioned fetch() URLs inside the JS
(search-index.json, site-knowledge.json): content updates used to ship
stale to cached browsers because only style.css/docs.js were bumped.
Usage: python docs/bump_assets.py 26
"""
import pathlib
import re
import sys

VER = sys.argv[1] if len(sys.argv) > 1 else "4"
docs = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else pathlib.Path(__file__).resolve().parent
html_pat = re.compile(r"(assets/(?:style\.css|docs\.js|i18n\.js|support-ai\.js))(\?v=\d+)?")
fetch_pat = re.compile(r"((?:search-index|site-knowledge)\.json\?v=)\d+")

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
