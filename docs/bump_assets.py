"""Bump ?v=N on local asset URLs so browsers drop stale cache after updates."""
import pathlib
import re
import sys

VER = sys.argv[1] if len(sys.argv) > 1 else "4"
docs = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else pathlib.Path(__file__).resolve().parent
pat = re.compile(r"(assets/(?:style\.css|docs\.js))(\?v=\d+)?")

for f in sorted(docs.glob("*.html")):
    html = f.read_text(encoding="utf-8")
    new = pat.sub(r"\1?v=" + VER, html)
    if new != html:
        f.write_text(new, encoding="utf-8")
        print("bumped", f.name)
