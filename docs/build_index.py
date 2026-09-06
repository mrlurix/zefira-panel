"""Build assets/search-index.json for the Ctrl+K palette and ensure every
h2/h3 in the docs has a stable id anchor. Re-run after editing docs:

    python docs/build_index.py
"""
import html as _html
import json
import pathlib
import re

DOCS = pathlib.Path(__file__).resolve().parent
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")
HEAD_RE = re.compile(r"<(h[23])((?:\s[^>]*)?)>(.*?)</\1>", re.DOTALL)


def slug(text: str, used: set) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"
    s, i = base, 2
    while s in used:
        s, i = f"{base}-{i}", i + 1
    used.add(s)
    return s


def clean(html: str) -> str:
    return WS_RE.sub(" ", TAG_RE.sub(" ", _html.unescape(html))).strip()


entries = []
for page in sorted(DOCS.glob("*.html")):
    html = page.read_text(encoding="utf-8")
    m = re.search(r"<title>(.*?)</title>", html, re.DOTALL)
    title = clean(m.group(1)).split("—")[0].strip() if m else page.stem

    used: set = set()
    heads = list(HEAD_RE.finditer(html))
    # inject missing ids (stable anchors for search jumps)
    out = []
    pos = 0
    for h in heads:
        tag, attrs, inner = h.group(1), h.group(2), h.group(3)
        if 'id="' in attrs or "id='" in attrs:
            out.append(html[pos:h.end()])
        else:
            aid = slug(clean(inner), used)
            out.append(html[pos:h.start()] + f"<{tag}{attrs} id=\"{aid}\">" + inner + f"</{tag}>")
        pos = h.end()
    out.append(html[pos:])
    page.write_text("".join(out), encoding="utf-8")

    # re-scan with ids
    html = "".join(out)
    heads = list(HEAD_RE.finditer(html))
    for idx, h in enumerate(heads):
        attrs, inner = h.group(2), h.group(3)
        aid = re.search(r'id="([^"]+)"', attrs).group(1)
        body_html = html[h.end():heads[idx + 1].start() if idx + 1 < len(heads) else len(html)]
        entries.append({
            "u": f"{page.name}#{aid}",
            "p": title,
            "s": clean(inner),
            "t": clean(body_html)[:300],
        })

(DOCS / "assets" / "search-index.json").write_text(
    json.dumps(entries, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
)
print(f"indexed {len(entries)} sections across {len(list(DOCS.glob('*.html')))} pages")
