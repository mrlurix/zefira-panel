"""Build assets/search-index.json for the Ctrl+K palette and ensure every
h2/h3 in the docs has a stable id anchor. Re-run after editing docs:

    python docs/build_index.py

It also owns the asset cache-bust, which used to be a manual step and was
therefore done half-way. The counter lives in FOURTEEN places - twelve pages
carrying `assets/i18n.js?v=N` plus `docs.js` and `support-ai.js` fetching the
search index and the AI knowledge base - and bumping only the pages leaves the
fetchers pinned to the old number, so a page loads fresh HTML and then asks for
a stale JSON. frontend_bugs_test.py caught exactly that, which is the only
reason it was noticed at all; now one command moves all fourteen together and
refuses to leave them disagreeing.
"""
import html as _html
import json
import pathlib
import re
import subprocess
import sys

DOCS = pathlib.Path(__file__).resolve().parent
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")
HEAD_RE = re.compile(r"<(h[23])((?:\s[^>]*)?)>(.*?)</\1>", re.DOTALL)


def bump_asset_version() -> None:
    """Run docs/bump_assets.py, so one command really is one command.

    The cache-bust lives in fourteen places: twelve pages carrying
    `assets/i18n.js?v=N` plus docs.js and support-ai.js fetching the search
    index and the AI knowledge base. Bump only the pages and the fetchers stay
    pinned to the old number, so a visitor gets fresh HTML and then asks for
    stale JSON. That is not hypothetical - it is exactly what happened while
    fixing the v1.15.1 install, and frontend_bugs_test.py was what caught it.

    bump_assets.py has always covered all fourteen and derives the next number
    from the maximum it finds, so a half-bumped tree heals itself. A first
    attempt at this function re-implemented the bump and instead REFUSED to run
    when the numbers disagreed - which is worse, since disagreeing is the
    recoverable state and being unable to build is not. One implementation,
    called, beats a second opinion.
    """
    bump = DOCS / "bump_assets.py"
    if not bump.exists():
        print("build_index: docs/bump_assets.py is missing, assets NOT bumped")
        sys.exit(1)
    r = subprocess.run([sys.executable, str(bump)], cwd=str(DOCS),
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    for ln in (r.stdout or "").splitlines():
        if ln.startswith(("bumped", "setting", "no version")):
            print(ln)
    if r.returncode != 0:
        print("build_index: the asset bump failed:\n" + (r.stderr or r.stdout))
        sys.exit(r.returncode)


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
        aid = re.search(r"id\s*=\s*[\"']([^\"']+)[\"']", attrs).group(1)
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

# Last, so the index is written before anything reads it: the cache-bust moves
# with the index, never apart from it.
bump_asset_version()
