"""Generate the repository's CHANGELOG.md from the docs' changelog page.

The release notes live on GitHub and in docs/changelog.html, and the
repository itself had no changelog to read. Rather than write a second copy
that would immediately start drifting, this generates the markdown FROM the
docs page - which is the source of truth - so the two can never disagree.

The generated file is checked in (GitHub renders it on the repository page)
and release_notes_test.py checks it against a fresh rendering, so an edited
changelog page that nobody regenerated fails the suite instead of shipping a
stale file.

render_changelog() returns the markdown; nothing is written unless this file
is run as a script. That split is what lets the guard compare without
touching the working tree.
"""

import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CHANGELOG = os.path.join(ROOT, "docs", "changelog.html")
OUT = os.path.join(ROOT, "CHANGELOG.md")

HEADER = ["# Changelog", "",
          "Every release, newest first. Generated from "
          "[`docs/changelog.html`](docs/changelog.html), which is the source of",
          "truth; run `python docs/gen_changelog.py` after editing that page.",
          ""]


def _unescape(text):
    return (text.replace("&quot;", '"').replace("&amp;", "&")
            .replace("&lt;", "<").replace("&gt;", ">")
            .replace("&mdash;", "\u2014").replace("&nbsp;", " ")
            .replace("&#8212;", "\u2014"))


def parse_releases(html):
    """Every release in the page, newest first: (version, title, items)."""
    # a release: <h2 id="vNNNNN"><span>vN.N.NN</span> <span data-i18n="chg.vNNNNN">TITLE</span></h2>
    releases = []
    for m in re.finditer(
            r'<h2 id="(v\d+)"><span>(v[\d.]+)</span>\s*'
            r'<span data-i18n="chg\.\1">(.*?)</span></h2>(.*?)(?=<h2 id="v|\Z)',
            html, re.S):
        ident, version, title, body = m.groups()
        items = []
        for li in re.finditer(
                r'<li><b data-i18n="chg\.\w+">(.*?)</b>'
                r'<span data-i18n="chg\.\w+">(.*?)</span></li>', body, re.S):
            lead, text = li.groups()
            lead = re.sub(r"<[^>]+>", "", lead).strip()
            text = re.sub(r"<[^>]+>", "", text).strip()
            text = _unescape(text)
            if lead or text:
                items.append((lead, text))
        title = _unescape(title)
        # The docs' heading is "v1.15.54 \u2014 Title"; the markdown heading adds
        # its own dash, so the leading one is dropped here rather than
        # producing "## v1.15.54 - \u2014 Title".
        title = title.strip().lstrip("\u2014").strip()
        releases.append((version, title, items))
    return releases


def render_changelog(html):
    """The markdown for the given changelog page."""
    releases = parse_releases(html)
    assert releases, "no releases were found in docs/changelog.html"
    out = list(HEADER)
    for version, title, items in releases:
        out.append("## %s - %s" % (version, title))
        out.append("")
        for lead, text in items:
            # The first item's lead is usually the release title again, and the
            # heading already says it.
            if lead and title and lead.strip() in (title.strip(),
                                                  title.strip().rstrip(".")):
                lead = ""
            if lead and text:
                out.append("- **%s** %s" % (lead, text))
            elif lead:
                out.append("- **%s**" % lead)
            else:
                out.append("- %s" % text)
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main():
    html = io.open(CHANGELOG, encoding="utf-8", errors="replace").read()
    text = render_changelog(html)
    payload = text.encode("utf-8")
    io.open(OUT, "wb").write(payload)
    b = io.open(OUT, "rb").read()
    assert b.count(b"\r\n") == 0, "the markdown must be LF-only"
    assert "\ufffd" not in b.decode("utf-8"), "U+FFFD"
    releases = parse_releases(html)
    print("  CHANGELOG.md written: %d releases, %d bytes"
          % (len(releases), len(b)))
    print("  the newest is %s - %s" % (releases[0][0], releases[0][1][:60]))
    print("  the oldest is %s" % releases[-1][0])


if __name__ == "__main__":
    main()
