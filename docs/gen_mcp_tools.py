"""Write the generated MCP tool table into docs/api.html.

The block lives between two markers, so regenerating it is a replacement and
not a guess. The guard (mcp_docs_test.py) regenerates it and compares, so a
tool added without a doc line fails the suite rather than being noticed
later.

The prose around the table is translated in all four languages; the table
itself is generated from the code and is the same in every language.
"""

import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from mcp_tools_table import (BEGIN, END, current_block,  # noqa: E402
                             render_tools_table)

API = os.path.join(ROOT, "docs", "api.html")
raw = io.open(API, "rb").read()
text = raw.decode("utf-8")
CRLF = b"\r\n" in raw
NL = "\r\n" if CRLF else "\n"

block = render_tools_table()
if CRLF:
    block = block.replace("\n", "\r\n")

if BEGIN in text:
    i = text.index(BEGIN)
    j = text.index(END) + len(END)
    new = text[:i] + block + text[j:]
    action = "regenerated"
else:
    # the section goes right after the endpoints table, before "Public"
    anchor = '<h2 id="public"'
    assert text.count(anchor) == 1, "the Public heading"
    at = text.index(anchor)
    new = text[:at] + block + NL + NL + text[at:]
    action = "inserted"

payload = new.encode("utf-8")
io.open(API, "wb").write(payload)
b = io.open(API, "rb").read()
# Adding the table legitimately grows the CRLF count; the invariant is
# that no bare LF appeared.
assert (b.count(b"\n") - b.count(b"\r\n")) == 0, "a bare LF appeared"
assert (b.count(b"\n") - b.count(b"\r\n")) == 0, "a bare LF appeared"
assert "\ufffd" not in b.decode("utf-8"), "U+FFFD"

n = block.count("<tr><td><code>")
print("  docs/api.html: the MCP tool table was %s" % action)
print("  %d tool rows, from the code itself" % n)
print("  CRLF kept: %d" % b.count(b"\r\n"))
