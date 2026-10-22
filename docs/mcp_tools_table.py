"""Render the MCP tool table for the API reference, from the code.

The reference promises that "every tool, its arguments and the confirmation
strings are in the endpoint reference", and it was not: none of the twenty-five
tool names appeared in docs/api.html. A bot author following that sentence
found nothing.

Generating the table from mcp_tools.TOOLS fixes that AND makes it impossible
to fall behind again: the same table the panel serves to an AI client is the
table the reference prints. There is no second copy to maintain.

The tool names, their arguments, the REST call each one makes and the
confirmation a destructive tool needs are all CODE - they are the same in every
language, so they are not translated. Only the surrounding prose is, and the
tool descriptions are shown exactly as the client sees them, because that is
what a bot author needs to match against what the model was told.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

BEGIN = "<!-- MCP-TOOLS:BEGIN -->"
END = "<!-- MCP-TOOLS:END -->"


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def _args(tool):
    """The tool's arguments, rendered from its JSON schema."""
    props = (tool.get("input_schema") or {}).get("properties") or {}
    if not props:
        return '<span data-i18n="api.mcpNoArgs">none</span>'
    out = []
    for name in sorted(props):
        spec = props[name] or {}
        kind = spec.get("type") or "any"
        if kind == "array":
            inner = (spec.get("items") or {}).get("type")
            kind = "array of %s" % inner if inner else "array"
        desc = spec.get("description") or ""
        # The type is CODE - "string", "integer", "array of string" -
        # and it reads the same in every language, so it is not put
        # through a translated key. It was, once, and the dictionary
        # held "(%s)" - a format string nothing formats - so every
        # argument type rendered as "(%s)".
        out.append("<code>%s</code> (%s)%s"
                   % (_esc(name), _esc(kind),
                      (" &mdash; " + _esc(desc)) if desc else ""))
    return "<br>".join(out)


def _target(tool):
    """The panel endpoint the tool forwards to."""
    method = (tool.get("method") or "").upper()
    path = tool.get("path") or ""
    return '<span class="badge %s">%s</span> <code>%s</code>' % (
        {"GET": "get", "POST": "post", "PUT": "put", "DELETE": "del",
         "PATCH": "post"}.get(method, "get"), _esc(method), _esc(path))


def render_tools_table():
    """The whole generated block, markers included."""
    from mcp_tools import DESTRUCTIVE, TOOLS

    rows = []
    for t in sorted(TOOLS, key=lambda x: x["name"]):
        destructive = t["name"] in DESTRUCTIVE
        note = ""
        if destructive:
            note = ('<br><span data-i18n="api.mcpNeedsConfirm">needs the exact '
                    'confirmation string</span>')
        rows.append(
            '<tr><td><code>%s</code></td>'
            '<td>%s%s</td>'
            '<td>%s</td>'
            '<td>%s</td></tr>'
            % (_esc(t["name"]), _esc(t.get("description") or ""), note,
               _args(t), _target(t)))

    return "\n".join([
        BEGIN,
        '<h2 id="mcp-tools" data-i18n="api.hMcpTools">MCP tools</h2>',
        '<p><span data-i18n="api.mcpToolsIntro">Every tool below is one call to the panel, forwarded with the caller\'s own token - so an MCP token reaches exactly what that token could reach. The descriptions are the ones your client is given, verbatim. Destructive tools need the exact confirmation string the refusal names.</span></p>',
        "<table>",
        '<tr><th data-i18n="api.mcpThTool">Tool</th>'
        '<th data-i18n="api.mcpThWhat">What it does</th>'
        '<th data-i18n="api.mcpThArgs">Arguments</th>'
        '<th data-i18n="api.mcpThCalls">It calls</th></tr>',
        "\n".join(rows),
        "</table>",
        END,
    ])


def current_block(path):
    """The block as it stands in the file, or None."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    i = text.find(BEGIN)
    j = text.find(END)
    if i < 0 or j < 0:
        return None
    return text[i:j + len(END)]


if __name__ == "__main__":
    print(render_tools_table())
