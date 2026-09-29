"""docs_coverage_test.py — does the docs site actually cover the panel?

Docs drift silently. A section or an endpoint gets added to the panel, the
docs site keeps its last hand-written list, and the two disagree with nothing
turning red. This file makes the drift loud, and is deliberately a *behavioural*
check: it reads the route table out of main.py, the sidebar out of app.js, the
settings keys out of protocols.py, and then requires a real mention in the
real HTML — no sidecar manifest that can be edited to hide a gap.

Offline: no server, no database. Safe to run anywhere.
"""
import io
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
DOCS = ROOT / "docs"
fails = []
n = 0


def check(label, ok, detail=""):
    global n
    n += 1
    if ok:
        print(f"  [PASS] {label}")
    else:
        print(f"  [FAIL] {label}" + (f"  ({detail})" if detail else ""))
        fails.append(label)


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


app_js = read("static/app.js")
main_py = read("main.py")
prot_py = read("protocols.py")
api_html = read("docs/api.html")
cfg_html = read("docs/configuration.html")
ug_html = read("docs/user-guide.html")

# ---------------------------------------------------------------- sidebar ---
# Every section the operator can navigate to must have a docs page that talks
# about it. The anchor is checked to exist as a real id=, not merely named here.
m = re.search(r"const MENU_IDS = \[(.*?)\]", app_js, re.S)
menu_ids = re.findall(r'"([\w-]+)"', m.group(1)) if m else []
check("the sidebar section list was found", bool(menu_ids), "MENU_IDS not in app.js")

# section -> (page, anchor id that must exist in that page)
SECTION_DOCS = {
    "dashboard": ("user-guide.html", "panel-dashboard"),
    "users": ("user-guide.html", "creating-a-user"),
    "inbounds": ("user-guide.html", "inbounds"),
    "tunnels": ("user-guide.html", "tunnels-backpack"),
    "nodes": ("user-guide.html", "server-nodes"),
    "reality": ("user-guide.html", "anti-censorship-settings"),
    "blocker": ("user-guide.html", "site-blocker"),
    "update": ("user-guide.html", "panel-updates"),
    "customize": ("user-guide.html", "appearance-branding"),
    "api": ("api.html", None),
    "settings": ("configuration.html", "panel-settings"),
}
pages = {p.name: p.read_text(encoding="utf-8", errors="replace") for p in DOCS.glob("*.html")}
missing_map = [s for s in menu_ids if s not in SECTION_DOCS]
check("every sidebar section has a docs destination",
      not missing_map, f"unmapped: {missing_map}")
bad_anchor = []
for section in menu_ids:
    target = SECTION_DOCS.get(section)
    if not target:
        continue
    page, anchor = target
    if page not in pages:
        bad_anchor.append(f"{section}: page {page} does not exist")
    elif anchor and f'id="{anchor}"' not in pages[page]:
        bad_anchor.append(f"{section}: no id=\"{anchor}\" in {page}")
check("every mapped docs destination really exists",
      not bad_anchor, "; ".join(bad_anchor[:4]))

# ----------------------------------------------------------------- routes ---
registered = re.findall(r'@app\.(?:get|post|put|patch|delete)\("([^"]+)"', main_py)
api_routes = sorted({r for r in registered if r.startswith("/api")})
check("the route table was found", len(api_routes) > 30, f"only {len(api_routes)} routes")

# The docs write a family as `/api/users…` and its sub-resources bare
# (`/config`, `/regen-token`). Expand that shorthand so the comparison is
# against the real route strings, not against the prose.
def normalise(p):
    """`/api/nodes/{id}/check` -> `/api/nodes/*`, for matching only."""
    p = re.sub(r"\{[^}]+\}", "*", p)
    return p.rstrip("/") or p


api_body = api_html[api_html.find("<main"):]
exact = set()
families = set()
tails = set()
for c in re.findall(r"<code[^>]*>([^<]{1,90})</code>", api_body):
    c = c.strip().split("?")[0]
    if c.endswith("…"):
        fam = normalise(c[:-1].rstrip(".").rstrip("/"))
        if fam:
            families.add(fam)
        continue
    if c.startswith("/api") or c.startswith("/sub"):
        exact.add(normalise(c))
    if c.startswith("/") and " " not in c:
        # `/ssl/renew` and `/config` sit beside their parent in the reference
        tails.add(normalise(c))


def documented(route):
    """A route counts as documented when the reference contains it exactly, when
    a family entry (`/api/nodes…`) covers it, or when the reference spells out
    its own tail. Nothing is fuzzy-matched: only paths the page actually shows
    can satisfy a route, so a newly added endpoint with no mention still fails.
    """
    r = normalise(route)
    if r in exact:
        return True
    if any(r == f or r.startswith(f + "/") for f in families):
        return True
    parts = r.split("/")                       # ["", "api", "users", "*", "config"]
    for n in (1, 2, 3):
        if len(parts) - n >= 2:                 # keep the /api root
            if normalise("/" + "/".join(parts[len(parts) - n:])) in tails:
                return True
    return False


undocumented = [r for r in api_routes if not documented(r)]
check("every registered /api endpoint appears in the docs API reference",
      not undocumented, f"{len(undocumented)} missing: {undocumented[:6]}")

# --------------------------------------------------------------- settings ---
m = re.search(r"DEFAULT_SRV = \{(.*?)\n\}", prot_py, re.S)
srv_keys = re.findall(r'"([a-z0-9_]+)":', m.group(1)) if m else []
check("the settings key list was found", bool(srv_keys))
cfg_body = cfg_html[cfg_html.find("<main"):]
# Only <code> spans count. A bare substring search over the whole page passed
# `domain` and `dns` off data-i18n="cfg.domain" - the attribute NAME is not the
# setting, and a check that green-lights on it reports coverage nobody has.
cfg_code = set()
for c in re.findall(r"<code[^>]*>([^<]{1,60})</code>", cfg_body):
    cfg_code.add(c.strip())
cfg_missing = [k for k in srv_keys if k not in cfg_code]
check("every server setting key is documented by name in configuration.html",
      not cfg_missing, f"{len(cfg_missing)} missing: {cfg_missing[:8]}")

# ------------------------------------------------------------ i18n / four ---
# Deliberately NOT re-implemented here: whether every docs string exists in all
# four languages is i18n_dict_check.js's job, and it does it by running the
# shipped dictionary, which a json.loads() in this file cannot. A second,
# weaker copy of that check would be a guard that can pass while the real one
# fails. This file only asks the question docs *coverage* owns: is the feature
# written down at all.

print(f"  === {n - len(fails)}/{n} checks passed ===")
sys.exit(1 if fails else 0)
