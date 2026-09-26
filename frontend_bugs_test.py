"""
Regression: the front-end bugs this round fixed.

Static assertions over the real files (the six HTTP suites cannot see JS
logic), plus a live check of the two markup/JS mismatches that made whole
features invisible.
"""
import io
import json
import re
import sys
import urllib.error
import urllib.request
import uuid

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = r"C:\Users\mrlurix\Desktop\laptop pro\zefira"
BASE = "http://127.0.0.1:8000"
PW = "kf0MrM3rm0GLg47x"
XW = {"X-Requested-With": "XMLHttpRequest"}
COOKIE = {"v": ""}
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def read(rel):
    return io.open(ROOT + "\\" + rel, encoding="utf-8").read()


app = read("static/app.js")
sub = read("static/sub.js")
docs_js = read("docs/assets/docs.js")
ai_js = read("docs/assets/support-ai.js")
panel = read("templates/panel.html")
subtpl = read("templates/sub.html")
docs_i18n = read("docs/assets/i18n.js")
# The asset version is asserted against the real docs pages, not a constant.
panel_docs_html = "".join(
    read("docs/" + f) for f in
    ("index.html", "api.html", "changelog.html", "configuration.html", "faq.html",
     "installation.html", "security.html", "setup-guides.html", "subscription.html",
     "support.html", "user-guide.html", "donate.html"))

# ---------------------------------------------------------------- 1. hideable elements
# The update warnings used the `hidden` ATTRIBUTE while the JS toggled the
# `.hidden` CLASS, so "Upstream commit is NOT signed" and the stale-unit
# instruction could never be shown - while the server refuses unsigned
# commits by default.
for eid in ("update-unit-warning", "update-signature"):
    m = re.search(r'<p[^>]*id="%s"[^>]*>' % eid, panel)
    check(f"#{eid} uses the .hidden class, not the attribute",
          bool(m) and "hidden" in m.group(0) and ' hidden>' not in m.group(0)
          and 'hidden=""' not in m.group(0), m.group(0) if m else "not found")
check("the update card still renders the signature line", "update.sigBad" in app)
check("the update card still renders the unit warning", "update.unitStale" in app)

# ---------------------------------------------------------------- 2. sequence guards
check("loadInbounds has a generation guard",
      re.search(r"async function loadInbounds\(\)\s*\{[^}]*nextSeq\(\"inbounds\"\)", app)
      is not None)
check("loadInbounds discards a stale response",
      re.search(r"async function loadInbounds\(\).*?isCurrent\(\"inbounds\", token\)",
                app, re.S) is not None)

# ---------------------------------------------------------------- 3. dead buttons
check("the user delete/reset button is re-enabled on failure",
      re.search(r'btn\.dataset\.act === "del".*?finally\s*\{\s*btn\.disabled = false;',
                app, re.S) is not None)
check("the API-token revoke button is re-enabled on failure",
      re.search(r'del-token.*?finally\s*\{\s*btn\.disabled = false;', app, re.S) is not None)

# ---------------------------------------------------------------- 4. NaN ports
check("the server-node check port is range-checked before the request",
      re.search(r"check_port: port.{0,400}?", app) is not None
      and "if (!Number.isFinite(port))" in app)
check("the inbound port is range-checked (1..65535)",
      re.search(r"if \(!name \|\| !port\).{0,300}?port < 1 \|\| port > 65535", app, re.S)
      is not None)
check("the tunnel port is range-checked",
      "tunnel_port: (() => {" in app and "tp < 1 || tp > 65535" in app)

# ---------------------------------------------------------------- 5. usage sort
check("usage sorting no longer clamps sub-1GB quotas",
      "Math.max(b.volume_gb, 1)" not in app
      and "const ratio = (u) => u.used_gb / (Number(u.volume_gb) || 1);" in app)

# ---------------------------------------------------------------- 6. reality key + cdn preset
check("a loaded REALITY public key reveals its panel",
      re.search(r'reality_pub\)\s*\{\s*rpub\.value = srv\.reality_pub;.*?'
                r'\$?\("#reality-out"\)\?\.classList\.remove\("hidden"\)', app, re.S) is not None)
check("the CDN preset dropdown is re-synced from the stored SNI",
      'preset.value = Array.from(preset.options)' in app)

# ---------------------------------------------------------------- 7. search box vs list
check("the dashboard nav reload keeps the visible search query",
      'btn.dataset.section === "dashboard"' in app
      and re.search(r'section === "dashboard".*?loadUsers\(\$\("#search"\).*?value\.trim\(\)',
                    app, re.S) is not None)

# ---------------------------------------------------------------- 8. init failure is visible
_i = app.find('(async function init()')
_j = app.find('const me = await api("/api/me")', _i if _i >= 0 else 0)
check("a failed /api/me is reported instead of silently blanking the panel",
      _i >= 0 and _j > _i
      and 'if (err && err.message !== "auth") toast(err.message, false);' in app[_j:_j + 500]
      and 'catch (_) { return; }' not in app[_j:_j + 500],
      "init block not found" if _i < 0 else app[_j:_j + 200].replace("\n", " ")[:120])

# ---------------------------------------------------------------- 9. docs copy button
check("the docs copy button snapshots the code before appending itself",
      re.search(r"var code = pre\.innerText;.*?writeText\(code\)", docs_js, re.S) is not None)
check("the docs copy button has a failure path",
      "docs.copyFailed" in docs_js and "legacyCopy" in docs_js)
check("the docs copy button has a legacy clipboard fallback",
      'execCommand("copy")' in docs_js)

# ---------------------------------------------------------------- 10. docs search palette
check("the palette re-renders once the index arrives",
      re.search(r"index = j;\s*if \(isOpen\(\)\) render\(\);", docs_js) is not None)
check("a failed index load has its own state",
      "index = false" in docs_js and "docs.palFail" in docs_js)
check("the palette no longer advertises a hard-coded section count",
      "{n: index ? index.length : 69}" not in docs_js)
# The invariant is CONSISTENCY, not a specific number: the fetch() URLs inside
# the JS must carry the same version as the <script> tags in the HTML, or the
# search index / knowledge base stay cached while the page is fresh.
_html_v = set()
for _f in re.findall(r'assets/[\w.-]+\?v=(\d+)', panel_docs_html):
    _html_v.add(_f)
_js_v = set(re.findall(r'\.json\?v=(\d+)', docs_js)) | set(
    re.findall(r'\.json\?v=(\d+)', ai_js))
check("the docs pages all use ONE asset version", len(_html_v) == 1, str(sorted(_html_v)))
check("the palette and the assistant use the CURRENT asset version",
      bool(_js_v) and _js_v == _html_v,
      f"html={sorted(_html_v)} js={sorted(_js_v)}")
check("docs.palFail exists in all four languages",
      docs_i18n.count('"docs.palFail"') == 4, str(docs_i18n.count('"docs.palFail"')))

# ---------------------------------------------------------------- 11. assistant
check("a failed knowledge-base load is not retried forever",
      "KB_FAILED = true" in ai_js and "kbLoading = false;\n      KB_FAILED" in ai_js)
check("the assistant greeting works for Persian",
      "\\p{L}" in ai_js or "(?:سلام)" in ai_js)
check("single newlines are preserved in assistant answers",
      "body.split(/\\n+/)" in ai_js)
check("the assistant chat is capped", "msgsBox.children.length > 40" in ai_js)

# ---------------------------------------------------------------- 12. customer dashboard
check("the sub page guards t() on the copy path",
      'const T = (k) => (typeof t === "function"' in sub)
check("the sub page reload measures the HIDDEN period, not the page age",
      "hiddenAt" in sub and "Date.now() - hiddenAt" in sub
      and "(window.__zefiraRenderedAt || 0)" not in sub)
check("the sub page persists a detected language the server did not render",
      "zefira_lang_synced" in sub and 'document.cookie = "zefira_lang="' in sub)
check("the language sync cannot loop", "sessionStorage" in sub)

# ---------------------------------------------------------------- 13. live markup
def req(method, path, body=None, headers=None, timeout=40):
    h = {"User-Agent": "zefira-regress/1.0", "Content-Type": "application/json"}
    h.update(headers or {})
    if COOKIE["v"]:
        h["Cookie"] = f"zefira_session={COOKIE['v']}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        for p in (resp.headers.get("set-cookie") or "").split(";"):
            if p.strip().startswith("zefira_session="):
                COOKIE["v"] = p.split("=", 1)[1]
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


try:
    st, b = req("POST", "/api/login", {"username": "admin", "password": PW}, XW)
    if st == 200:
        st, page = req("GET", "/panel", headers=XW)
        html = page.decode("utf-8", "replace")
        check("the served panel HTML carries the fixable update warnings",
              'id="update-unit-warning"' in html and 'id="update-signature"' in html, "")
        check("neither update warning ships with the hidden attribute",
              not re.search(r'id="update-(unit-warning|signature)"[^>]*\shidden(?![-\w])',
                            html), "attribute still present")
except Exception as exc:
    check("panel reachable for the live check", False, str(exc)[:80])

passed = sum(1 for _, ok, _ in results if ok)
print(f"\n=== {passed}/{len(results)} passed ===")
for n, ok, d in results:
    if not ok:
        print(f"  FAIL {n}: {d}")
sys.exit(0 if passed == len(results) else 1)
