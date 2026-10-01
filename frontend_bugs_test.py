"""
Regression: the front-end bugs this round fixed.

Static assertions over the real files (the six HTTP suites cannot see JS
logic), plus a live check of the two markup/JS mismatches that made whole
features invisible.
"""
import io
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = r"C:\Users\mrlurix\Desktop\laptop pro\zefira"
# Take the target from argv like every other suite. It used to hard-code
# 127.0.0.1:8000, so under run_all_tests.py - which serves on 8011 - the live
# markup checks silently probed a different server (or nothing) and the result
# depended on whatever happened to be listening on 8000.
BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 and sys.argv[1] else "http://127.0.0.1:8000"
# No default password: run_all_tests.py always passes it. A real credential
# used to live in this line, so cloning the repo shipped a working login.
PW = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"
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
docs_css = read("docs/assets/style.css")
panel_i18n = read("static/i18n.js")
_docs_api = read("docs/api.html")
login_html = read("templates/login.html")
auth_js = read("static/auth.js")
css = read("static/style.css")
_main_py = read("main.py")
ANCHOR_I18N = "title.api"
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

# ------------------------------------------- 12. section wiring: update/reality/tunnels
# Each of these shipped as a real bug, verified by reading app.js:
# the reviewed-SHA guard was defeated by re-reading the head at click time,
# the post-update verdict compared `latest` (the upstream head, identical
# before and after) so every successful update ended on the red warning, the
# error card required `!current` and so never rendered, "Copy Both Keys" sent
# an empty private key after a reload, the regen button stayed disabled after
# a failure, the Enabled badge was hard-coded English, and the auto guide
# download was silently eaten by the popup blocker.
check("the update apply sends the SHA the card displayed, not a fresh head read",
      re.search(r"let sha = approvedUpdateSha;.*?expected_sha: sha", app, re.S) is not None
      and 'const sha = before.latest_full || approvedUpdateSha' not in app,
      "approvedUpdateSha must win over before.latest_full")
check("the post-update verdict compares the running commit, not the upstream head",
      app.count('(after.current || "") === (before.current || "")') == 2
      and '(after.latest || "") === (before.latest || "")' not in app,
      f"current-compare count: {app.count('(after.current || \"\") === (before.current || \"\")')}")
check("a failed update check is shown as an error, not as 'up to date'",
      re.search(r"if \(st\.error\) \{", app) is not None
      and "st.error && !st.current" not in app)
# Accepts either spelling: the handler body is what matters, not whether the
# binding goes through bind() or addEventListener directly.
_copy = re.search(r'(?:reality-copy-btn"\)|bind\("#reality-copy-btn", )\s*'
                  r'(?:addEventListener\(|)"click".*?\n\}\);', app, re.S)
_copy_body = _copy.group(0) if _copy else ""
check("Copy Both Keys fetches the private key instead of copying it empty",
      'let priv = $("#reality-priv").value;' in _copy_body
      and "/api/reality/private" in _copy_body
      and "if (!priv)" in _copy_body,
      "handler not found" if not _copy_body else "no DOM read / no fetch")
check("the tunnel token regen re-enables its button on failure",
      re.search(r'act === "refresh".*?finally \{[^}]*btn\.disabled = false;', app, re.S)
      is not None)
check("the inbound Enabled badge is translated, not hard-coded ON/OFF",
      'badge(ib.enabled ? t("badge.on") : t("badge.off")' in app
      and 'badge(ib.enabled ? "ON" : "OFF"' not in app)
check("an auto-downloaded guide reports a blocked popup",
      "function openGuide(url)" in app and "openDownload(url)) toast(t(\"msg.popupBlocked\")"
      in app and "setTimeout(() => openDownload(" not in app)
check("the destructive Update button is guarded against a double click",
      re.search(r'(?:update-now-btn"\)|bind\("#update-now-btn", )\s*'
                r'(?:addEventListener\(|)"click".*?guardBtn\(btn\)',
                app, re.S) is not None)
_guard_chunks = re.split(r"if \(!guardBtn\(btn\)\) return;", app)[1:]
check("every guardBtn call is released again",
      bool(_guard_chunks) and all("btn.disabled = false" in c for c in _guard_chunks),
      "unguarded chunks: "
      + str(sum(1 for c in _guard_chunks if "btn.disabled = false" not in c)))
check("the new private-key message exists in all four panel languages",
      panel_i18n.count('"msg.realityNoPriv"') == 4,
      str(panel_i18n.count('"msg.realityNoPriv"')))

# ------------------------------------------- 12b. docs header + sidebar
# docs.js with the comment lines dropped, so a check about code cannot be
# satisfied (or broken) by the comment that explains the code.
_docs_code = "\n".join(ln for ln in docs_js.splitlines()
                      if not ln.strip().startswith(("//", "*", "/*")))
# The header must NOT react to scrolling: a compact-on-scroll pill was built,
# shipped and then reverted at the operator's request, so pin the decision -
# a stray scroll listener or a leftover .mini rule would bring it back
# silently. The sidebar measurement stays, because that one is about layout
# correctness (a hardcoded 80px drifts when the bar wraps on mobile), not
# about the bar changing size.
check("the docs header does NOT change on scroll",
      'addEventListener("scroll"' not in _docs_code
      and "classList.add(\"mini\")" not in _docs_code
      and "classList.remove(\"mini\")" not in _docs_code,
      "a scroll listener or a .mini toggle is back")
check("no compact-header styling survives in the stylesheet",
      ".topbar.mini" not in docs_css
      and "max-width .24s" not in docs_css
      and "transition: padding .22s ease" not in docs_css,
      ".mini rules or scroll transitions are still in style.css")
check("the header keeps its resting size",
      re.search(r"^\.topbar\s*\{[^}]*max-width:\s*860px", docs_css, re.M) is not None
      and re.search(r"^\.topbar\s*\{[^}]*padding:\s*7px 16px", docs_css, re.M) is not None
      and re.search(r"^\.brand img\s*\{\s*width: 28px", docs_css, re.M) is not None,
      "the resting header size drifted")
check("the sidebar follows the header's real height instead of a guessed offset",
      "--topbar-h" in docs_css and "var(--topbar-h" in docs_css
      and 'setProperty("--topbar-h"' in docs_js
      and re.search(r"\.sidebar\s*\{[^}]*top:\s*80px", docs_css) is None,
      "hardcoded sidebar offset still present")
check("the header height is published from a measurement, not from a rect",
      "ResizeObserver" in docs_js and "bar.offsetHeight" in docs_js
      and "getBoundingClientRect().bottom" not in _docs_code,
      "a sticky element's rect is a viewport position, not a height")

# ---------------------------------------------------------------- 13. customer dashboard
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

# ---- API tokens: the UI must match the server's re-prompt ---------------
# POST /api/api-tokens requires the admin password (a `full` token can mint
# another, so a leaked one used to be self-perpetuating). The button has to
# collect it, or the operator gets a bare 422 with no way to recover in-place.
_tok_i = app.find('"/api/api-tokens", { method: "POST"')
check("the token create call exists",
      _tok_i != -1, "no POST /api/api-tokens in app.js")
# The body object is nested, so a bracket-balanced regex is the wrong tool:
# look at the call's own text instead of trying to match the literal.
_tok_win = app[_tok_i:_tok_i + 240] if _tok_i != -1 else ""
check("the token form sends password_confirm with the create request",
      _tok_i != -1 and "password_confirm: pw" in _tok_win,
      "the UI would 422 against the server contract")
check("the token form prompts for the password before creating",
      re.search(r'prompt\(t\("prm\.tokenPw"\)\)', app) is not None,
      "no prompt: the operator only sees a 422")
check("a cancelled prompt creates nothing",
      re.search(r'const pw = prompt\(t\("prm\.tokenPw"\)\);\s*\n\s*if \(!pw\) return;',
                app) is not None,
      "a cancelled prompt must abort, not send an empty confirm")
check("prm.tokenPw exists in all four panel locales",
      panel_i18n.count('"prm.tokenPw"') == 4,
      f"found {panel_i18n.count(chr(34) + 'prm.tokenPw' + chr(34))} of 4")
check("the token form does not leak the password into the query string",
      "password_confirm=" not in app,
      "a credential in a URL lands in logs and Referer")
_schemas = read("schemas.py")
check("the server really does require the confirm password",
      re.search(r"class ApiTokenCreateIn\(RestoreConfirmIn\):", _schemas) is not None,
      "the UI and the schema disagree")
check("a new token's lifetime is bounded by default",
      re.search(r"expires_in_days: int = Field\(default=(?!0)\d+", _schemas) is not None,
      "no default expiry: an integration token lives forever")
# A token that silently stops working reads as a broken bot, so the expiry has
# to be on the row - and an already-dead one has to look different from a live
# one, or the operator keeps debugging the integration.
check("the token row shows the expiry",
      re.search(r"if \(tk\.expires_at\)", app) is not None
      and '"tokens.expiresAt"' in app,
      "the list gives no hint that a token has a lifetime")
check("an expired token is marked, not just dated",
      re.search(r'if \(_dead\) li\.classList\.add\("bad"\)', app) is not None
      and '"tokens.expiredAt"' in app,
      "an expired token looks identical to a live one")
# The Check button's own message has to branch on the same flag. A global
# search for the key is not enough: an earlier version of this guard passed
# even with the branch hard-coded, because it only looked for the key's
# presence and for the `li` class - neither of which the branch controls.
_ct = re.search(r'dataset\.act === "check-token"\)?\s*\{(.*?)\n      return;', app, re.S)
_ct_body = _ct.group(1) if _ct else ""
check("the Check button says EXPIRED when the token is past its date",
      re.search(r'_dead\s*\?\s*"api\.checkExpired"\s*:\s*"api\.checkOk"', _ct_body) is not None
      and re.search(r'_dead\s*\?\s*"warn-text"\s*:\s*"ok-text"', _ct_body) is not None,
      "an expired token would be reported as active")
check("the expiry strings exist in all four panel locales",
      panel_i18n.count('"tokens.expiresAt"') == 4
      and panel_i18n.count('"tokens.expiredAt"') == 4,
      f"expiresAt={panel_i18n.count(chr(34) + 'tokens.expiresAt' + chr(34))} "
      f"expiredAt={panel_i18n.count(chr(34) + 'tokens.expiredAt' + chr(34))} of 4")
check("the API reference states the new token contract",
      all(s in _docs_api for s in ("password", "expires_in_days"))
      and all(s in docs_i18n for s in ("expires_in_days",)),
      "docs still say only 'create (once-only secret)'")

# ---- the Developer API section -----------------------------------------
# NOTE ON THE TOKEN-TEST DESIGN, because it changed for a reason. The post-
# create check used to be a cookie-less `GET /api/me` carrying the raw token in
# an Authorization header, on the reasoning that "exactly what a bot sends" is
# the only test worth having. It was right about the request and wrong about
# the consequence: require_admin stamps `last_used_at` on every bearer request,
# so the panel's own self-test made the `null` that means "never used"
# unreachable for every token the UI ever created, and the Check button then
# reported "just now" for a token nobody had used. That field is what an
# operator scans for a leaked credential, so forging it is worse than not
# testing. It now goes through a dedicated endpoint that does the same
# hash-and-lookup WITHOUT the write.
_tv = re.search(r"async function verifyTokenLive\([^)]*\)\s*\{(.*?)\n\}", app, re.S)
_tv_body = _tv.group(1) if _tv else ""
check("the token test exists and runs right after the token is minted",
      _tv is not None
      and re.search(r"await verifyTokenLive\(r\.token_once\);", app) is not None,
      "no live token check")
check("the token test is called BEFORE the secret is shown",
      "await verifyTokenLive(r.token_once);" in app
      and app.index("await verifyTokenLive(r.token_once);")
      < app.index('prompt(t("prm.tokenOnce"), r.token_once);'),
      "testing after the prompt means the operator already pasted it")
check("a failed token test is reported, not swallowed",
      all(k in _tv_body for k in ("api.testRejected", "api.testFailed")),
      "a rejected token must be distinguishable from a crash")
# Every {placeholder} in a string must be one the call site actually supplies.
# The self-test kept a {user} after the endpoint stopped returning a username,
# and the panel printed it literally: "authenticated as full for {user}." A
# visible placeholder is worse than none, and nothing else in the suite would
# have noticed - the string is valid, the keys are all present, and the test
# passes.
def _placeholders_in(lang_block, key):
    m = re.search(r'"' + re.escape(key) + r'":\s*"((?:[^"\\]|\\.)*)"',
                  lang_block)
    if m is None:
        return None
    return set(re.findall(r"\{(\w+)\}", m.group(1)))


_blocks = [(m.start(), m.group(1)) for m in
           re.finditer(r"Object\.assign\(Z_STRINGS\.(\w+), \{", panel_i18n)]
# A language has SEVERAL Object.assign blocks and the api.* keys are not in the
# last one, so concatenate them per language. Taking only the final block made
# this lookup return None and the two checks below report nonsense.
_lang_block = {}
for _i, (_p, _l) in enumerate(_blocks):
    _end = _blocks[_i + 1][0] if _i + 1 < len(_blocks) else len(panel_i18n)
    _lang_block[_l] = _lang_block.get(_l, "") + panel_i18n[_p:_end]
_st_ok = _placeholders_in(_lang_block.get("en", ""), "api.testOk")
check("no dictionary value keeps a placeholder the call site never fills",
      _st_ok == {"name", "scope"},
      f"api.testOk wants {_st_ok}, verifyTokenLive supplies name and scope")
_tv_call = re.search(r't\("api\.testOk",\s*\{(.*?)\}\)', _tv_body, re.S)
_supplied = set(re.findall(r"(\w+):", _tv_call.group(1))) if _tv_call else set()
check("...and the call site supplies exactly those",
      _st_ok is not None and _supplied == _st_ok,
      f"string wants {sorted(_st_ok or [])}, call supplies {sorted(_supplied)}")
check("no {user} survives anywhere in the panel dictionary",
      "{user}" not in panel_i18n,
      "an unfilled placeholder is printed verbatim to the operator")
# The same check across every {…} value the section uses, so the next string
# added there is covered too.
_bad_ph = []
for _lang, _blk in _lang_block.items():
    for _key in ("api.checkOk", "api.checkExpired", "api.testFailed",
                 "api.testRejected", "api.checkGone", "tokens.expiresAt",
                 "tokens.expiredAt", "tokens.lastUsed"):
        _ph = _placeholders_in(_blk, _key)
        if _ph and ("dt" in _ph) and _key.startswith("api."):
            # these are filled by the row/Check handlers
            if not re.search(r"dt:\s*", app):
                _bad_ph.append(f"{_lang}.{_key} wants dt but nothing supplies it")
check("the section's other placeholders are all supplied",
      not _bad_ph, "; ".join(_bad_ph[:3]))
check("the panel never keeps the token secret in web storage",
      re.search(r"(localStorage|sessionStorage)[^\n]*token_once", app) is None
      and re.search(r"(localStorage|sessionStorage)[^\n]*zfp_", app) is None,
      "a stored token is one XSS away from being stolen")

# ---- the section itself -------------------------------------------------
check("the API section is in the sidebar",
      re.search(r'class="nav-btn"[^>]*data-section="api"', panel) is not None,
      "no nav button for it")
check("the API section has a DOM section to show",
      re.search(r'<section id="section-api"', panel) is not None,
      "the nav button would switch to nothing")
check("the nav button and the section agree on the title key",
      re.search(r'data-section="api"[^>]*data-title-key="title\.api"', panel) is not None
      and f'"{ANCHOR_I18N}"' in panel_i18n,
      "the topbar heading would stay on the previous page's title")
check("the API section is wired to its loader",
      re.search(r'btn\.dataset\.section === "api"\) loadApiDev\(\)', app) is not None
      and "async function loadApiDev(" in app,
      "clicking it would show an empty page")
check("the tokens card MOVED: exactly one copy of each id exists",
      all(len(re.findall(f'id="{i}"', panel)) == 1 for i in
          ("apitoken-name", "apitoken-create-btn", "apitoken-list")),
      "two #apitoken-create-btn elements: $(\"…\") binds only the first, so "
      "one copy of the button would be dead")
check("Settings no longer loads the token list",
      re.search(r'btn\.dataset\.section === "settings"[^\n]*loadApiTokens', app) is None,
      "both sections loading it is harmless, but it means the move is half done")
check("the quick start shows a base URL built from the deployment",
      "function apiBaseUrl(" in app
      and re.search(r'#api-base-url', panel) is not None
      and re.search(r"location\.origin", app) is not None,
      "the base URL was never shown anywhere in the panel")
check("the quick start prefers the operator's public_url over the origin",
      re.search(r"apiBaseUrl\(pub\)", app) is not None
      and re.search(r'api\("/api/tunnel-settings"\)', app) is not None,
      "behind a proxy, location.origin is whatever host the admin typed")
check("public_url is read from the tunnel settings, not /api/settings",
      re.search(r'api\("/api/settings"\)[^\n]*\.public_url', app) is None
      and re.search(r"tun\.public_url", app) is not None,
      "public_url does not exist on /api/settings, so that read is always "
      "undefined and the whole prefer-public_url rule is dead code")
check("the base URL is stripped of a trailing slash anyway",
      re.search(r'replace\(/\\/\+\$/, ""\)', app) is not None,
      "the server refuses to store one, but `domain` and an older install's "
      "setting can still carry it, and https://host/ + /api/me is a double "
      "slash in every copy-pasted example")
check("every copy button is handled by one delegated listener",
      re.search(r'data-copy', panel) is not None
      and re.search(r'closest\("\[data-copy\]"\)', app) is not None,
      "a per-button listener would need editing for every new row")
check("a failed copy is reported",
      # Scoped to the [data-copy] handler on purpose: an earlier version of
      # this guard was a global substring search, and the QR button already
      # had an identical `else toast(t("msg.copyFailed"), false)` - so the
      # guard passed with the new handler's failure path removed.
      re.search(r'closest\("\[data-copy\]"\)(.*?)\n\}\);', app, re.S) is not None
      and re.search(
          r'closest\("\[data-copy\]"\).*?else toast\(t\("msg\.copyFailed"\), false\);',
          app, re.S) is not None,
      "a silent copy means the operator pastes an empty string")
check("the scope table explains both scopes and bot's limits",
      all(f'"{k}"' in panel_i18n for k in
          ("api.scopeFullCan", "api.scopeBotCan", "api.scopeBotCant")),
      "the section would ship a token-scope list with no text")
check("the rules list covers the things bot authors get wrong",
      sum(1 for k in ("api.ruleAuth", "api.ruleCsrf", "api.ruleScope403",
                      "api.ruleThrottle", "api.ruleExpiry", "api.ruleRotate")
          if f'"{k}"' in panel_i18n) == 6,
      "a developer section with no rules is just a link")
check("the copy-row style exists",
      re.search(r"^\.copy-row", css, re.M) is not None,
      "the value and the button would stack instead of sitting in a row")
check("the check button uses a real icon",
      re.search(r"check:\s*'<svg", app) is not None
      and "ICONS.check" in app,
      "the button would render blank")
check("the check button reports status, and says so honestly",
      re.search(r'chkBtn\.dataset\.expired', app) is not None
      and re.search(r'api\.checkExpired', app) is not None
      and re.search(r'api\.checkOk', app) is not None,
      "an expired token must not look like a live one")

# ---- the saved menu layout must not strand a new section ----------------
# Personalize stores the sidebar order. A section added by a later release is
# not in that stored list, and the original loop ("append every button the
# layout mentions") left the unknown one at the FRONT: Developer API rendered
# above Dashboard on every existing install. The fix slots an unknown section
# in after the last known one that precedes it in the template.
sys.path.insert(0, ROOT)

_ml = re.search(r"function applyMenuLayout\(layout\)\s*\{(.*?)\n\}", app, re.S)
_ml_body = _ml.group(1) if _ml else ""
check("the menu layout records the template order before moving anything",
      "templateOrder" in _ml_body
      and re.search(r"templateOrder\.push", _ml_body) is not None,
      "without the original order there is nowhere to put a new section")
check("a section missing from the saved layout is placed, not stranded",
      re.search(r"placed\.splice\(", _ml_body) is not None
      and re.search(r"if \(rank\.has\(id\)\) continue;", _ml_body) is not None,
      "an unknown section would keep its DOM position and end up first")
check("a new section is visible, not hidden by default",
      re.search(r"const hide = !!\(item && item\.hidden\);", _ml_body) is not None,
      "a section with no saved entry must not default to hidden")


def _real_menu_order():
    """Run the SHIPPED applyMenuLayout() in node against a fake nav.

    A Python port of the same logic proved nothing - it tested the port, not
    the code - and two guards "MISSED" a re-introduced regression for exactly
    that reason. This executes the function that actually ships, with a layout
    saved before the api section existed and one item dragged by the operator.
    """
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        return None
    try:
        r = subprocess.run([node, "menu_order_check.js", "static/app.js"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", cwd=ROOT, timeout=60)
    except Exception:
        return None
    if r.returncode != 0:
        return {"error": (r.stderr or "").strip().splitlines()[-1:] or ["?"]}
    out = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[parts[0]] = int(parts[1])
        elif len(parts) == 2 and parts[1] in ("true", "false"):
            out[parts[0]] = parts[1] == "true"
        elif len(parts) >= 2:
            # e.g. "sparse_order dashboard,users,...", "sparse_all_present true"
            key = parts[0]
            rest = " ".join(parts[1:])
            out[key] = (rest == "true") if rest in ("true", "false") else rest
    return out


# Built before the checks that use it, and defined here rather than inline in a
# call: a `check(` whose argument list is never closed is a SyntaxError that
# takes the whole suite down with it.
_order = _real_menu_order()

# Where the section is SUPPOSED to sit, derived from the template rather than
# hardcoded: the operator's default position is simply the one in panel.html,
# and moving the button there must not require editing this test. What matters
# is that the saved layout does not override it.
_tpl = re.findall(r'class="nav-btn[^"]*"[^>]*data-section="([a-z]+)"', panel)
_api_at = _tpl.index("api") if "api" in _tpl else -1
_want_after = _tpl[_api_at - 1] if _api_at > 0 else None
_want_before = _tpl[_api_at + 1] if 0 <= _api_at < len(_tpl) - 1 else None
check("the section is actually reachable from a real install",
      # The real check: run the SHIPPED applyMenuLayout against a layout saved
      # BEFORE the api section existed, and assert it lands where the template
      # puts it. The position itself is the operator's default, read from
      # panel.html - not a constant in this test.
      _order is not None
      and "error" not in _order
      and _api_at > 0
      and _order.get("api") == _order.get(_want_after, -99) + 1
      and (_want_before is None
           or _order.get("api", 99) < _order.get(_want_before, -1)),
      f"order={_order} want api right after {_want_after!r} and before {_want_before!r}")
check("...and the saved order of the other sections is still honoured",
      _order is not None and "error" not in _order
      and _order.get("dashboard") == 0
      # The harness drags Nodes above Inbounds; if that reordering survives,
      # applyMenuLayout is genuinely reading the saved layout.
      and _order.get("nodes", 99) < _order.get("inbounds", -1),
      f"the operator's dragged order was lost: {_order}")
check("...every section survives, and a new one is visible",
      _order is not None and "error" not in _order
      and _order.get("all_present") is True
      and _order.get("api_visible") is True
      and _order.get("count") == len(re.findall(r'data-section="[a-z]+"', panel)),
      f"count={_order.get('count') if _order else None}, "
      f"nav buttons in the template="
      f"{len(re.findall(chr(39) + 'data-section=' + chr(34) + '[a-z]+' + chr(34), panel))}")

# ---- a SPARSE layout must not invert the menu --------------------------
# The unknown-section splice fell back to index 0 when the layout mentioned no
# EARLIER section, which reversed the whole menu - the precise regression the
# block claims to fix. Unreachable today only because both normalizers backfill
# every id, so the shipped helper has to exercise it explicitly.
check("a sparse layout does not invert the menu",
      _order is not None
      and _order.get("sparse_all_present") is True
      and _order.get("sparse_dashboard_at") == 0
      and _order.get("sparse_settings_at") == _order.get("count", -1) - 1,
      f"sparse={_order.get('sparse_order') if _order else None}")
check("a sparse layout still puts the unknown section at its template slot",
      _order is not None
      and _order.get("sparse_order")
      and "api" in [x for x in _order["sparse_order"].split(",")]
      and "customize" in [x for x in _order["sparse_order"].split(",")]
      and ([x for x in _order["sparse_order"].split(",")].index("api")
           == [x for x in _order["sparse_order"].split(",")].index("customize") + 1),
      f"sparse={_order.get('sparse_order') if _order else None}")

# ---- the section must be a first-class menu citizen --------------------
# "api" was missing from MENU_IDS and MENU_SECTIONS, so normalizeMenu dropped
# it and the server refused to store a layout mentioning it: Personalize could
# neither move nor hide it, which is the one thing that section exists for.
_mids = re.search(r"const MENU_IDS = \[([^\]]*)\]", app)
_mids_list = re.findall(r'"([a-z]+)"', _mids.group(1)) if _mids else []
_msrv = re.search(r"MENU_SECTIONS = \(([^)]*)\)", _main_py)
_msrv_list = re.findall(r'"([a-z]+)"', _msrv.group(1)) if _msrv else []
_tpl_secs = re.findall(r'data-section="([a-z]+)"', panel)
check("the api section is in the client's menu id list",
      "api" in _mids_list, f"MENU_IDS={_mids_list}")
check("the api section is in the server's menu section list",
      "api" in _msrv_list, f"MENU_SECTIONS={_msrv_list}")
check("the two canonical menu lists agree with each other",
      sorted(_mids_list) == sorted(_msrv_list),
      f"client={sorted(_mids_list)} server={sorted(_msrv_list)}")
check("...and with the sections that actually exist in the template",
      sorted(_mids_list) == sorted(set(_tpl_secs)),
      f"lists={sorted(_mids_list)} template={sorted(set(_tpl_secs))}")
check("the api section can therefore be reordered and hidden",
      "api" in _mids_list and "api" in _msrv_list
      and re.search(r'"api"\s*,\s*"settings"', _mids.group(1)) is not None,
      "the default slot is the one the operator asked for, and it is editable")

# ---- the token self-test must not forge usage -------------------------
# require_admin stamps last_used_at on EVERY bearer request. A cookie-less
# GET /api/me as the self-test therefore made "never used" unreachable for
# every UI-minted token, and the Check button reported "just now" for a token
# nobody had used - destroying the exact signal an operator scans for a leak.
_vt = re.search(r"async function verifyTokenLive\([^)]*\)\s*\{(.*?)\n\}", app, re.S)
_vt_body = _vt.group(1) if _vt else ""
_st = re.search(r'def api_token_self_test\(.*?\n(?=\n\n)', _main_py, re.S)
_st_body = _st.group(0) if _st else ""
check("the self-test goes through the dedicated endpoint, not the auth path",
      re.search(r'api\("/api/api-tokens/self-test"', _vt_body) is not None
      and re.search(r'fetch\("/api/me"', _vt_body) is None
      and 'Authorization: "Bearer "' not in _vt_body,
      "a bearer call stamps last_used_at and forges a use")
check("the self-test endpoint exists and is admin-only",
      _st_body != "" and "Depends(require_admin)" in _st_body,
      "no self-test endpoint")
check("the self-test endpoint never stamps last_used_at",
      _st_body != "" and "last_used_at =" not in _st_body
      and "ApiToken.last_used_at" not in _st_body,
      "it would forge the usage signal it exists to preserve")
check("the self-test response cannot echo the token back",
      _st_body != "" and '"token":' not in _st_body
      and "token_once" not in _st_body
      and re.search(r'return \{"ok": True, \*\*info\}', _st_body) is not None,
      "the raw credential must not come back in the response")
check("the self-test is rate-limited and audited without the value",
      _st_body != "" and "sensitive_limiter.hit" in _st_body
      and "APITOKEN_SELFTEST" in _st_body
      and re.search(r"audit\(s, \"APITOKEN_SELFTEST\",\s*\n?\s*f\"\{'ok' if ok else 'failed'\} \{info\.get\('name'", _st_body)
      is not None,
      "an audit row that quoted the token would be the worst possible place for it")
check("a wrong token is a reported result, not a missing resource",
      _st_body != "" and 'status_code=404' not in _st_body
      and re.search(r'return \{"ok": False', _st_body) is not None,
      "404 reads like a bug; the panel wants a rendered verdict")

# ---- the quick start must not advise a cleartext token ----------------
check("the quick start warns when the base URL is plain HTTP",
      re.search(r'const insecure = /\^http:\\/\\//i\.test\(b\);', app) is not None
      and re.search(r'warn\.classList\.toggle\("hidden", !insecure\)', app) is not None,
      "a full-scope bearer token was being copied to the clipboard over http "
      "with nothing said about it")
check("the warning exists in all four locales",
      panel_i18n.count('"api.insecureWarning"') == 4,
      f"found {panel_i18n.count(chr(34) + 'api.insecureWarning' + chr(34))} of 4")
check("the warning element exists in the section",
      re.search(r'id="api-insecure-warning"', panel) is not None,
      "nothing to show the warning in")
check("copying is not blocked, but the button is marked",
      re.search(r'btn\.classList\.toggle\("warn-btn", insecure\)', app) is not None,
      "an outright refusal just teaches people to work around it")

# ---- the copy handler must stay narrow --------------------------------
_cc = re.search(r'const API_COPY_IDS = \[([^\]]*)\]', app)
_cc_list = re.findall(r'"([^"]+)"', _cc.group(1)) if _cc else []
_ccl = re.search(r'document\.addEventListener\("click".*?API_COPY_IDS\.indexOf\(sel\) === -1', app, re.S)
check("the copy handler is allowlisted, not page-wide",
      len(_cc_list) == 3
      and _ccl is not None
      and re.search(r'btn\.closest\("#section-api"\)', app) is not None,
      f"allowlist={_cc_list}")
check("the copy handler cannot throw on a malformed selector",
      re.search(r'try \{\s*\n\s*src = \$\(sel\);', app) is not None
      or re.search(r'src = \$\(sel\);\s*\n\s*\} catch', app) is not None,
      "a SyntaxError from $() would look like a dead button with no reason")
check("the allowlist covers every copy button in the template",
      sorted(set(re.findall(r'data-copy="([^"]+)"', panel))) == sorted(_cc_list),
      f"template={sorted(set(re.findall(chr(39) + 'data-copy=' + chr(34) + '([^' + chr(34) + ']+)', panel)))} "
      f"allowlist={sorted(_cc_list)}")

# ---- a credential form must POST even if the JS never runs -------------
# No form declared `method`, so the HTML default is GET: with auth.js blocked,
# a stale asset_v, a proxy that strips the script, or JS simply off, pressing
# Enter submitted natively and put the password in the URL -
#   GET /panel?current=<old>&new1=<new>&new2=<new>
# The panel's own logs were not exposed (--no-access-log, nginx access_log off,
# Referrer-Policy: no-referrer, CSP form-action 'self'), but browser history,
# synced accounts, any third-party proxy and a screen share were.
_forms = re.findall(r"<form\b[^>]*>", panel) + re.findall(r"<form\b[^>]*>", login_html)
check("every form declares a method, so the safe default is the default",
      _forms and all('method="post"' in f for f in _forms),
      f"forms without method=post: {[f[:60] for f in _forms if 'method=' not in f]}")
check("the password forms are among them",
      sum(1 for f in _forms if "pw-form" in f or "login-form" in f) >= 2
      and all('method="post"' in f for f in _forms
              if "pw-form" in f or "login-form" in f),
      "the login and password-change forms are the ones that leak")
check("the panel's own JS still intercepts these forms",
      # The login form lives in auth.js, the rest in app.js.
      re.search(r'login-form', auth_js) is not None
      and 'addEventListener("submit"' in auth_js
      and all(re.search(rf'bind\("#{i}", "submit"', app) is not None
              for i in ("pw-form", "srv-form", "add-user-form", "edit-user-form")),
      "with method=post a JS failure now 405s instead of leaking, but the "
      "normal path must still be JS-driven")

# ---- one missing id must not disable the rest of the page --------------
# ~60 top-level `$("#id").addEventListener(...)` statements: a null from
# querySelector threw a TypeError that aborted every LATER top-level statement,
# so one element the template lacks silently disabled the password form, the AI
# form, the token form and the audit list. Two hand-guarded `if (el)`
# workarounds for exactly this were already in the file.
check("there is a bind() helper that tolerates a missing element",
      re.search(r"function bind\(sel, evt, fn, opts\)", app) is not None
      and re.search(r'console\.warn\("\[zefira\] bind: no element for", sel\)', app)
      is not None,
      "a missing element must be reported without taking the page down")
check("the missing element is still reported, not swallowed",
      "console.warn" in app,
      "silently ignoring a typo hides the very bug it is about")
_remaining = re.findall(r'^\s*\$\("(#[\w-]+)"\)\.addEventListener\(', app, re.M)
check("no top-level binding can still abort the ones after it",
      not _remaining,
      f"still unguarded: {_remaining[:5]}")
# Not "every binding goes through bind": nine of them legitimately do not,
# on receivers that are already resolved (btn, overlay, document, ...). Not a
# tautology either - the previous version compared two counts of the same
# pattern, which differ only when a call is glued to an identifier, and that
# never happens (measured 10 == 10, zero such occurrences). This is the general
# form of what the two neighbouring checks test in specific spellings: an
# addEventListener whose RECEIVER came from a selector lookup is the one that
# aborts the rest of the script when the id is renamed.
_lookup_receivers = []
for _m in re.finditer(r'([A-Za-z0-9_$.\[\]()\s]{0,70}?)\.addEventListener\(', app):
    _recv = _m.group(1).strip()
    if ("$(" in _recv or "getElementById" in _recv
            or "querySelector" in _recv or "querySelectorAll" in _recv):
        _lookup_receivers.append(
            f"line {app[:_m.start()].count(chr(10)) + 1}: {app[app.rfind(chr(10), 0, _m.start()) + 1:app.find(chr(10), _m.start())].strip()[:70]}")
check("no addEventListener is attached to a selector lookup",
      not _lookup_receivers,
      f"{len(_lookup_receivers)} unguarded binding(s); use bind(): "
      + "; ".join(_lookup_receivers[:3]))
_optional = re.findall(r'(?:\$\("(#[\w-]+)"\)|getElementById\("([\w-]+)"\))'
                       r'\?\.addEventListener\(', app)
check("no binding is left with its own ad-hoc null guard",
      not _optional,
      f"still optional: {[(a or b) for a, b in _optional][:5]}")
check("bind() also survives an INVALID selector, which throws rather than "
      "returning null",
      re.search(r"function bind\(sel, evt, fn, opts\)\s*\{.*?catch \(err\)", app, re.S)
      is not None,
      "querySelector THROWS on an invalid selector, and `if (!el)` cannot "
      "help because the exception happens while evaluating the argument")
_sel = subprocess.run([sys.executable, "find_bad_selectors.py"], capture_output=True,
                      text=True, encoding="utf-8", errors="replace", cwd=ROOT)
check("no literal selector in app.js would make querySelector throw",
      _sel.returncode == 0,
      (_sel.stdout or "").strip().splitlines()[-1][:120] if _sel.stdout else "no node/python")

# ---- the panel script must actually LOAD --------------------------------
# `node --check` only parses, and every suite in this repo is HTTP-level: it
# never clicks a nav button. A scripted refactor left `document.bind(...)` -
# valid JavaScript that throws on the first call - and all 902 checks stayed
# green while the panel's entire lower half was dead. The browser found it.
# This evaluates the whole file against a DOM stub built from panel.html, so
# the only thing it can report is "the script asked for an id the template does
# not have" or "module-scope code threw".
check("the panel script is checked by RUNNING it, not by parsing it",
      os.path.exists(os.path.join(ROOT, "app_smoke_check.js")),
      "a parse check cannot see a call that throws when it runs")
_smoke = subprocess.run(["node", "app_smoke_check.js"], capture_output=True,
                        text=True, encoding="utf-8", errors="replace", cwd=ROOT)
check("app.js evaluates without throwing at module scope",
      _smoke.returncode == 0,
      " ".join((_smoke.stdout or _smoke.stderr or "").split())[:150])
check("the smoke stub's element list comes from the template, not a hand-typed one",
      re.search(r'PANEL = path\.join\(__dirname, "templates", "panel\.html"\)',
                io.open(os.path.join(ROOT, "app_smoke_check.js"),
                        encoding="utf-8").read()) is not None,
      "a typed-in list goes stale on the first new button and then reports a "
      "product bug that is not there")
check("no call was accidentally qualified with document.",
      "document.bind(" not in app,
      "a scripted rewrite left `document.bind(...)`, which throws on the first "
      "call and aborts every later top-level statement")

# ---- the docs renderer must be checked by EXECUTING it ----------------
check("the i18n renderer is checked by running it, not by reading it",
      os.path.exists(os.path.join(ROOT, "i18n_render_check.js")),
      "its safety is a chain of escape-order invariants; reading them by eye "
      "is how they stay safe for a year and then are not")
check("the renderer escapes the ampersand FIRST, so the sink is safe by "
      "construction rather than by a parser invariant",
      re.search(r'plain\.replace\(/&/g, "&amp;"\)\.replace\(/</g, "&lt;"\)'
                r'\.replace\(/>/g, "&gt;"\)', docs_i18n) is not None,
      "a decoded &#60; then reaches innerHTML as a live character reference - "
      "harmless per spec, but the safety would rest on the spec")

# ---- a bug hunt round: six front-end defects, each reproduced first -------
# Every guard below is the RULE, not the string that happens to satisfy it
# today, because five guards in this project's history were a restated
# implementation detail that could not fail: the lock's hashes-per-package
# average, the installer's hardcoded `echo 1.14.2`, a hand-written attribute
# list, the README's per-suite counts, and `[[ -t 0 ]] && INTERACTIVE=1`.
panel_i18n = read("static/i18n.js")

# 1. Every sidebar id needs a menu label in ALL FOUR panel dictionaries.
#    `menu.api` came in with the Developer API section and went into nav.api and
#    title.api, but never menu.* - so the Personalize menu layout rendered the
#    literal string "menu.api" to the operator, in every language. Asserting the
#    whole class is the point; asserting "menu.api exists" would let the next
#    section repeat it.
_menu_ids_m = re.search(r"const MENU_IDS = \[([^\]]*)\]", app)
_menu_ids = re.findall(r'"([\w-]+)"', _menu_ids_m.group(1)) if _menu_ids_m else []
_missing_menu = []
for _id in _menu_ids:
    for _lang in ("en", "fa", "zh", "ru"):
        _s = panel_i18n.find("Object.assign(Z_STRINGS.%s, {" % _lang)
        if _s == -1:
            continue
        _e = panel_i18n.find("});", _s)
        if ('"menu.%s"' % _id) not in panel_i18n[_s:_e]:
            _missing_menu.append("%s/%s" % (_lang, _id))
check("every sidebar id has a menu label in all four languages",
      bool(_menu_ids) and not _missing_menu,
      f"missing menu labels: {_missing_menu[:8]} - a missing one renders the raw "
      f"key to the operator, e.g. the literal text 'menu.api'")

# 2. The floating AI button is position:fixed and sits ON TOP of the AI settings
#    form, so opening the chat must not rewrite the fields underneath it.
#    loadAi() did exactly that, and a later Save then persisted the OLD values.
_ai_fab = re.search(r'bind\("#ai-fab"[\s\S]{0,600}?\n\}', app)
check("opening the AI chat does not rewrite the AI settings form",
      _ai_fab is not None and "loadAi(false)" in _ai_fab.group(0)
      and not re.search(r"loadAi\(\s*\)", _ai_fab.group(0)),
      "the button is visible on the Settings page where those five inputs live; "
      "a bare loadAi() overwrites all of them with the stored values, so an "
      "unsaved edit is silently lost and then saved as the OLD one")

# 3. A null/garbage body must not throw AFTER a list was cleared. loadInbounds
#    and renderApiTokens already carried this guard with a comment; loadAudit
#    did not, so Security Events could stay permanently blank, silently.
_audit_fn = re.search(r"async function loadAudit\(\) \{([\s\S]*?)\n\}", app)
_audit_body = _audit_fn.group(1) if _audit_fn else ""
check("a non-array body cannot blank a list that was already cleared",
      bool(_audit_body) and "Array.isArray" in _audit_body
      and _audit_body.find("Array.isArray") < _audit_body.find('textContent = ""'),
      "the guard must come BEFORE the clear, or the exception still lands after "
      "the DOM is emptied")

# 4. `numInput(x) || default` swallows the very NaN the validation loop exists
#    to catch, because NaN || 1701 is 1701. Four ports did this while the other
#    four were correctly refused.
_short = re.findall(r"=\s*numInput\([^)]*\)\s*\|\|\s*\d", app)
check("no port is silently defaulted in a way that hides an invalid value",
      not _short,
      f"`numInput(x) || n` turns a blank field into n, so it never reaches the "
      f"Number.isFinite check that refuses the other ports; found {len(_short)}")

# 5. Row actions must guard against a double submit AND hand the button back.
#    Guarding without releasing is worse than the double click it prevents: a
#    declined confirm leaves the button dead for the whole session.
_row = re.search(r'bind\("#inbounds-tbody"[\s\S]{0,1800}?\n\}\);', app)
_row_body = _row.group(0) if _row else ""
check("the inbound row actions are guarded and the guard is released",
      "guardBtn(btn)" in _row_body
      and re.search(r"finally\s*\{\s*btn\.disabled = false", _row_body) is not None,
      "guardBtn disables the button; without a release the declined-confirm path "
      "and any failed request leave it permanently dead")
check("the inbound toggle reads its state from data, not from a CSS class",
      re.search(r'btn\.dataset\.on === "1"', app) is not None
      and not re.search(r'btn\.classList\.contains\("warn"\)', app),
      "the class is only a paint - the users table was fixed for exactly this "
      "and the comment there says why")

# 6. A copy and a QR are independent actions. One shared generation counter made
#    the copy return with no toast, no clipboard write and no error.
check("the subscription-copy path does not share a counter with the QR path",
      re.search(r"const seq = \+\+qrCopySeq;", app) is not None
      and not re.search(r"const seq = \+\+qrSeq;[\s\S]{0,400}?subCopied", app),
      "one qrSeq for both meant clicking a QR while a copy was in flight "
      "silently discarded the copy - a button that appeared to do nothing")

passed = sum(1 for _, ok, _ in results if ok)
print(f"\n=== {passed}/{len(results)} passed ===")
for n, ok, d in results:
    if not ok:
        print(f"  FAIL {n}: {d}")
sys.exit(0 if passed == len(results) else 1)
