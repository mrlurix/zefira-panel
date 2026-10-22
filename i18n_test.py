"""Permanent i18n coverage guard (no server needed).

Fails when:
- a data-i18n* key used in panel templates is missing from any locale,
- a t("...") key used in panel JS is missing from any locale,
- backend sub-dashboard words/months drift from the JS dicts.

Run: .venv/Scripts/python i18n_test.py
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
fails = []


def fail(msg):
    fails.append(msg)
    print("FAIL", msg)


# ---- 1. dict completeness across locales ----
src = (HERE / "static" / "i18n.js").read_text(encoding="utf-8")
locales = {}
for m in re.finditer(r"Object\.assign\(Z_STRINGS\.(\w+), \{(.*?)\}\);\n", src, re.S):
    loc, body = m.group(1), m.group(2)
    locales.setdefault(loc, set()).update(re.findall(r'"([a-zA-Z0-9_.]+)":', body))
base = locales.get("en", set())
if len(base) < 100:
    fail(f"suspiciously few en keys: {len(base)}")
for loc in ("fa", "zh", "ru"):
    missing = sorted(base - locales.get(loc, set()))
    extra = sorted(locales.get(loc, set()) - base)
    for k in missing:
        fail(f"missing {loc}.{k}")
    for k in extra:
        fail(f"extra {loc}.{k} (add to en too)")

# ---- 2. every data-i18n* key used in templates exists in en ----
used = set()
for tpl in ("login.html", "panel.html", "sub.html"):
    html = (HERE / "templates" / tpl).read_text(encoding="utf-8")
    for attr in ("data-i18n", "data-i18n-ph", "data-i18n-title", "data-i18n-aria"):
        used.update(re.findall(attr + r'="([^"]+)"', html))
missing = sorted(u for u in used if u not in base)
for k in missing:
    fail(f"template key missing from en dict: {k}")

print(f"template keys used: {len(used)}")

# ---- 3. every t("...") key used in panel JS exists in en ----
# (comments stripped: doc examples like t("x") must not count)
used_js = set()
for js in ("app.js", "auth.js", "sub.js", "i18n.js"):
    code = (HERE / "static" / js).read_text(encoding="utf-8")
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code = re.sub(r"(^|\n)\s*//[^\n]*", r"\1", code)
    used_js.update(re.findall(r'\bt\("([a-zA-Z0-9_.]+)"[,)]', code))
missing_js = sorted(u for u in used_js if u not in base)
for k in missing_js:
    fail(f"JS key missing from en dict: {k}")
print(f"JS keys used: {len(used_js)}")

# dynamic t("menu."+id) / t("dlayout."+id) / t("event."+code): ids must be covered
#
# menu. and dlayout. are read OUT of app.js, not restated here. The previous
# version carried a hand-copied list, and it had already gone stale: the
# Developer API section is in MENU_IDS in app.js, so the sidebar renders
# t("menu.api") on every panel load, but "api" was missing from the list below
# and nothing noticed. A missing fa/zh/ru translation for a sidebar entry is
# invisible to every other check here, so a hand-kept copy of the id list is
# exactly the wrong place to keep it - the code already knows the answer.
_appjs = (HERE / "static" / "app.js").read_text(encoding="utf-8")
_m = re.search(r"const MENU_IDS = \[(.*?)\]", _appjs, re.S)
if not _m:
    fail("could not read MENU_IDS out of static/app.js")
    _menu_ids = []
else:
    _menu_ids = re.findall(r'"([\w-]+)"', _m.group(1))
_m = re.search(r"const DASH_IDS = \[(.*?)\]", _appjs, re.S)
if not _m:
    fail("could not read DASH_IDS out of static/app.js")
    _dash_ids = []
else:
    _dash_ids = re.findall(r'"([\w-]+)"', _m.group(1))
if not _menu_ids or not _dash_ids:
    fail("reading the id lists out of app.js produced nothing - the check "
         "below would pass vacuously")
print(f"menu sections read from app.js: {len(_menu_ids)}  dashboard cards: {len(_dash_ids)}")

for prefix, ids in (
    ("menu.", _menu_ids),
    ("dlayout.", _dash_ids),
    ("event.", ["LOGIN_OK", "LOGIN_FAIL", "RATE_LIMIT", "USER_CREATE", "USER_PATCH", "USER_DELETE",
                "USER_RESET", "TOKEN_RESET", "USAGE_RESET", "PW_CHANGE", "SETTINGS_UPDATE", "BACKUP_DL",
                "RESTORE", "RESTORE_FAIL", "REALITY_GENERATE", "REALITY_REVEAL", "TEMPLATE_SAVE",
                "TEMPLATE_DELETE", "USER_START", "TUNNEL_SETTINGS", "NODE_CREATE", "NODE_DELETE",
                "NODE_CHECK", "NODE_TOKEN_REVEAL", "NODE_TOKEN_REGEN", "NODE_GUIDE_DL", "INBOUND_CREATE",
                "INBOUND_PATCH", "INBOUND_DELETE", "TG_SAVE", "TG_TEST", "SSL_ISSUE", "SSL_RENEW",
                "AI_CREATE", "AI_PATCH"]),
):
    for i in ids:
        if prefix + i not in base:
            fail(f"dynamic key missing: {prefix}{i}")

# ---- 4. backend sub-dashboard words match the JS dict ----
main = (HERE / "main.py").read_text(encoding="utf-8")
en_words = set(re.findall(r'"(pending|first_use|no_expiry|expired|limited|active|days_left|never|just_now|min_ago|h_ago|d_ago|last_active)"\s*:', main))
for w in ("pending", "first_use", "no_expiry", "expired", "limited", "active",
          "days_left", "never", "just_now", "min_ago", "h_ago", "d_ago", "last_active"):
    if w not in en_words:
        fail(f"backend word key missing: {w}")

# ---- 5. docs: chrome + content keys in docs dicts, all locales ----
_dsrc = (HERE / "docs" / "assets" / "i18n.js").read_text(encoding="utf-8")
_dlocales = {}
for m in re.finditer(r"Object\.assign\(Z_STRINGS\.(\w+), \{(.*?)\}\);", _dsrc, re.S):
    loc, body = m.group(1), m.group(2)
    _dlocales.setdefault(loc, set()).update(re.findall(r'"([a-zA-Z0-9_.]+)":', body))
_dbase = _dlocales.get("en", set())
if len(_dbase) < 50:
    fail(f"suspiciously few docs en keys: {len(_dbase)}")
for loc in ("fa", "zh", "ru"):
    for k in sorted(_dbase - _dlocales.get(loc, set())):
        fail(f"missing docs {loc}.{k}")
    for k in sorted(_dlocales.get(loc, set()) - _dbase):
        fail(f"extra docs {loc}.{k}")
_dused = set()
for f in (HERE / "docs").glob("*.html"):
    html = f.read_text(encoding="utf-8")
    for attr in ("data-i18n", "data-i18n-ph", "data-i18n-title", "data-i18n-aria", "data-i18n-alt"):
        _dused.update(re.findall(attr + r'="([^"]+)"', html))
for k in sorted(_dused - _dbase):
    fail(f"docs template key missing from en dict: {k}")
print(f"docs template keys used: {len(_dused)}")
_djs = set()
for js in ("docs.js", "support-ai.js", "i18n.js"):
    code = (HERE / "docs" / "assets" / js).read_text(encoding="utf-8")
    code_nc = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code_nc = re.sub(r"(^|\n)\s*//[^\n]*", r"\1", code_nc)
    _djs.update(re.findall(r'\bt\("([a-zA-Z0-9_.]+)"[,)]', code_nc))
for k in sorted(_djs - _dbase):
    fail(f"docs JS key missing from en dict: {k}")
print(f"docs JS keys used: {len(_djs)}")
# ---- 6. no value written in the wrong language ----
# A Russian draft pasted into the en block shipped for months: English
# visitors saw "Нравится Zefira?" on the support page. Key-parity checks
# cannot catch that (the key exists, in every locale), so look at the SCRIPT
# each value is written in.
_CYR = re.compile(r"[\u0400-\u04FF\u0500-\u052F]")
_CJK = re.compile(r"[\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF]")
_FA = re.compile(r"[\u0600-\u06FF\uFB50-\uFDFF\uFE70-\uFEFF]")
# A value may quote a word from another script ON PURPOSE (the changelog
# explains that a Persian "سلام" was mis-answered). Listed explicitly.
_SCRIPT_OK = {
    # quotes the Persian greeting as an example, in every locale
    ("en", "chg.v1141f"),
    ("fa", "chg.v1141f"),
    ("zh", "chg.v1141f"),
    ("ru", "chg.v1141f"),
}


def _script_mix(path, blocks_re, label):
    src = path.read_text(encoding="utf-8")
    marks = [(m.start(), m.end(), m.group(1)) for m in blocks_re.finditer(src)]
    for i, (s, _e, loc) in enumerate(marks):
        nxt = marks[i + 1][0] if i + 1 < len(marks) else len(src)
        for km in re.finditer(r'"([a-zA-Z0-9_.]+)"\s*:\s*"((?:[^"\\]|\\.)*)"',
                              src[s:nxt]):
            key, val = km.group(1), km.group(2)
            if (loc, key) in _SCRIPT_OK:
                continue
            bad = []
            if loc in ("en", "fa"):
                if _CYR.search(val):
                    bad.append("Cyrillic")
            if loc in ("en", "fa", "ru"):
                if _CJK.search(val):
                    bad.append("CJK")
            if loc in ("en", "ru", "zh"):
                if _FA.search(val):
                    bad.append("Persian/Arabic")
            for b in bad:
                fail(f"{label} {loc}.{key} contains {b} text (wrong language)")


_script_mix(HERE / "docs" / "assets" / "i18n.js",
            re.compile(r"Object\.assign\(Z_STRINGS\.(\w+), \{"), "docs")
_script_mix(HERE / "static" / "i18n.js",
            re.compile(r"Object\.assign\(Z_STRINGS\.(\w+), \{"), "panel")
print("language-mix scan: done")

# Every check above is a REGEX over the file, so all of them passed on a
# dictionary that did not even parse: a changelog value contained `$("…")`,
# whose unescaped double quotes ended the JS string, and this suite still
# printed ALL OK. Only a real JS parser sees that, and the only place it is run
# is `node --check` in the shell - not in the suite that is supposed to be the
# gate. So gate it here: node if present, otherwise at minimum a structural
# scan of every literal (an unescaped quote inside a value shows up as an
# unterminated literal).
_JS_FILES = [HERE / "docs" / "assets" / "i18n.js", HERE / "static" / "i18n.js"]
try:
    import shutil as _sh
    import subprocess as _sp
    _node = _sh.which("node")
except Exception:
    _node = None

if _node:
    for _f in _JS_FILES:
        try:
            r = _sp.run([_node, "--check", str(_f)], capture_output=True,
                        text=True, encoding="utf-8", errors="replace")
            if r.returncode != 0:
                first = (r.stderr or "").strip().splitlines()
                msg = next((ln for ln in first if "Error" in ln), first[0] if first else "?")
                fail(f"{_f.name} does not parse as JavaScript: {msg.strip()[:120]}")
            else:
                print(f"js parse ok: {_f.name}")
        except Exception as exc:
            fail(f"could not run node --check on {_f.name}: {exc}")
else:
    # No node: fall back to a structural check so a missing interpreter still
    # cannot hide an unterminated literal.
    for _f in _JS_FILES:
        _src = _f.read_text(encoding="utf-8")
        for _m in re.finditer(r'"(?:[^"\\\n]|\\.)*"', _src):
            pass
        # A value that opens a quote and never closes before the newline shows
        # up as a line whose quotes are unbalanced.
        for _i, _ln in enumerate(_src.splitlines(), 1):
            _q = len(re.findall(r'(?<!\\)"', _ln))
            if _q % 2 == 1:
                fail(f"{_f.name}:{_i} has an unbalanced quote (an unescaped one "
                     f"inside a value?) - the file may not parse")
                break
    print("node not found: used the structural quote check")

# ---- 7. an inline fallback and its binding must not disagree about a ratio ----
# docs/security.html carried an inline English fallback for the pentest paragraph
# AND four data-i18n bindings for the same sentence. The fallback said 117/117 and
# the bindings said 119/119, so the page read one number before its own script ran
# and a different one after - and nothing compared the two copies.
#
# Scoped to N/N on purpose: that is the shape that drifts. Comparing whole strings
# flags 61 pairs across the site, almost all of them HTML entities, and a guard
# that fires on false positives trains people to ignore it.
_docs_i18n = (HERE / "docs" / "assets" / "i18n.js").read_text(encoding="utf-8")
_en_cut = _docs_i18n.find('"idx.statPentest"')
if _en_cut < 0:
    fail("docs i18n: cannot locate the English block to compare fallbacks against")
else:
    import html as _html
    _en = {}
    for _m in re.finditer(r'"([\w.]+)"\s*:\s*"((?:[^"\\]|\\.)*)"', _docs_i18n[:_en_cut]):
        _en[_m.group(1)] = _m.group(2)
    _RATIO = re.compile(r"\b\d+\s*/\s*\d+\b")
    _pairs = 0
    for _page in sorted((HERE / "docs").glob("*.html")):
        _text = _page.read_text(encoding="utf-8")
        for _m in re.finditer(r'data-i18n="([\w.]+)"[^>]*>([^<]{1,})<', _text):
            _key = _m.group(1)
            _inline = _html.unescape(_m.group(2))
            _a = _RATIO.findall(_inline)
            if not _a:
                continue
            _pairs += 1
            _b = _RATIO.findall(_html.unescape(_en.get(_key, "")))
            if [_x.replace(" ", "") for _x in _b] != [_x.replace(" ", "") for _x in _a]:
                fail(f"{_page.name} {_key}: the inline fallback says {_a} but the "
                     f"en binding says {_b or 'no ratio at all'}")
    if _pairs < 4:
        fail(f"only {_pairs} inline fallbacks state a pass-ratio; the scan is "
             f"probably not finding them any more")
    print(f"pass-ratio fallbacks compared: {_pairs}")

# ---- 7. the changelog's lead and body must not share one key ----
# The renderer does one thing per element:
#     q("[data-i18n]").forEach((el) => { el.innerHTML = zRenderI18n(t(...)) })
# so an element's text is whatever its OWN key says. Forty-four bullets
# wrote the lead and the body with the SAME key, so the body element was
# overwritten with the lead and the whole explanation vanished from the page
# - for the last eleven releases. The key existed in every locale, so every
# other check here passed straight over it: a key that is present and
# translated is still the wrong key.
_chg = (HERE / "docs" / "changelog.html").read_text(encoding="utf-8")
_same = []
for _m in re.finditer(r"<li>(.*?)</li>", _chg, re.S):
    _keys = re.findall(r'data-i18n="([^"]+)"', _m.group(1))
    if len(_keys) >= 2 and len(set(_keys)) == 1:
        _same.append(_keys[0])
for _k in sorted(set(_same)):
    fail(f"changelog bullet: the lead and the body share the key {_k}, so "
         f"the body is overwritten by the lead")
print(f"changelog bullets sharing one key: {len(_same)}")

print("i18n checks:", "ALL OK" if not fails else f"{len(fails)} FAILURES")
sys.exit(1 if fails else 0)
