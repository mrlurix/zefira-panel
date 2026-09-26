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
for prefix, ids in (
    ("menu.", ["dashboard", "users", "inbounds", "tunnels", "nodes", "reality", "blocker", "update", "customize", "settings"]),
    ("dlayout.", ["usage", "link", "groups", "apps"]),
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

print("i18n checks:", "ALL OK" if not fails else f"{len(fails)} FAILURES")
sys.exit(1 if fails else 0)
