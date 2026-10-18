"""The API reference's response examples must match what the panel returns.

The reference has always listed every route, every method badge and every error
code, and never showed what actually comes back. That was the one part a third
party - a Telegram bot author - genuinely needed and did not have.

Writing the examples by hand would have made things worse rather than better,
because a response shape that is subtly wrong is worse than no shape: a
developer codes against it and finds out in production. So every example on the
page was generated from a capture of a running panel, and this suite is what
keeps that honest. It starts its own panel, calls the same routes, and compares
the live key sets and value types against the JSON the page publishes.

The comparison is on KEYS AND TYPES, not on values. Values are environment
specific by definition; a key that appears or disappears, or a field that
changes from integer to float, is a real breaking change for anyone coding
against the page.

This caught three things a plausible-looking hand-written example would almost
certainly have got wrong, all of them measured rather than assumed:

    volume_gb   is a float, not an integer
    used_gb     is an integer, not a float
    scopes      is a single string, not an array

And one that is not a type at all: GET /api/users/{id}/config does not answer
JSON. It answers text/plain with the subscription document - one connection URI
per line. A bot author who expected an object there would fail on the single
most-requested call a reseller bot makes.
"""

import html
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = 8198
BASE = "http://127.0.0.1:%d" % PORT
DOC = os.path.join(ROOT, "docs", "api.html")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:190])
                         if (detail and not cond) else ""))



def jtype(v):
    if isinstance(v, bool):
        return "bool"
    if v is None:
        return "null"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def typemap(obj):
    return {k: jtype(v) for k, v in obj.items()}


# ------------------------------------------------------------------ the page
doc = io.open(DOC, encoding="utf-8", errors="replace").read()

# <pre data-resp-route="POST /api/users"><code>{...}</code></pre>
EXAMPLES = {}
for m in re.finditer(
        r'<pre data-resp-route="([^"]+)"><code>(.*?)</code></pre>',
        doc, re.S):
    EXAMPLES[m.group(1)] = m.group(2)

check("the reference publishes response examples", len(EXAMPLES) >= 6,
      "found %d, wanted at least 6" % len(EXAMPLES))

EXPECTED = {"POST /api/users", "GET /api/users", "POST /api/api-tokens",
            "GET /api/users/{id}/config", "POST /api/users/{id}/reset-usage",
            "DELETE /api/users/{id}",
            "POST /api/users (duplicate name)"}
check("and it covers every route a bot author needs",
      EXPECTED <= set(EXAMPLES),
      "missing: %s" % sorted(EXPECTED - set(EXAMPLES)))

# The config route is deliberately NOT json, so it must not go through the
# JSON parser at all. Feeding it to json.loads produced a real failure on
# the first run of this suite - the guard was wrong, not the page - and
# that is worth recording because the naive version of this check is
# 'parse every example', which fails precisely on the route that most
# needs documenting.
NOT_JSON = {'GET /api/users/{id}/config'}
DOCUMENTED = {}
for route, body in EXAMPLES.items():
    if route in NOT_JSON:
        continue
    try:
        DOCUMENTED[route] = json.loads(html.unescape(body))
    except Exception as exc:
        DOCUMENTED[route] = None
        check("the %s example is valid JSON" % route, False, str(exc))
check("every example not in the not-json set parses as JSON",
      set(EXAMPLES) - set(DOCUMENTED) == NOT_JSON,
      "unparsed: %s" % sorted(set(EXAMPLES) - set(DOCUMENTED)))

# ------------------------------------------------------------- the live API
proc = subprocess.Popen(
    [os.path.join(ROOT, ".venv", "Scripts", "python.exe"), "-m", "uvicorn",
     "main:app", "--host", "127.0.0.1", "--port", str(PORT),
     "--no-server-header", "--no-proxy-headers"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
live = {}
POLY = {}
try:
    for _ in range(280):
        time.sleep(0.25)
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2).read()
            break
        except Exception:
            continue

    import http.cookiejar
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    CSRF = {"X-Requested-With": "XMLHttpRequest"}
    CH = dict(CSRF)

    def call(method, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        h = dict(headers or {})
        if data is not None:
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(BASE + path, data=data, headers=h,
                                     method=method)
        try:
            with opener.open(req, timeout=45) as r:
                blob = r.read()
                ct = (r.headers.get("Content-Type") or "").split(";")[0]
        except urllib.error.HTTPError as e:
            blob = e.read()
            ct = (e.headers.get("Content-Type") or "").split(";")[0]
            r = e
        if not blob:
            return getattr(r, "status", getattr(r, "code", 0)), None, ct
        try:
            return r.status, json.loads(blob), ct
        except Exception:
            return r.status, blob.decode("utf-8", "replace"), ct

    cred = io.open(os.path.join(ROOT, "instance", "first-run-credentials.txt"),
                   encoding="utf-8", errors="replace").read()
    U = re.search(r"(?im)^\s*(?:username|user|admin)\s*[:=]\s*(\S+)",
                  cred).group(1)
    PW = re.search(r"(?im)^\s*(?:password|pass)\s*[:=]\s*(\S+)", cred).group(1)
    call("POST", "/api/login", {"username": U, "password": PW}, CSRF)
    for h in opener.handlers:
        if hasattr(h, "cookiejar") and h.cookiejar:
            for k in h.cookiejar:
                if k.name == "zefira_session":
                    CH["Cookie"] = "zefira_session=" + k.value

    nm = "shapecheck-%d" % os.getpid()
    _s, existing, _c = call("GET", "/api/api-tokens", headers=CH)
    for r in (existing or []):
        if isinstance(r, dict) and str(r.get("name", "")).startswith(
                "shapecheck"):
            call("DELETE", "/api/api-tokens/%d" % r["id"], headers=CH)
    _s, tok, _c = call("POST", "/api/api-tokens",
                       {"name": nm, "scopes": "full", "password_confirm": PW},
                       CH)
    token = (tok or {}).get("token_once")
    live["POST /api/api-tokens"] = tok
    A = {"Authorization": "Bearer " + (token or ""), **CSRF}

    uname = "shapecheck_%d" % os.getpid()
    _s, created, _c = call("POST", "/api/users",
                           {"username": uname, "protocols": ["vless"],
                            "volume_gb": 5, "days": 30}, A)
    uid = (created or {}).get("id")
    live["POST /api/users"] = created
    live["POST /api/users/{id}/reset-usage"] = call(
        "POST", "/api/users/%d/reset-usage" % uid, None, A)[1]
    live["GET /api/users"] = call("GET", "/api/users?limit=3", headers=A)[1]
    live["POST /api/users (duplicate name)"] = call(
        "POST", "/api/users",
        {"username": uname, "protocols": ["vless"], "volume_gb": 5,
         "days": 30}, A)[1]
    live["GET /api/users/{id}/config"] = call(
        "GET", "/api/users/%d/config" % uid, headers=A)

    # used_gb is polymorphic, so it has to be probed rather than compared.
    # These three calls run HERE, inside the panel's lifetime: an earlier
    # version put them after the finally block that shuts the panel down, and
    # every one of them failed with a connection reset - which is what a
    # guard does when it is measuring something that no longer exists.
    _p1 = call("PATCH", "/api/users/%d" % uid, {"used_gb": 12.5}, A)[1] or {}
    _p2 = call("PATCH", "/api/users/%d" % uid, {"used_gb": 12.75}, A)[1] or {}
    _st_neg, _neg, _ct_neg = call("PATCH", "/api/users/%d" % uid,
                                  {"used_gb": -1.5}, A)
    POLY = {"first": _p1.get("used_gb"), "second": _p2.get("used_gb"),
            "neg_status": _st_neg, "neg_body": _neg,
            "fresh": (live.get("POST /api/users") or {}).get("used_gb")}
    call("PATCH", "/api/users/%d" % uid, {"used_gb": 0}, A)
    live["DELETE /api/users/{id}"] = call("DELETE", "/api/users/%d" % uid,
                                          headers=A)[1]
    call("DELETE", "/api/api-tokens/%s" % nm, headers=CH)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=25)
    except Exception:
        proc.kill()


def same_keys(name, documented, real):
    if documented is None or real is None:
        check(name, False, "one side is missing (doc=%s live=%s)"
              % (documented is None, real is None))
        return
    dk, rk = sorted(documented), sorted(real)
    check(name, dk == rk,
          "documented %s, live %s; only-doc %s only-live %s"
          % (dk, rk, sorted(set(dk) - set(rk)), sorted(set(rk) - set(dk))))


for route in sorted(EXPECTED & set(EXAMPLES) - NOT_JSON):
    same_keys("the %s example lists the live keys" % route,
              DOCUMENTED.get(route), live.get(route))

# envelope vs its first item, because the list example nests a user object
doc_env = DOCUMENTED.get("GET /api/users") or {}
live_env = live.get("GET /api/users") or {}
di = (doc_env.get("items") or [{}])[0]
li = (live_env.get("items") or [{}])[0]
same_keys("the GET /api/users example's envelope matches",
          {k: v for k, v in doc_env.items() if k != "items"},
          {k: v for k, v in live_env.items() if k != "items"})
same_keys("...and its nested item matches the live user object", di, li)

# and now the TYPES, which is where a hand-written example would have drifted
# EVERY published JSON example, not a hand-picked subset. The list was
# short by reset-usage, and the mutation that changed its used_gb from 12
# to "12" passed with rc=0 because key names were identical and the
# route was never in this loop at all. Deriving the list from the page
# means a newly documented route cannot be silently left unchecked.
for route in sorted(set(DOCUMENTED) - NOT_JSON):
    d, r = DOCUMENTED.get(route), live.get(route)
    if d is None or r is None:
        check("the %s example's types are checkable" % route, False,
              "documented=%s live=%s"
              % (d is not None, route in live))
        continue
    dt, rt = typemap(d), typemap(r)
    # used_gb IS compared here, against the freshly created user whose
    # usage is 0 - an integer, which is what the published example shows.
    # An earlier version excluded it, reasoning that a polymorphic field
    # cannot be compared; the consequence was that changing used_gb to a
    # string in the example passed with rc=0. The polymorphism does not
    # need an exemption, it needs its own measurement - which is the four
    # probes below.
    wrong = {k: (dt.get(k), rt.get(k)) for k in rt
             if dt.get(k) != rt.get(k)}
    check("the %s example's value types match the live ones" % route,
          not wrong, "doc/live differ: %s" % wrong)

# ---- the measured facts, named so they cannot be quietly regressed
_doc_user = DOCUMENTED.get("POST /api/users") or {}
_live_user = live.get("POST /api/users") or {}
check("volume_gb is documented as the float it is",
      jtype(_doc_user.get("volume_gb"))
      == jtype(_live_user.get("volume_gb")) == "float",
      "doc=%s live=%s" % (jtype(_doc_user.get("volume_gb")),
                          jtype(_live_user.get("volume_gb"))))
check("a token's scopes is documented as the single string it is",
      jtype((DOCUMENTED.get("POST /api/api-tokens") or {}).get("scopes"))
      == jtype((live.get("POST /api/api-tokens") or {}).get("scopes"))
      == "str")

# ---- used_gb is polymorphic, so measure it rather than compare it
_frac, _frac2 = POLY["first"], POLY["second"]
check("a fractional used_gb really comes back as a float",
      jtype(_frac) == "float" and _frac == 12.5,
      "got %r (%s)" % (_frac, jtype(_frac)))
check("...and is not truncated to an integer",
      _frac != 12 and _frac2 == 12.75,
      "12.5 came back %r and 12.75 came back %r" % (_frac, _frac2))
check("...and the integer case is still an integer",
      jtype(POLY["fresh"]) == "int",
      "a fresh user reported %r" % POLY["fresh"])
check("a negative used_gb is refused rather than clamped",
      POLY["neg_status"] == 422,
      "status %s, body %r" % (POLY["neg_status"], POLY["neg_body"]))

_note_html = html.unescape(re.search(
    r'<span data-i18n="api.respUser">(.*?)</span>', doc, re.S).group(1))
check("...and the page says so in all four locales",
      all(tok in _note_html for tok in ("float the moment",))
      or all(tok in _note_html for tok in ("never",)),
      "the note no longer states the float case")

# ---- the config route, which is not JSON and this is the whole point -------
cfg = live.get("GET /api/users/{id}/config")
cfg_body, cfg_ct = (cfg[1], cfg[2]) if isinstance(cfg, tuple) else (None, "")
check("GET /api/users/{id}/config really is not JSON",
      isinstance(cfg_body, str), "type %s" % type(cfg_body).__name__)
check("...and its content type is plain text",
      cfg_ct == "text/plain", "got %r" % cfg_ct)
first = [l for l in (cfg_body or "").split("\n") if l.strip()]
check("...and the body is connection URIs, one per line",
      bool(first) and all(l.startswith(("vless://", "vmess://", "trojan://",
                                       "ss://", "reality://"))
                          for l in first),
      "first line: %r" % (first[0][:60] if first else None))
doc_cfg = (EXAMPLES.get("GET /api/users/{id}/config") or "").strip()
check("the published config example also starts with a connection URI",
      doc_cfg.startswith(("vless://", "vmess://", "trojan://", "ss://",
                          "reality://")),
      "got %r" % doc_cfg[:60])
check("and the page says in prose that this one is not JSON",
      "not</strong> JSON" in doc or "JSON نیست" in doc
      or "不是</strong> JSON" in doc or "не</strong> JSON" in doc,
      "the note no longer says so in any locale")

n = sum(1 for _k, v in ok if v)
print()
print("  compared %d published examples against a live panel" % len(EXAMPLES))
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)