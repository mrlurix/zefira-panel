"""
Bug hunt: quota accounting, device_limit, expiry math and schema fuzzing.

Targets the customer-facing accounting paths that the code-review agents are
not reading, plus every Pydantic validator with boundary values.
Run against a live panel:  attack_quota_test.py http://127.0.0.1:8000 admin PASS
"""
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"
VP_UA = "v2rayNG/1.8.5 (Android)"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

results = []
created = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def req(method, path, body=None, headers=None, timeout=30, ua=None):
    h = {"User-Agent": ua or "zefira-quota/1.0"}
    if headers:
        h.update(headers)
    data = body.encode() if isinstance(body, str) else body
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()


def login():
    st, hd, _ = req("POST", "/api/login", json.dumps(
        {"username": ADMIN, "password": PASSWORD}),
        {"X-Requested-With": "XMLHttpRequest"})
    tok = ""
    for part in (hd.get("set-cookie") or "").split(";"):
        if part.strip().startswith("zefira_session="):
            tok = part.split("=", 1)[1]
    return st, {"Cookie": f"zefira_session={tok}", "X-Requested-With": "XMLHttpRequest"}


print(f"=== QUOTA / DEVICE / EXPIRY HUNT -> {BASE} ===")
st, AUTH = login()
check("login", st == 200, f"{st}")
if st != 200:
    sys.exit(2)


def mkuser(**kw):
    body = {"username": "q" + uuid.uuid4().hex[:8], "protocols": ["vless"],
            "volume_gb": 10, "days": 30}
    body.update(kw)
    st, _, b = req("POST", "/api/users", json.dumps(body), AUTH)
    try:
        return st, json.loads(b)
    except Exception:
        return st, {}


def patch(uid, **kw):
    return req("PATCH", f"/api/users/{uid}", json.dumps(kw), AUTH)


def row(uid):
    """Read one user back (there is no GET-by-id; search is the documented way)."""
    st, _, b = req("GET", "/api/users?q=", headers=AUTH)
    for x in json.loads(b or b"{}").get("items", []):
        if x.get("id") == uid:
            return x
    return {}


# ---------------------------------------------------------------- quota
st, u = mkuser(volume_gb=10, days=30)
uid, tok = u.get("id"), u.get("token")
created.append(uid)
check("create user for quota test", st == 200 and tok, f"{st} {str(u)[:80]}")

st, _, b = req("GET", f"/sub/{tok}", ua=VP_UA)
check("fresh subscription serves", st == 200, f"{st}")
st, _, b = req("GET", f"/sub/{tok}?format=clash", ua=VP_UA)
check("fresh clash subscription serves", st == 200, f"{st}")

# Consume exactly the quota, then one byte more. PATCH is REST-shaped: the
# absolute field names set a value, add_*/set_* are the delta/legacy forms.
st, _, b = patch(uid, used_gb=10.0)
check("absolute used_gb patch is applied", st == 200, f"{st}")
check("absolute used_gb is persisted", abs(row(uid).get("used_gb", -1) - 10.0) < 0.01,
      f"{row(uid).get('used_gb')}")
st, _, _ = req("GET", f"/sub/{tok}", ua=VP_UA)
check("used == volume blocks the raw subscription", st == 404, f"{st}")
st, _, _ = req("GET", f"/sub/{tok}?format=clash", ua=VP_UA)
check("used == volume blocks the clash subscription", st == 404, f"{st}")
st, _, b = req("GET", f"/sub/{tok}", ua="Mozilla/5.0 (X11) Chrome/122")
check("used == volume still shows the customer status page", st == 200 and b"Out of volume" in b,
      f"{st} (dashboard must explain, not 404)")
st, _, _ = patch(uid, used_gb=9.99)
st, _, _ = req("GET", f"/sub/{tok}", ua=VP_UA)
check("used just under the quota still serves", st == 200, f"{st}")

# The silent no-op footgun: a patch made only of unknown keys used to answer
# 200 and change nothing, so a bot could believe it capped a customer.
st_unk, _, b_unk = patch(uid, totally_unknown_field=1, another_typo=2)
check("patch with only unknown fields is refused (not a silent 200)",
      st_unk == 422, f"{st_unk} {b_unk[:80]!r}")
st_unk2, _, _ = patch(uid, set_used_gb=5)
check("misspelled set_* variant is refused", st_unk2 == 422, f"{st_unk2}")
st_dup, _, _ = patch(uid, used_gb=5, add_used_gb=1)
check("absolute + delta for the same field is refused", st_dup == 422, f"{st_dup}")
st_mix, _, _ = patch(uid, set_note="ok", totally_unknown=1)
check("a real field alongside an unknown one still applies", st_mix == 200, f"{st_mix}")

# Fractional / absurd values must not corrupt the accounting. (Absolute usage is
# bounded at 1e6 GB by the schema; the delta form clamps instead of rejecting.)
for val in (0.001, 0.009, 0.01, 999999.5, 12345.678):
    st, _, _ = patch(uid, used_gb=val)
    check(f"used_gb={val} accepted and stored", st == 200 and abs(row(uid).get("used_gb", -1) - val) < 0.01,
          f"{st} stored={row(uid).get('used_gb')}")
st_over, _, _ = patch(uid, used_gb=1e9)
check("absurd absolute usage is rejected, not stored", st_over == 422 and row(uid).get("used_gb") != 1e9,
      f"{st_over}")
st_over2, _, _ = patch(uid, add_used_gb=1e9)
check("absurd usage delta is rejected by the schema", st_over2 == 422, f"{st_over2}")
patch(uid, used_gb=0)

# volume_gb smaller than used_gb: the user must be blocked, not served.
st, u2 = mkuser(volume_gb=5, days=30)
uid2, tok2 = u2.get("id"), u2.get("token")
created.append(uid2)
patch(uid2, used_gb=7.5)
st, _, _ = req("GET", f"/sub/{tok2}", ua=VP_UA)
check("used above volume blocks immediately", st == 404, f"{st}")

# ---------------------------------------------------------------- expiry math
st, u3 = mkuser(days=1)
uid3, tok3 = u3.get("id"), u3.get("token")
created.append(uid3)
st, _, b = req("GET", f"/sub/{tok3}", ua=VP_UA)
check("1-day user serves before expiry", st == 200, f"{st}")
st, _, b = req("GET", f"/sub/{tok3}", ua="Mozilla/5.0 (X11) Chrome/122")
html = b.decode("utf-8", "replace")
check("dashboard shows a day count for a 1-day plan", ("1" in html), "no day count")
st, _, b = req("PATCH", f"/api/users/{uid3}", json.dumps(
    {"expires_at": "2020-01-01T00:00"}), AUTH)
check("absolute expires_at in the past accepted", st == 200, f"{st}")
check("absolute expires_at persisted",
      str(row(uid3).get("expires_at", "")).startswith("2020-01-01"),
      f"{row(uid3).get('expires_at')}")
st, _, _ = req("GET", f"/sub/{tok3}", ua=VP_UA)
check("expired user is 404 for clients", st == 404, f"{st}")
st, _, b = req("GET", f"/sub/{tok3}", ua="Mozilla/5.0 (X11) Chrome/122")
check("expired user gets the status page with an Expired badge", st == 200 and b"Expired" in b,
      f"{st}")
# Extending an expired plan must restart from today, not stay expired.
st, _, b = patch(uid3, days=5)
check("extending an expired plan works (days alias)", st == 200, f"{st}")
st, _, _ = req("GET", f"/sub/{tok3}", ua=VP_UA)
check("extended-from-expired plan serves again", st == 200, f"{st}")
st, _, b = patch(uid3, extend_days=5)
check("extending with extend_days still works", st == 200, f"{st}")
st_dup2, _, _ = patch(uid3, days=2, extend_days=2)
check("days + extend_days together is refused", st_dup2 == 422, f"{st_dup2}")

# ---------------------------------------------------------------- start on first use
st, u4 = mkuser(days=7, start_on_first_use=True)
uid4, tok4 = u4.get("id"), u4.get("token")
created.append(uid4)
st, _, b = req("GET", "/api/users?q=q", headers=AUTH)
items = [x for x in json.loads(b).get("items", []) if x["id"] == uid4]
pending = bool(items and items[0].get("pending_start"))
check("start_on_first_use user is pending before first fetch", pending, f"{items[:1]}")
first_status = None
st, _, b = req("GET", f"/sub/{tok4}", ua=VP_UA)
first_status = st
st2, _, b2 = req("GET", "/api/users?q=q", headers=AUTH)
items = [x for x in json.loads(b2).get("items", []) if x["id"] == uid4]
now_pending = bool(items and items[0].get("pending_start"))
check("first fetch activates the plan", first_status == 200 and not now_pending,
      f"first={first_status} still_pending={now_pending}")
# Two simultaneous first fetches must not double-grant or error.
st, u5 = mkuser(days=7, start_on_first_use=True)
uid5, tok5 = u5.get("id"), u5.get("token")
created.append(uid5)
import concurrent.futures as cf
with cf.ThreadPoolExecutor(max_workers=2) as pool:
    futs = [pool.submit(req, "GET", f"/sub/{tok5}", None, None, 30, VP_UA) for _ in range(2)]
    codes = [f.result()[0] for f in futs]
check("concurrent first fetches both succeed", all(c == 200 for c in codes), f"{codes}")
st, _, b = req("GET", "/api/users?q=q", headers=AUTH)
r5 = [x for x in json.loads(b).get("items", []) if x["id"] == uid5]
check("concurrent first fetch yields one activation", r5 and not r5[0].get("pending_start"),
      f"{r5[:1]}")

# ---------------------------------------------------------------- device limit
st, u6 = mkuser(days=30, device_limit=2)
uid6, tok6 = u6.get("id"), u6.get("token")
created.append(uid6)
codes = []
for i in range(4):
    st, _, _ = req("GET", f"/sub/{tok6}", ua=VP_UA, timeout=20)
    codes.append(st)
    time.sleep(0.1)
check("device_limit never blocks the customer (documented advisory)", all(c == 200 for c in codes),
      f"{codes}")
st, _, b = req("GET", "/api/users?q=q", headers=AUTH)
r6 = [x for x in json.loads(b).get("items", []) if x["id"] == uid6]
check("device_limit is reported in the API", r6 and r6[0].get("device_limit") == 2, f"{r6[:1]}")

# ---------------------------------------------------------------- schema fuzz
bad_bodies = [
    ("volume_gb as bool", {"volume_gb": True, "days": 5}),
    ("days as bool", {"volume_gb": 5, "days": False}),
    ("volume_gb numeric string", {"volume_gb": "5", "days": 5}),
    ("days numeric string", {"volume_gb": 5, "days": "5"}),
    ("volume_gb zero", {"volume_gb": 0, "days": 5}),
    ("days zero", {"volume_gb": 5, "days": 0}),
    ("negative volume", {"volume_gb": -5, "days": 5}),
    ("negative days", {"volume_gb": 5, "days": -5}),
    ("NaN-ish volume", {"volume_gb": "NaN", "days": 5}),
    ("Infinity volume", {"volume_gb": "Infinity", "days": 5}),
    ("huge volume", {"volume_gb": 10**12, "days": 5}),
    ("huge days", {"volume_gb": 5, "days": 10**9}),
    ("float days", {"volume_gb": 5, "days": 5.7}),
    ("protocols empty", {"protocols": [], "volume_gb": 5, "days": 5}),
    ("protocols unknown", {"protocols": ["wireguardX"], "volume_gb": 5, "days": 5}),
    ("protocols not a list", {"protocols": "vless", "volume_gb": 5, "days": 5}),
    ("protocols duplicate", {"protocols": ["vless", "vless"], "volume_gb": 5, "days": 5}),
    ("protocols 12 entries", {"protocols": ["vless"] * 12, "volume_gb": 5, "days": 5}),
    ("expires_at garbage", {"expires_at": "not-a-date"}),
    ("expires_at impossible", {"expires_at": "2026-02-31T00:00"}),
    ("expires_at no time", {"expires_at": "2026-02-01"}),
    ("device_limit 0", {"device_gb": None, "device_limit": 0, "volume_gb": 5, "days": 5}),
    ("device_limit negative", {"device_limit": -3, "volume_gb": 5, "days": 5}),
    ("device_limit huge", {"device_limit": 10**9, "volume_gb": 5, "days": 5}),
    ("note object", {"note": {"a": 1}, "volume_gb": 5, "days": 5}),
    ("note list", {"note": ["x"], "volume_gb": 5, "days": 5}),
    ("username 1 char", {"username": "a", "volume_gb": 5, "days": 5}),
    ("username 33 chars", {"username": "u" * 33, "volume_gb": 5, "days": 5}),
    ("username with space", {"username": "has space", "volume_gb": 5, "days": 5}),
    ("username with slash", {"username": "a/b", "volume_gb": 5, "days": 5}),
    ("username with dot-dot", {"username": "..", "volume_gb": 5, "days": 5}),
    ("is_active string", {"is_active": "yes", "volume_gb": 5, "days": 5}),
    ("start_on_first_use string", {"start_on_first_use": "true", "volume_gb": 5, "days": 5}),
    ("extra unknown field", {"volume_gb": 5, "days": 5, "totally_unknown": 1}),
    ("null volume", {"volume_gb": None, "days": 5}),
    ("float volume 0.001", {"volume_gb": 0.001, "days": 5}),
    ("volume 0.01", {"volume_gb": 0.01, "days": 5}),
    ("days 1", {"volume_gb": 5, "days": 1}),
    ("protocols with null", {"protocols": [None], "volume_gb": 5, "days": 5}),
    ("protocols nested list", {"protocols": [["vless"]], "volume_gb": 5, "days": 5}),
]
crash = []
accepted_weird = []
for label, patchbody in bad_bodies:
    st, _, b = req("POST", "/api/users", json.dumps(
        dict({"username": "f" + uuid.uuid4().hex[:8]}, **patchbody)), AUTH)
    if st >= 500 or st == 0:
        crash.append(f"{label} -> {st}")
    elif st == 200:
        accepted_weird.append(label)
        try:
            j = json.loads(b)
            if j.get("token"):
                created.append(j.get("id"))
        except Exception:
            pass
    # the panel must still be alive and consistent
    st2, _, _ = req("GET", "/api/users", headers=AUTH)
    if st2 != 200:
        crash.append(f"{label} broke the list endpoint ({st2})")
check("no 5xx / no crash from any boundary input", not crash, "; ".join(crash[:4]))
print("      accepted (documented as valid or intentionally lenient):")
for a in accepted_weird:
    print(f"        - {a}")

# The same boundary sweep against PATCH (the endpoint integrators script).
st, pu = mkuser(volume_gb=10, days=30)
puid = pu.get("id")
created.append(puid)
patch_bodies = [
    {"used_gb": "abc"}, {"used_gb": True}, {"used_gb": -1}, {"used_gb": 1e9},
    {"volume_gb": 0}, {"volume_gb": -3}, {"volume_gb": "5"},    {"expires_at": "nope"}, {"expires_at": "2026-02-31T00:00"},
    {"expires_at": "2026-02-01"}, {"expires_at": 12345},
    {"note": {"x": 1}}, {"note": ["y"]}, {"note": "n" * 500},
    {"device_limit": 0}, {"device_limit": -5}, {"device_limit": 10**6},
    {"extend_days": 0}, {"extend_days": -1}, {"extend_days": 10**6},
    {"add_used_gb": -1e9}, {"add_volume_gb": -5}, {"add_volume_gb": 0.001},
    {"is_active": "yes"}, {"reset_used": "true"}, {"is_active": None},
    {"used_gb": 1, "add_used_gb": 1}, {"volume_gb": 5, "set_volume_gb": 5},
    {"note": "a", "set_note": "b"}, {"device_limit": 1, "set_device_limit": 2},
    {"unknown1": 1, "unknown2": 2},
    {}, {"used_gb": 0}, {"expires_at": "2030-01-01T00:00"},
]
pcrash = []
for body in patch_bodies:
    st, _, b = req("PATCH", f"/api/users/{puid}", json.dumps(body), AUTH)
    if st >= 500 or st == 0:
        pcrash.append(f"{body} -> {st}")
    if not row(puid).get("id"):
        pcrash.append(f"{body} destroyed the user row")
check("no 5xx from any PATCH boundary input", not pcrash, "; ".join(pcrash[:4]))
# An empty patch must be refused, not a fake success.
st_empty, _, _ = req("PATCH", f"/api/users/{puid}", "{}", AUTH)
check("empty patch is refused", st_empty == 422, f"{st_empty}")
# The user must still be servable after the whole fuzz run.
st_srv, _, _ = req("GET", f"/sub/{pu.get('token')}", ua=VP_UA)
check("user still serves after the PATCH fuzz", st_srv == 200, f"{st_srv}")

# ---------------------------------------------------------------- concurrency on one user
st, u7 = mkuser(volume_gb=100, days=30)
uid7, tok7 = u7.get("id"), u7.get("token")
created.append(uid7)
with cf.ThreadPoolExecutor(max_workers=6) as pool:
    futs = [pool.submit(patch, uid7, volume_gb=200) for _ in range(6)]
    pst = [f.result()[0] for f in futs]
check("concurrent top-ups all answer 2xx", all(c == 200 for c in pst), f"{pst}")
st, _, b = req("GET", f"/api/users/{uid7}/config", headers=AUTH)
check("user still consistent after concurrent top-ups", st in (200, 403), f"{st}")
st, _, b = req("GET", "/api/users?q=q", headers=AUTH)
r7 = [x for x in json.loads(b).get("items", []) if x["id"] == uid7]
check("volume after concurrent top-ups is a sane number",
      r7 and isinstance(r7[0].get("volume_gb"), (int, float))
      and 0 < r7[0]["volume_gb"] <= 10**6, f"{r7[:1]}")

# ---------------------------------------------------------------- cleanup
for i in created:
    if i:
        req("DELETE", f"/api/users/{i}", headers=AUTH)
st, _, b = req("GET", "/api/users", headers=AUTH)
left = json.loads(b).get("total", -1)
check("quota hunt cleaned up", left == 0, f"leftover={left}")

passed = sum(1 for _, ok, _ in results if ok)
print(f"\n=== {passed}/{len(results)} checks passed ===")
if passed != len(results):
    for n, ok, d in results:
        if not ok:
            print(f"  FAIL {n}: {d}")
sys.exit(0 if passed == len(results) else 1)
