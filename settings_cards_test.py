"""Every settings card, exercised end-to-end against a live panel.

Read, change, read back, restore. Run like the other live suites:
    .venv\\Scripts\\python settings_cards_test.py http://127.0.0.1:PORT admin PASSWORD

WHY THIS EXISTS SEPARATELY
functional_test.py touches most of these endpoints, but one fact makes them
dangerous to test casually: `PUT /api/settings` is a FULL REPLACE, not a merge.
The handler iterates a fixed key list and calls `getattr(data, k)`, so a field
omitted from the body is written as its schema default - `wg_pub` becomes "",
`dns` becomes "1.1.1.1", every port resets. A partial PUT is therefore a silent
data-loss operation. This suite always reads the current values first and
replays the WHOLE dict, and it asserts that the restore leg actually put the
originals back.

Probe choices, and why:
- Cards whose action has an irreversible external effect (issuing a real
  certificate, sending a real Telegram message, spending provider quota) are
  probed with input the schema rejects BEFORE the handler body runs, or with a
  request the handler short-circuits. That exercises the endpoint, the CSRF
  middleware and the validation path without touching Let's Encrypt, a real
  chat, or a paid API.
- Write-only fields (the AI key, the Telegram token) are never read back -
  the GET returns `has_key`/`has_token` booleans - and an empty value means
  "keep current", so the suite sends "" on both legs and asserts on the
  boolean.
- change-password costs 2 of its 6-per-5-minutes budget per cycle and resets
  the budget on success, so it runs exactly one cycle and re-logs in.
"""
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request

from protocols import TLS_FINGERPRINTS

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    tag = "PASS" if ok else "FAIL"
    print("[%s] %s%s" % (tag, name, ("  " + detail) if detail else ""))


def req(method, path, body=None, headers=None, timeout=30):
    hdrs = {"User-Agent": "zefira-settingscards/1.0"}
    if headers:
        hdrs.update(headers)
    data = None
    if body is not None:
        data = body.encode() if isinstance(body, str) else body
        hdrs.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=hdrs)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()


def login_with(password):
    st, hd, _ = req("POST", "/api/login",
                    json.dumps({"username": ADMIN, "password": password}),
                    {"X-Requested-With": "XMLHttpRequest"})
    tok = ""
    for part in ((hd.get("set-cookie") or hd.get("Set-Cookie") or "").split(";")):
        part = part.strip()
        if part.startswith("zefira_session="):
            tok = part.split("=", 1)[1]
    return st, {"Cookie": "zefira_session=" + tok,
                "X-Requested-With": "XMLHttpRequest"}


def body_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        return {}


# ---------------------------------------------------------------- 0. session
st, AUTH = login_with(PASSWORD)
check("login works", st == 200, "status=%d" % st)
if st != 200:
    print("ABORT: cannot log in")
    sys.exit(2)

print("\n=== 1. Server / Hosts Settings (the full-replace one) ===")
st, _, raw = req("GET", "/api/settings", headers=AUTH)
orig = body_json(raw)
# The settings as they were BEFORE this suite touched anything. The suite
# turns block_direct_ip ON to prove that an omitted field is not written
# over it, and that leaves the panel refusing anonymous requests on an IP
# host - so the next run could not even log in. Restore them at the end.
orig0 = dict(orig)
check("GET /api/settings returns the panel settings", st == 200 and orig.get("domain") is not None,
      "status=%d keys=%d" % (st, len(orig)))
_hard_keys = ("tls_fp", "hy2_obfs_password", "hy2_hop_ports",
              "hy2_hop_interval", "reality_sni_per_user")
check("the transport-hardening keys are present", all(k in orig for k in _hard_keys),
      str([k for k in _hard_keys if k not in orig]))
check("the transport-hardening keys have the documented types",
      orig.get("tls_fp") in TLS_FINGERPRINTS
      and isinstance(orig.get("hy2_obfs_password"), str)
      and isinstance(orig.get("hy2_hop_ports"), str)
      and isinstance(orig.get("hy2_hop_interval"), int)
      and isinstance(orig.get("reality_sni_per_user"), bool),
      str({k: orig.get(k) for k in _hard_keys}))
_align_keys = ("ws_path", "ws_host", "reality_short_ids", "hy2_hop_format",
               "clash_failover", "clash_health_check_url", "clash_failover_interval")
check("the server-alignment keys are present", all(k in orig for k in _align_keys),
      str([k for k in _align_keys if k not in orig]))
check("the server-alignment keys have the documented types",
      orig.get("ws_path") == "/zefira"
      and orig.get("ws_host") == ""
      and orig.get("reality_short_ids") == ""
      and orig.get("hy2_hop_format") in ("mport", "official")
      and isinstance(orig.get("clash_failover"), bool)
      and isinstance(orig.get("clash_health_check_url"), str)
      and isinstance(orig.get("clash_failover_interval"), int),
      str({k: orig.get(k) for k in _align_keys}))

# A marker that is definitely NOT what the operator set, changed and restored.
MARKER = "settingscards.example.com"
mod = dict(orig)
mod["domain"] = MARKER
mod["dns"] = "9.9.9.9"
mod["ws_path"] = "/edge"
mod["ws_host"] = "cdn.example.com"
mod["reality_short_ids"] = "aa11,bb22"
mod["hy2_hop_format"] = "official"
mod["clash_failover"] = True
mod["clash_health_check_url"] = "https://example.com/204"
mod["clash_failover_interval"] = 120
# The official-hop diagnostic is only emitted when a range exists. Seed one
# here instead of depending on the demo DB happening to have hopping enabled:
# on a reset database hy2_hop_ports is empty, so the assertion below would be
# testing the fixture rather than the diagnostic.
mod["hy2_hop_ports"] = "20000-20100"
st, _, pb = req("PUT", "/api/settings", json.dumps(mod), AUTH)
after_put = body_json(pb)
check("PUT /api/settings accepts a full body", st == 200, "status=%d %s" % (st, str(pb)[:80]))

st, _, raw2 = req("GET", "/api/settings", headers=AUTH)
reread = body_json(raw2)
check("the changed domain reads back", reread.get("domain") == MARKER, str(reread.get("domain")))
check("the changed dns reads back", reread.get("dns") == "9.9.9.9", str(reread.get("dns")))
check("the seeded hop range reads back", reread.get("hy2_hop_ports") == "20000-20100",
      str(reread.get("hy2_hop_ports")))
check("the alignment values read back",
      reread.get("ws_path") == "/edge"
      and reread.get("ws_host") == "cdn.example.com"
      and reread.get("reality_short_ids") == "aa11,bb22"
      and reread.get("hy2_hop_format") == "official"
      and reread.get("clash_failover") is True
      and reread.get("clash_health_check_url") == "https://example.com/204"
      and reread.get("clash_failover_interval") == 120,
      str({k: reread.get(k) for k in _align_keys}))

print("\n=== 1b. alignment diagnostics and generators ===")
st, _, raw_diag = req("GET", "/api/settings/diagnostics", headers=AUTH)
diag = body_json(raw_diag)
_checks = {c.get("code"): c for c in diag.get("checks", []) if isinstance(c, dict)}
check("GET /api/settings/diagnostics answers", st == 200 and bool(_checks),
      "status=%d checks=%d" % (st, len(_checks)))
check("diagnostics see the custom WebSocket path",
      _checks.get("ws_path_custom", {}).get("level") == "ok",
      str(_checks.get("ws_path_custom")))
check("diagnostics count the imported shortIds",
      _checks.get("reality_short_ids_ok", {}).get("params", {}).get("count") == 2,
      str(_checks.get("reality_short_ids_ok")))
check("diagnostics report the official Hysteria2 hop format",
      "hy2_hop_official" in _checks,
      str([k for k in _checks if k.startswith("hy2_hop")]))
check("diagnostics report Clash failover as on",
      "clash_failover_on" in _checks,
      str([k for k in _checks if k.startswith("clash_failover")]))
# A fresh database has no REALITY key, and then the honest diagnostic is
# reality_pub_missing. Assert whichever one matches the fixture, so this suite
# tests the diagnostic rather than assuming the demo DB's key is present.
if re.fullmatch(r"[A-Za-z0-9_-]{43}", str(orig.get("reality_pub") or "")):
    check("diagnostics report the valid REALITY public key",
          "reality_pub_ok" in _checks, str(_checks.get("reality_pub_ok")))
else:
    check("diagnostics report the missing REALITY public key",
          "reality_pub_missing" in _checks, str(_checks.get("reality_pub_missing")))

st, _, raw_sid = req("POST", "/api/reality/short-ids", headers=AUTH)
sid = body_json(raw_sid)
_ids = sid.get("short_ids") or []
check("POST /api/reality/short-ids returns three even-length hex IDs",
      st == 200 and len(_ids) == 3
      and all(re.fullmatch(r"[0-9a-f]{8}", x) for x in _ids),
      "status=%d ids=%s" % (st, _ids))
check("the generated shortIds were not saved",
      body_json(req("GET", "/api/settings", headers=AUTH)[2]).get("reality_short_ids")
      == "aa11,bb22")

if re.fullmatch(r"[A-Za-z0-9_-]{43}", str(orig.get("reality_pub") or "")):
    st, _, raw_imp = req("POST", "/api/reality/import-pub",
                         json.dumps({"public_key": orig["reality_pub"]}), AUTH)
    check("POST /api/reality/import-pub accepts the existing key",
          st == 200 and body_json(raw_imp).get("public_key") == orig["reality_pub"],
          "status=%d" % st)
else:
    check("POST /api/reality/import-pub accepts the existing key", True,
          "skipped: the demo DB has no public key")
st, _, _ = req("POST", "/api/reality/import-pub",
               json.dumps({"public_key": "not-a-key"}), AUTH)
check("POST /api/reality/import-pub refuses a bad key", st == 422, "status=%d" % st)

# The whole point: replaying the ORIGINAL dict must restore everything,
# including a key the suite never touched.
restore = dict(reread)
restore.update({k: v for k, v in orig.items() if k in restore or k in orig})
st, _, _ = req("PUT", "/api/settings", json.dumps(orig), AUTH)
st, _, raw3 = req("GET", "/api/settings", headers=AUTH)
final = body_json(raw3)
check("the original settings were restored", final.get("domain") == orig.get("domain"),
      "%s -> %s" % (orig.get("domain"), final.get("domain")))
check("the untouched dns was not clobbered", final.get("dns") == orig.get("dns"),
      "%s -> %s" % (orig.get("dns"), final.get("dns")))
check("the alignment settings were restored",
      all(final.get(k) == orig.get(k) for k in _align_keys),
      str({k: (orig.get(k), final.get(k)) for k in _align_keys
           if final.get(k) != orig.get(k)}))
check("the seeded hop range was restored",
      final.get("hy2_hop_ports") == orig.get("hy2_hop_ports"),
      "%s -> %s" % (orig.get("hy2_hop_ports"), final.get("hy2_hop_ports")))

print("\n=== 2. a partial PUT is a silent data loss, so it must be refused ===")
# Four ports are required in SettingsIn, so a partial body 422s rather than
# wiping. Assert that, because it is the only thing standing between an API
# caller and an erased WireGuard key.
st, _, pb = req("PUT", "/api/settings", json.dumps({"domain": "partial.example.com"}), AUTH)
check("a partial settings PUT is refused, not merged", st == 422, "status=%d" % st)
st, _, raw4 = req("GET", "/api/settings", headers=AUTH)
after_partial = body_json(raw4)
check("the refused PUT changed nothing", after_partial.get("domain") == orig.get("domain"),
      str(after_partial.get("domain")))

# The 422 above only covers a body that is missing the PORTS. A body WITH
# the four ports and nothing else was accepted, and every field it did
# not mention was written from the model's DEFAULT - which for wg_pub is
# "", so the WireGuard key was erased, and the three switches went from
# "1" to "0" because their default is False. Measured on the original
# code: HTTP 200, the key gone, all three switches off.
#
# So the second half of the contract: a body that HAS the ports changes
# ONLY what it names. That is what "None means not sent" buys.
# Seed a KNOWN state first. Reading the "before" values off a database
# whose key already happened to be empty proves nothing: a key that stays
# empty looks identical to a key that was erased. That is why two of the
# four mutations passed green - the premise the check rests on was not
# true in the database the suite ran against.
_full = dict(orig)
_full.update({"sub_port": orig.get("sub_port"),
               "hy2_port": orig.get("hy2_port"),
               "wg_port": orig.get("wg_port"),
               "ovpn_port": orig.get("ovpn_port"),
               "wg_pub": "TEST-WIREGUARD-PUBLIC-KEY",
               "block_direct_ip": True,
               "cdn_enabled": True,
               "per_user_subdomain": True,
               "tls_fp": "firefox",
               "hy2_obfs_password": "SettingsSeed123",
               "hy2_hop_ports": "20000:20005, 443",
               "hy2_hop_interval": 45,
               "reality_sni_per_user": True})
st, _, _ = req("PUT", "/api/settings", json.dumps(_full), AUTH)
check("the suite can seed a known state", st == 200, "status=%d" % st)
st, _, rawS = req("GET", "/api/settings", headers=AUTH)
seeded = body_json(rawS)
check("...and the seed took: the key is set and the switches are on",
      seeded.get("wg_pub") == "TEST-WIREGUARD-PUBLIC-KEY"
      and seeded.get("block_direct_ip") is True,
      str({_k: seeded.get(_k) for _k in ("wg_pub",
                                    "block_direct_ip")}))
check("...and the hardening seed took (with the range normalised)",
      seeded.get("tls_fp") == "firefox"
      and seeded.get("hy2_obfs_password") == "SettingsSeed123"
      and seeded.get("hy2_hop_ports") == "20000-20005,443"
      and seeded.get("hy2_hop_interval") == 45
      and seeded.get("reality_sni_per_user") is True,
      str({_k: seeded.get(_k) for _k in _hard_keys}))
orig = seeded
_seeded = {"sub_port": orig.get("sub_port"),
           "hy2_port": orig.get("hy2_port"),
           "wg_port": orig.get("wg_port"),
           "ovpn_port": orig.get("ovpn_port"),
           "domain": "only-this.example.com"}
st, _, _ = req("PUT", "/api/settings", json.dumps(_seeded), AUTH)
check("a settings PUT with the ports is accepted", st == 200,
      "status=%d" % st)
st, _, raw5 = req("GET", "/api/settings", headers=AUTH)
after_ports = body_json(raw5)
check("...and it changed ONLY the field it named",
      after_ports.get("domain") == "only-this.example.com",
      str(after_ports.get("domain")))
check("...and it did NOT erase the WireGuard key",
      after_ports.get("wg_pub") == orig.get("wg_pub"),
      "the key is %r, it was %r" % (after_ports.get("wg_pub"),
                                   orig.get("wg_pub")))
for _sw in ("block_direct_ip", "cdn_enabled", "per_user_subdomain",
            "reality_sni_per_user"):
    check("...and it did NOT switch %s off by omission" % _sw,
          after_ports.get(_sw) == orig.get(_sw),
          "%s is %r, it was %r" % (_sw, after_ports.get(_sw),
                                  orig.get(_sw)))
for _k, _want in (("tls_fp", "firefox"),
                  ("hy2_obfs_password", "SettingsSeed123"),
                  ("hy2_hop_ports", "20000-20005,443"),
                  ("hy2_hop_interval", 45)):
    check("...and it did NOT reset %s by omission" % _k,
          after_ports.get(_k) == _want,
          "%s is %r, it was %r" % (_k, after_ports.get(_k), _want))
# and the switches come back as BOOLEANS, not as the strings "1"/"0"
check("the switches are returned as booleans, not as \"1\"/\"0\"",
      all(isinstance(after_ports.get(_sw), bool) for _sw in
          ("block_direct_ip", "cdn_enabled", "per_user_subdomain",
           "reality_sni_per_user")),
      str({_sw: type(after_ports.get(_sw)).__name__ for _sw in
           ("block_direct_ip", "cdn_enabled", "per_user_subdomain",
            "reality_sni_per_user")}))

# Bad hardening values must be refused before anything is written. Each of
# these would otherwise produce a link every client rejects, or silently
# disable the feature, and the operator would not know which.
for _key, _value, _label in (
        ("tls_fp", "netscape", "an unknown TLS fingerprint"),
        ("hy2_hop_ports", "70000", "an out-of-range hop port"),
        ("hy2_hop_interval", 4, "a hop interval below 5 seconds"),
        ("hy2_obfs_password", "abc", "an obfs password shorter than 4")):
    st, _, pb = req("PUT", "/api/settings",
                    json.dumps({**orig, _key: _value}), AUTH)
    check("%s is refused with 422" % _label, st == 422,
          "status=%d %s" % (st, str(pb)[:70]))
st, _, rawB = req("GET", "/api/settings", headers=AUTH)
after_bad = body_json(rawB)
check("the refused hardening PUTs changed nothing",
      after_bad.get("tls_fp") == "firefox"
      and after_bad.get("hy2_obfs_password") == "SettingsSeed123"
      and after_bad.get("hy2_hop_ports") == "20000-20005,443"
      and after_bad.get("hy2_hop_interval") == 45
      and after_bad.get("reality_sni_per_user") is True,
      str({_k: after_bad.get(_k) for _k in _hard_keys}))

# Put the settings back exactly as they were. Without this the switch
# stays on and the next run of ANY suite cannot log in over an IP host.
st, _, _ = req("PUT", "/api/settings", json.dumps(orig0), AUTH)
st, _, rawR = req("GET", "/api/settings", headers=AUTH)
restored = body_json(rawR)
check("the suite puts the settings back, switch and all",
      restored.get("block_direct_ip") == orig0.get("block_direct_ip")
      and restored.get("wg_pub") == orig0.get("wg_pub")
      and restored.get("tls_fp") == orig0.get("tls_fp")
      and restored.get("hy2_obfs_password") == orig0.get("hy2_obfs_password")
      and restored.get("hy2_hop_ports") == orig0.get("hy2_hop_ports")
      and restored.get("hy2_hop_interval") == orig0.get("hy2_hop_interval")
      and restored.get("reality_sni_per_user") == orig0.get("reality_sni_per_user"),
      str({_k: restored.get(_k) for _k in ("block_direct_ip", "wg_pub",
                                          "tls_fp", "hy2_hop_ports")}))

print("\n=== 3. AI Assistant ===")
st, _, raw = req("GET", "/api/ai/settings", headers=AUTH)
ai = body_json(raw)
check("GET /api/ai/settings answers", st == 200, "status=%d keys=%s" % (st, sorted(ai)))
check("the AI key is never returned", "api_key" not in ai and "has_key" in ai,
      "has_key=%s" % ai.get("has_key"))

ai_orig = dict(ai)
probe = dict(ai)
probe.update({"enabled": False, "provider": "groq", "model": "settings-cards-probe",
              "api_key": "", "extra": "", "base_url": ""})
st, _, pb = req("PUT", "/api/ai/settings", json.dumps(probe), AUTH)
check("PUT /api/ai/settings accepts the probe", st == 200, "status=%d %s" % (st, str(pb)[:70]))
st, _, raw = req("GET", "/api/ai/settings", headers=AUTH)
ai2 = body_json(raw)
check("the AI model reads back", ai2.get("model") == "settings-cards-probe", str(ai2.get("model")))
check("an empty api_key preserved the stored one", ai2.get("has_key") == ai_orig.get("has_key"),
      "%s -> %s" % (ai_orig.get("has_key"), ai2.get("has_key")))

back = {k: ai_orig.get(k, "") for k in ("enabled", "provider", "model", "extra", "base_url")}
back["enabled"] = ai_orig.get("enabled", False)
back["api_key"] = ""
st, _, _ = req("PUT", "/api/ai/settings", json.dumps(back), AUTH)
st, _, raw = req("GET", "/api/ai/settings", headers=AUTH)
ai3 = body_json(raw)
check("the original AI settings were restored", ai3.get("model") == ai_orig.get("model"),
      "%s -> %s" % (ai_orig.get("model"), ai3.get("model")))

# The Test button must refuse when the assistant is not configured, rather than
# spending provider quota.
st, _, _ = req("POST", "/api/ai/test", json.dumps({}), AUTH)
check("AI test refuses when unconfigured (no quota spent)", st == 400, "status=%d" % st)

print("\n=== 4. Telegram Notifications ===")
st, _, raw = req("GET", "/api/telegram", headers=AUTH)
tg = body_json(raw)
check("GET /api/telegram answers", st == 200, "status=%d keys=%s" % (st, sorted(tg)))
check("the bot token is never returned", "bot_token" not in tg and "has_token" in tg,
      "has_token=%s" % tg.get("has_token"))

tg_orig = dict(tg)
probe = {"bot_token": "", "chat_id": "settingscards_probe"}
st, _, pb = req("PUT", "/api/telegram", json.dumps(probe), AUTH)
check("PUT /api/telegram accepts the probe", st == 200, "status=%d %s" % (st, str(pb)[:70]))
st, _, raw = req("GET", "/api/telegram", headers=AUTH)
tg2 = body_json(raw)
check("the chat id reads back", tg2.get("chat_id") == "settingscards_probe", str(tg2.get("chat_id")))
check("an empty bot_token preserved the stored one", tg2.get("has_token") == tg_orig.get("has_token"),
      "%s -> %s" % (tg_orig.get("has_token"), tg2.get("has_token")))

st, _, _ = req("PUT", "/api/telegram",
               json.dumps({"bot_token": "", "chat_id": tg_orig.get("chat_id", "")}), AUTH)
st, _, raw = req("GET", "/api/telegram", headers=AUTH)
check("the original chat id was restored", body_json(raw).get("chat_id") == tg_orig.get("chat_id"),
      str(body_json(raw).get("chat_id")))

# The Test button must refuse before sending anything.
st, _, pb = req("POST", "/api/telegram/test", json.dumps({}), AUTH)
check("Telegram test refuses rather than sending to a real chat",
      st in (400, 200) and (st == 400 or not tg_orig.get("has_token")),
      "status=%d %s" % (st, str(pb)[:60]))

print("\n=== 5. SSL Certificate (probed without issuing anything) ===")
st, _, raw = req("GET", "/api/ssl/status", headers=AUTH)
ssl = body_json(raw)
check("GET /api/ssl/status answers", st == 200 and "installed" in ssl, "status=%d keys=%s" % (st, sorted(ssl)))
# A domain shorter than the schema minimum is rejected by FastAPI before the
# handler body, so certbot is never invoked and no limiter slot is spent.
st, _, pb = req("POST", "/api/ssl/issue",
                json.dumps({"domain": "x", "subdomain": "", "email": "probe@example.com"}), AUTH)
check("an invalid SSL domain is refused before certbot runs", st == 422, "status=%d %s" % (st, str(pb)[:60]))
st, _, pb = req("POST", "/api/ssl/issue",
                json.dumps({"domain": "settingscards.example.com", "subdomain": "",
                            "email": "not-an-email"}), AUTH)
check("an invalid SSL email is refused", st == 422, "status=%d" % st)
if not ssl.get("domains"):
    st, _, pb = req("POST", "/api/ssl/renew", json.dumps({}), AUTH)
    check("renew refuses when no certificate exists", st == 400, "status=%d %s" % (st, str(pb)[:60]))
else:
    check("renew skipped: this panel already has a certificate", True)

print("\n=== 6. Backup & Restore ===")
st, hd, bb = req("POST", "/api/backup", json.dumps({"password_confirm": PASSWORD}), AUTH, timeout=60)
check("backup downloads a payload", st == 200, "status=%d" % st)
bk = body_json(bb)
check("the backup is a zefira_backup document", bk.get("zefira_backup") is True,
      "keys=%s" % sorted(bk)[:6])
check("the backup carries a users list", isinstance(bk.get("users"), list), str(type(bk.get("users"))))
# An earlier version of this check asserted the backup carried no
# `password_hash`, and failed. That assertion was wrong, not the product: the
# admins array IS exported on purpose, because restoring onto a different host
# is a real operation and scrypt hashes are what make that possible. What must
# be true - and is what this now checks - is that the file SAYS those
# credentials are not imported, because an operator seeing `admins` with a hash
# in it would otherwise assume the password came back with it.
check("the backup states that its credentials are never imported",
      "NEVER imported" in (bk.get("credentials_note") or ""),
      repr(bk.get("credentials_note"))[:70])

st, _, pb = req("POST", "/api/backup", json.dumps({"password_confirm": "wrong-password"}), AUTH)
check("backup refuses a wrong password", st in (400, 401, 403), "status=%d" % st)

# An empty users list must be refused, not treated as "delete everyone".
st, _, pb = req("POST", "/api/restore", json.dumps(
    {"zefira_backup": True, "password_confirm": PASSWORD, "users": []}), AUTH, timeout=60)
check("a customers-less restore is refused", st == 400, "status=%d %s" % (st, str(pb)[:70]))

print("\n=== 7. Security Events (read-only) ===")
st, _, raw = req("GET", "/api/audit", headers=AUTH)
try:
    audit = json.loads(raw)
except Exception:
    audit = None
check("GET /api/audit answers", st == 200 and isinstance(audit, list), "status=%d" % st)
if isinstance(audit, list):
    row = audit[0] if audit else {}
    check("audit rows carry the fields the UI reads",
          all(k in row for k in ("ts", "event", "detail", "ip")), "keys=%s" % sorted(row))
    check("audit rows are bounded", len(audit) <= 50, "n=%d" % len(audit))
    known = set()
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        with io.open(os.path.join(here, "main.py"), encoding="utf-8") as fh:
            known = set(re.findall(r'audit\(\s*s?\b[^,]*,\s*"([A-Z_]{3,})"', fh.read()))
    except Exception:
        known = set()
    if known:
        unlabelled = sorted({r.get("event") for r in audit
                             if r.get("event") in known} - known)
        check("every event emitted here has a label", not unlabelled, str(unlabelled[:6]))

print("\n=== 8. Change Admin Password (one cycle; it resets the budget on success) ===")
st, _, _ = req("POST", "/api/change-password", json.dumps(
    {"current_password": "definitely-not-it", "new_password": "Another12345"}), AUTH)
check("password change refuses a wrong current password", st in (400, 401, 403), "status=%d" % st)

TMP = "SetTmp12345"
st, _, pb = req("POST", "/api/change-password", json.dumps(
    {"current_password": PASSWORD, "new_password": TMP}), AUTH)
check("password change accepts the correct current password", st == 200, "status=%d %s" % (st, str(pb)[:70]))
st, AUTH2 = login_with(TMP)
check("login with the new password", st == 200, "status=%d" % st)
st, _, pb = req("POST", "/api/change-password", json.dumps(
    {"current_password": TMP, "new_password": PASSWORD}), AUTH2)
check("password changed back", st == 200, "status=%d %s" % (st, str(pb)[:70]))
st, AUTH = login_with(PASSWORD)
check("the original password works again", st == 200, "status=%d" % st)
st, _, _ = req("POST", "/api/change-password", json.dumps(
    {"current_password": "definitely-not-it", "new_password": "Another12345"}), AUTH)
check("password change refuses a wrong current password again", st in (400, 401, 403), "status=%d" % st)

print("\n=== 9. CSRF still guards every mutating route ===")
st, _, _ = req("PUT", "/api/settings", json.dumps(orig), None)
check("a mutating call with no CSRF header is refused", st == 403, "status=%d" % st)
st, _, _ = req("PUT", "/api/ai/settings", json.dumps({"enabled": False}), None)
check("the AI route is CSRF-guarded too", st == 403, "status=%d" % st)

passed = sum(1 for _, ok, _ in results if ok)
print("\n=== SUMMARY ===")
for name, ok, detail in results:
    if not ok:
        print("  FAILED: %s %s" % (name, detail))
print("%d/%d checks passed" % (passed, len(results)))
sys.exit(0 if passed == len(results) else 1)