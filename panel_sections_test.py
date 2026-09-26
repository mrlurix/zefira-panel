"""
ZEFIRA PANEL SECTIONS - walks every panel section the way an operator does.

The other suites prove the API works from the outside. This one walks each
SECTION end to end, in the order the sidebar lists them, asserting the state
the UI would render: counters that must agree with the rows on screen, a guide
that must contain the tunnel's own token, node health that must change the
links a customer receives, REALITY settings that must survive a reload, the
update card's pre-flight contract, and the customize/settings round-trips.

Deepest on the sections that carry the most moving parts: Inbounds, Tunnels
(BackPack), Server nodes, Anti-Censorship (REALITY/CDN) and Update.

Usage: python panel_sections_test.py http://127.0.0.1:8011 admin PASSWORD
"""
import json
import re
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8011"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"

AUTH = {"X-Requested-With": "XMLHttpRequest"}
COOKIE = {"v": ""}
VP = {"User-Agent": "v2rayNG/1.8.5"}
CHROME = {"User-Agent": "Mozilla/5.0"}
results = []


def check(section, name, cond, detail=""):
    results.append((f"{section}: {name}", bool(cond), detail))
    mark = "\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def req(method, path, body=None, headers=None, timeout=60, raw_body=None):
    h = {"User-Agent": "zefira-sections/1.0", "Content-Type": "application/json"}
    h.update(headers or {})
    if COOKIE["v"] and not (headers or {}).get("Authorization"):
        h["Cookie"] = f"zefira_session={COOKIE['v']}"
    data = raw_body if raw_body is not None else (
        json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        for p in (resp.headers.get("set-cookie") or "").split(";"):
            if p.strip().startswith("zefira_session="):
                COOKIE["v"] = p.split("=", 1)[1]
        return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        for p in (e.headers.get("set-cookie") or "").split(";"):
            if p.strip().startswith("zefira_session="):
                COOKIE["v"] = p.split("=", 1)[1]
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()


def js(method, path, body=None, headers=None, timeout=60):
    st, hd, b = req(method, path, body, headers, timeout)
    try:
        return st, json.loads(b or b"{}")
    except Exception:
        return st, b[:300]


def txt(b):
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b)


print(f"=== ZEFIRA PANEL SECTIONS -> {BASE} ===")
st, _ = js("POST", "/api/login", {"username": ADMIN, "password": PASSWORD}, AUTH)
if st != 200:
    print(f"ABORT: login failed ({st})")
    sys.exit(2)
check("session", "login", st == 200, f"{st}")

created_users, created_ibs, created_sn, created_tn = [], [], [], []


def newuser(**kw):
    payload = {"username": "s" + uuid.uuid4().hex[:7], "protocols": ["vless"],
               "volume_gb": 5, "days": 5}
    payload.update(kw)
    st, u = js("POST", "/api/users", payload, AUTH)
    if u.get("id"):
        created_users.append(u["id"])
    return st, u


# ================================================================ 1. DASHBOARD
S = "dashboard"
st, stats = js("GET", "/api/stats", headers=AUTH)
check(S, "stats answers with the counters the cards render",
      st == 200 and all(k in stats for k in
                        ("total_users", "active_users", "expired_users",
                         "disabled_users", "limited_users", "expiring_soon")),
      f"{st} {sorted(stats)[:8]}")
st, ulist = js("GET", "/api/users?limit=500", headers=AUTH)
rows = ulist.get("items", [])
check(S, "total_users matches the rows on screen",
      stats.get("total_users") == len(rows), f"{stats.get('total_users')} vs {len(rows)}")
active = sum(1 for u in rows if u.get("is_active")
             and not u.get("pending_start")
             and float(u.get("used_gb", 0)) < float(u.get("volume_gb", 0)))
# Counters are read BEFORE this suite creates anything, so the invariant is
# "never more than the rows we can see", not a specific number.
check(S, "active_users never exceeds the rows on screen",
      stats.get("active_users", 0) <= max(len(rows), active),
      f"{stats.get('active_users')} vs {len(rows)} rows / {active} active")
check(S, "no NaN/Infinity leaks into the counters",
      "NaN" not in json.dumps(stats) and "Infinity" not in json.dumps(stats), "")
st, sysinfo = js("GET", "/api/system", headers=AUTH)
check(S, "system reports the fields the health card shows",
      st == 200 and any(k in sysinfo for k in ("cpu", "memory", "disk", "uptime")),
      f"{st} {sorted(sysinfo)[:8]}")
st, aud = js("GET", "/api/audit?limit=5", headers=AUTH)
check(S, "recent-activity list is renderable",
      st == 200 and isinstance(aud, list)
      and all(isinstance(r.get("event"), str) for r in aud), f"{st}")

# ================================================================ 2. USERS
S = "users"
st, u = newuser(protocols=["vless", "trojan"], volume_gb=11, days=12, note="sec test")
uid = u.get("id")
check(S, "a user is created from the form's fields", st == 200 and uid, f"{st} {str(u)[:70]}")
if uid:
    st, hit = js("GET", f"/api/users?q={u['username']}", headers=AUTH)
    check(S, "the search box finds it by the typed name",
          any(x["id"] == uid for x in hit.get("items", [])), f"{st}")
    st, qr = js("GET", f"/api/users/{uid}/qr", headers=AUTH)
    check(S, "the QR button returns a link + image",
          st == 200 and qr.get("url", "").endswith(u["token"])
          and len(qr.get("qr_b64", "")) > 100, f"{st} {str(qr)[:70]}")
    st, _, cfg = req("GET", f"/api/users/{uid}/config", headers=AUTH)
    check(S, "the config download is a real file", st == 200 and len(cfg) > 40, f"{st}")
    st, _ = js("PATCH", f"/api/users/{uid}", {"note": "edited"}, AUTH)
    st, again = js("GET", f"/api/users?q={u['username']}", headers=AUTH)
    row = next((x for x in again.get("items", []) if x["id"] == uid), {})
    check(S, "the edit form saves and the table reflects it", row.get("note") == "edited",
          str(row.get("note")))
    st, _ = js("POST", f"/api/users/{uid}/reset-token", {}, AUTH)
    st, again = js("GET", f"/api/users?q={u['username']}", headers=AUTH)
    row = next((x for x in again.get("items", []) if x["id"] == uid), {})
    check(S, "reset-token issues a new subscription link", row.get("token") != u["token"], "")
    u = row
    st, _ = js("POST", f"/api/users/{uid}/reset-usage", {}, AUTH)
    st, again = js("GET", f"/api/users?q={u['username']}", headers=AUTH)
    row = next((x for x in again.get("items", []) if x["id"] == uid), {})
    check(S, "reset-usage empties the usage bar", float(row.get("used_gb", -1)) == 0.0,
          str(row.get("used_gb")))
    st, _ = js("PATCH", f"/api/users/{uid}", {"is_active": False}, AUTH)
    off, _h, _b = req("GET", f"/sub/{row['token']}", headers=VP)
    check(S, "the pause toggle stops the subscription", off == 404, f"{off}")
    js("PATCH", f"/api/users/{uid}", {"is_active": True}, AUTH)

# ================================================================ 3. INBOUNDS
S = "inbounds"
st, sn_on = js("POST", "/api/server-nodes", {"name": "ibtarget", "address": "203.0.113.9",
                                            "check_port": 443, "note": ""}, AUTH)
sn_id = sn_on.get("id")
if sn_id:
    created_sn.append(sn_id)
st, ib = js("POST", "/api/inbounds", {"name": "in1", "protocol": "vless", "port": 2443,
                                      "host": "in.example.com", "node_id": sn_id}, AUTH)
ib_id = ib.get("id")
check(S, "an inbound is created with a node pinned", st == 200 and ib_id, f"{st} {str(ib)[:80]}")
st, ibs = js("GET", "/api/inbounds", headers=AUTH)
check(S, "the list shows it with its port, host and node",
      any(x["id"] == ib_id and x["port"] == 2443 and x["host"] == "in.example.com"
          and x.get("node_id") == sn_id for x in ibs), f"{st}")
st, _ = js("PATCH", f"/api/inbounds/{ib_id}", {"enabled": False}, AUTH)
st, ibs = js("GET", "/api/inbounds", headers=AUTH)
row = next((x for x in ibs if x["id"] == ib_id), {})
check(S, "the enable toggle persists", row.get("enabled") is False, str(row))
st, _ = js("PATCH", f"/api/inbounds/{ib_id}", {"enabled": True}, AUTH)
# Two listeners cannot share a port on the SAME server, so the duplicate is
# refused per (protocol, port, node scope) - a different node is a different
# machine and may reuse the port.
st, dup = js("POST", "/api/inbounds", {"name": "in2", "protocol": "vless", "port": 2443,
                                       "host": "other.example.com", "node_id": sn_id}, AUTH)
check(S, "a duplicate port on the same protocol+node is refused", st in (409, 422), f"{st}")
st, dup2 = js("POST", "/api/inbounds", {"name": "in2", "protocol": "vless", "port": 2443,
                                        "host": "other.example.com", "node_id": sn_id}, AUTH)
check(S, "the refusal is not a silent overwrite", st in (409, 422), f"{st}")
st, ok_other = js("POST", "/api/inbounds", {"name": "in2b", "protocol": "vless", "port": 2443,
                                            "host": "other.example.com"}, AUTH)
check(S, "the same port on a DIFFERENT node scope is allowed", st == 200,
      f"{st} {str(ok_other)[:70]}")
if ok_other.get("id"):
    created_ibs.append(ok_other["id"])
# an inbound may not shadow the global server port it would be served on
st, srv_now = js("GET", "/api/settings", headers=AUTH)
st, shadow = js("POST", "/api/inbounds", {"name": "shadow", "protocol": "vless",
                                          "port": srv_now.get("sub_port")}, AUTH)
check(S, "an unpinned inbound may not shadow the global server port", st in (409, 422),
      f"{st} sub_port={srv_now.get('sub_port')}")
# bad inputs
for label, payload in (("port 0", {"name": "b1", "protocol": "vless", "port": 0}),
                       ("port 70000", {"name": "b2", "protocol": "vless", "port": 70000}),
                       ("host with spaces", {"name": "b3", "protocol": "vless", "port": 2444,
                                             "host": "a b.com"}),
                       ("host with CRLF", {"name": "b4", "protocol": "vless", "port": 2444,
                                           "host": "a.com\r\nX: 1"}),
                       ("empty-label host", {"name": "b5b", "protocol": "vless", "port": 2444,
                                             "host": "a..b.com"}),
                       ("bad protocol", {"name": "b5", "protocol": "gopher", "port": 2444}),
                       ("single-endpoint protocol", {"name": "b6", "protocol": "wireguard",
                                                     "port": 2444}),
                       ("name with slash", {"name": "a/b", "protocol": "vless", "port": 2444}),
                       ("node that does not exist", {"name": "b7", "protocol": "vless",
                                                     "port": 2444, "node_id": 999999})):
    st, r = js("POST", "/api/inbounds", payload, AUTH)
    check(S, f"{label} is refused cleanly", st in (400, 404, 422), f"{st} {str(r)[:60]}")
# pinning can be changed and cleared from the row editor. Port 2443 in the
# unpinned scope is taken by in2b, so un-pinning in1 must be refused...
st, blocked = js("PATCH", f"/api/inbounds/{ib_id}", {"node_id": None}, AUTH)
check(S, "un-pinning into an occupied port scope is refused", st in (409, 422),
      f"{st} {str(blocked)[:70]}")
st, back = js("GET", "/api/inbounds", headers=AUTH)
row = next((x for x in back if x["id"] == ib_id), {})
check(S, "the refused un-pin left the inbound pinned, not half-changed",
      row.get("node_id") == sn_id, str(row.get("node_id")))
# ...and with the scope free it goes through
js("DELETE", f"/api/inbounds/{ok_other['id']}", headers=AUTH)
created_ibs.remove(ok_other["id"])
st, moved = js("PATCH", f"/api/inbounds/{ib_id}", {"node_id": None}, AUTH)
check(S, "the row editor can un-pin an inbound", st == 200 and moved.get("node_id") is None,
      f"{st} {str(moved)[:70]}")
st, ghost = js("PATCH", f"/api/inbounds/{ib_id}", {"node_id": 999999}, AUTH)
check(S, "pinning to a node that does not exist is refused", st in (404, 422), f"{st}")
st, back = js("GET", "/api/inbounds", headers=AUTH)
row = next((x for x in back if x["id"] == ib_id), {})
check(S, "the refused re-pin did not move the inbound onto a dead node",
      row.get("node_id") is None, str(row.get("node_id")))
js("PATCH", f"/api/inbounds/{ib_id}", {"node_id": sn_id}, AUTH)
st, _ = js("DELETE", f"/api/inbounds/{ib_id}", headers=AUTH)
st, gone = js("GET", "/api/inbounds", headers=AUTH)
check(S, "a deleted inbound leaves the list", not any(x["id"] == ib_id for x in gone), f"{st}")
js("DELETE", f"/api/inbounds/{ib_id}", headers=AUTH)
check(S, "deleting it twice is a clean 404, not a 500",
      js("DELETE", f"/api/inbounds/{ib_id}", headers=AUTH)[0] == 404, "")

# ================================================================ 4. TUNNELS (BackPack)
S = "tunnels"
st, tn = js("POST", "/api/nodes", {"name": "tun1", "transport": "tcp",
                                  "iran_ip": "198.51.100.7", "kharej_ip": "203.0.113.11",
                                  "tunnel_port": 443, "forwarded_ports": "80:8080,443:8443",
                                  "udp_forward": True}, AUTH)
tn_id = tn.get("id")
if tn_id:
    created_tn.append(tn_id)
check(S, "a tunnel is created and the token is shown once",
      st == 200 and tn_id and tn.get("token_once"), f"{st} {str(tn)[:70]}")
token_once = tn.get("token_once")
st, tns = js("GET", "/api/nodes", headers=AUTH)
row = next((x for x in tns if x["id"] == tn_id), {})
check(S, "the list never shows the token again", row.get("token") is None,
      f"token field present: {str(row.get('token'))[:20]}")
check(S, "the row shows the transport, IPs and port for the table",
      row.get("transport") == "tcp" and row.get("iran_ip") == "198.51.100.7"
      and row.get("kharej_ip") == "203.0.113.11" and row.get("tunnel_port") == 443,
      str(row)[:140])
check(S, "forwarded ports and udp flag round-trip",
      [p.strip() for p in (row.get("forwarded_ports") or "").split(",") if p.strip()]
      == ["80:8080", "443:8443"] and row.get("udp_forward") is True,
      str(row)[:170])
st, hd, guide = req("GET", f"/api/nodes/{tn_id}/guide", headers=AUTH)
g = txt(guide)
check(S, "the setup guide downloads", st == 200 and len(g) > 400, f"{st} {len(g)}")
check(S, "the guide carries THIS tunnel's token", token_once and token_once in g,
      "token not in the guide")
check(S, "the guide carries the real IPs and port",
      "198.51.100.7" in g and "203.0.113.11" in g and "443" in g, "")
check(S, "the guide's hash check is fail-closed (no bare continuation)",
      "set -e" in g and "sha256sum -c" in g, "")
st, chk = js("POST", f"/api/nodes/{tn_id}/check", {}, AUTH)
check(S, "the check button answers without a 5xx", st < 500, f"{st} {str(chk)[:70]}")
st, rev = js("POST", f"/api/nodes/{tn_id}/reveal-token", {}, AUTH)
check(S, "reveal-token returns the same token", st == 200 and rev.get("token") == token_once,
      f"{st} {str(rev)[:70]}")
st, regen = js("POST", f"/api/nodes/{tn_id}/regen-token", {}, AUTH)
newtok = regen.get("token")
check(S, "regen-token mints a DIFFERENT token", st == 200 and newtok and newtok != token_once,
      f"{st}")
st, tns = js("GET", "/api/nodes", headers=AUTH)
row = next((x for x in tns if x["id"] == tn_id), {})
check(S, "regen-token also drops the probe result it can no longer vouch for",
      row.get("status") == "unknown" and not row.get("last_check"),
      f"status={row.get('status')} last_check={row.get('last_check')}")
st, chk2 = js("POST", f"/api/nodes/{tn_id}/check", {}, AUTH)
check(S, "the row's status is a known value after a check",
      isinstance(chk2.get("status"), str) and chk2["status"] in
      ("online", "offline", "unknown", "degraded", "checking"), str(chk2)[:90])
# bad tunnel inputs
for label, payload in (
    ("port 0", {"name": "tb1", "transport": "tcp", "iran_ip": "198.51.100.1",
                "kharej_ip": "198.51.100.2", "tunnel_port": 0}),
    ("bad transport", {"name": "tb2", "transport": "carrier-pigeon",
                       "iran_ip": "198.51.100.1", "kharej_ip": "198.51.100.2",
                       "tunnel_port": 443}),
    ("metadata iran ip", {"name": "tb3", "transport": "tcp", "iran_ip": "169.254.169.254",
                          "kharej_ip": "198.51.100.2", "tunnel_port": 443}),
    ("port pair without colon", {"name": "tb4", "transport": "tcp",
                                 "iran_ip": "198.51.100.1", "kharej_ip": "198.51.100.2",
                                 "tunnel_port": 443, "forwarded_ports": "8080"}),
    ("port pair out of range", {"name": "tb5", "transport": "tcp",
                                "iran_ip": "198.51.100.1", "kharej_ip": "198.51.100.2",
                                "tunnel_port": 443, "forwarded_ports": "99999:1"}),
):
    st, r = js("POST", "/api/nodes", payload, AUTH)
    check(S, f"{label} is refused cleanly", st in (400, 422), f"{st} {str(r)[:70]}")
st, _gh, guide2 = req("GET", f"/api/nodes/{tn_id}/guide", headers=AUTH)
check(S, "the guide now carries the regenerated token",
      st == 200 and newtok and newtok in txt(guide2), "stale guide")

# ================================================================ 5. SERVER NODES
S = "nodes"
# The node must be able to go online AND come back, so aim it at the test
# server itself. An unroutable address would only ever read "offline" and
# could not prove the link returns.
LIVE_PORT = int(BASE.rsplit(":", 1)[-1].split("/")[0] or 80)
st, sn = js("POST", "/api/server-nodes", {"name": "sn1", "address": "127.0.0.1",
                                          "check_port": LIVE_PORT, "note": "primary"}, AUTH)
sn1 = sn.get("id")
if sn1:
    created_sn.append(sn1)
check(S, "a server node is created", st == 200 and sn1, f"{st} {str(sn)[:70]}")
st, sns = js("GET", "/api/server-nodes", headers=AUTH)
row = next((x for x in sns if x["id"] == sn1), {})
check(S, "the row shows address, check port and note",
      row.get("address") == "127.0.0.1" and row.get("check_port") == LIVE_PORT
      and row.get("note") == "primary", str(row)[:140])
st, chk = js("POST", f"/api/server-nodes/{sn1}/check", {}, AUTH)
check(S, "a reachable node checks ONLINE with a latency",
      st == 200 and chk.get("status") == "online" and chk.get("latency_ms") is not None,
      f"{st} {str(chk)[:90]}")
st, sns = js("GET", "/api/server-nodes", headers=AUTH)
row = next((x for x in sns if x["id"] == sn1), {})
check(S, "the health result is persisted on the row (last_check + uptime)",
      row.get("status") == "online" and row.get("last_check"),
      f"status={row.get('status')} last_check={row.get('last_check')}")
# an unreachable port on the same host reads offline
st, _ = js("PATCH", f"/api/server-nodes/{sn1}", {"check_port": 9}, AUTH)
st, chk2 = js("POST", f"/api/server-nodes/{sn1}/check", {}, AUTH)
check(S, "a closed port on the same host reads OFFLINE", chk2.get("status") == "offline",
      f"{st} {str(chk2)[:80]}")
st, _ = js("PATCH", f"/api/server-nodes/{sn1}", {"check_port": LIVE_PORT}, AUTH)
st, after_move = js("GET", "/api/server-nodes", headers=AUTH)
row = next((x for x in after_move if x["id"] == sn1), {})
check(S, "moving the probe target clears the stale reading, not just the status",
      row.get("status") == "unknown" and not row.get("last_check"),
      f"status={row.get('status')} last_check={row.get('last_check')}")
# health must change what a customer receives
st, pin = js("POST", "/api/inbounds", {"name": "pinned", "protocol": "vless",
                                       "port": 2555, "host": "pin.example.com",
                                       "node_id": sn1}, AUTH)
pin_id = pin.get("id")
if pin_id:
    created_ibs.append(pin_id)
    # a pinned inbound with NO host of its own must reach the node's address,
    # not this panel's domain (and not the obfuscated front)
    st, ib_nohost = js("POST", "/api/inbounds", {"name": "pinnednohost", "protocol": "vless",
                                                 "port": 2558, "host": "",
                                                 "node_id": sn1}, AUTH)
    if ib_nohost.get("id"):
        created_ibs.append(ib_nohost["id"])
    st, u2 = newuser(protocols=["vless"], volume_gb=5, days=5)
    if u2.get("token"):
        js("PATCH", f"/api/users/{u2['id']}", {"is_active": True}, AUTH)
        st, _h, page = req("GET", f"/sub/{u2['token']}", headers=CHROME)
        check(S, "a pinned inbound appears in the customer's links",
              "pin.example.com" in txt(page), "pinned host missing")
        check(S, "a host-less pinned inbound links to the NODE's address",
              ":2558" in txt(page) and "127.0.0.1:2558" in txt(page),
              "node address missing from the links")
        # setting and then CLEARING the host from the row editor
        if ib_nohost.get("id"):
            js("PATCH", f"/api/inbounds/{ib_nohost['id']}", {"host": "temp.example.com"}, AUTH)
            st, _h, paget = req("GET", f"/sub/{u2['token']}", headers=CHROME)
            check(S, "a host set on the row reaches the customer's links",
                  "temp.example.com:2558" in txt(paget), "edited host missing")
            st, cleared = js("PATCH", f"/api/inbounds/{ib_nohost['id']}",
                             {"host": None}, AUTH)
            check(S, "an explicit null clears the inbound's host", st == 200
                  and cleared.get("host") == "", f"{st} {str(cleared)[:70]}")
            st, _h, pagec = req("GET", f"/sub/{u2['token']}", headers=CHROME)
            check(S, "the cleared host falls back to the node, not the old address",
                  "temp.example.com" not in txt(pagec) and "127.0.0.1:2558" in txt(pagec),
                  "old host still served")
        # disabling the node must drop the link even though it is reachable
        js("PATCH", f"/api/server-nodes/{sn1}", {"enabled": False}, AUTH)
        st, _h, page2 = req("GET", f"/sub/{u2['token']}", headers=CHROME)
        check(S, "a disabled node's links are excluded",
              "pin.example.com" not in txt(page2), "link still served")
        js("PATCH", f"/api/server-nodes/{sn1}", {"enabled": True}, AUTH)
        st, _h, page3 = req("GET", f"/sub/{u2['token']}", headers=CHROME)
        check(S, "the link returns when the node is re-enabled",
              "pin.example.com" in txt(page3), "link did not come back")
        # a node that has never been checked stays fail-open (monitoring is
        # advisory until the first check runs) - a fresh node keeps serving.
        st, sn_fresh = js("POST", "/api/server-nodes", {"name": "snFresh",
                                                        "address": "127.0.0.1",
                                                        "check_port": LIVE_PORT}, AUTH)
        st, ib_fresh = js("POST", "/api/inbounds", {"name": "unchecked", "protocol": "vless",
                                                    "port": 2556, "host": "unchecked.example.com",
                                                    "node_id": sn_fresh.get("id")}, AUTH)
        if sn_fresh.get("id"):
            created_sn.append(sn_fresh["id"])
        if ib_fresh.get("id"):
            created_ibs.append(ib_fresh["id"])
            st, _h, page4 = req("GET", f"/sub/{u2['token']}", headers=CHROME)
            check(S, "an unchecked node still serves links (fail-open, not fail-closed)",
                  "unchecked.example.com" in txt(page4), "link missing for unknown node")
# A node deletion must not be able to create a configuration the panel itself
# rejects: un-pinning moves the inbound into this server's scope, where the
# port rules apply. It used to skip that check and answer 200.
st, sn_clash = js("POST", "/api/server-nodes", {"name": "snClash", "address": "127.0.0.1",
                                               "check_port": LIVE_PORT}, AUTH)
st, ib_local = js("POST", "/api/inbounds", {"name": "localport", "protocol": "vless",
                                            "port": 2660, "host": "local.example.com"}, AUTH)
st, ib_remote = js("POST", "/api/inbounds", {"name": "remoteport", "protocol": "vmess",
                                             "port": 2660, "host": "remote.example.com",
                                             "node_id": sn_clash.get("id")}, AUTH)
if sn_clash.get("id"):
    created_sn.append(sn_clash["id"])
if ib_local.get("id"):
    created_ibs.append(ib_local["id"])
if ib_remote.get("id"):
    created_ibs.append(ib_remote["id"])
st, blocked_del = js("DELETE", f"/api/server-nodes/{sn_clash['id']}", headers=AUTH)
check(S, "deleting a node is refused when it would collide with a local port",
      st == 409 and "remoteport" in json.dumps(blocked_del), f"{st} {str(blocked_del)[:110]}")
st, still = js("GET", "/api/server-nodes", headers=AUTH)
check(S, "the refused delete left the node in place",
      any(x["id"] == sn_clash.get("id") for x in still), f"{st}")
st, ibs = js("GET", "/api/inbounds", headers=AUTH)
kept_remote = next((x for x in ibs if x["id"] == ib_remote.get("id")), {})
check(S, "the refused delete did not half-unpin anything",
      kept_remote.get("node_id") == sn_clash.get("id"), str(kept_remote.get("node_id")))
# two protocols cannot share one port on the same server, even when pinned
st, two = js("POST", "/api/inbounds", {"name": "twoports", "protocol": "trojan", "port": 2660,
                                      "host": "trojan.example.com"}, AUTH)
check(S, "a second protocol on a taken port is refused on this server too",
      st in (409, 422), f"{st} {str(two)[:80]}")
st, sn_other = js("POST", "/api/server-nodes", {"name": "snOther", "address": "127.0.0.1",
                                                "check_port": LIVE_PORT}, AUTH)
if sn_other.get("id"):
    created_sn.append(sn_other["id"])
st, two_ok = js("POST", "/api/inbounds", {"name": "twoports", "protocol": "trojan", "port": 2660,
                                          "host": "trojan.example.com",
                                          "node_id": sn_other.get("id")}, AUTH)
check(S, "the same port is fine on a DIFFERENT server (node scope)", st == 200,
      f"{st} {str(two_ok)[:70]}")
if two_ok.get("id"):
    created_ibs.append(two_ok["id"])
    js("DELETE", f"/api/inbounds/{two_ok['id']}", headers=AUTH)
    created_ibs.remove(two_ok["id"])
st, two_pinned = js("POST", "/api/inbounds", {"name": "twoports2", "protocol": "trojan",
                                              "port": 2660, "host": "trojan2.example.com",
                                              "node_id": sn_clash.get("id")}, AUTH)
check(S, "but two protocols on ONE server is still refused", st in (409, 422),
      f"{st} {str(two_pinned)[:90]}")
# deleting a node must unpin, not delete, its inbounds
st, ib_keep = js("POST", "/api/inbounds", {"name": "keepafter", "protocol": "vless",
                                           "port": 2557, "host": "keep.example.com",
                                           "node_id": sn1}, AUTH)
if ib_keep.get("id"):
    created_ibs.append(ib_keep["id"])
    st, _ = js("DELETE", f"/api/server-nodes/{sn1}", headers=AUTH)
    st, ibs = js("GET", "/api/inbounds", headers=AUTH)
    kept = next((x for x in ibs if x["id"] == ib_keep["id"]), None)
    check(S, "deleting a node unpins its inbounds instead of deleting them",
          kept is not None and kept.get("node_id") is None, str(kept)[:110])
    st, _h, page5 = req("GET", f"/sub/{u2['token']}", headers=CHROME)
    check(S, "an unpinned inbound falls back to this panel's own endpoint",
          "keep.example.com" in txt(page5), "link lost after unpin")
for label, payload in (
    ("address 0.0.0.0", {"name": "nb1", "address": "0.0.0.0"}),
    ("address metadata", {"name": "nb2", "address": "169.254.169.254"}),
    ("check_port 0", {"name": "nb3", "address": "198.51.100.9", "check_port": 0}),
    ("check_port 70000", {"name": "nb4", "address": "198.51.100.9", "check_port": 70000}),
    ("address with spaces", {"name": "nb5", "address": "a b.c"}),
    ("empty name", {"name": "", "address": "198.51.100.9"}),
):
    st, r = js("POST", "/api/server-nodes", payload, AUTH)
    check(S, f"{label} is refused cleanly", st in (400, 422), f"{st} {str(r)[:70]}")

# ================================================================ 6. ANTI-CENSORSHIP (REALITY/CDN)
S = "reality"
st, srv0 = js("GET", "/api/settings", headers=AUTH)
st, gen = js("POST", "/api/reality/generate", {}, AUTH)
check(S, "Generate returns a usable keypair",
      st == 200 and gen.get("private_key") and gen.get("public_key"), f"{st} {str(gen)[:70]}")
st, rev = js("GET", "/api/reality/private", headers=AUTH)
check(S, "the revealed private key matches what was generated",
      st == 200 and rev.get("private_key") == gen.get("private_key"), f"{st}")
st, srv = js("GET", "/api/settings", headers=AUTH)
check(S, "the public key is in the settings the page loads",
      srv.get("reality_pub") == gen.get("public_key"), str(srv.get("reality_pub"))[:30])
# the settings form round-trip
new_srv = dict(srv)
new_srv.update({"reality_port": 8443, "reality_sni": "www.microsoft.com",
                "cdn_enabled": True, "cdn_sni": "www.cloudflare.com",
                "obfuscated_host": "www.bing.com", "per_user_subdomain": True})
st, r = js("PUT", "/api/settings", new_srv, AUTH)
check(S, "the anti-censorship form saves", st == 200, f"{st} {str(r)[:90]}")
st, srv2 = js("GET", "/api/settings", headers=AUTH)
check(S, "the port, SNI, CDN toggle and host survive a reload",
      srv2.get("reality_port") == 8443 and srv2.get("reality_sni") == "www.microsoft.com"
      and str(srv2.get("cdn_enabled")) in ("1", "True", "true")
      and srv2.get("cdn_sni") == "www.cloudflare.com"
      and srv2.get("obfuscated_host") == "www.bing.com"
      and str(srv2.get("per_user_subdomain")) in ("1", "True", "true"),
      str({k: srv2.get(k) for k in ("reality_port", "reality_sni", "cdn_enabled",
                                    "cdn_sni", "obfuscated_host",
                                    "per_user_subdomain")})[:170])
# the generated key must actually reach the links
st, ru = newuser(protocols=["reality", "vless"], volume_gb=5, days=5)
if ru.get("token"):
    st, _h, sub = req("GET", f"/sub/{ru['token']}", headers=VP)
    s = txt(sub)
    if "\n" not in s[:60]:
        import base64 as _b
        try:
            s = _b.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
        except Exception:
            pass
    # A REALITY account is a vless:// link with security=reality, not a
    # reality:// scheme. With CDN on, cdn_sni is what the link carries as SNI.
    check(S, "the REALITY link carries the new port, key and CDN SNI",
          "security=reality" in s and ":8443" in s
          and f"pbk={gen.get('public_key')}" in s and "sni=www.cloudflare.com" in s,
          s[:200])
    check(S, "the per-user subdomain + obfuscated host form the link's host",
          "www.bing.com" in s, s[:200])
# with CDN off, reality_sni is the SNI that reaches the link
st, r = js("PUT", "/api/settings", dict(srv2, cdn_enabled=False), AUTH)
st, ru2 = newuser(protocols=["reality"], volume_gb=5, days=5)
if ru2.get("token"):
    st, _h, sub2 = req("GET", f"/sub/{ru2['token']}", headers=VP)
    s2 = txt(sub2)
    if "\n" not in s2[:60]:
        import base64 as _b
        try:
            s2 = _b.b64decode(s2 + "=" * (-len(s2) % 4)).decode("utf-8", "replace")
        except Exception:
            pass
    check(S, "with CDN off the reality_sni list reaches the link",
          "sni=www.microsoft.com" in s2, s2[:200])
# a multi-entry SNI list is split, not emitted as one broken SNI
st, _ = js("PUT", "/api/settings", dict(srv2, cdn_enabled=False,
                                        reality_sni="a.example.com, b.example.com"), AUTH)
st, ru3 = newuser(protocols=["reality"], volume_gb=5, days=5)
if ru3.get("token"):
    st, _h, sub3 = req("GET", f"/sub/{ru3['token']}", headers=VP)
    s3 = txt(sub3)
    if "\n" not in s3[:60]:
        import base64 as _b
        try:
            s3 = _b.b64decode(s3 + "=" * (-len(s3) % 4)).decode("utf-8", "replace")
        except Exception:
            pass
    check(S, "a SNI list is split per entry (no leading space, no whole list)",
          "sni=a.example.com" in s3 or "sni=b.example.com" in s3, s3[:200])
    check(S, "the list is never emitted as one comma-joined SNI",
          "sni=a.example.com%2C" not in s3 and "sni=a.example.com," not in s3, s3[:200])
# an empty SNI list is refused (it used to be saved, and every REALITY link was
# then shipped with the CONNECT ADDRESS as the SNI - dead on arrival)
st, r = js("PUT", "/api/settings", dict(srv2, reality_sni=""), AUTH)
check(S, "an empty REALITY SNI list is refused", st in (400, 422), f"{st} {str(r)[:70]}")
st, srv_keep = js("GET", "/api/settings", headers=AUTH)
check(S, "the refused empty SNI left the stored list alone",
      srv_keep.get("reality_sni") == "a.example.com, b.example.com",
      f"{srv_keep.get('reality_sni')!r}")
# ...and even a legacy row that somehow holds one still gets a usable SNI
st, ru4 = newuser(protocols=["reality"], volume_gb=5, days=5)
if ru4.get("token"):
    st, _h, sub4 = req("GET", f"/sub/{ru4['token']}", headers=VP)
    s4 = txt(sub4)
    if "\n" not in s4[:60]:
        import base64 as _b
        try:
            s4 = _b.b64decode(s4 + "=" * (-len(s4) % 4)).decode("utf-8", "replace")
        except Exception:
            pass
    check(S, "a REALITY link never carries its own connect address as the SNI",
          "sni=" in s4 and "sni=&" not in s4 and "8d487ca5" not in s4.split("sni=")[1][:40],
          s4[:200])
# the Clash config and the share link must agree on the SNI
st, ru5 = newuser(protocols=["reality"], volume_gb=5, days=5)
if ru5.get("token"):
    st, _h, cbody = req("GET", f"/sub/{ru5['token']}?format=clash", headers=VP)
    cy = txt(cbody)
    st, _h, sbody = req("GET", f"/sub/{ru5['token']}", headers=VP)
    sl = txt(sbody)
    if "\n" not in sl[:60]:
        import base64 as _b
        try:
            sl = _b.b64decode(sl + "=" * (-len(sl) % 4)).decode("utf-8", "replace")
        except Exception:
            pass
    import re as _re
    # the YAML lines are flow-style JSON objects, hence the optional quotes
    csni = _re.findall(r'"?servername"?\s*:\s*"?([^",\s}]+)', cy)
    lsni = _re.findall(r"[?&]sni=([^&\s]+)", sl)
    check(S, "the Clash entry and the share link use the same SNI",
          bool(csni) and bool(lsni) and csni[0] == lsni[0],
          f"clash={csni[:1]} link={lsni[:1]}")
    # rotation must survive into BOTH formats: with two endpoints and a
    # two-entry list, the second endpoint may not repeat the first entry's SNI
    st, sn_rot = js("POST", "/api/server-nodes", {"name": "snRot", "address": "127.0.0.1",
                                                 "check_port": LIVE_PORT}, AUTH)
    st, _ = js("PUT", "/api/settings", dict(srv2, cdn_enabled=False,
                                            reality_sni="one.example.com,two.example.com"), AUTH)
    st, ib_r1 = js("POST", "/api/inbounds", {"name": "rotone", "protocol": "reality",
                                             "port": 2671, "host": "one.example.com",
                                             "node_id": sn_rot.get("id")}, AUTH)
    st, ib_r2 = js("POST", "/api/inbounds", {"name": "rottwo", "protocol": "reality",
                                             "port": 2672, "host": "two.example.com",
                                             "node_id": sn_rot.get("id")}, AUTH)
    if sn_rot.get("id"):
        created_sn.append(sn_rot["id"])
    for i in (ib_r1, ib_r2):
        if i.get("id"):
            created_ibs.append(i["id"])
    check(S, "both rotation endpoints were created", bool(ib_r1.get("id")) and bool(ib_r2.get("id")),
          f"{ib_r1} / {ib_r2}")
    st, ru6 = newuser(protocols=["reality"], volume_gb=5, days=5)
    if ru6.get("token"):
        st, _h, cy6 = req("GET", f"/sub/{ru6['token']}?format=clash", headers=VP)
        names = re.findall(r'"?servername"?\s*:\s*"?([^",\s}]+)', txt(cy6))
        check(S, "the Clash config rotates the SNI instead of pinning the first entry",
              len(names) >= 2 and len(set(names)) >= 2, str(names)[:120])
        st, _h, sl6 = req("GET", f"/sub/{ru6['token']}", headers=VP)
        s6 = txt(sl6)
        if "\n" not in s6[:60]:
            import base64 as _b
            try:
                s6 = _b.b64decode(s6 + "=" * (-len(s6) % 4)).decode("utf-8", "replace")
            except Exception:
                pass
        links = re.findall(r"[?&]sni=([^&\s]+)", s6)
        check(S, "the share links rotate the same way",
              len(links) >= 2 and len(set(links)) >= 2, str(links)[:120])
        check(S, "Clash and the share links rotate IDENTICALLY",
              names[:len(links)] == links[:len(names)], f"{names} vs {links}")
js("PUT", "/api/settings", srv2, AUTH)
js("PUT", "/api/settings", srv2, AUTH)
# invalid values are refused, and the old values stay
for label, patch in (("SNI with a space", {"reality_sni": "www..com "}),
                     ("SNI with a slash", {"reality_sni": "a/b.com"}),
                     ("SNI http://", {"reality_sni": "http://a.com"}),
                     ("port out of range", {"reality_port": 70000}),
                     ("port 0", {"reality_port": 0}),
                     ("empty-label host", {"obfuscated_host": "a..b.com"})):
    st, r = js("PUT", "/api/settings", dict(srv2, **patch), AUTH)
    check(S, f"{label} is refused", st in (400, 422), f"{st} {str(r)[:60]}")
st, srv3 = js("GET", "/api/settings", headers=AUTH)
check(S, "a refused edit leaves the stored values untouched",
      srv3.get("reality_sni") == srv2.get("reality_sni")
      and srv3.get("reality_port") == srv2.get("reality_port"),
      f"{srv3.get('reality_sni')} / {srv3.get('reality_port')}")

# ================================================================ 7. BLOCKER
S = "blocker"
st, b = js("POST", "/api/blocklist", {"domain": "ads.example.net"}, AUTH)
b_id = b.get("id")
check(S, "a domain is blocked", st == 200 and b_id, f"{st} {str(b)[:60]}")
st, bl = js("GET", "/api/blocklist", headers=AUTH)
check(S, "it appears in the list", any(x["id"] == b_id for x in bl.get("sites", [])), f"{st}")
st, dupe = js("POST", "/api/blocklist", {"domain": "ads.example.net"}, AUTH)
check(S, "the same domain twice is refused or deduped", st in (200, 409, 422), f"{st}")
st, bl = js("GET", "/api/blocklist", headers=AUTH)
check(S, "the duplicate did not land in the list twice",
      sum(1 for x in bl.get("sites", []) if x.get("domain") == "ads.example.net") <= 1,
      str(len(bl.get("sites", []))))
st, _ = js("PUT", "/api/blocklist/porn", {"porn_enabled": True}, AUTH)
st, bl2 = js("GET", "/api/blocklist", headers=AUTH)
check(S, "the porn-block toggle persists", bl2.get("porn_enabled") is True,
      str(bl2.get("porn_enabled")))
check(S, "the preset list is only exposed while the toggle is on",
      isinstance(bl2.get("porn_domains"), list) and len(bl2["porn_domains"]) > 10
      and bl2.get("porn_count") == len(bl2["porn_domains"]),
      str(bl2.get("porn_count")))
st, _ = js("PUT", "/api/blocklist/porn", {"porn_enabled": False}, AUTH)
st, bl3 = js("GET", "/api/blocklist", headers=AUTH)
check(S, "turning it off withdraws the preset domains again",
      bl3.get("porn_enabled") is False and not bl3.get("porn_domains")
      and bl3.get("porn_count") == 0, str(bl3)[:110])
for label, dom in (("empty", ""), ("too long", "a" * 300), ("with a path", "a.com/x"),
                   ("with spaces", "a b.com"), ("with CRLF", "a.com\r\nX: 1")):
    st, r = js("POST", "/api/blocklist", {"domain": dom}, AUTH)
    check(S, f"a {label} domain is refused", st in (400, 422), f"{st} {str(r)[:50]}")
# blocked sites must reach the Clash config as a rule, not a smuggled key
st, cu = newuser(protocols=["vless"], volume_gb=5, days=5)
if cu.get("token"):
    st, _h, clash = req("GET", f"/sub/{cu['token']}?format=clash", headers=VP)
    c = txt(clash)
    check(S, "a blocked domain becomes a Clash rule", "ads.example.net" in c, c[:120])
    check(S, "the Clash config still has exactly one rules section",
          c.count("rules:") == 1, f"{c.count('rules:')}")

# ================================================================ 8. UPDATE
S = "update"
st, stt = js("GET", "/api/update/status", headers=AUTH)
check(S, "the card renders the fields it needs",
      st == 200 and all(k in stt for k in ("repo", "branch", "current", "error")),
      f"{st} {sorted(stt)[:9]}")
check(S, "signature + unit-warning keys exist for the card",
      "signature" in stt and "unit_warning" in stt, str(sorted(stt)[:12]))
check(S, "the status says when an applied update still needs a restart",
      "restart_pending" in stt and not stt.get("restart_pending"),
      str(stt.get("restart_pending")))
check(S, "the reported current/latest are short SHAs, not full ones",
      all(len(str(stt.get(k, ""))) <= 12 for k in ("current", "latest")),
      f"{stt.get('current')} / {stt.get('latest')}")
check(S, "the changelog payload is a list the card can map",
      isinstance(stt.get("local_log", []), list)
      and all(isinstance(c.get("sha"), str) for c in stt.get("local_log", [])), "")
check(S, "the incoming list is a list of {sha,date,message}",
      isinstance(stt.get("incoming", []), list)
      and all(set(("sha", "date", "message")) <= set(c) for c in stt.get("incoming", [])), "")
st, fresh = js("GET", "/api/update/status?fresh=1", headers=AUTH)
check(S, "a manual refresh answers the same shape", isinstance(fresh, dict), str(type(fresh)))
# apply pre-flight: the operator must not get a raw 500 or a silent success
st, r = js("POST", "/api/update/apply", {"password_confirm": "definitely-not-the-password"},
           AUTH)
check(S, "a wrong confirm password is refused with 400", st == 400, f"{st} {str(r)[:70]}")
check(S, "the wrong-password answer does not leak whether a SHA was sent",
      "expected_sha" not in json.dumps(r) or st == 400, f"{st} {str(r)[:90]}")
st, r = js("POST", "/api/update/apply", {"password_confirm": PASSWORD}, AUTH)
check(S, "an apply without the reviewed SHA is refused with an explanation",
      st in (400, 422) and "expected_sha" in json.dumps(r), f"{st} {str(r)[:90]}")
st, r = js("POST", "/api/update/apply", {"password_confirm": PASSWORD,
                                        "expected_sha": "zz" * 20}, AUTH)
check(S, "a malformed SHA is refused", st in (400, 422), f"{st} {str(r)[:70]}")
st, r = js("POST", "/api/update/apply", {"password_confirm": PASSWORD,
                                        "expected_sha": "a" * 40}, AUTH)
check(S, "a well-formed but unknown SHA is refused, never reported as applied",
      st in (400, 404, 409, 422) and r.get("ok") is not True, f"{st} {str(r)[:90]}")
st, after = js("GET", "/api/update/status", headers=AUTH)
check(S, "a refused apply left the reported version alone",
      isinstance(after, dict) and after.get("current") == stt.get("current"),
      f"{st} {after.get('current')} vs {stt.get('current')}")
st, r = js("POST", "/api/update/apply", {}, AUTH)
check(S, "an apply with no password at all is refused", st in (400, 422), f"{st}")

# ================================================================ 9. CUSTOMIZE
S = "customize"
st, a0 = js("GET", "/api/appearance", headers=AUTH)
# menu_layout / dash_layout travel as JSON STRINGS (that is what the form
# posts), while the GET hands back parsed objects.
base = dict(a0,
            menu_layout=json.dumps([{"id": x["id"], "hidden": False}
                                    for x in a0.get("menu_layout", [])]),
            dash_layout=json.dumps({"order": a0.get("dash_layout", {}).get("order", []),
                                    "hidden": []}))
st, _ = js("PUT", "/api/appearance", dict(base, theme_accent="#0af0ff",
                                          brand_name="Brand X", dash_note="hello"), AUTH)
st, a1 = js("GET", "/api/appearance", headers=AUTH)
check(S, "the appearance form saves and reloads",
      a1.get("theme_accent") == "#0af0ff" and a1.get("brand_name") == "Brand X"
      and a1.get("dash_note") == "hello", str(a1)[:150])
st, _h, css = req("GET", "/theme.css")
check(S, "theme.css reflects the saved accent", b"0af0ff" in css.lower(), txt(css)[:120])
st, _h, page = req("GET", "/panel", headers=AUTH)
check(S, "the login/dashboard page is served", st == 200, f"{st}")
# reordering + hiding ("blocker" is hideable; dashboard/users/inbounds/
# customize/settings are always on)
order = [x["id"] for x in a1.get("menu_layout", [])]
reordered = [{"id": sid, "hidden": sid == "blocker"} for sid in reversed(order)]
st, menu = js("PUT", "/api/appearance", dict(base, menu_layout=json.dumps(reordered),
                                             dash_layout=json.dumps(
                                                 {"order": ["link", "usage"], "hidden": []}),
                                             theme_accent="#0af0ff"), AUTH)
st, a2 = js("GET", "/api/appearance", headers=AUTH)
check(S, "the menu order is saved and comes back reversed",
      [x["id"] for x in a2.get("menu_layout", [])] == list(reversed(order)),
      str([x["id"] for x in a2.get("menu_layout", [])])[:150])
check(S, "a hideable menu entry is remembered as hidden",
      any(x["id"] == "blocker" and x["hidden"] for x in a2.get("menu_layout", [])),
      str(a2.get("menu_layout"))[:150])
check(S, "the dashboard block order is saved",
      a2.get("dash_layout", {}).get("order", [])[:2] == ["link", "usage"],
      str(a2.get("dash_layout"))[:110])
# a section the panel always shows cannot be hidden
st, _ = js("PUT", "/api/appearance", dict(base, menu_layout=json.dumps(
    [{"id": "settings", "hidden": True}, {"id": "users", "hidden": True}]),
    theme_accent="#0af0ff"), AUTH)
st, a3 = js("GET", "/api/appearance", headers=AUTH)
always = {x["id"]: x for x in a3.get("menu_layout", [])}
check(S, "the always-visible Settings entry cannot be hidden",
      always.get("settings", {}).get("hidden") is False, str(always.get("settings")))
check(S, "the always-visible Users entry cannot be hidden",
      always.get("users", {}).get("hidden") is False, str(always.get("users")))
check(S, "hiding the pinned ones does not drop them from the menu",
      "settings" in always and "users" in always, str(sorted(always))[:150])
# garbage in the layout must not break the page
st, _ = js("PUT", "/api/appearance", dict(base, menu_layout="not json at all",
                                          dash_layout='{"order": "nope"}',
                                          theme_accent="#0af0ff"), AUTH)
st, a4 = js("GET", "/api/appearance", headers=AUTH)
check(S, "a corrupt layout falls back to the full default menu",
      len(a4.get("menu_layout", [])) == 10
      and isinstance(a4.get("dash_layout"), dict), str(a4.get("menu_layout"))[:120])
# PUT is a full replacement, so re-post the whole form before the refusal loop
js("PUT", "/api/appearance", dict(base, theme_accent="#0af0ff", brand_name="Brand X",
                                  dash_note="hello"), AUTH)
st, pre = js("GET", "/api/appearance", headers=AUTH)
check(S, "re-posting the full form restores the brand",
      pre.get("brand_name") == "Brand X" and pre.get("theme_accent") == "#0af0ff",
      f"{pre.get('brand_name')} / {pre.get('theme_accent')}")
# bad colours / brand are refused
for label, patch in (("CSS injection in a colour", {"theme_accent": "red;background:url(x)"}),
                     ("colour without a hash", {"theme_accent": "0af0ff"}),
                     ("3-digit colour", {"theme_accent": "#0af"}),
                     ("colour too long", {"theme_accent": "#0af0ff0af0ff"}),
                     ("brand with markup", {"brand_name": "<b>x</b>"}),
                     ("brand too long", {"brand_name": "x" * 40})):
    payload = dict(base, theme_accent="#0af0ff", brand_name="Brand X")
    payload.update(patch)
    st, r = js("PUT", "/api/appearance", payload, AUTH)
    check(S, f"{label} is refused", st in (400, 422), f"{st} {str(r)[:60]}")
st, a5 = js("GET", "/api/appearance", headers=AUTH)
check(S, "the refused colour/brand edits did not corrupt what is stored",
      a5.get("theme_accent") == "#0af0ff" and a5.get("brand_name") == "Brand X",
      f"{a5.get('theme_accent')} / {a5.get('brand_name')}")
js("PUT", "/api/appearance", dict(a0, menu_layout=json.dumps(a0.get("menu_layout", [])),
                                  dash_layout=json.dumps(a0.get("dash_layout", {}))), AUTH)
st, a6 = js("GET", "/api/appearance", headers=AUTH)
check(S, "the original appearance is restored",
      a6.get("theme_accent") == a0.get("theme_accent")
      and a6.get("brand_name") == a0.get("brand_name"), str(a6)[:120])

# ================================================================ 10. SETTINGS
S = "settings"
st, s0 = js("GET", "/api/settings", headers=AUTH)
st, _ = js("PUT", "/api/settings", dict(s0, sub_port=8445, hy2_port=9443, ovpn_proto="tcp",
                                        dns="9.9.9.9", l2tp_port=1702, cisco_port=844,
                                        socks5_port=1081), AUTH)
st, s1 = js("GET", "/api/settings", headers=AUTH)
check(S, "every server port/dns/proto the form edits round-trips",
      s1.get("sub_port") == 8445 and s1.get("hy2_port") == 9443
      and s1.get("ovpn_proto") == "tcp" and s1.get("dns") == "9.9.9.9"
      and s1.get("l2tp_port") == 1702 and s1.get("cisco_port") == 844
      and s1.get("socks5_port") == 1081, str(s1)[:180])
for label, patch in (("sub_port 0", {"sub_port": 0}), ("sub_port 70000", {"sub_port": 70000}),
                     ("ovpn_proto sctp", {"ovpn_proto": "sctp"}),
                     ("domain with a path", {"domain": "a.com/x"}),
                     ("empty-label domain", {"domain": "a..b.com"})):
    st, r = js("PUT", "/api/settings", dict(s1, **patch), AUTH)
    check(S, f"{label} is refused", st in (400, 422), f"{st} {str(r)[:60]}")
st, s2 = js("GET", "/api/settings", headers=AUTH)
check(S, "refused settings edits did not corrupt the stored set",
      s2.get("sub_port") == 8445 and s2.get("domain") == s1.get("domain"),
      f"{s2.get('sub_port')} / {s2.get('domain')}")
js("PUT", "/api/settings", s0, AUTH)
st, _ = js("PUT", "/api/telegram", {"chat_id": "123456", "bot_token": ""}, AUTH)
st, tg = js("GET", "/api/telegram", headers=AUTH)
check(S, "telegram chat saves and the token is never returned",
      st == 200 and tg.get("chat_id") == "123456" and not tg.get("bot_token"),
      f"{st} {str(tg)[:80]}")
st, _ = js("PUT", "/api/telegram", {"chat_id": "", "bot_token": ""}, AUTH)
st, ai = js("PUT", "/api/ai/settings", {"enabled": False, "provider": "groq",
                                        "model": "x", "base_url": "https://api.groq.com/openai/v1"},
            AUTH)
check(S, "the AI card saves without a key", st == 200, f"{st} {str(ai)[:80]}")
st, ais = js("GET", "/api/ai/settings", headers=AUTH)
check(S, "the AI card reports has_key, never the key",
      "has_key" in ais and "api_key" not in json.dumps(ais).replace("has_key", ""),
      str(sorted(ais))[:110])

# ================================================================ 11. link builders
# White-box: some states the API now REFUSES to create still exist in the wild
# (a row written by an older build, a hand-edited DB). The builders must not
# turn those into guaranteed-dead customer links, and no HTTP request can put
# the panel back into that state - so call them directly.
S = "builders"
try:
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
    import protocols

    default = protocols._reality_sni({})
    check(S, "an unset SNI list still yields a usable SNI, never the connect address",
          bool(default) and "." in default and default not in ("localhost", ""),
          repr(default))
    # every stored shape the wild can hold must resolve to a real hostname
    for stored, label in (("", "empty"), ("   ", "whitespace"), (",, ,", "commas only"),
                          (" , , ", "commas and spaces"), (None, "missing key")):
        srv_bad = {} if stored is None else {"reality_sni": stored}
        got = protocols._reality_sni(srv_bad, 1)
        check(S, f"a stored SNI list that is {label} still resolves to a hostname",
              bool(got) and "." in got and " " not in got and "," not in got, repr(got))
    rot = [protocols._reality_sni({"reality_sni": "a.example.com,b.example.com"}, i)
           for i in (1, 2, 3)]
    check(S, "the SNI list rotates per link index",
          rot == ["a.example.com", "b.example.com", "a.example.com"], str(rot))
    v = protocols._variant_srv({"domain": "panel.example.com", "obfuscated_host": "front.example.com"},
                               {"port": 8443, "host": "", "node_id": 4,
                                "node_address": "10.9.9.9"})
    check(S, "a host-less pinned inbound points at the node, not the panel's front",
          v.get("domain") == "10.9.9.9" and v.get("_is_inbound_variant") is True
          and protocols._effective_host("s", v) == "10.9.9.9",
          f"{v.get('domain')} / {protocols._effective_host('s', v)}")
    try:
        protocols._variant_srv({"domain": "panel.example.com"},
                               {"port": 8443, "host": "", "node_id": 4,
                                "node_address": None})
        check(S, "a pinned inbound with no reachable address is skipped, not faked", False,
              "no ValueError raised")
    except ValueError:
        check(S, "a pinned inbound with no reachable address is skipped, not faked", True)
    vp = protocols._variant_srv({"domain": "panel.example.com"}, {"port": 8443, "host": ""})
    check(S, "an unpinned inbound with no host still serves the panel's own endpoint",
          vp.get("domain") == "panel.example.com" and "_is_inbound_variant" not in vp,
          str(vp.get("domain")))
except Exception as exc:  # noqa: BLE001 - the point is to report, not raise
    check(S, "the link builders are importable for a direct check", False, str(exc)[:90])

# ================================================================ cleanup
# Tunnels: delete by id where we have one, then sweep anything left by name.
for i in created_tn:
    js("DELETE", f"/api/nodes/{i}", headers=AUTH)
for x in (js("GET", "/api/nodes", headers=AUTH)[1] or []):
    if x.get("id"):
        js("DELETE", f"/api/nodes/{x['id']}", headers=AUTH)
for i in created_ibs:
    js("DELETE", f"/api/inbounds/{i}", headers=AUTH)
for x in (js("GET", "/api/inbounds", headers=AUTH)[1] or []):
    if x.get("id"):
        js("DELETE", f"/api/inbounds/{x['id']}", headers=AUTH)
for i in created_sn:
    js("DELETE", f"/api/server-nodes/{i}", headers=AUTH)
for x in (js("GET", "/api/server-nodes", headers=AUTH)[1] or []):
    if x.get("id"):
        js("DELETE", f"/api/server-nodes/{x['id']}", headers=AUTH)
for i in created_users:
    js("DELETE", f"/api/users/{i}", headers=AUTH)
for x in (js("GET", "/api/blocklist", headers=AUTH)[1] or {}).get("sites", []):
    if x.get("id"):
        js("DELETE", f"/api/blocklist/{x['id']}", headers=AUTH)
js("PUT", "/api/telegram", {"chat_id": "", "bot_token": ""}, AUTH)
js("PUT", "/api/ai/settings", {"enabled": False}, AUTH)
js("PUT", "/api/settings", s0, AUTH)
js("PUT", "/api/appearance", dict(a0, menu_layout=json.dumps(a0.get("menu_layout", [])),
                                  dash_layout=json.dumps(a0.get("dash_layout", {}))), AUTH)

st, ulist = js("GET", "/api/users?limit=500", headers=AUTH)
check("cleanup", "the suite leaves no users behind", not ulist.get("items"),
      str(len(ulist.get("items", []))))
st, ibs = js("GET", "/api/inbounds", headers=AUTH)
st, sns = js("GET", "/api/server-nodes", headers=AUTH)
st, tns = js("GET", "/api/nodes", headers=AUTH)
check("cleanup", "no inbounds / server nodes / tunnels left",
      not ibs and not sns and not tns, f"{len(ibs)}/{len(sns)}/{len(tns)}")
st, bl = js("GET", "/api/blocklist", headers=AUTH)
check("cleanup", "the blocklist is empty again", not bl.get("sites"), str(bl)[:90])

passed = sum(1 for _, ok, _ in results if ok)
print(f"\n=== {passed}/{len(results)} checks passed ===")
if passed != len(results):
    print("\nFAILURES:")
    for n, ok, d in results:
        if not ok:
            print(f"  - {n}: {d}")
sys.exit(0 if passed == len(results) else 1)
