"""Every share link must encode its remark. Offline, no server, no database.

The remark after '#' is the profile name the customer sees in their client. If a
builder interpolates it raw, a name carrying '#' splits the link into a second
fragment and the client shows a truncated name with the rest as garbage:

    vless/trojan  -> already percent-encoded (protocols.py:_v2ray_link)
    ss/hysteria2/REALITY -> were not, and a '#' produced THREE fragments

Measured before the fix: ss, hysteria2 and reality each decoded to 'a' for the
input 'a#b'. After: all five decode back to 'a#b'.

Reachability, stated honestly: USERNAME_RE is ^[a-zA-Z0-9_]{3,32}$ and
InboundIn.name is ^[a-zA-Z0-9_\\-]+$, and restore re-validates inbound names
(main.py:5031), so no current input path can carry a '#' into a remark. This is
defence in depth, and it is worth having for two reasons: percent-encoding
[a-zA-Z0-9_-] is a no-op, so no valid link changes; and the builder's own
comment already promised the property ("a legacy row must not be able to inject
a second line") when only two of five protocols honoured it.

Non-ASCII is deliberately NOT required to be encoded. A raw fragment is legal
per RFC 3986 and the clients accept it; this checks the round-trip, not the
spelling.
"""
import io
import os
import sys
from urllib.parse import parse_qs, unquote, urlsplit

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import protocols as P  # noqa: E402
from schemas import InboundIn  # noqa: E402
from pydantic import ValidationError  # noqa: E402

n = 0
fails = []


def check(label, ok, detail=""):
    global n
    n += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))
    if not ok:
        fails.append(label)


SRV = {
    "domain": "panel.example.com", "obfuscated_host": "", "per_user_subdomain": "0",
    "reality_port": 443, "reality_sni": "a.example.com,b.example.com",
    "reality_pub": "OhuXKHlnnUbaD2kyV93XpMMS9-UcVUtr_LyYNsIFugU",
    "sub_port": 443, "hy2_port": 8443, "socks5_port": 1080, "ovpn_port": 1194,
    "ovpn_proto": "udp", "dns": "1.1.1.1", "wg_port": 51820, "wg_pub": "",
    "l2tp_port": 1701, "cisco_port": 443,
}
SEC = "11111111-2222-3333-4444-555555555555"
BUILDERS = {
    "vless": lambda name: P._v2ray_link("vless", SEC, name, 1, SRV),
    "vmess": lambda name: P._v2ray_link("vmess", SEC, name, 1, SRV),
    "trojan": lambda name: P._v2ray_link("trojan", SEC, name, 1, SRV),
    "ss": lambda name: P._v2ray_link("ss", "pw", name, 1, SRV),
    "hysteria2": lambda name: P._v2ray_link("hysteria2", SEC, name, 1, SRV),
    "reality": lambda name: P._reality_link(SEC, name, 1, SRV),
}

print("=== 1. every protocol that emits a '#' remark encodes it ===")
for proto, build in BUILDERS.items():
    link = build("a#b")
    if link is None:
        check(f"{proto}: builds a link", False, "builder returned None")
        continue
    parts = link.split("#")
    if len(parts) == 1:
        # vmess carries the name inside a base64 payload, not as a fragment.
        check(f"{proto}: the remark cannot break the link", True,
              "base64 payload, no raw fragment")
        continue
    check(f"{proto}: exactly one '#' in the link", len(parts) == 2,
          f"{len(parts)} fragments - the client reads {unquote(parts[1])[:16]!r} "
          f"as the name and the remainder as garbage")
    check(f"{proto}: the remark decodes back to the name",
          unquote(parts[1]) == "a#b", f"decoded {unquote(parts[1])[:24]!r}")

print()
print("=== 2. a valid name is untouched (encoding is a no-op) ===")
# vmess carries the profile name in a base64 JSON payload ("ps"), not as a raw
# fragment, so the two formats are read differently. Checking that matters: the
# first version of this block asserted "#alice-01" in link for every protocol
# and went red on vmess, which never had a fragment to mangle - a check that
# fails on correct code teaches people to ignore it.
import base64
import json


def profile_name(link):
    """The name a client will display, whichever format carries it."""
    if not link.startswith("vmess://"):
        return unquote(link.split("#", 1)[1]) if "#" in link else None
    payload = link[len("vmess://"):]
    payload += "=" * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8")).get("ps")
    except Exception as exc:                       # noqa: BLE001
        return f"<undecodable: {exc}>"


for proto, build in BUILDERS.items():
    link = build("alice-01")
    if link is None:
        check(f"{proto}: builds for a valid name", False, "returned None")
        continue
    got = profile_name(link)
    check(f"{proto}: a valid ASCII name is not mangled", got == "alice-01",
          f"client will see {got!r}")

print()
print("=== 3. non-ASCII names round-trip (a Persian panel) ===")
NAME = "مشتری"
for proto, build in BUILDERS.items():
    link = build(NAME)
    if link is None:
        check(f"{proto}: builds for a non-ASCII name", False, "returned None")
        continue
    if "#" not in link:
        check(f"{proto}: non-ASCII name", True, "base64 payload")
        continue
    check(f"{proto}: non-ASCII name round-trips",
          unquote(link.split("#", 1)[1]) == NAME,
          f"emitted {link.split('#', 1)[1][:30]!r}")

print()
print("=== 4. the subscription body carries share links and nothing else ===")
# A customer's subscription feed is consumed by a link importer, one entry per
# line. It used to carry the file-based config sections too ("### OpenVPN ###"
# plus a 90-line .ovpn), on the belief that clients "skip the ### sections" -
# a client skips the ONE line starting with '#'; the rest are not URIs.
# Measured before the fix: vless+openvpn served 92 lines, 91 of them unparseable,
# with the customer's single working link among them.
#
# Nothing consumes those sections: subscription_body() has one caller (the /sub
# route), the dashboard is rendered from user_links() and the file download from
# build_files(). The panel's own error for a link-less plan already promised the
# opposite - "WireGuard/OpenVPN/L2TP/Cisco plans are served as config files, not
# link lists".
import base64 as _b64

# What a link importer can actually parse. Defined here rather than imported:
# this file is the one place that asserts it, and a shared constant would let
# the assertion drift with whatever the code emits.
URI_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://",
               "hy2://", "socks5://", "wireguard://", "wg://",
               "openvpn://", "l2tp://", "cisco://")

SRV2 = dict(SRV)
SRV2["wg_pub"] = "kR4mZQ8vGq2sT1pLxN7bYcW3eH6jF9dA0uI5oP8sT3vX6zY1cE4gH7jK0lM="
USER_D = {"username": "subbody", "id": 1, "protocols": ["vless"],
          "volume_gb": 5.0, "used_gb": 0.0, "is_active": True, "note": "",
          "device_limit": None, "start_on_first_use": False,
          "pending_start": False, "created_at": None, "expires_at": None,
          "last_fetch_at": None, "last_fetch_ip": None}

# The file-config builders need the instance CA, which does not exist in an
# offline run - they raise, the existing `except (ValueError, OSError)` skips
# them, and `extras` comes back EMPTY. The first version of this guard was
# therefore blind: reverting subscription_body() to the mixed-bundle form still
# passed, because the guard could not make the bug happen. It stubs the
# builders instead, so the config sections are always present and the check is
# about the BODY, not about whether this machine happens to have a CA.
_FAKE_OVPN = ("client\ndev tun\nproto udp\nremote panel.example.com 1194\n"
              "resolv-retry infinite\nremote-cert-tls server\nverify-x509-name vpn\n"
              "<ca>\n-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
              "</ca>\nremote-random\npull\npush\n")
_FAKE_WG = "[Interface]\nPrivateKey = kR4mZQ8vGq2sT1pLxN7bYcW3eH6jF9dA0uI5oP8sT3vX6zY1cE4gH7jK0lM=\nAddress = 10.7.0.7/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = pK3x\n"
_ovpn_real, _wg_real = P._ovpn_config, P._wg_config
P._ovpn_config = lambda u, srv, sec: _FAKE_OVPN
P._wg_config = lambda u, srv, sec: _FAKE_WG
for plan, expect_at_least in ((["vless"], 1), (["vless", "openvpn"], 1),
                              (["vmess", "trojan"], 2), (["vless", "reality"], 1),
                              (["vless", "openvpn", "wireguard", "l2tp", "cisco"], 1)):
    u = dict(USER_D, protocols=list(plan),
             secret_map={p: (SEC if p not in ("openvpn", "wireguard") else "pw")
                         for p in plan})
    body, ct = P.subscription_body(u, SRV2, [])
    check(f"{'+'.join(plan)}: the body is base64 text", ct == "text/plain", f"ct={ct!r}")
    try:
        # subscription_body returns str (b64encode(...).decode()), so pad as str.
        decoded = _b64.b64decode(body + "===").decode("utf-8", "replace")
    except Exception as exc:                                   # noqa: BLE001
        check(f"{'+'.join(plan)}: the body decodes", False, str(exc)[:70])
        continue
    lines = [l for l in decoded.splitlines() if l.strip()]
    junk = [l for l in lines if not l.lower().startswith(URI_SCHEMES)]
    check(f"{'+'.join(plan)}: every line is a share link", not junk,
          f"{len(junk)} of {len(lines)} line(s) a link importer cannot parse, "
          f"first: {junk[0][:44]!r}" if junk else "")
    check(f"{'+'.join(plan)}: no '###' section header leaked into the feed",
          "###" not in decoded)
    check(f"{'+'.join(plan)}: the plan still produces its links",
          len(lines) >= expect_at_least, f"{len(lines)} line(s)")

P._ovpn_config, P._wg_config = _ovpn_real, _wg_real

print()
print("=== 5. the schema layer is what keeps '#' out in the first place ===")
for cand in ("a#b", "a b", "a\nb", "مشتری"):
    try:
        InboundIn(name=cand, protocol="vless", port=8443)
        check(f"inbound name {cand!r} is refused", False, "it was ACCEPTED")
    except ValidationError:
        check(f"inbound name {cand!r} is refused", True)

print()
print("=== 6. transport hardening defaults keep the links byte-identical ===")
# These five settings were added for operators who need more than the stock
# profile. The invariant that matters on upgrade is the other direction: with
# every default in place, the output must be exactly what the panel emitted
# before the settings existed.
DEF = P.resolve_srv({})
check("resolve_srv fills every hardening key",
      all(k in DEF for k in ("tls_fp", "hy2_obfs_password", "hy2_hop_ports",
                             "hy2_hop_interval", "reality_sni_per_user")),
      str(sorted(DEF)))
check("the default fingerprint is chrome", DEF.get("tls_fp") == "chrome",
      str(DEF.get("tls_fp")))
check("Hysteria2 obfs is off by default", DEF.get("hy2_obfs_password") == "",
      repr(DEF.get("hy2_obfs_password")))
check("Hysteria2 port hopping is off by default", DEF.get("hy2_hop_ports") == "",
      repr(DEF.get("hy2_hop_ports")))
check("the default hop interval is 30 seconds", DEF.get("hy2_hop_interval") == 30,
      str(DEF.get("hy2_hop_interval")))
check("per-user REALITY SNI is off by default", DEF.get("reality_sni_per_user") == "0",
      repr(DEF.get("reality_sni_per_user")))

_D = DEF["domain"]
_default_hy2 = f"hysteria2://{SEC}@{_D}:{DEF['hy2_port']}/?sni={_D}&insecure=0#alice"
check("the default Hysteria2 link is unchanged",
      P._v2ray_link("hysteria2", SEC, "alice", 1, DEF) == _default_hy2,
      P._v2ray_link("hysteria2", SEC, "alice", 1, DEF))

print()
print("=== 7. the TLS fingerprint reaches every protocol and Clash ===")


def clash_proxies(text):
    """Parse the `  - {json}` proxy lines the builder emits."""
    out = []
    for line in text.splitlines():
        if line.startswith("  - {"):
            out.append(json.loads(line.strip()[2:]))
    return out


FP_SRV = dict(SRV)
FP_SRV["tls_fp"] = "firefox"
vless_fp = P._v2ray_link("vless", SEC, "alice", 1, FP_SRV)
check("VLESS carries the configured fingerprint", "&fp=firefox&" in vless_fp,
      vless_fp)
vmess_fp = P._v2ray_link("vmess", SEC, "alice", 1, FP_SRV)
_vp = vmess_fp[len("vmess://"):]
_vp += "=" * (-len(_vp) % 4)
_vj = json.loads(base64.urlsafe_b64decode(_vp).decode("utf-8"))
check("VMess carries the configured fingerprint in its JSON",
      _vj.get("fp") == "firefox", str(_vj.get("fp")))
trojan_fp = P._v2ray_link("trojan", SEC, "alice", 1, FP_SRV)
check("Trojan carries the configured fingerprint", "&fp=firefox&" in trojan_fp,
      trojan_fp)
reality_fp = P._reality_link(SEC, "alice", 1, FP_SRV)
check("REALITY carries the configured fingerprint", "&fp=firefox&" in reality_fp,
      reality_fp)

FP_USER = {
    "username": "alice",
    "protocols": ["vless", "vmess", "trojan", "reality", "hysteria2"],
    "secret_map": {"vless": SEC, "vmess": SEC, "trojan": SEC,
                   "reality": SEC, "hysteria2": SEC},
}
fp_proxies = clash_proxies(P.clash_yaml(FP_USER, FP_SRV))
_fp_tls = [p for p in fp_proxies if p.get("type") in ("vless", "vmess", "trojan")]
check("Clash carries the configured client fingerprint on every TLS proxy",
      len(_fp_tls) == 4 and all(p.get("client-fingerprint") == "firefox"
                                for p in _fp_tls),
      str([p.get("client-fingerprint") for p in fp_proxies]))

check("an unknown fingerprint is refused by resolve_srv",
      P.resolve_srv({"tls_fp": "netscape"})["tls_fp"] == "chrome",
      str(P.resolve_srv({"tls_fp": "netscape"})["tls_fp"]))
check("a smuggled fingerprint cannot reach a query string",
      P.resolve_srv({"tls_fp": "chrome&evil=1"})["tls_fp"] == "chrome",
      str(P.resolve_srv({"tls_fp": "chrome&evil=1"})["tls_fp"]))

print()
print("=== 8. Hysteria2 obfs and port hopping are opt-in and encoded ===")
HY = dict(SRV)
HY.update({
    "hy2_obfs_password": "p@ss word&x",
    "hy2_hop_ports": "20000:20005, 443",
    "hy2_hop_interval": 45,
})
hy_link = P._v2ray_link("hysteria2", SEC, "alice", 1, HY)
_hy = urlsplit(hy_link)
_hyq = parse_qs(_hy.query)
check("the authority keeps a numeric port for older clients", _hy.port == 8443,
      str(_hy.port))
check("obfs=salamander is emitted only when a password is set",
      _hyq.get("obfs") == ["salamander"], str(_hyq))
check("the obfs password is percent-encoded and round-trips",
      _hyq.get("obfs-password") == ["p@ss word&x"], str(_hyq.get("obfs-password")))
check("a colon range is normalised for the link",
      _hyq.get("mport") == ["20000-20005,443"], str(_hyq.get("mport")))
check("hop-interval is emitted with port hopping",
      _hyq.get("hop-interval") == ["45"], str(_hyq.get("hop-interval")))

_obfs_only = dict(SRV, hy2_obfs_password="obfs-secret")
_ol = P._v2ray_link("hysteria2", SEC, "alice", 1, _obfs_only)
check("obfs alone does not enable port hopping",
      "mport=" not in _ol and "hop-interval" not in _ol, _ol)
_hop_only = dict(SRV, hy2_hop_ports="20000-20005")
_hl = P._v2ray_link("hysteria2", SEC, "alice", 1, _hop_only)
check("port hopping alone does not enable obfs",
      "obfs=" not in _hl and "obfs-password" not in _hl, _hl)
check("a default link carries no hardening parameters",
      not any(k in _default_hy2 for k in ("obfs=", "mport=", "hop-interval")),
      _default_hy2)

hy_proxies = clash_proxies(P.clash_yaml(
    {"username": "alice", "protocols": ["hysteria2"],
     "secret_map": {"hysteria2": SEC}}, HY))
check("Clash carries the Hysteria2 obfs fields",
      hy_proxies and hy_proxies[0].get("obfs") == "salamander"
      and hy_proxies[0].get("obfs-password") == "p@ss word&x",
      str(hy_proxies[:1]))
check("Clash carries ports and hop-interval, and keeps the anchor port",
      hy_proxies[0].get("port") == 8443
      and hy_proxies[0].get("ports") == "20000-20005,443"
      and hy_proxies[0].get("hop-interval") == 45,
      str(hy_proxies[:1]))
check("a default Clash Hysteria2 proxy stays minimal",
      not any(k in clash_proxies(P.clash_yaml(
          {"username": "alice", "protocols": ["hysteria2"],
           "secret_map": {"hysteria2": SEC}}, SRV))[0]
          for k in ("obfs", "obfs-password", "ports", "hop-interval")))

print()
print("=== 9. per-user REALITY SNI agrees between links and Clash ===")
PS = dict(SRV)
PS["reality_sni"] = "one.example.com,two.example.com,three.example.com"
PS["reality_sni_per_user"] = "1"
_sni_pool = {"one.example.com", "two.example.com", "three.example.com"}
_sni_user = P._reality_sni(PS, 1, SEC)
check("the per-user SNI is stable across link indexes",
      _sni_user == P._reality_sni(PS, 9, SEC), f"{_sni_user}")
check("the per-user SNI comes from the configured list", _sni_user in _sni_pool,
      _sni_user)
_spread = {P._reality_sni(PS, 1, f"user-{i}") for i in range(64)}
check("different users are spread across the list", len(_spread) > 1, str(_spread))
check("every per-user choice stays inside the list", _spread <= _sni_pool,
      str(_spread))

OFF_SRV = dict(SRV)
OFF_SRV["reality_sni_per_user"] = "0"
check("with the option off, the first link uses the first SNI",
      P._reality_sni(OFF_SRV, 1, SEC) == "a.example.com",
      P._reality_sni(OFF_SRV, 1, SEC))

_ps_link = P._reality_link(SEC, "alice", 1, PS)
_ps_sni = parse_qs(urlsplit(_ps_link).query).get("sni", [""])[0]
_ps_clash = clash_proxies(P.clash_yaml(
    {"username": "alice", "protocols": ["reality"],
     "secret_map": {"reality": SEC}}, PS))[0]
check("the REALITY link and the Clash proxy pick the same per-user SNI",
      _ps_sni == _ps_clash.get("servername") and _ps_sni in _sni_pool,
      f"link={_ps_sni} clash={_ps_clash.get('servername')}")

print()
print("=== 10. hand-edited rows and backups are normalised at the builder ===")
_BAD = P.resolve_srv({
    "tls_fp": "netscape",
    "hy2_obfs_password": "x",
    "hy2_hop_ports": "70000",
    "hy2_hop_interval": "999",
    "reality_sni_per_user": "maybe",
})
check("a bad fingerprint falls back to chrome", _BAD["tls_fp"] == "chrome",
      _BAD["tls_fp"])
check("a too-short obfs password disables obfs", _BAD["hy2_obfs_password"] == "",
      repr(_BAD["hy2_obfs_password"]))
check("an unusable hop range disables hopping", _BAD["hy2_hop_ports"] == "",
      repr(_BAD["hy2_hop_ports"]))
check("an out-of-range hop interval falls back to 30",
      _BAD["hy2_hop_interval"] == 30, str(_BAD["hy2_hop_interval"]))
check("an unknown switch value is stored as off",
      _BAD["reality_sni_per_user"] == "0", repr(_BAD["reality_sni_per_user"]))

_GOOD = P.resolve_srv({
    "tls_fp": " FIREFOX ",
    "hy2_obfs_password": "  abcd  ",
    "hy2_hop_ports": "20000:20005, 443",
    "hy2_hop_interval": "45",
    "reality_sni_per_user": "yes",
})
check("a valid fingerprint is lowercased and trimmed",
      _GOOD["tls_fp"] == "firefox", _GOOD["tls_fp"])
check("a valid obfs password is trimmed", _GOOD["hy2_obfs_password"] == "abcd",
      repr(_GOOD["hy2_obfs_password"]))
check("a valid hop range is canonicalised",
      _GOOD["hy2_hop_ports"] == "20000-20005,443", _GOOD["hy2_hop_ports"])
check("a numeric interval string becomes an int",
      _GOOD["hy2_hop_interval"] == 45, str(_GOOD["hy2_hop_interval"]))
check("a truthy switch is stored as \"1\"", _GOOD["reality_sni_per_user"] == "1",
      repr(_GOOD["reality_sni_per_user"]))
check("a boolean interval is refused rather than read as 1",
      P._safe_hop_interval(True) == 30, str(P._safe_hop_interval(True)))
check("normalize_hop_ports rejects a reversed range",
      P.normalize_hop_ports("20000-19999") == "")
check("normalize_hop_ports rejects an empty member",
      P.normalize_hop_ports("1,,2") == "")

print(f"  === {n - len(fails)}/{n} checks passed ===")
sys.exit(1 if fails else 0)
