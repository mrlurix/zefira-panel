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
from urllib.parse import unquote

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
print("=== 4. the schema layer is what keeps '#' out in the first place ===")
for cand in ("a#b", "a b", "a\nb", "مشتری"):
    try:
        InboundIn(name=cand, protocol="vless", port=8443)
        check(f"inbound name {cand!r} is refused", False, "it was ACCEPTED")
    except ValidationError:
        check(f"inbound name {cand!r} is refused", True)

print(f"  === {n - len(fails)}/{n} checks passed ===")
sys.exit(1 if fails else 0)
