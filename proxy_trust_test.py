"""client_ip() and request_scheme() must agree on what a trusted peer is.

They did not. request_scheme() honoured X-Forwarded-Proto from a loopback peer;
client_ip() honoured X-Forwarded-For only from an EXPLICITLY configured proxy.
So a panel behind a local reverse proxy the operator never listed believed the
scheme (Secure cookies) but not the address - and every visitor collapsed onto
one key.

That is a denial of service, not a cosmetic mismatch, and the measurement that
established it is in the commit message: against a running panel, 16 wrong
passwords from an anonymous client, then the operator's CORRECT password:
  trusted_proxies = ''        -> 429  (locked out of their own panel)
  trusted_proxies = 127.0.0.1 -> 200

The bucket is only cleared by a successful login, which is the request being
refused, so it repeats every window for as long as the flood continues.

Offline and DB-free: both functions are pure with respect to the request. The
trusted_networks() lookup is stubbed to the two cases that matter, so the test
cannot pass by inheriting a settings row from a previous suite.
"""
import ipaddress
import os
import sys
from unittest import mock

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import main
from starlette.requests import Request

n = 0
fails = []


def check(label, ok, detail=""):
    global n
    n += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))
    if not ok:
        fails.append(label)


def req(peer, xff=None, xfp=None):
    hdrs = [(b"host", b"panel.example.com")]
    if xff is not None:
        hdrs.append((b"x-forwarded-for", xff.encode()))
    if xfp is not None:
        hdrs.append((b"x-forwarded-proto", xfp.encode()))
    return Request({"type": "http", "method": "GET", "path": "/", "headers": hdrs,
                    "scheme": "http", "server": (peer, 80), "query_string": b"",
                    "root_path": "", "client": (peer, 40000)})


def with_nets(nets):
    return mock.patch.object(main, "trusted_networks", lambda: list(nets))


# The bug is only visible when NOTHING is configured. An earlier version of this
# harness stubbed trusted_networks() to [127.0.0.0/8] for the "loopback" cases,
# which made "loopback peer" and "configured proxy" the same thing: the shipped
# asymmetry passed, and reverting the fix produced a green run that looked like
# a broken test rather than a passing one.
NOTHING = []
CONFIGURED = [ipaddress.ip_network("10.9.0.0/16")]

print("=== 1. a local proxy's forwarding headers are believed, configured or not ===")
with with_nets(NOTHING):
    check("a loopback peer's X-Forwarded-For is honoured with NOTHING configured",
          main.client_ip(req("127.0.0.1", xff="203.0.113.55")) == "203.0.113.55",
          f"got {main.client_ip(req('127.0.0.1', xff='203.0.113.55'))} - every "
          f"visitor collapses onto the proxy's own address")
    check("a loopback peer's X-Forwarded-Proto: https is honoured",
          main.request_scheme(req("127.0.0.1", xfp="https")) == "https")

print()
print("=== 2. two customers behind that proxy must be two rate-limit keys ===")
with with_nets(NOTHING):
    a = main.client_ip(req("127.0.0.1", xff="203.0.113.55"))
    b = main.client_ip(req("127.0.0.1", xff="198.51.100.9"))
check("two different forwarded addresses are two different keys",
      a != b and a == "203.0.113.55" and b == "198.51.100.9", f"{a} vs {b}")

print()
print("=== 3. a REMOTE peer still cannot spoof (the reason loopback is safe) ===")
with with_nets(NOTHING):
    remote = main.client_ip(req("203.0.113.250", xff="1.2.3.4"))
check("an untrusted remote peer's X-Forwarded-For is ignored",
      remote == "203.0.113.250", f"got {remote} - a remote client could then mint "
      f"a fresh rate-limit key per request")
with with_nets(CONFIGURED):
    check("an untrusted remote peer's X-Forwarded-Proto: https is ignored",
      main.request_scheme(req("203.0.113.250", xfp="https")) == "http")
with with_nets(CONFIGURED):
    check("a configured remote proxy IS honoured (that is the point of the list)",
          main.client_ip(req("10.9.9.9", xff="1.2.3.4")) == "1.2.3.4",
          f"got {main.client_ip(req('10.9.9.9', xff='1.2.3.4'))}")

print()
print("=== 4. the two functions agree, which is the invariant that broke ===")
for peer, xff, xfp, label in (
        ("127.0.0.1", "203.0.113.55", "https", "loopback proxy, nothing configured"),
        ("10.9.9.9", "1.2.3.4", "https", "configured remote proxy"),
        ("203.0.113.250", "1.2.3.4", "https", "untrusted remote")):
    nets = CONFIGURED if label == "configured remote proxy" else NOTHING
    with with_nets(nets):
        trusts_proto = main.request_scheme(req(peer, xff=xff, xfp=xfp)) == "https"
        trusts_for = main.client_ip(req(peer, xff=xff)) != peer
    check(f"{label}: scheme and address are believed together, or not at all",
          trusts_proto == trusts_for,
          f"scheme_believed={trusts_proto} address_believed={trusts_for}")

print()
print("=== 5. a malformed or absent header must not break anything ===")
with with_nets(NOTHING):
    check("no X-Forwarded-For at all -> the peer address",
          main.client_ip(req("127.0.0.1")) == "127.0.0.1")
    check("a junk X-Forwarded-For falls back to the peer",
          main.client_ip(req("127.0.0.1", xff="not-an-ip")) == "127.0.0.1")
    check("an XFF chain of junk still falls back",
          main.client_ip(req("127.0.0.1", xff="junk, 203.0.113.9")) == "203.0.113.9")
    check("a bare X-Forwarded-Proto: http is not https",
          main.request_scheme(req("127.0.0.1", xfp="http")) == "http")

print(f"  === {n - len(fails)}/{n} checks passed ===")
sys.exit(1 if fails else 0)
