"""The rule that decides WHO a request is.

client_ip() answers one question - whose request is this? - and the answer
goes into the rate limiter it spends, the audit row it writes and the admin
session it belongs to. It is the function that makes "we rate-limit by IP"
mean anything.

So this tests the RULE, with a synthetic peer, rather than the deployment. A
test client always connects from the loopback, and the loopback is exactly the
peer the panel trusts - so an end-to-end probe can only ever exercise the
trusted case and says nothing about the untrusted one, which is the case an
attacker is in.

The rule, stated once:

  - the peer is NOT trusted  -> the header is ignored entirely and the socket
    address is the answer. A client that forges the header gains nothing.
  - the peer IS trusted      -> the header is walked from the RIGHT and the
    first hop that is not itself trusted is the answer. The hop a proxy
    appended is the real client; anything the client put in front of it is
    ignored.

The second case depends on the proxy APPENDING. That is how HTTP is meant to
work and what the installer's nginx does ($proxy_add_x_forwarded_for), but it
is worth stating rather than assuming.
"""

import io
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:190])
                         if (detail and not cond) else ""))


import main as panel  # noqa: E402
from starlette.requests import Request  # noqa: E402


def scope(client, xff=None, trusted="127.0.0.1"):
    headers = []
    if xff is not None:
        headers.append((b"x-forwarded-for", xff.encode()))
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/me",
        "raw_path": b"/api/me",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": client,
        "server": ("127.0.0.1", 8000),
        "state": {},
    }


def resolve(client, xff=None):
    return panel.client_ip(Request(scope(client, xff)))


# The panel's own trusted-proxy setting, read from the instance. The installer
# writes 127.0.0.1 for the same-host nginx case.
import sqlite3  # noqa: E402
DB = os.path.join(ROOT, "instance", "zefira.db")
try:
    con = sqlite3.connect(DB)
    row = con.execute("SELECT value FROM settings WHERE key='trusted_proxies'"
                      ).fetchone()
    con.close()
except Exception:
    row = None
print("  the panel's trusted_proxies setting: %r" % (row[0] if row else None,))
print()

# ---- (1) an UNTRUSTED peer forges the header -------------------------------
check("an untrusted peer with a forged header is answered by its socket "
      "address",
      resolve(("198.51.100.4", 1234), "203.0.113.9") == "198.51.100.4",
      resolve(("198.51.100.4", 1234), "203.0.113.9"))
check("...even with a whole chain of forged hops",
      resolve(("198.51.100.4", 1234), "203.0.113.9, 10.0.0.1")
      == "198.51.100.4",
      resolve(("198.51.100.4", 1234), "203.0.113.9, 10.0.0.1"))
check("...and with no header at all it is still the socket address",
      resolve(("198.51.100.4", 1234), None) == "198.51.100.4",
      resolve(("198.51.100.4", 1234), None))

# ---- (2) a TRUSTED peer, with the proxy's appended hop ---------------------
check("a trusted peer with the proxy's appended hop resolves to the REAL "
      "client",
      resolve(("127.0.0.1", 1234), "203.0.113.9, 198.51.100.4")
      == "198.51.100.4",
      resolve(("127.0.0.1", 1234), "203.0.113.9, 198.51.100.4"))
check("...and the forged hop in front of it is ignored",
      resolve(("127.0.0.1", 1234), "203.0.113.9, 198.51.100.4")
      != "203.0.113.9",
      resolve(("127.0.0.1", 1234), "203.0.113.9, 198.51.100.4"))
check("...and a trusted peer with no header is the peer itself",
      resolve(("127.0.0.1", 1234), None) == "127.0.0.1",
      resolve(("127.0.0.1", 1234), None))

# ---- (3) the rule the deployment depends on --------------------------------
# A trusted proxy that PASSES the header through unchanged, without appending,
# hands the client the last word. That is a property of HTTP's X-Forwarded-For
# and of the proxy, not of the panel - but it is the thing an operator must
# get right, so it is worth stating out loud rather than discovering.
_appended = resolve(("127.0.0.1", 1234), "203.0.113.9, 198.51.100.4")
_not_appended = resolve(("127.0.0.1", 1234), "203.0.113.9")
print("  with the proxy appending the real hop : %s" % _appended)
print("  with the proxy passing it through     : %s" % _not_appended)
print()

# ---- (4) a malformed header must not crash or mislead ----------------------
for bad in ("", "   ", "not-an-ip", "1.2.3.4, not-an-ip, 5.6.7.8",
            "999.999.999.999", "::1", "1.2.3.4,", ",1.2.3.4"):
    try:
        got = resolve(("198.51.100.4", 1234), bad)
        ok_res = isinstance(got, str) and got
        check("a malformed header %r does not break the resolution" % bad,
              bool(ok_res), got)
    except Exception as exc:
        check("a malformed header %r does not break the resolution" % bad,
              False, repr(exc))

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)