"""The customer dashboard link must actually reach the panel.

The bug this guards: install.sh writes ZEFIRA_DOMAIN= (empty) when the
operator presses Enter at the domain prompt. config.py then GUESSES the
server's own IP so the generated VPN configs are not shipped to the
zefira.example.com placeholder. public_base_url() treated that guess like a
CONFIGURED domain and returned scheme+host with no port, so on an install that
serves on 8000 with no reverse proxy the panel handed the operator

    http://203.0.113.7/sub/<token>

Port 80. On a fresh Ubuntu box that is nginx's default site, which answers
"404 Not Found / nginx/1.24.0 (Ubuntu)" for every path - exactly the report.
The panel was healthy the whole time; the link it printed was pointing at
something else.

This runs against a genuinely fresh database in a temp directory, because a
settings row left by an earlier suite makes the check pass for the wrong
reason.
"""
import importlib
import os
import shutil
import sys
import tempfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ["ZEFIRA_DOMAIN"] = ""          # what install.sh writes for IP mode
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="zefira-link-"), "t.db")
os.environ["SECRET_KEY_FILE"] = os.path.join(
    tempfile.gettempdir(), "zefira-link-secret.key")

import config  # noqa: E402
import main  # noqa: E402
from starlette.requests import Request  # noqa: E402

n = 0
fails = []


def check(label, ok, detail=""):
    global n
    n += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))
    if not ok:
        fails.append(label)


def req(host, port, scheme="http"):
    hdrs = [(b"host", host.encode())]
    if scheme == "https":
        hdrs.append((b"x-forwarded-proto", b"https"))
    return Request({"type": "http", "method": "GET", "path": "/", "headers": hdrs,
                    "scheme": scheme, "server": ("127.0.0.1", port),
                    "query_string": b"", "root_path": "", "client": ("1.2.3.4", 1)})


main.db.init()

print("=== IP mode: operator pressed Enter at the domain prompt ===")
check("the domain really is a guess, not something the operator typed",
      config.DOMAIN_IS_GUESS is True, f"DOMAIN_IS_GUESS={config.DOMAIN_IS_GUESS!r}")

base = main.public_base_url(req("1.2.3.4:8000", 8000))
check("the dashboard link keeps the port the panel serves on",
      base.endswith(":8000"), f"got {base!r} - without the port the customer "
      f"lands on port 80, which is nginx's default site, and gets a 404")
check("the link is not the placeholder domain",
      "zefira.example.com" not in base, f"got {base!r}")

print()
print("=== domain mode: a real domain must NOT inherit a request port ===")
os.environ["ZEFIRA_DOMAIN"] = "vpn.example.org"
importlib.reload(config)
importlib.reload(main)
main.db.init()
dom_base = main.public_base_url(req("vpn.example.org:8443", 8443))
check("a configured domain stays scheme+host with no port",
      dom_base == "http://vpn.example.org", f"got {dom_base!r}")
check("the configured domain is not treated as a guess",
      config.DOMAIN_IS_GUESS is False, f"DOMAIN_IS_GUESS={config.DOMAIN_IS_GUESS!r}")

print()
print("=== the Host header must not steer a configured domain ===")
spoof = main.public_base_url(req("attacker.example.net:9999", 9999))
check("a spoofed Host cannot move a configured domain",
      spoof == "http://vpn.example.org", f"got {spoof!r}")

print()
print("=== the fix is exactly the guessed-domain case, nothing wider ===")
os.environ["ZEFIRA_DOMAIN"] = ""
importlib.reload(config)
importlib.reload(main)
main.db.init()
check("a guessed domain on the default port still omits it",
      main.public_base_url(req("1.2.3.4", 80)) == f"http://{config.DOMAIN}",
      f"got {main.public_base_url(req('1.2.3.4', 80))!r}")
check("a guessed domain behind https keeps the scheme and adds the port",
      main.public_base_url(req("1.2.3.4:8443", 8443, "https")) == f"https://{config.DOMAIN}:8443",
      f"got {main.public_base_url(req('1.2.3.4:8443', 8443, 'https'))!r}")

print(f"  === {n - len(fails)}/{n} checks passed ===")
sys.exit(1 if fails else 0)
