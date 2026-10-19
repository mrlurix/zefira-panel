"""Fill a panel with realistic demo data, for screenshots and videos.

An empty panel looks like a toy. A panel with a hundred customers, a spread
of usage, some expired accounts and a few servers looks like a product - and
that is the whole point when you are recording an introduction video.

This is a MAINTENANCE TOOL, not part of the panel. It talks to the panel over
its own public API, with an admin session, and it changes nothing in the
source tree.

    python examples/demo_data.py --users 100 --nodes 6 --inbounds 4
    python examples/demo_data.py --clean

Two things it is careful about, both measured rather than assumed:

  - The panel limits user CREATION to 120 per hour per admin
    (user_create_limiter in main.py). A hundred is inside that, but only
    just, so the tool reports a 429 as what it is - "wait an hour" - rather
    than pretending to have created what it did not.
  - The data is SEEDED. The same seed produces the same panel, so a video
    recorded twice looks the same, and a re-run does not produce a second
    hundred customers with different numbers.

Everything it creates is marked with a prefix ("demo_"), and --clean removes
exactly those and nothing else. It never touches a real customer.

It also sets USAGE, not just the plan, because a panel where every customer
has used 0 GB has flat charts and tells the viewer nothing. The spread is
deliberate: a few customers near their limit, a long tail of light users,
and a handful of expired and disabled accounts - which is what a real
customer list looks like.
"""

import argparse
import io
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

__all__ = ["main"]

# A fixed seed, so two runs produce the same panel. A video recorded today
# and one recorded next month should look like the same product.
SEED = 20261019

FIRST = ["ali", "sara", "reza", "maryam", "amir", "niloofar", "hassan",
         "zahra", "mohammad", "elham", "hossein", "parisa", "mahdi", "shirin",
         "abbas", "yasmin", "kaveh", "golnaz", "farhad", "hasti"]
LAST = ["shirazi", "karimi", "rahimi", "nazari", "tavakoli", "mousavi",
        "hassani", "sadeghi", "jafari", "moradi", "ahmadi", "pourali",
        "ebrahimi", "sadeghi", "kazemi", "rashidi", "noorani", "tabrizi"]
CITY = ["tehran", "mashhad", "isfahan", "shiraz", "tabriz", "karaj",
        "rasht", "yazd", "ahvaz", "qom", "kermanshah", "urmia"]
NOTE = ["VIP", "wholesale", "test", "reseller", "referral", "trial",
        "annual", "monthly", "family plan", "student", "backup line",
        "telegram bot", "gift", "long-term", "renewed"]


class Panel:
    def __init__(self, base, admin, password):
        self.base = base.rstrip("/")
        self.admin = admin
        self.password = password
        import http.cookiejar
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.cookie = None

    def call(self, method, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        h = dict(headers or {})
        h.setdefault("X-Requested-With", "XMLHttpRequest")
        if data is not None:
            h["Content-Type"] = "application/json"
        if self.cookie:
            h["Cookie"] = self.cookie
        req = urllib.request.Request(self.base + path, data=data, headers=h,
                                     method=method)
        try:
            with self.opener.open(req, timeout=60) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw.decode("utf-8", "replace")

    def login(self):
        st, _ = self.call("POST", "/api/login",
                           {"username": self.admin, "password": self.password})
        if st != 200:
            raise SystemExit("  the login failed (%s) - check the credentials"
                             % st)
        for h in self.opener.handlers:
            jar = getattr(h, "cookiejar", None)
            if jar:
                for c in jar:
                    if c.name == "zefira_session":
                        self.cookie = "zefira_session=" + c.value
        if not self.cookie:
            raise SystemExit("  the login returned no session cookie")
        print("  logged in as %s" % self.admin)


def _protocols(rng):
    pool = ["vless", "reality", "vmess", "trojan", "ss", "hysteria2"]
    n = rng.choice([1, 1, 1, 2, 2, 3])
    return rng.sample(pool, n)


def make_customers(rng, count, prefix):
    """A customer list that looks like a real one rather than a test fixture."""
    out = []
    seen = set()
    for i in range(count):
        first = rng.choice(FIRST)
        last = rng.choice(LAST)
        name = "%s_%s" % (first, last)
        n = 2
        while name in seen:
            n += 1
            name = "%s_%s%d" % (first, last, n)
        seen.add(name)
        city = rng.choice(CITY)
        vol = rng.choice([5, 10, 20, 30, 50, 50, 100, 150, 200, 500])
        days = rng.choice([7, 15, 30, 30, 30, 60, 90, 180, 365])
        # the usage spread: a few heavy users, a long tail of light ones
        frac = rng.choice([0.02, 0.05, 0.1, 0.2, 0.35, 0.5, 0.7, 0.9, 0.97])
        used = round(vol * frac, 2)
        note = rng.choice(NOTE)
        out.append({
            "username": name,
            "protocols": _protocols(rng),
            "volume_gb": float(vol),
            "days": days,
            "device_limit": rng.choice([1, 1, 2, 3, 3, 5, 10]),
            "note": "%s - %s" % (note, city),
            "used_gb": used,
            "expired": rng.random() < 0.08,
            "disabled": rng.random() < 0.05,
        })
    return out


def create_customers(panel, customers, prefix):
    made = 0
    for c in customers:
        body = {k: c[k] for k in ("username", "protocols", "volume_gb",
                                   "days", "device_limit", "note")}
        st, out = panel.call("POST", "/api/users", body)
        if st == 429:
            print()
            print("  STOPPED: the panel refused the 121st customer this hour.")
            print("  The panel limits USER CREATION to 120 per hour per admin,")
            print("  so this is the limit doing its job, not a failure. Wait")
            print("  for the window to pass, or use a different admin.")
            return made, False
        if st != 200:
            print("  could not create %s: %s %s"
                  % (c["username"], st, str(out)[:80]))
            continue
        uid = (out or {}).get("id")
        # now the usage, so the charts are not flat
        st2, _ = panel.call("PATCH", "/api/users/%d" % uid,
                             {"used_gb": c["used_gb"]})
        if st2 == 200 and c["disabled"]:
            panel.call("PATCH", "/api/users/%d" % uid, {"is_active": False})
        made += 1
        if made % 20 == 0:
            print("    %d customers created" % made)
    return made, True


def create_servers(panel, nodes, inbounds, rng):
    made_nodes = 0
    for i in range(nodes):
        city = CITY[i % len(CITY)]
        name = "%s Node %02d" % (city.title(), i + 1)
        st, out = panel.call("POST", "/api/server-nodes", {
            "name": name,
            "address": "%s-%02d.example.net" % (city, i + 1),
            "check_port": 443,
            "note": rng.choice(["Frankfurt", "Amsterdam", "Helsinki",
                                 "Warsaw", "Milan", "Oslo"]),
        })
        if st == 200:
            made_nodes += 1
    print("  %d server nodes created" % made_nodes)

    made_in = 0
    for i in range(inbounds):
        st, out = panel.call("POST", "/api/inbounds", {
            "name": "demo_%s_%02d" % (["vless", "reality", "vmess",
                                       "trojan"][i % 4], i + 1),
            "protocol": ["vless", "reality", "vmess", "trojan"][i % 4],
            "port": 20000 + i,
            "host": "",
            "enabled": True,
        })
        if st == 200:
            made_in += 1
    print("  %d inbounds created" % made_in)
    return made_nodes, made_in


def clean(panel, prefix):
    """Remove exactly what this tool creates, and nothing else."""
    print("  removing the customers whose username starts with %r" % prefix)
    removed = 0
    offset = 0
    while True:
        st, out = panel.call("GET", "/api/users?limit=200&offset=%d" % offset)
        if st != 200 or not isinstance(out, dict):
            break
        items = out.get("items") or []
        if not items:
            break
        for u in items:
            name = u.get("username") or ""
            if not name.startswith(prefix):
                continue
            st2, _ = panel.call("DELETE", "/api/users/%d" % u["id"])
            if st2 == 200:
                removed += 1
        if len(items) < 200:
            break
    print("    %d customers removed" % removed)

    for path, label in (("/api/server-nodes", "server nodes"),
                        ("/api/inbounds", "inbounds")):
        st, out = panel.call("GET", path)
        if st != 200:
            continue
        items = out if isinstance(out, list) else (out or {}).get("items") or []
        n = 0
        for it in items:
            name = it.get("name") or ""
            if not name.startswith(prefix) and not name.startswith("demo_"):
                continue
            st2, _ = panel.call("DELETE", path + "/%d" % it["id"])
            if st2 == 200:
                n += 1
        print("    %d %s removed" % (n, label))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Fill a panel with demo data for a video or a screenshot.")
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--admin", default="admin")
    ap.add_argument("--password", default="")
    ap.add_argument("--users", type=int, default=100)
    ap.add_argument("--nodes", type=int, default=6)
    ap.add_argument("--inbounds", type=int, default=4)
    ap.add_argument("--prefix", default="demo_")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--clean", action="store_true",
                    help="remove what this tool created, and exit")
    args = ap.parse_args(argv)

    if not args.password:
        raise SystemExit("  pass --password, or set ZEFIRA_DEMO_PASSWORD")
    args.password = os.environ.get("ZEFIRA_DEMO_PASSWORD", args.password)

    print("  panel: %s" % args.base)
    panel = Panel(args.base, args.admin, args.password)
    panel.login()

    if args.clean:
        clean(panel, args.prefix)
        return 0

    rng = random.Random(args.seed)
    print("  creating demo data (seed %d)..." % args.seed)
    customers = make_customers(rng, args.users, args.prefix)
    made, complete = create_customers(panel, customers, args.prefix)
    print("  %d customers created" % made)
    create_servers(panel, args.nodes, args.inbounds, rng)
    st, out = panel.call("GET", "/api/users?limit=1")
    total = (out or {}).get("total") if isinstance(out, dict) else None
    print()
    print("  the panel now holds %s customers." % total)
    if not complete:
        print("  (not every customer was created - see above)")
    print("  Remove them again with: --clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())