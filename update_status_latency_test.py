"""The update page must never wait on GitHub. Enforced, and proved red.

Measured on this machine, before the fix:

    _update_status()                       12.0 s
    _github_json (the call it makes)       11.6 s   getaddrinfo failed
    raw api.github.com/rate_limit         18.1 s
    functional_test.py's request timeout  20.0 s

The suite reported it as "update status shape got 0". A status of 0 is not a
shape mismatch - it is the client reporting a request that never completed -
and the panel log held no traceback. The same commit passed on the next run,
which is what identified it as latency rather than a regression. It is
reproducible here because this machine's link to api.github.com is genuinely
slow, which is why the stub in this file sleeps instead of calling out.

Why it matters beyond a slow page: the panel is enforced single-worker, and
/api/update/status is a GET a browser polls every 5 seconds, so a request parked
in a network timeout holds a worker thread for the whole duration.

What this guards:
  - a plain read does not block on the network;
  - the GitHub half is fetched at most once per TTL, not once per request;
  - a cold answer says it is still checking instead of silently reporting
    "no update available", which during an outage reads as "you are current";
  - ?fresh=1 still forces a real refresh, because the update poller depends on it;
  - the request path contains no direct call to the network helper at all.

    .venv\\Scripts\\python.exe update_status_latency_test.py
"""
import ast
import io
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, r"C:\Users\mrlurix\AppData\Local\Temp\opencode")

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MAIN = os.path.join(ROOT, "main.py")
SRC = io.open(MAIN, encoding="utf-8").read()
results = []

# --------------------------------------------------------------------------
# Child mode. The parent mutates main.py and re-runs this file; the child says
# which guard it broke, and nothing else, so the parent can look for one token.
# --------------------------------------------------------------------------
if os.environ.get("ZEFIRA_LATENCY_CHILD") == "1":
    import main as _panel  # the MUTATED module

    STUB_C = 1.5
    _n = {"n": 0}
    _real = _panel._github_json

    def _stub(path):
        _n["n"] += 1
        time.sleep(STUB_C)
        return False, "stubbed network"

    # The arguments the ROUTE would pass, read from the route itself. Calling
    # _update_status(wait=...) with a hand-picked value tested this script's
    # choice rather than the code's, so removing the `0.0` from the route - the
    # mutation that reintroduces the stall - changed nothing the child saw.
    _src0 = io.open(MAIN, encoding="utf-8").read()
    _route_src = ""
    for _f in ast.parse(_src0).body:
        if isinstance(_f, ast.FunctionDef) and _f.name == "api_update_status":
            _route_src = ast.get_source_segment(_src0, _f) or ""
    # Match the call that passes `force=` - the only one there is. A bare
    # `wait=` search finds the first of the two `ent[0] if ent else
    # _update_status(wait=0.0)` fallbacks instead, which is the right answer
    # for the wrong reason and cannot go red when the real call changes.
    _mc = re.search(r"_update_status\(wait=(.+?),\s*force=([^)]+)\)", _route_src)
    if _mc is None:
        print("GUARD:route the route no longer passes both wait and force")
        raise SystemExit(0)
    _wait_plain = eval(_mc.group(1).strip(),
                       {"fresh": False,
                        "_UPDATE_REMOTE_WAIT": _panel._UPDATE_REMOTE_WAIT})
    _force_fresh = eval(_mc.group(2).strip(), {"fresh": True})

    _panel._github_json = _stub
    try:
        _panel._update_remote["data"] = None
        _panel._update_remote["at"] = 0.0
        _panel._update_remote_busy.clear()
        _t = time.time()
        _out = _panel._update_status(wait=_wait_plain, force=False)
        _cold = time.time() - _t
        if _cold >= STUB_C / 2:
            print("GUARD:latency cold read took %.3fs against a %.1fs network"
                  % (_cold, STUB_C))

        _keys = ("current", "latest", "incoming", "local_log", "error", "version",
                 "update_available", "updating", "unit_warning", "restart_pending",
                 "signature", "signature_detail", "latest_full", "repo", "branch")
        _missing = [k for k in _keys if k not in _out]
        if _missing:
            print("GUARD:shape missing %s" % ", ".join(_missing))

        if _out.get("error") != "checking upstream...":
            print("GUARD:cold error=%r" % str(_out.get("error"))[:60])

        _panel._update_remote_done.wait(timeout=STUB_C * 3)
        _before = _n["n"]
        _panel._update_status(wait=0.0)
        if _n["n"] != _before:
            print("GUARD:cache the stub ran %d more time(s) on a warm cache"
                  % (_n["n"] - _before))

        # Same for ?fresh=1: ask with whatever force the ROUTE would pass.
        _before = _n["n"]
        _panel._update_status(wait=STUB_C * 3, force=_force_fresh)
        if _n["n"] == _before:
            print("GUARD:force ?fresh=1 served the cache instead of re-fetching")

        # The last mutation puts a network call back in the worker's own body,
        # which the timing checks above cannot see: a request that reaches the
        # network directly is exactly the defect, so it has to be read.
        _src = io.open(MAIN, encoding="utf-8").read()
        _tree = ast.parse(_src)
        for _f in _tree.body:
            if isinstance(_f, ast.FunctionDef) and _f.name == "api_update_status":
                _seg = ast.get_source_segment(_src, _f) or ""
                if "_github_json(" in _seg:
                    print("GUARD:inline the route calls the network helper itself")
        _for_f = next((_f for _f in _tree.body
                       if isinstance(_f, ast.FunctionDef)
                       and _f.name == "_update_status"), None)
        if _for_f is not None:
            _seg = ast.get_source_segment(_src, _for_f) or ""
            if "_github_json(" in _seg:
                print("GUARD:inline _update_status calls the network helper itself")
    finally:
        _panel._github_json = _real
    raise SystemExit(0)


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print("[%s] %s" % ("\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m", name)
          + (("  (%s)" % detail) if detail and not cond else ""))


def body_of(name):
    """The source of a top-level function, by AST rather than by index."""
    tree = ast.parse(SRC)
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(SRC, n) or ""
    return ""


# --------------------------------------------------------------------------
# Behaviour, against the real functions with the network replaced by a sleep.
# --------------------------------------------------------------------------
print()
print("  --- behaviour: the request path must not wait on the network ---")

import main as panel  # noqa: E402

STUB = 1.5          # a slow "GitHub"
calls = {"n": 0}
real_github_json = panel._github_json


def slow_stub(path):
    calls["n"] += 1
    time.sleep(STUB)
    return False, "stubbed network"


panel._github_json = slow_stub
try:
    # A cold cache, and a request that does not wait.
    panel._update_remote["data"] = None
    panel._update_remote["at"] = 0.0
    panel._update_remote_busy.clear()
    t0 = time.time()
    out = panel._update_status(wait=0.0)
    cold_dt = time.time() - t0
    print("    cold read with a %.1fs 'GitHub': %.3fs" % (STUB, cold_dt))
    # The CHECK is made further down, once the warm read has been timed.
    # The invariant is "the cold read did not wait for the network", and a
    # fixed fraction of the stub measures the MACHINE as much as the panel:
    # on a loaded box the cold read crossed STUB/2 and the check failed
    # while the read was still plainly not waiting - the stub alone costs
    # 1.5s. What has to be true is that the cold read costs LESS THAN THE
    # STUB more than the warm one does on the same machine.

    keys = ("current", "latest", "incoming", "local_log", "error", "version",
            "update_available", "updating", "unit_warning", "restart_pending",
            "signature", "signature_detail", "latest_full", "repo", "branch")
    missing = [k for k in keys if k not in out]
    check("the payload keeps every key it always had",
          not missing, "missing %s" % ", ".join(missing))
    check("a cold answer says it is still checking",
          out.get("error") == "checking upstream...",
          repr(str(out.get("error"))[:50]))
    check("a cold answer does not claim an update is available",
          out.get("update_available") is False)
    check("a cold answer still reports the local truth",
          bool(out.get("current")) and bool(out.get("version")),
          "current=%r version=%r" % (out.get("current"), out.get("version")))

    # Let the background thread finish, then confirm it is cached.
    panel._update_remote_done.wait(timeout=STUB * 3)
    t0 = time.time()
    out2 = panel._update_status(wait=0.0)
    warm_dt = time.time() - t0
    before = calls["n"]
    panel._update_status(wait=0.0)
    again = calls["n"]
    print("    warm read: %.3fs   stub invocations: %d then %d"
          % (warm_dt, before, again))
    print("    cold read: %.3fs   warm read: %.3fs   extra: %.3fs"
          % (cold_dt, warm_dt, cold_dt - warm_dt))
    check("a plain read does not block on the network",
          cold_dt - warm_dt < STUB / 2,
          "the cold read cost %.3fs more than the warm one, and the "
          "stub alone costs %.1fs" % (cold_dt - warm_dt, STUB))
    check("the GitHub half is fetched once and then cached",
          again == before, "the stub ran %d more time(s) on a warm cache" % (again - before))
    check("a warm read is fast", warm_dt < STUB / 2, "%.3fs" % warm_dt)

    # force= (what ?fresh=1 does) must actually re-fetch.
    out3 = panel._update_status(wait=STUB * 3, force=True)
    check("force=True re-fetches rather than serving the cache",
          calls["n"] > again, "the stub was not called again")
    check("a forced refresh reports what the network said",
          out3.get("error") == "stubbed network",
          repr(str(out3.get("error"))[:50]))
finally:
    panel._github_json = real_github_json

# --------------------------------------------------------------------------
# Structure: the request path must not name the network helper at all.
# --------------------------------------------------------------------------
print()
print("  --- structure: only the background function may call GitHub ---")
route = body_of("api_update_status")
check("the route does not call _github_json directly",
      "_github_json(" not in route)
check("the route reaches the network only through _update_status",
      "_update_status(" in route and "_update_remote_half(" not in route)
check("the route bounds the wait and passes fresh through as force",
      re.search(r"_update_status\(\s*wait=.*force=fresh\s*\)", route) is not None,
      "the wait/force arguments are not both there")
remote = body_of("_update_status_remote")
check("the GitHub calls live in _update_status_remote, which is the worker's job",
      remote.count("_github_json(") >= 2 and "_commit_verification(" in remote)
# `[^)]*` cannot cross the `)` inside args=(...), which is exactly where it
# sits in the real call - so it matched a correct file and reported FAIL.
check("_update_remote_half starts the refresh on a daemon thread",
      re.search(r"threading\.Thread\(.*?daemon=True",
                body_of("_update_remote_half"), re.S) is not None)
check("the wait bound is small enough to keep the page responsive",
      0 < panel._UPDATE_REMOTE_WAIT <= 5.0, "%r" % panel._UPDATE_REMOTE_WAIT)
check("the cache TTL is longer than the poller's interval, or every poll refetches",
      panel._UPDATE_REMOTE_TTL > 5.0, "%r" % panel._UPDATE_REMOTE_TTL)

# --------------------------------------------------------------------------
# Prove each of the above fails when its fix is removed.
# --------------------------------------------------------------------------
print()
print("  --- proving each check fails when its fix is removed ---")
BACKUP = os.path.join(os.environ.get("TEMP", "."), "main_latency_backup.py")

MUTATIONS = [
    ("the request path stops waiting on the network",
     "GUARD:latency",
     lambda s: s.replace("wait=_UPDATE_REMOTE_WAIT if fresh else 0.0, force=fresh",
                        "wait=_UPDATE_REMOTE_WAIT, force=fresh")),
    ("the payload loses a key it always had",
     "GUARD:shape",
     lambda s: s.replace('"restart_pending": _update_restart_pending,', "")),
    ("a cold answer stops admitting it is still checking",
     "GUARD:cold",
     lambda s: s.replace('"error": "checking upstream...",', '"error": "",')),
    ("the GitHub half is no longer cached between requests",
     "GUARD:cache",
     lambda s: s.replace("time_mod.monotonic() - _update_remote[\"at\"] < _UPDATE_REMOTE_TTL",
                        "False")),
    ("?fresh=1 no longer forces a refresh",
     "GUARD:force",
     lambda s: s.replace("force=fresh)", "force=False)")),
    # _update_status_remote is the BACKGROUND worker's body, so a call added
    # there is not on the request path and the child was right to stay green.
    # _update_status is what the route calls, so that is where it has to go.
    ("the GitHub calls move back into the request path",
     "GUARD:inline",
     lambda s: s.replace(
         "    rem = _update_remote_half(repo, branch, local, wait, force)",
         "    _github_json(f\"/repos/{repo}/commits/{branch}\")\n"
         "    rem = _update_remote_half(repo, branch, local, wait, force)")),
]

with io.open(MAIN, encoding="utf-8", newline="") as fh:
    original = fh.read()
io.open(BACKUP, "w", encoding="utf-8", newline="").write(original)

try:
    for label, token, fn in MUTATIONS:
        broken = fn(original)
        if broken == original:
            check("goes red without this fix: %s" % label, False,
                  "the mutation did not apply, so it proves nothing")
            continue
        io.open(MAIN, "w", encoding="utf-8", newline="").write(broken)
        try:
            r = subprocess.run([sys.executable, os.path.abspath(__file__)],
                               capture_output=True, text=True, timeout=240,
                               env=dict(os.environ, ZEFIRA_LATENCY_CHILD="1"))
            check("goes red without this fix: %s" % label, token in r.stdout,
                  "child said %r" % r.stdout.strip()[-160:])
        finally:
            io.open(MAIN, "w", encoding="utf-8", newline="").write(original)
    check("main.py restored byte-for-byte after mutation",
          io.open(MAIN, encoding="utf-8", newline="").read() == original)
finally:
    io.open(MAIN, "w", encoding="utf-8", newline="").write(original)
    try:
        os.remove(BACKUP)
    except OSError:
        pass

passed = sum(1 for _n, c in results if c)
print()
print("=== %d/%d checks passed ===" % (passed, len(results)))
sys.exit(0 if passed == len(results) else 1)