"""Run every suite back-to-back on one panel, restarting between them.

Proves the suites are order-independent (no hidden state carried over) and
that the security fixes hold under the live adversarial probes too.
Usage: .venv\\Scripts\\python run_all_tests.py [admin] [password]
"""
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
# Per-run panel logs, outside the repo so a failing run never leaves untracked
# files in the tree the pre-push gate inspects.
LOG_DIR = os.path.join(tempfile.gettempdir(), "zefira-suite-logs")
os.makedirs(LOG_DIR, exist_ok=True)
ADMIN = sys.argv[1] if len(sys.argv) > 1 else "admin"
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else "YOUR_PASSWORD"
HOST, PORT = "127.0.0.1", "8011"
BASE = f"http://{HOST}:{PORT}"
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
if not os.path.exists(PY):
    PY = sys.executable

SUITES = [
    ("feature_test.py", "feature coverage"),
    ("security_test.py", "security / abuse"),
    ("functional_test.py", "functional flows"),
    ("attack_test.py", "live attack probes"),
    ("attack_quota_test.py", "quota / schema boundaries"),
    ("attack_paths_test.py", "operator paths / restore"),
    ("frontend_bugs_test.py", "front-end regressions"),
    ("panel_sections_test.py", "panel sections end-to-end"),
    ("security_audit_test.py", "security audit round 1"),
]
# Suites that need no running panel: static guards over the installer, which
# is only ever executed on a Linux VPS (never here), and the docs site.
OFFLINE_SUITES = [
    ("installer_test.py", "installer CLI"),
    # Runs public_base_url() against a genuinely fresh database with
    # ZEFIRA_DOMAIN= (what install.sh writes when the operator pressed Enter at
    # the domain prompt). No server, no suite state. This is the check that was
    # missing when every fresh install handed the customer a port-less link and
    # the customer got nginx's 404.
    ("dashboard_link_test.py", "customer dashboard link"),
    # client_ip() and request_scheme() disagreed on what a trusted peer is, so
    # a panel behind a local reverse proxy believed the scheme but not the
    # address - every visitor collapsed onto one rate-limit key and a flood
    # locked the operator out of login. DB-free; trusted_networks() is stubbed
    # to the EMPTY case, because stubbing it to a loopback network makes the
    # configured and unconfigured cases identical and hides the whole defect.
    ("proxy_trust_test.py", "proxy trust + client IP"),
    # ss/hysteria2/REALITY interpolated the remark raw while vless/trojan
    # percent-encoded it, so a name carrying "#" split the link into three
    # fragments and the client showed "a". Runs the real builders, offline.
    ("link_encoding_test.py", "share-link remark encoding"),
    ("i18n_test.py", "docs i18n dictionaries"),
    # Reads the route table out of main.py, the sidebar out of app.js and the
    # setting keys out of protocols.py, then requires a real mention in the
    # real HTML. Written because the docs covered every feature in prose and
    # still shipped five endpoints and seventeen setting names nowhere.
    ("docs_coverage_test.py", "docs cover the panel"),
    # Runs the shipped i18n.js and reads the resulting object, so a key that is
    # missing or empty in one language is a failure. Loading the file caught
    # six empty translations on its first run, in three languages.
    ("__NODE__ i18n_dict_check.js", "docs i18n coverage"),
    ("__NODE__ i18n_render_check.js", "docs i18n renderer safety"),
]


def wait_up(timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(BASE + "/api/me", timeout=2)
            return True
        except urllib.error.HTTPError:
            return True  # 401 means the app is up
        except Exception:
            time.sleep(0.5)
    return False


def stop(proc):
    if proc and proc.poll() is None:
        try:
            os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
        except Exception:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


RESET_SQL = (
    "import sqlite3;"
    "c=sqlite3.connect('instance/zefira.db');"
    "[c.execute('delete from '+t) for t in "
    "('vpn_users','inbounds','server_nodes','tunnel_nodes','user_templates',"
    "'api_tokens','blocked_sites')];"
    # block_direct_ip must NEVER survive into a suite: with it on, the panel
    # (correctly) refuses every request that arrives on 127.0.0.1, and the
    # whole suite talks to 127.0.0.1.
    "c.execute(\"update settings set value='0' where key='block_direct_ip'\");"
    "c.execute(\"update settings set value='' where key in "
    "('tg_bot_token','tg_chat_id','ai_api_key_enc')\");"
    "c.execute(\"update settings set value='0' where key='ai_enabled'\");"
    # trusted_proxies is the key of every per-IP rate limiter, and
    # ai_base_url/ai_extra steer the assistant: a suite that plants either (the
    # security one does, on purpose) must not hand it to the next suite.
    "c.execute(\"update settings set value='' where key='trusted_proxies'\");"
    "c.execute(\"update settings set value='' where key in "
    "('ai_base_url','ai_extra')\");"
    "c.commit()"
)


def reset_db(when):
    try:
        subprocess.check_call([PY, "-c", RESET_SQL], cwd=ROOT, stdout=subprocess.DEVNULL)
    except Exception as exc:
        print(f"[warn] db reset {when} failed: {exc}")


results = []

# When this harness's output is REDIRECTED to a file, the child's writes go
# straight to the shared fd while the parent's own stdout stays block-buffered,
# so the two interleave and the transcript stops being a faithful record. It
# cost real time here: frontend_bugs_test.py's "130/130 passed" line vanished
# from the captured log, which made the run look like 902 checks across eight
# counted suites when it is 1032 across nine, and sent me attributing another
# suite's count to the wrong file. Unbuffer the parent and the children, so the
# transcript is ordered and complete.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
CHILD_ENV = dict(os.environ, PYTHONUNBUFFERED="1")

for script, label in SUITES:
    # Reset BEFORE each suite too: a dirty workdir (leftovers from manual
    # testing) must never decide a suite's result.
    reset_db(f"before {label}")
    # The panel's own output used to go to DEVNULL. A suite that failed with
    # `status 0` on one endpoint - which is what a crashed or wedged worker
    # looks like from the client side - left nothing behind to explain it, and
    # the only honest answer was "could not reproduce". Keep the log, and print
    # its tail when the suite fails, so a server-side fault is attributable to
    # a traceback instead of guessed at.
    log_path = os.path.join(LOG_DIR, re.sub(r"[^A-Za-z0-9_.-]", "_", script) + ".log")
    log_fh = open(log_path, "wb")
    proc = subprocess.Popen(
        [PY, "-m", "uvicorn", "main:app", "--host", HOST, "--port", str(PORT),
         "--no-server-header", "--no-proxy-headers", "--no-access-log"],
        cwd=ROOT, stdout=log_fh, stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    if not wait_up():
        print(f"[FAIL] {label}: server did not start")
        log_fh.close()
        stop(proc)
        sys.exit(1)
    print(f"\n===== {label} ({script}) =====")
    sys.stdout.flush()   # the header must land before the child's first line
    rc = subprocess.call([PY, script, BASE, ADMIN, PASSWORD], cwd=ROOT,
                         env=CHILD_ENV)
    results.append((label, rc))
    stop(proc)
    log_fh.close()
    if rc != 0:
        # Only on failure: a 40-line traceback in a passing transcript is noise
        # that trains people to skip the output.
        try:
            with open(log_path, "rb") as fh:
                tail = fh.read()[-6000:].decode("utf-8", "replace")
        except OSError:
            tail = ""
        interesting = [ln for ln in tail.splitlines()
                       if ln.strip() and "Traceback" in ln or "Error" in ln
                       or "Exception" in ln or "CRITICAL" in ln]
        if interesting:
            print(f"----- panel log for {label} ({log_path}) -----")
            for ln in interesting[-25:]:
                print("  " + ln[:160])
        else:
            print(f"----- panel log for {label}: no traceback in {log_path} -----")
    time.sleep(1)
    # Each suite gets a clean slate: rows the previous one intentionally left
    # (password-change token revocations, restored admins…) must not decide
    # the next suite's result.
    reset_db(f"after {label}")

print("\n===== ALL SUITES =====")
for script, label in OFFLINE_SUITES:
    print(f"\n===== {label} ({script}) =====")
    sys.stdout.flush()   # the header must land before the child's first line
    # "__NODE__ foo.js" runs a harness under node instead of the interpreter.
    # A missing node is recorded as a FAILURE, not skipped: i18n_test.py already
    # shells out to `node --check`, so node is a hard requirement of this suite
    # anyway, and a guard that quietly did not run is worse than no guard.
    if script.startswith("__NODE__ "):
        target = script[len("__NODE__ "):]
        node = shutil.which("node")
        if not node:
            print(f"[FAIL] {label}: node is not on PATH, so {target} did not run")
            results.append((label, 1))
            continue
        rc = subprocess.call([node, target], cwd=ROOT)
    else:
        rc = subprocess.call([PY, script], cwd=ROOT, env=CHILD_ENV)
    results.append((label, rc))

bad = 0
for label, rc in results:
    print(f"{'PASS' if rc == 0 else 'FAIL'}  {label}")
    if rc != 0:
        bad += 1
print(f"\n{len(results) - bad}/{len(results)} suites passed")
sys.exit(1 if bad else 0)
