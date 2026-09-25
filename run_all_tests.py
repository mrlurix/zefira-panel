"""Run every suite back-to-back on one panel, restarting between them.

Proves the suites are order-independent (no hidden state carried over) and
that the security fixes hold under the live adversarial probes too.
Usage: .venv\\Scripts\\python run_all_tests.py [admin] [password]
"""
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
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
    "c.execute(\"update settings set value='' where key in "
    "('tg_bot_token','tg_chat_id','ai_api_key_enc')\");"
    "c.execute(\"update settings set value='0' where key='ai_enabled'\");"
    "c.commit()"
)


def reset_db(when):
    try:
        subprocess.check_call([PY, "-c", RESET_SQL], cwd=ROOT, stdout=subprocess.DEVNULL)
    except Exception as exc:
        print(f"[warn] db reset {when} failed: {exc}")


results = []
for script, label in SUITES:
    # Reset BEFORE each suite too: a dirty workdir (leftovers from manual
    # testing) must never decide a suite's result.
    reset_db(f"before {label}")
    proc = subprocess.Popen(
        [PY, "-m", "uvicorn", "main:app", "--host", HOST, "--port", str(PORT),
         "--no-server-header", "--no-proxy-headers", "--no-access-log"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    if not wait_up():
        print(f"[FAIL] {label}: server did not start")
        stop(proc)
        sys.exit(1)
    print(f"\n===== {label} ({script}) =====")
    rc = subprocess.call([PY, script, BASE, ADMIN, PASSWORD], cwd=ROOT)
    results.append((label, rc))
    stop(proc)
    time.sleep(1)
    # Each suite gets a clean slate: rows the previous one intentionally left
    # (password-change token revocations, restored admins…) must not decide
    # the next suite's result.
    reset_db(f"after {label}")

print("\n===== ALL SUITES =====")
bad = 0
for label, rc in results:
    print(f"{'PASS' if rc == 0 else 'FAIL'}  {label}")
    if rc != 0:
        bad += 1
print(f"\n{len(results) - bad}/{len(results)} suites passed")
sys.exit(1 if bad else 0)
