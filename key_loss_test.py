"""A missing master key must not silently destroy the data it protects.

The panel was careful about an EXISTING but unusable key: it refuses to start,
because replacing the master key would sign out every session and make every
Fernet blob permanently undecryptable.

A MISSING key took the other branch and a new one was generated. Measured on a
live panel: delete instance/secret.key, keep instance/zefira.db, and the
panel started without a word, showed all 100 customers, and every encrypted
field among them - the REALITY key, the Telegram token, the AI key, every
customer's private config - was gone.

The comment in the code said "delete it to intentionally start a fresh
instance", which is only true when the DATABASE is fresh too. So now a missing
key plus an existing database is a LOST KEY, and the panel says so.

This suite copies the instance directory and works on the COPY, so the real
one is never touched. It checks all four cases, because a check that only
proves the refusal also has to prove the refusal is not over-eager: a panel
that refused to start a genuinely fresh instance would be just as broken.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:190])
                         if (detail and not cond) else ""))


# The panel is started against a COPY of the repository, so the real instance
# directory is never at risk. A copy of the whole tree is expensive, so the
# copy is made of the parts that matter: the application, the instance, and
# the VERSION file.
WORK = tempfile.mkdtemp(prefix="zefira_keycheck_")
APP = os.path.join(WORK, "app")
os.makedirs(APP, exist_ok=True)
for name in ("main.py", "config.py", "database.py", "security.py",
             "protocols.py", "schemas.py", "VERSION", "templates", "static"):
    src = os.path.join(ROOT, name)
    dst = os.path.join(APP, name)
    if os.path.isdir(src):
        shutil.copytree(src, dst, dirs_exist_ok=True)
    elif os.path.exists(src):
        shutil.copy2(src, dst)
shutil.copytree(os.path.join(ROOT, "instance"), os.path.join(APP, "instance"),
                dirs_exist_ok=True)

PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")


def run_panel(timeout=25):
    """Start the panel and report (started, output)."""
    proc = subprocess.Popen(
        [PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port",
         "8299", "--no-server-header", "--no-proxy-headers"],
        cwd=APP, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=dict(os.environ, PYTHONUNBUFFERED="1"),
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    out = b""
    started = False
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(0.3)
        try:
            import urllib.request
            urllib.request.urlopen("http://127.0.0.1:8299/login", timeout=1)
            started = True
            break
        except Exception:
            continue
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except Exception:
            proc.kill()
    try:
        out = proc.stdout.read() if proc.stdout else b""
    except Exception:
        out = b""
    return started, out.decode("utf-8", "replace")


KEY = os.path.join(APP, "instance", "secret.key")
DB = os.path.join(APP, "instance", "zefira.db")
key_backup = io.open(KEY, "rb").read() if os.path.exists(KEY) else None

# ---- 1. the normal case: the key is there, the panel starts ---------------
started, out = run_panel()
check("the panel starts normally with its key in place", started,
      out[-300:] if not started else "")
check("...and says nothing about a missing key", "is missing" not in out,
      out[-300:])

# ---- 2. the bug: the key is gone, the database is not ---------------------
if key_backup is not None:
    os.remove(KEY)
    started, out = run_panel()
    check("with the key GONE and the database present, the panel REFUSES "
          "to start", not started, "it started anyway")
    check("...and it says WHY", "is missing" in out and "database" in out,
          out[-400:])
    check("...and it says how to get out of it",
          "Restore the key" in out or "restore the key" in out.lower(),
          out[-400:])
    check("...and it names what would be destroyed",
          "undecryptable" in out, out[-400:])
    io.open(KEY, "wb").write(key_backup)

# ---- 3. a genuinely fresh instance: no key AND no database ----------------
os.remove(KEY)
db_backup = io.open(DB, "rb").read() if os.path.exists(DB) else None
if db_backup is not None:
    os.remove(DB)
started, out = run_panel()
check("a genuinely fresh instance - no key and no database - still starts",
      started, out[-300:] if not started else "")
check("...and it created a key", os.path.exists(KEY))
if key_backup is not None:
    io.open(KEY, "wb").write(key_backup)
if db_backup is not None:
    io.open(DB, "wb").write(db_backup)

# ---- 4. a key missing but an EMPTY database file --------------------------
# An empty file is not a database with data in it, so this is still fresh.
if key_backup is not None:
    os.remove(KEY)
    io.open(DB, "wb").write(b"")
    started, out = run_panel()
    check("a key missing but an EMPTY database file still starts", started,
          out[-300:] if not started else "")
    io.open(KEY, "wb").write(key_backup)
    io.open(DB, "wb").write(db_backup)

# ---- 5. and the real instance was never touched ---------------------------
REAL_KEY = os.path.join(ROOT, "instance", "secret.key")
if key_backup is not None and os.path.exists(REAL_KEY):
    check("the real instance's key was never touched",
          io.open(REAL_KEY, "rb").read() == key_backup)

shutil.rmtree(WORK, ignore_errors=True)

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)