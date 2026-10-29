"""The restore's report must say what was LOST, not what was refused.

The report used to mix four different things under one number, and the
operator could not tell them apart:

  - the RESTORE_ORIGIN_KEYS (domain, public_url, trusted_proxies), which are
    reset ON PURPOSE
  - a REALITY key or Telegram chat id that belonged to ANOTHER server and
    could not be moved - a real loss, and the operator's customers lose their
    links until they re-provision
  - a node, inbound or tunnel that was already in the panel, where nothing
    was lost at all
  - a row that was genuinely rejected

Measured on a live panel, restoring 101 customers onto a panel that already
had its own nodes and inbounds:

    added_users: 101, skipped: 13, restored_snodes: 0, restored_inbounds: 0

and NONE of the 13 were lost. The operator reading that concludes they lost
thirteen customers.

This suite works on a COPY and checks both directions, because a report that
always says "nothing was lost" is as useless as one that never says it:

  1. a clean restore: skipped is 0, already_present counts what was already
     there, refused counts the credentials, and the origin keys are counted
     as refused-by-design rather than as lost
  2. a restore whose REALITY secret belongs to another server: the report
     must say a setting was LOST, and `skipped` must still be 0
"""

import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:190])
                         if (detail and not cond) else ""))


WORK = tempfile.mkdtemp(prefix="zefira_report_")
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
PORT = 8220
BASE = "http://127.0.0.1:%d" % PORT
PW = "kf0MrM3rm0GLg47x"
OPENER = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(__import__("http.cookiejar",
                                                  fromlist=["x"]).CookieJar()))


def call(method, path, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    h = dict(headers or {})
    h.setdefault("X-Requested-With", "XMLHttpRequest")
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=h,
                                 method=method)
    try:
        with OPENER.open(req, timeout=120) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode("utf-8", "replace")


def login():
    """A restore revokes every session on purpose, so log in again."""
    call("POST", "/api/login", {"username": "admin", "password": PW},
         {"X-Requested-With": "XMLHttpRequest"})
    for h in OPENER.handlers:
        jar = getattr(h, "cookiejar", None)
        if jar:
            for c in jar:
                if c.name == "zefira_session":
                    return {"Cookie": "zefira_session=" + c.value,
                            "X-Requested-With": "XMLHttpRequest"}
    return {"X-Requested-With": "XMLHttpRequest"}


def restore(payload, CH):
    body = dict(payload)
    body["zefira_backup"] = True
    body["password_confirm"] = PW
    st, out = call("POST", "/api/restore", body, CH)
    return st, (out if isinstance(out, dict) else {})


# The runner deletes the admin row before every live suite, so this copy has
# no admin. Bootstrap the known account from the environment instead of
# relying on the demo DB's credential, which is no longer there.
con = sqlite3.connect(os.path.join(APP, "instance", "zefira.db"))
con.execute("delete from admins")
con.commit()
con.close()

proc = subprocess.Popen(
    [PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port",
     str(PORT), "--no-server-header", "--no-proxy-headers"],
    cwd=APP, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    env=dict(os.environ, ZEFIRA_ADMIN_USERNAME="admin",
             ZEFIRA_ADMIN_PASSWORD=PW))
try:
    for _ in range(280):
        time.sleep(0.25)
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2).read()
            break
        except urllib.error.HTTPError:
            break
        except Exception:
            continue
    CH = login()

    # The suite has to build its OWN fixtures. The runner resets the
    # instance's customers, nodes and inbounds before every suite, so a
    # test that backs up whatever happens to be there restores an EMPTY
    # file - which the panel rightly refuses, because restoring it would
    # delete every customer. That is correct behaviour and a broken test.
    for i in range(3):
        st, c = call("POST", "/api/users",
                     {"username": "rr_%d_%d" % (os.getpid(), i),
                      "protocols": ["vless"], "volume_gb": 20,
                      "days": 30}, CH)
        if st != 200:
            check("the suite can create its own customers", False, st)
    for i in range(2):
        st, _ = call("POST", "/api/server-nodes",
                      {"name": "rr node %d" % i,
                       "address": "rr%d.example.net" % i,
                       "check_port": 443, "note": ""}, CH)
        if st != 200:
            check("the suite can create its own nodes", False, st)
    for i in range(2):
        st, _ = call("POST", "/api/inbounds",
                      {"name": "rr_in_%d" % i,
                       "protocol": "vless", "port": 21000 + i,
                       "host": "", "enabled": True}, CH)
        if st != 200:
            check("the suite can create its own inbounds", False, st)

    st, payload = call("POST", "/api/backup", {"password_confirm": PW}, CH)
    check("the backup answers with a document", st == 200
          and isinstance(payload, dict), st)
    n_users = len(payload.get("users") or [])
    n_nodes = len(payload.get("server_nodes") or [])
    n_inb = len(payload.get("inbounds") or [])
    n_tok = len(payload.get("api_tokens") or [])
    n_adm = len(payload.get("admins") or [])
    print("  the file holds %d users, %d nodes, %d inbounds, %d tokens, "
          "%d admins" % (n_users, n_nodes, n_inb, n_tok, n_adm))

    # ---- 1. a clean restore -------------------------------------------------
    st, out = restore(payload, CH)
    check("the restore answers 200", st == 200, st)
    check("...and it added every customer",
          out.get("added_users") == n_users,
          "added_users=%r, the file had %d" % (out.get("added_users"),
                                              n_users))
    check("...and it reports NOTHING lost", out.get("skipped") == 0,
          "skipped=%r" % (out.get("skipped"),))
    check("...and the rows that were already there are counted apart",
          out.get("already_present") == n_nodes + n_inb,
          "already_present=%r, the panel already had %d nodes and %d inbounds"
          % (out.get("already_present"), n_nodes, n_inb))
    check("...and the credentials are counted as refused",
          out.get("refused") == n_tok + n_adm,
          "refused=%r, the file had %d tokens and %d admins"
          % (out.get("refused"), n_tok, n_adm))
    check("...and the origin keys are counted as REFUSED, not as lost",
          out.get("skipped_settings_refused") >= 1
          and out.get("skipped_settings_lost") == 0,
          "refused=%r lost=%r"
          % (out.get("skipped_settings_refused"),
             out.get("skipped_settings_lost")))
    # The note has to mention the categories the response does not
    # spell out on its own - already_present is the one an operator
    # reading "skipped: 0, restored_snodes: 0" needs most.
    check("...and the report explains what each number means",
          "already_present" in (out.get("counts_note") or ""),
          str(out.get("counts_note"))[:120])

    # ---- 2. a REALITY secret that belongs to another server ----------------
    CH = login()
    broken = dict(payload)
    settings = dict(broken.get("settings") or {})
    settings["reality_priv_enc"] = "not-a-blob-this-server-cannot-decrypt"
    broken["settings"] = settings
    st, out2 = restore(broken, CH)
    check("a restore with another server's REALITY secret answers 200",
          st == 200, st)
    check("...and it says a setting was LOST",
          (out2.get("skipped_settings_lost") or 0) >= 1,
          "skipped_settings_lost=%r" % (out2.get("skipped_settings_lost"),))
    check("...and it still does not claim a customer was lost",
          out2.get("skipped") == 0, "skipped=%r" % (out2.get("skipped"),))
    check("...and the note points at the one that needs action",
          "skipped_settings_lost" in (out2.get("counts_note") or ""),
          str(out2.get("counts_note"))[:120])
finally:
    proc.terminate()
    try:
        proc.wait(timeout=25)
    except Exception:
        proc.kill()
    shutil.rmtree(WORK, ignore_errors=True)

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)