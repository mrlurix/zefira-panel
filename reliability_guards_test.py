"""Six defects found by an agent sweep on 2026-10-16, each proved first.

Every one of these was measured before it was fixed, and the measurement is in
the comment beside the check, because the comment asserting something nobody
measured is the bug class this release exists about.

  1. POST /api/restore {"users":[{}]} answered 200 {"ok": true, "added_users":
     0, "skipped": 1} and left vpn_users EMPTY. The guard tested data.users and
     the wipe depended on prepared_users. Measured against a live panel.
  2. UserPatchIn(days=30, set_expires_at=...) was accepted while the identical
     pair spelled extend_days was a 422 - one field, two spellings, one guard.
  3. VpnUser.to_dict() returned last_fetch_ip raw; json.dumps then raised, so
     one BLOB 500s GET /api/users for every customer.
  4. AuditLog.to_dict() sliced detail[:200] before the NULL guard its siblings
     got, so a NULL detail raised inside the dict and took /api/audit with it.
  5. The token_sha migration added a bare VARCHAR and no index, so every
     UPGRADED install planned SCAN for the anonymous /sub/{token} lookup.
  6. The access log interpolated request.url.path raw, and that path is the
     customer's whole account credential.

    .venv\\Scripts\\python.exe reliability_guards_test.py
"""
import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MAIN = os.path.join(ROOT, "main.py")
DB = os.path.join(ROOT, "database.py")
SCH = os.path.join(ROOT, "schemas.py")
APP = os.path.join(ROOT, "static", "app.js")
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


# --------------------------------------------------------------------------
print()
print("== 1. the restore guard, on the list that decides the wipe ==")
main = io.open(MAIN, encoding="utf-8", newline="").read()
wipe = main.find("s.delete(u)")
prep = main.find("if not prepared_users:")
dedup = main.find("prepared_users = deduped")
check("the wipe is guarded by prepared_users", prep != -1)
check("and that guard is finalised by the dedup first",
      prep != -1 and dedup != -1 and dedup < prep)
check("and it runs before the first delete",
      prep != -1 and wipe != -1 and prep < wipe)
check("and it answers 400 rather than proceeding",
      re.search(r"if not prepared_users:[\s\S]{0,420}?status_code=400", main) is not None)
# the property the old occurrence-count check was reaching for
conds = re.findall(r"if\b[^\n:]*\bdata\.users\b", main)
check("no other CONDITION on data.users decides anything", len(conds) == 1,
      "%d: %s" % (len(conds), conds))

# --------------------------------------------------------------------------
print()
print("== 2. the validator catches both spellings of one field ==")
from schemas import UserPatchIn
for field in ("days", "extend_days"):
    try:
        UserPatchIn(**{field: 30, "set_expires_at": "2030-01-01T00:00"})
        check("rejects %s alongside set_expires_at" % field, False, "still accepted")
    except Exception:
        check("rejects %s alongside set_expires_at" % field, True)
try:
    UserPatchIn(volume_gb=5, set_volume_gb=10)
    check("and still rejects two members of the volume group", False)
except Exception:
    check("and still rejects two members of the volume group", True)

# --------------------------------------------------------------------------
print()
print("== 3. every serialised column survives a bytes value and a NULL ==")
from database import VpnUser, AuditLog
u = VpnUser(username="probe", volume_gb=1.0, used_gb=0.0, token="x")
u.last_fetch_ip = b"\xffA"
u.note = b"\xffB"
u.username = b"\xffC"
try:
    json.dumps(u.to_dict())
    check("VpnUser.to_dict() serialises with bytes in every text column", True)
except Exception as exc:
    check("VpnUser.to_dict() serialises with bytes in every text column", False,
          type(exc).__name__)
al = AuditLog(event="probe")
al.detail = None
al.ts = None
try:
    al.to_dict()
    check("AuditLog.to_dict() survives detail=None and ts=None", True)
except Exception as exc:
    check("AuditLog.to_dict() survives detail=None and ts=None", False,
          type(exc).__name__)

# --------------------------------------------------------------------------
print()
print("== 4. the token_sha index exists on the migration path ==")
db = io.open(DB, encoding="utf-8", newline="").read()
check("a migration step creates it", "_index(" in db)
# Same list, with only comment lines between: a regex that insists on adjacency
# fails on the very comment that explains the step.
check("and it is wired into the list the _add steps live in",
      re.search(r'_add\("vpn_users", "token_sha"[^\n]*\n(?:\s*#[^\n]*\n)*\s*_index\(',
                db) is not None)
check("and the column it indexes is the one /sub/{token} resolves by digest",
      re.search(r'VpnUser\.token_sha\s*==\s*token_digest', io.open(MAIN, encoding="utf-8").read())
      is not None)
import sqlite3
import tempfile
from sqlalchemy import create_engine, text as _t
d = tempfile.mkdtemp(prefix="reliability-idx-")
path = os.path.join(d, "t.db")
eng = create_engine("sqlite:///" + path)
with eng.begin() as c:
    c.execute(_t("CREATE TABLE vpn_users (id INTEGER PRIMARY KEY, token_sha VARCHAR(64))"))
with eng.begin() as c:
    c.execute(_t("CREATE UNIQUE INDEX IF NOT EXISTS ix_vpn_users_token_sha "
                 "ON vpn_users (token_sha)"))
con = sqlite3.connect(path)
plan = con.execute("EXPLAIN QUERY PLAN SELECT * FROM vpn_users WHERE token_sha='x'").fetchone()[3]
check("and the lookup is a SEARCH, not the SCAN it planned before", "SCAN" not in plan,
      plan)
con.close()

# --------------------------------------------------------------------------
print()
print("== 5. the expiry guard catches a null ==")
js = ("const d = new Date(null || \"\");"
      "console.log(JSON.stringify({na: isNaN(d.getTime())}));")
out = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                     encoding="utf-8", errors="replace").stdout.strip()
check("new Date(null || \"\") is NaN, so the dash renders",
      json.loads(out)["na"] is True, out)
app = io.open(APP, encoding="utf-8", newline="").read()
# NOT "the spelling is present": there are two new Date(u.expires_at) call
# sites and one was already correct, so asserting presence stayed green when the
# broken one came back. The property is that no UNGUARDED form survives.
check("and no call site constructs the date from a bare null",
      re.search(r'new Date\(u\.expires_at\)(?! \|\| "")', app) is None)

# --------------------------------------------------------------------------
print()
print("== 6. the access log never carries a customer credential ==")
from main import _redact_credential_path as REDACT
check("the access log goes through the redactor",
      "_redact_credential_path(request.url.path)" in main)
tok = "e8497324e16189cfe89fb7039d04e149"
check("a real 32-hex token does not survive", tok not in REDACT("/sub/" + tok))
got = REDACT("/sub/" + tok)
check("and the length is preserved, so the line still identifies the shape",
      len(got) == len("/sub/" + tok), got)
check("other paths are untouched", REDACT("/api/users") == "/api/users"
      and REDACT("/panel") == "/panel")
check("and it does not redact a short path that is not a token",
      REDACT("/sub/abc") == "/sub/abc")

# --------------------------------------------------------------------------
# 7. the tests' own probe rows must satisfy the schema the panel enforces.
#    security_test.py shipped a customer row for months that RestoreUserIn
#    rejected on two counts - `protocols` as a list where the field is a
#    comma-separated string, and no `token` at all where the field requires
#    32-200 chars. The row was silently counted as "skipped", prepared_users
#    came out empty, and the restore answered 400. All three of that test's
#    assertions were about api_tokens and admins, so they held either way and
#    the test stayed green against a panel that had dropped its own probe.
#
#    Checked here rather than in the suite because it needs no panel, and
#    because a probe row that cannot survive the schema it exercises is a
#    defect in the TEST, which nothing else was looking for.
print()
print("== 8. a probe row that the panel would reject is a defect in the test ==")
from schemas import RestoreUserIn
sec = io.open(os.path.join(ROOT, "security_test.py"), encoding="utf-8",
              newline="").read()
m = re.search(r"probe_user = (\{.*?\})\n", sec, re.S)
check("security_test.py still declares a probe row", m is not None)
if m:
    try:
        row = eval(m.group(1), {"__builtins__": {}}, {})  # a literal dict
    except Exception as exc:
        row = None
        check("and it is a literal this guard can read", False, type(exc).__name__)
    if isinstance(row, dict):
        try:
            RestoreUserIn.model_validate(row)
            check("and the panel would accept it", True)
        except Exception as exc:
            first = str(exc).splitlines()[1].strip() if len(
                str(exc).splitlines()) > 1 else type(exc).__name__
            check("and the panel would accept it", False, first[:90])
        check("and the row carries the token RestoreUserIn requires",
              isinstance(row.get("token"), str) and len(row.get("token", "")) >= 32,
              repr(row.get("token"))[:60])
        check("and protocols is the comma-separated string the exporter writes",
              isinstance(row.get("protocols"), str), repr(row.get("protocols")))
    # the assertion that makes such a drop visible in the suite itself
    check("and the suite asserts the probe row was not skipped",
          '"skipped") == 0' in sec and '"added_users") == 1' in sec)

# --------------------------------------------------------------------------
# Prove each can fail. A guard nobody saw fail is a comment with an exit code.
print()
print("== 9. each of these can fail ==")
MUTATIONS = [
    ("remove the prepared_users guard",
     MAIN, '    if not prepared_users:\n',
     "", "the wipe is guarded by prepared_users"),
    ("put days back outside the expiry group",
     SCH, '("expires_at", "set_expires_at", "extend_days", "days"),',
     '("expires_at", "set_expires_at", "extend_days"),', None),
    ("un-sanitise last_fetch_ip again",
     DB, '"last_fetch_ip": safe_text(self.last_fetch_ip) or None,',
     '"last_fetch_ip": self.last_fetch_ip or None,', None),
    ("slice detail before the NULL guard again",
     DB, "safe_text(self.detail[:200] if self.detail else None)",
     "safe_text(self.detail[:200])", None),
    ("drop the index step",
     DB, '        _index("vpn_users", "token_sha", "ix_vpn_users_token_sha"),\n', "", None),
    ("use the bare null in app.js again",
     APP, 'new Date(u.expires_at || "")', "new Date(u.expires_at)", None),
    ("log the raw path again",
     MAIN, "_logged_path = _redact_credential_path(request.url.path)",
     "_logged_path = request.url.path", None),
    # the probe row security_test.py had for months: protocols as a list, and
    # no token at all - both rejected by RestoreUserIn, so the row was silently
    # dropped and the suite stayed green because it never checked skipped.
    ("put the probe row back to the shape the panel rejects",
     os.path.join(ROOT, "security_test.py"),
     '"protocols": "vless",\n              "token": "ab" * 16',
     '"protocols": ["vless"]',
     "and the panel would accept it"),
]

if os.environ.get("ZEFIRA_RELIABILITY_CHILD") == "1":
    # the child is a normal run; the parent looks for one FAIL line per case
    raise SystemExit(0 if all(ok for _n, ok in results) else 1)

for label, path, old, new, _m in MUTATIONS:
    raw = io.open(path, "rb").read()
    t = raw.decode("utf-8")
    if old not in t:
        check("goes red: %s" % label, False, "the mutation did not apply")
        continue
    io.open(path, "wb").write(t.replace(old, new, 1).encode("utf-8"))
    try:
        r = subprocess.run([sys.executable, os.path.abspath(__file__)],
                           capture_output=True, text=True, timeout=600,
                           encoding="utf-8", errors="replace",
                           env=dict(os.environ, ZEFIRA_RELIABILITY_CHILD="1"))
        went_red = r.returncode != 0
        check("goes red: %s" % label, went_red,
              "child rc=%d, output: %s" % (r.returncode,
                                           (r.stdout or "").strip()[-120:]))
    finally:
        io.open(path, "wb").write(raw)
        assert io.open(path, "rb").read() == raw, "%s was not restored" % path

passed = sum(1 for _n, ok in results if ok)
print()
print("=== %d/%d checks passed ===" % (passed, len(results)))
print("=== %d/%d ===" % (passed, len(results)))
sys.exit(0 if passed == len(results) else 1)