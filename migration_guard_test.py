"""A failure in one migration step must not discard the steps before it.

init() used to wrap all eighteen schema steps in a single `engine.begin()`.
Both column helpers are idempotent, but _add_column deliberately lets a failed
ALTER propagate - as did the final backfill UPDATE. On SQLite and PostgreSQL,
where DDL is transactional, that raised out of the block and rolled back every
step before it. The panel then started against the old schema, the ORM's SELECTs
named columns that did not exist, and it was dead - identically dead on every
later boot, because the same step kept failing.

MySQL was never affected: its DDL implies a COMMIT, so each step autocommitted
and the outer `with` was decorative.

This reproduces the failure for real rather than asserting the shape of the code.
It builds a database, ages it by removing columns, makes one mid-list ALTER
raise, re-runs init(), and asks the schema what survived. Under the old single
transaction the earlier columns are gone; under per-step transactions they are
there and the panel can still open.

Offline, on SQLite, which is what the whole suite runs against.
"""
import io
import os
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database as _db  # noqa: E402
from sqlalchemy import inspect as sa_inspect, text as sa_text  # noqa: E402

fails = []


def check(label, cond, detail=""):
    if not cond:
        fails.append(label)
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", label,
                           ("  -> " + detail) if detail else ""))


def cols(path, table):
    eng = _db.Database(path).engine
    with eng.connect() as c:
        insp = sa_inspect(c)
        if not insp.has_table(table):
            return set()
        return {c["name"] for c in insp.get_columns(table)}


def fresh():
    fd, path = tempfile.mkstemp(prefix="zefira-mig-", suffix=".db")
    os.close(fd)
    os.unlink(path)
    return Path(path)


print()
print("=== 1. a fresh database migrates completely ===")
p1 = fresh()
_db.Database(p1).init()
first = cols(p1, "vpn_users")
for c in ("protocol", "secret_data", "protocols", "start_on_first_use",
          "duration_days", "device_limit", "last_fetch_at", "last_fetch_ip"):
    check("vpn_users.%-20s added" % c, c in first, str(sorted(first))[:90])
check("inbounds.node_id added", "node_id" in cols(p1, "inbounds"))
check("api_tokens.scopes added", "scopes" in cols(p1, "api_tokens"))
check("api_tokens.expires_at added", "expires_at" in cols(p1, "api_tokens"))

print()
print("=== 2. re-running init() on a migrated database is a no-op ===")
_db.Database(p1).init()
check("re-running changes nothing", cols(p1, "vpn_users") == first,
      str(sorted(cols(p1, "vpn_users")))[:90])

print()
print("=== 3. a mid-list failure is survivable ===")
# READ THIS BEFORE TRUSTING SECTION 3.
#
# The failure mode this fix addresses is: one failed ALTER rolls back every
# step before it, so the panel boots on a schema older than the one it already
# had. That needs DDL inside the transaction. Measured on THIS platform:
#
#   inside engine.begin(), a forced rollback left BOTH DDL statements applied
#   (the added column present, the dropped column still dropped)
#
# SQLAlchemy's pysqlite runs in the legacy isolation mode, which does not open a
# transaction for DDL - so the ADD and the DROP both committed despite the
# rollback. On SQLite the old single-transaction migration was therefore
# ALREADY SAFE, and the checks below pass identically before and after this
# change. They document the intended behaviour and prove the failure
# propagates and recovery works; they are NOT a regression test for the fix.
#
# The real exposure is PostgreSQL, where DDL genuinely is transactional and a
# failed ALTER did roll the list back. MySQL was never affected (implicit
# commits). No PostgreSQL server exists in this environment, so that half is
# reasoned from documented engine behaviour, not measured.
#
# Section 5 is the part that can go red here, and it does.
# Age the database: remove columns from the middle of the migration list, so a
# failure on one of them has earlier steps that must survive.
p2 = fresh()
_db.Database(p2).init()
with _db.Database(p2).engine.begin() as c:
    for col in ("protocol", "device_limit", "last_fetch_at"):
        c.execute(sa_text("ALTER TABLE vpn_users DROP COLUMN %s" % col))
    c.execute(sa_text("ALTER TABLE inbounds DROP COLUMN node_id"))
aged = cols(p2, "vpn_users")
check("the database really was aged",
      "protocol" not in aged and "device_limit" not in aged,
      str(sorted(aged))[:90])

BOOM = "duration_days"          # sits AFTER protocol, BEFORE device_limit
real_add = _db.Database._add_column
calls = {"n": 0}


# _add_column is a staticmethod taking (conn, table, name, ddl) - no self.
def exploding_add(conn, table, name, ddl):
    calls["n"] += 1
    if table == "vpn_users" and name == BOOM:
        raise RuntimeError("injected ALTER failure")
    return real_add(conn, table, name, ddl)


# staticmethod, or the replacement is an instance method and self gets bound
# as a fifth argument.
_db.Database._add_column = staticmethod(exploding_add)
raised = None
try:
    _db.Database(p2).init()
except RuntimeError as exc:
    raised = str(exc)
finally:
    _db.Database._add_column = staticmethod(real_add)
check("the injected failure did propagate", raised is not None,
      "no failure reached the caller - the test proves nothing")
check("the failure was the one we injected",
      "injected" in (raised or ""), repr(raised))

after = cols(p2, "vpn_users")
check("the schema is still usable after a mid-list failure",
      "protocol" in after,
      "the panel could not boot against the schema it needs")
check("the step AFTER the failure did not run",
      "device_limit" not in after,
      "steps after the failure must be left for the next boot")

print()
print("=== 4. the next boot completes the rest ===")
_db.Database(p2).init()
final = cols(p2, "vpn_users")
check("protocol present after the retry", "protocol" in final)
check("duration_days present after the retry", BOOM in final)
check("device_limit present after the retry", "device_limit" in final)
check("last_fetch_at present after the retry", "last_fetch_at" in final)
check("inbounds.node_id present after the retry", "node_id" in cols(p2, "inbounds"))
check("the retry reached the same schema as a fresh install",
      final >= first, str(sorted(final - first))[:90])

print()
print("=== 5. the boundary is per step, not per block ===")
src = io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "database.py"), encoding="utf-8-sig").read()
init_seg = src[src.index("    def init(self) -> None:"):
               src.index("\n    def ", src.index("    def init(self) -> None:") + 10)]
check("init() opens one transaction per step",
      init_seg.count("engine.begin()") >= 2
      and init_seg.count("self.engine.begin() as conn") == 0,
      "a single engine.begin() still wraps the whole list")
check("there is no engine.begin() left wrapping the step list",
      "with self.engine.begin() as conn:" not in init_seg)

for p in (p1, p2):
    try:
        os.unlink(p)
    except OSError:
        pass

print()
print("=== %s ===" % ("ALL OK" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)