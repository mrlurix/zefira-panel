"""Prove an UPGRADED install gets the index - not a fresh one.

`ast.parse` passed on a file whose migrations raised TypeError on every boot
and whose `_index` was a NameError. It only proves the syntax, never the names,
so this executes the real list.

The scenario that matters is the one create_all() does NOT cover:

    Base.metadata.create_all(engine)   # a FRESH install - index created here
    DROP INDEX ix_vpn_users_token_sha  # now it looks upgraded
    run every migration step           # and the index has to come back

A real `Database` instance is used on purpose. `_add` and `_drop` return
`lambda self, conn: self._add_column(...)`, so the method is reached by
descriptor lookup on the class - which is exactly what a missing `@staticmethod`
breaks, and which `None` or a stub would not catch.

    .venv\\Scripts\\python.exe verify_migrations_run.py
"""
import io
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sqlalchemy import create_engine, text as _t

import database as D

ok = []


def check(name, cond, detail=""):
    ok.append(bool(cond))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + detail) if detail and not cond else ""))


src = io.open("database.py", encoding="utf-8", errors="replace").read()
d = tempfile.mkdtemp(prefix="migrun-")
p = os.path.join(d, "t.db")
db = D.Database(Path(p))
db.engine = create_engine("sqlite:///" + p)

# --- a fresh install, which create_all() fully covers
D.Base.metadata.create_all(db.engine)
con = sqlite3.connect(p)
fresh = [r[1] for r in con.execute("PRAGMA index_list(vpn_users)").fetchall()]
plan = con.execute("EXPLAIN QUERY PLAN SELECT * FROM vpn_users "
                   "WHERE token_sha='x'").fetchone()[3]
print("  FRESH install (create_all)")
print("    indexes     : %r" % fresh)
print("    lookup plan : %s" % plan)
check("create_all() already indexes token_sha for a fresh table",
      "ix_vpn_users_token_sha" in fresh and "SCAN" not in plan)
con.execute("DROP INDEX ix_vpn_users_token_sha")
con.commit()
con.close()

# --- now it looks like an upgraded install: table present, index absent
steps = D._migration_steps("sqlite")
print("\n  UPGRADED install - %d migration steps, index dropped" % len(steps))
first_fail, ran = None, 0
with db.engine.begin() as c:
    for st in steps:
        try:
            st(db, c)
            ran += 1
        except Exception as exc:
            first_fail = "step %d of %d: %s: %s" % (ran + 1, len(steps),
                                                    type(exc).__name__, exc)
            break
print("    %d/%d steps ran%s" % (ran, len(steps),
                                 "" if not first_fail else
                                 "\n    stopped -> " + first_fail))
check("every migration step runs against a real Database instance",
      first_fail is None, first_fail or "")
check("and none of them is skipped", ran == len(steps), "%d of %d" % (ran, len(steps)))

con = sqlite3.connect(p)
idx = [r[1] for r in con.execute("PRAGMA index_list(vpn_users)").fetchall()]
plan = con.execute("EXPLAIN QUERY PLAN SELECT * FROM vpn_users "
                   "WHERE token_sha='x'").fetchone()[3]
print("    indexes     : %r" % idx)
print("    lookup plan : %s" % plan)
check("the migration recreated the index a fresh table gets for free",
      "ix_vpn_users_token_sha" in idx)
check("and the lookup is a SEARCH, not the SCAN it planned before",
      "SCAN" not in plan, plan)

# UNIQUE must be real, not just present. Read it off PRAGMA index_list, whose
# columns are (seq, name, unique, origin, partial) - a duplicate INSERT would
# have to satisfy every NOT NULL column on vpn_users first, which says nothing
# extra about the index.
uniq = {r[1]: r[2] for r in con.execute("PRAGMA index_list(vpn_users)").fetchall()}
print("    unique flags : %r" % uniq)
check("and it is UNIQUE, so the database enforces what the ORM declares",
      uniq.get("ix_vpn_users_token_sha") == 1)

# the decorator the whole repair was about
check("_add_column is still a staticmethod",
      re.search(r"@staticmethod\s*def _add_column\(", src) is not None)
check("and _index is defined beside _add, not on the class",
      re.search(r"\n    def _index\(", src) is not None
      and "Database._index" not in src)
# every helper the list calls must resolve - this is what ast.parse misses
body = src[src.index("def _migration_steps"):][:22000]
called = set(re.findall(r"^ {8}_(\w+)\(", body, re.M))
defined = set(re.findall(r"^def _(\w+)\(", src, re.M)) | set(
    re.findall(r"^ {4}def _(\w+)\(", src, re.M))
print("    helpers called by the list: %s" % sorted(called))
check("every helper the list calls is defined somewhere it can be reached",
      not (called - defined), str(sorted(called - defined)))

con.close()
db.engine.dispose()

# ---------------------------------------------------------------------------
# A guard nobody saw fail is a comment with an exit code. Each mutation below
# restores a defect that was actually in this file during development, so the
# red is a real past failure and not a shape I invented.
print("\n== each of these can fail ==")
MUTATIONS = [
    # self._add_column(conn, table, column, ddl) then binds self=conn and the
    # FIRST step raises TypeError - which is exactly how it failed here.
    ("lose the @staticmethod off _add_column again",
     ("    @staticmethod\n    def _add_column(conn, table: str",
      "    def _add_column(conn, table: str")),
    ("define _index somewhere the list cannot reach",
     ("\n    def _index(table, column, name):",
      "\n    def _index_typo(table, column, name):")),
    ("create the index without UNIQUE",
     ('"CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (%s)"',
      '"CREATE INDEX IF NOT EXISTS %s ON %s (%s)"')),
    ("index the wrong column",
     ('_index("vpn_users", "token_sha", "ix_vpn_users_token_sha"),',
      '_index("vpn_users", "username", "ix_vpn_users_token_sha"),')),
]
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.py")
# the child spawned per mutation must not recurse into the mutation section
if os.environ.get("ZEFIRA_MIGRATIONS_CHILD") == "1":
    # mirror EVERY property the parent asserts, or a mutation can turn a check
    # red in the child's output while the child still exits 0 and the parent
    # reads it as green - which is what the UNIQUE mutation did.
    con2 = sqlite3.connect(p)
    rows = con2.execute("PRAGMA index_list(vpn_users)").fetchall()
    i2 = {r[1]: r[2] for r in rows}
    p2 = con2.execute("EXPLAIN QUERY PLAN SELECT * FROM vpn_users "
                      "WHERE token_sha='x'").fetchone()[3]
    cols2 = {r[1] for r in con2.execute("PRAGMA table_info(vpn_users)").fetchall()}
    con2.close()
    src2 = io.open(DB, encoding="utf-8", errors="replace").read()
    good = ("ix_vpn_users_token_sha" in i2
            and i2.get("ix_vpn_users_token_sha") == 1
            and "SCAN" not in p2
            and re.search(r"@staticmethod\s*def _add_column\(", src2) is not None
            and "Database._index" not in src2)
    print("child: index=%s unique=%s plan=%s"
          % ("ix_vpn_users_token_sha" in i2,
             i2.get("ix_vpn_users_token_sha"), p2))
    raise SystemExit(0 if good else 1)
raw = io.open(DB, "rb").read()
for label, (old, new) in MUTATIONS:
    t = raw.decode("utf-8")
    if old not in t:
        check("goes red: %s" % label, False, "the mutation did not apply")
        continue
    io.open(DB, "wb").write(t.replace(old, new, 1).encode("utf-8"))
    try:
        r = subprocess.run([sys.executable, os.path.abspath(__file__)],
                           capture_output=True, text=True, timeout=600,
                           encoding="utf-8", errors="replace",
                           env=dict(os.environ, ZEFIRA_MIGRATIONS_CHILD="1"))
        went_red = r.returncode != 0
        tail = [l for l in (r.stdout or "").splitlines() if "[FAIL]" in l]
        check("goes red: %s" % label, went_red,
              "child rc=%d; it printed %s" % (r.returncode, tail or "no FAIL"))
    finally:
        io.open(DB, "wb").write(raw)
        assert io.open(DB, "rb").read() == raw, "database.py was not restored"

n = sum(ok)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)