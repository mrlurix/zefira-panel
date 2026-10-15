"""Three guards in main.py whose comments promised more than the code did.

1. `_snapshot_db_before_restore()` is the operator's only undo path before a
   destructive restore, and its SQLite branch logged a failure at DEBUG. The
   logging level is INFO, so the message was dropped entirely: the operator
   believed a rollback point existed when it did not, on the default install.
   Every other branch of the same snapshot logs at error or warning.

2. A restore REPLACES the customer table - line 4916 deletes every VpnUser
   before re-inserting. `users: List[dict] = Field(max_length=10000)` has no
   min_length, so a settings-only export parses fine, the loop body never
   runs, and every customer is deleted. The operator pastes the wrong file,
   re-types the password, and the panel wipes itself.

3. The API-token cap is commented "A live-token cap" but the count had no
   expires_at predicate, so a token that expired years ago still occupied a
   slot and the operator hit 409 and had to delete live credentials.

Each assertion is checked against a MUTATED copy of the real main.py, so a
guard that cannot go red is reported rather than trusted.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(ROOT, "main.py")
SCHEMAS = os.path.join(ROOT, "schemas.py")


def read(path):
    with io.open(path, encoding="utf-8-sig", newline="") as fh:
        return fh.read()


def checks(main, schemas):
    # 1. snapshot logging. Matched on its own line so an explanatory comment
    #    block above it cannot swallow the pattern.
    snap = re.search(r"^\s*(log\.\w+)\(\"pre-restore snapshot failed", main, re.M)
    snap_level = snap.group(1) if snap else ""

    # 2. empty-restore guard, and where it sits relative to the wipe
    guard = re.search(r"if not data\.users:\s*\n\s*raise HTTPException", main)
    wipe_at = main.find("s.delete(u)")
    guard_at = main.find("if not data.users:")
    loop_at = main.find("for ru_raw in data.users:")
    prep_guard_at = main.find("if not prepared_users:")
    dedup_at = main.find("prepared_users = deduped")

    # 3. token cap
    cap = re.search(r"live = s\.scalar\([\s\S]{0,320}?\)\s*or 0", main)
    cap_seg = cap.group(0) if cap else ""
    imported = re.search(r"from sqlalchemy import ([^\n]*)", main)
    sql_import = imported.group(1) if imported else ""

    return {
        "snapshot failure is logged at error or higher":
            snap_level in ("log.error", "log.warning"),
        "empty-restore guard exists": bool(guard),
        "guard returns 400": re.search(r"if not data\.users:[\s\S]{0,200}?status_code=400", main) is not None,
        "guard runs before the customer table is wiped":
            guard_at != -1 and wipe_at != -1 and guard_at < wipe_at,
        "guard runs before the loop that fills prepared_users":
            guard_at != -1 and loop_at != -1 and guard_at < loop_at,
        "the schema still has no min_length (guard is what protects us)":
            re.search(r"users:\s*List\[dict\]\s*=\s*Field\(max_length=10000\)", schemas) is not None,
        "token cap filters on expires_at": "ApiToken.expires_at" in cap_seg,
        "token cap treats NULL expiry as live": "ApiToken.expires_at.is_(None)" in cap_seg,
        "or_ is imported": re.search(r"\bor_\b", sql_import) is not None,
        # NOT `len(re.findall(r"data\.users", main)) == N`, which is what this
        # said and which was an occurrence count rather than a property. It
        # stayed green through a real data-loss bug: the guard tests
        # `data.users`, the wipe depends on `prepared_users`, and every per-row
        # path (bad row, missing volume, duplicate name or token) can empty the
        # second while leaving the first truthy. Measured against a live panel:
        # POST /api/restore {"users":[{}]} answered 200 {"ok": true,
        # "added_users": 0, "skipped": 1} and left vpn_users empty.
        # `if\b[^\n:]*\bdata\.users\b` and not `if\s+(?:not\s+)?data\.users`: the
        # narrower form missed `if len(data.users) > ...`, which is exactly the
        # shape the check exists to catch.
        "no other CONDITION on data.users decides anything":
            len(re.findall(r"if\b[^\n:]*\bdata\.users\b", main)) == 1,
        "the wipe is guarded by prepared_users too":
            re.search(r"if not prepared_users:\s*\n\s*raise HTTPException", main) is not None,
        "the prepared_users guard answers 400":
            re.search(r"if not prepared_users:[\s\S]{0,420}?status_code=400", main) is not None,
        "the prepared_users guard runs before the customer table is wiped":
            prep_guard_at != -1 and wipe_at != -1 and prep_guard_at < wipe_at,
        "prepared_users is finalised by the dedup before it is guarded":
            prep_guard_at != -1 and dedup_at != -1 and dedup_at < prep_guard_at,
    }


def main_run():
    src = read(MAIN)
    schemas = read(SCHEMAS)
    base = checks(src, schemas)
    failures = []

    print("== 1. the guards are in place ==")
    for name, ok in sorted(base.items()):
        print("   %-52s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2. each guard can fail: restore the bug, it must go red ==")
    mutations = [
        ("snapshot back to log.debug",
         lambda t: re.sub(r'(log\.)error\("pre-restore snapshot failed', r'\1debug("pre-restore snapshot failed', t),
         ["snapshot failure is logged at error or higher"]),
        ("remove the empty-restore guard",
         lambda t: re.sub(r"[ \t]*if not data\.users:\s*\n(?:\s*(?:#[^\n]*\n|raise HTTPException\([\s\S]*?\)|\s*\"[^\"]*\"\))\s*?)*\s*?\n(?=\s*prepared_users = \[\])", "", t),
         ["empty-restore guard exists", "guard returns 400",
          "guard runs before the customer table is wiped",
          "guard runs before the loop that fills prepared_users"]),
        # A bounded, non-greedy span rather than a nested quantifier: nested
        # (?:\s*(...|\s*"...")*)* over a 7000-line file backtracks catastrophically
        # and the mutation takes minutes instead of milliseconds.
        ("remove the prepared_users guard, as shipped",
         lambda t: re.sub(r"[ \t]*if not prepared_users:[\s\S]{0,700}?\n(?=\s*_snapshot_db_before_restore\(\))", "", t, count=1),
         ["the wipe is guarded by prepared_users too",
          "the prepared_users guard answers 400",
          "the prepared_users guard runs before the customer table is wiped",
          "prepared_users is finalised by the dedup before it is guarded"]),
        ("let data.users decide something again",
         lambda t: t.replace("    prepared_users = deduped\n",
                             "    if len(data.users) > 10000:\n        pass\n\n    prepared_users = deduped\n", 1),
         ["no other CONDITION on data.users decides anything"]),
        ("count expired tokens again",
         lambda t: re.sub(r"\.where\(or_\(ApiToken\.expires_at\.is_\(None\), ApiToken\.expires_at > _now\)\)", "", t),
         ["token cap filters on expires_at", "token cap treats NULL expiry as live"]),
        ("drop the or_ import",
         lambda t: t.replace("from sqlalchemy import func, or_, select,", "from sqlalchemy import func, select,"),
         ["or_ is imported"]),
    ]
    for name, mutate, must_go_red in mutations:
        mutated = mutate(src)
        if mutated == src:
            print("   %-34s FAIL (mutation inert - untestable)" % name)
            failures.append(name + ": inert")
            continue
        after = checks(mutated, schemas)
        still = [g for g in must_go_red if after[g]]
        if still:
            print("   %-34s FAIL (stayed green: %s)" % (name, ", ".join(still)))
            failures.append(name + ": cannot fail")
        else:
            print("   %-34s ok (goes red: %s)" % (name, ", ".join(must_go_red)))

    print()
    if failures:
        print("FAIL: %d problem(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("PASS: every guard holds, and each can fail.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_run())