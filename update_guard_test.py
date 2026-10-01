"""The updater's runtime-intrusion guard.

This guard has a history. It shipped as a single `forbidden` tuple fed to
`str.startswith`:

    forbidden = ("instance/", ".env", ".venv/", "*.db", "*.pem", "*.key")
    if p.startswith(forbidden) or p == ".env" or p.endswith((".db-wal", ".db-shm")):

Two defects, both invisible to a reading of the code and both measurable:

1. ".env" was applied as a PREFIX. Every release since v1.0.0 ships a
   `.env.example` template, so the guard flagged the template as an intrusion
   and _do_update raised "refusing to update: .env.example". The in-app Update
   button could not have succeeded on any version of this panel - measured
   against real trees, v1.15.2 and v1.15.8 both flag '.env.example'.

2. `*.db`, `*.pem` and `*.key` were handed to str.startswith, which does literal
   prefix matching and never interprets a glob. They could only match a file
   literally named `*.db`. The four inputs they exist to block - cert.pem,
   server.key, backup.db, keys/vpn.pem - all passed untouched.

No test covered this predicate, which is how it survived the entire history: a
guard that cannot fail is worse than no guard, because it reads as protection.

Offline by construction. The tree listing comes from `git ls-tree` on the real
repository, and the predicate is the real `main._runtime_intrusions` - but this
suite never calls the updater, so it cannot run `git reset --hard` on anyone's
worktree.
"""
import io
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import main  # noqa: E402

fails = []


def check(label, cond, detail=""):
    if not cond:
        fails.append(label)
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", label,
                           ("  -> " + detail) if detail else ""))


intr = main._runtime_intrusions


def tree_of(ref):
    r = subprocess.run(["git", "ls-tree", "-r", "--name-only", ref],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if r.returncode != 0:
        return None
    return [p for p in r.stdout.splitlines() if p.strip()]


print()
print("=== 1. a real release tree must never be flagged ===")
print("    This is the regression: it is why no update ever applied.")
refs = ["v1.15.2", "v1.15.5", "v1.15.7", "v1.15.8"]
seen = [r for r in refs if tree_of(r) is not None]
if not seen:
    # Shallow clone: fall back to the tree we are standing in, still real.
    seen = ["HEAD"]
    print("    (no release tags in this clone; using HEAD)")
for ref in seen:
    paths = tree_of(ref)
    bad = intr(paths)
    check("%-8s is updateable" % ref, not bad,
          "refused over %s - the operator cannot update" % bad[:4])

print()
print("=== 2. live runtime state is refused ===")
# Everything that would let an upstream commit forge or read the operator's
# installation. secret.key, ca.key/ca.crt and zefira.db are the real files
# (config.py, protocols.py, main.py); .env holds the DB URL and proxy trust.
for p in ("instance/secret.key", "instance/ca.key", "instance/ca.crt",
          "instance/zefira.db", ".env", "instance", ".venv"):
    check("%-22s blocked" % p, p in intr([p]))

print()
print("=== 3. the three dead globs now block what they claimed to ===")
for p in ("cert.pem", "server.key", "backup.db", "app.db", "keys/vpn.pem",
          "evil.key", "zefira.db-wal", "zefira.db-shm"):
    check("%-16s blocked" % p, p in intr([p]),
          "str.startswith('*.pem') cannot match this")

print()
print("=== 4. a template beside the real file is not the real file ===")
for p in (".env.example", ".env.sample", ".envrc", ".env.template",
          ".environment", "env.example"):
    check("%-16s allowed" % p, p not in intr([p]),
          "a docs template must not block updates")

print()
print("=== 5. the guard as a whole ===")
paths = tree_of("HEAD") or []
check("the checked-out tree is clean", not intr(paths),
      "flagged %s" % intr(paths)[:4])
smuggled = list(paths) + ["instance/zefira.db", "cert.pem", "server.key", ".env"]
check("a smuggled tree is still refused", len(intr(smuggled)) == 4,
      "flagged %d of 4 planted paths" % len(intr(smuggled)))
check("an empty tree flags nothing", intr([]) == [] and intr(["", "   "]) == [],
      "a guard that refuses an empty listing blocks every update")

print()
print("=== 6. the guard is reachable from the updater, not just defined ===")
# A predicate that is correct but unused would pass every check above, so assert
# the updater actually calls this one - and that no glob survives in the
# constants. Testing the constants rather than grepping the source for "*.db"
# matters: the comment explaining why globs were removed contains that literal,
# so a source grep reports the fix as broken.
src = io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py"),
              encoding="utf-8").read()
# The comment above the constants quotes the old code verbatim - including
# `startswith(forbidden)` - so grepping the raw source reports the fix as broken.
# Whole-line comments carry no code; drop them before asking what the code says.
code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
check("_do_update calls the tested function",
      "intrusions = _runtime_intrusions(" in code,
      "the predicate under test is not the one the updater uses")
check("the updater no longer prefix-matches a hand-rolled tuple",
      "startswith(forbidden)" not in code,
      "the old inline guard is back")
for _name in ("RUNTIME_DIR_PREFIXES", "RUNTIME_DIRS", "RUNTIME_FILE_EXACT",
              "RUNTIME_SECRET_SUFFIXES"):
    _vals = getattr(main, _name, None)
    check("%s carries no glob" % _name,
          _vals is not None and not any("*" in str(v) for v in _vals),
          "values %r - a glob in a prefix match is how three checks died" % (_vals,))

print()
print("=== %s ===" % ("ALL OK" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)