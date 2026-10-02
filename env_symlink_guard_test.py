"""Guard: the installer must never append through a symlink as root.

$TARGET (/opt/zefira) and every top-level entry in it are chowned to zefira, so
a panel that has been compromised owns /opt/zefira/.env and can replace it with
a symlink to any path on the host. The installer runs as root, so a plain
`>> "$ENV_FILE"` would follow that link and write into a root-owned target -
/etc/cron.d/x being the obvious one.

This derives the claim from the file rather than restating it: it finds the
chown that makes the symlink plantable, then asserts there is no unguarded
append to the env file and that the SSL block refuses a symlink outright.
"""
import io
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
src = io.open(os.path.join(HERE, "install.sh"), encoding="utf-8",
            errors="replace").read()
fails = []


def check(label, cond, detail=""):
    if not cond:
        fails.append(label)
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", label,
                           ("  -> " + detail) if detail else ""))


print()
print("=== 1. the premise: the service account can plant the symlink ===")
# Without this the append is harmless, so the guard must not assert a fix for a
# threat that does not exist.
check("$TARGET is chowned to the service account",
      re.search(r'chown\s+zefira:zefira\s+"\$TARGET"', src) is not None,
      "the service account cannot replace .env, so this guard is moot")
check("the tree's top level is chowned too",
      "-mindepth 1 -maxdepth 1" in src and "chown -R zefira:zefira" in src)
check("the installer runs as root",
      "[[ -z \"${EUID:-$(id -u)}\" ]] && EUID=0" in src
      or "EUID" in src,
      "if the installer does not run as root the escalation does not apply")

print()
print("=== 2. no unguarded append to the env file ===")
# Comment lines carry no code, and this file's comment quotes the very pattern
# being searched for - the same trap as the updater guard that matched its own
# explanation. Strip whole-line comments before asking what the code says.
code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
appends = [(n, l.strip()) for n, l in enumerate(code.splitlines(), 1)
           if re.search(r'>>\s*"\$(ENV_FILE|TARGET/\.env)"', l)]
check("no `>> \"$ENV_FILE\"` remains", not appends,
      "; ".join("line %d: %s" % (n, l[:60]) for n, l in appends))
tmp_appends = [l.strip() for l in src.splitlines() if '_env_ssl_tmp"' in l and ">>" in l]
check("the SSL settings go to a temp file first", len(tmp_appends) == 1,
      "%d append(s) to the temp file, expected 1" % len(tmp_appends))
check("that temp file is renamed into place",
      re.search(r'mv -f\s+"\$_env_ssl_tmp"\s+"\$ENV_FILE"', src) is not None,
      "a rename is what makes it atomic and replaces a symlink instead of "
      "writing through it")
check("the temp file is 0600 before the rename",
      'chmod 600 "$_env_ssl_tmp"' in src)

print()
print("=== 3. the SSL block refuses a symlink outright ===")
check("the refusal exists", "refusing to add SSL settings" in src)
check("the refusal exits non-zero", re.search(
    r'refusing to add SSL settings.*\n\s*echo.*\n\s*exit 1', src) is not None,
    "a warning without exit keeps going and still writes")

print()
print("=== 4. the earlier .env guard is still in place ===")
check("the original symlink refusal survives",
      'is a symlink - refusing to write through it' in src,
      "the mv -f path lost its own guard")

print()
print("=== 5. the .env backup is never readable by another account ===")
# `cp -a` preserves the SOURCE mode, so a legacy 0644 .env produced a
# world-readable copy of the admin password and the database credentials, and
# the chmod that followed left a window in which any local account could read
# it. The backup now exists as 0600 under a temp name and is renamed into place.
check("no `cp -a` of the env file remains",
      not re.search(r'cp -a\s+"\$ENV_FILE"', code),
      "the backup is still created at the source's mode")
check("the backup is written to a mktemp file",
      '_env_bak_tmp="$(mktemp "$TARGET/.env.bak.XXXXXX")"' in code)
check("that temp file is 0600 before it is named .bak",
      'chmod 600 "$_env_bak_tmp"' in code)
check("it is renamed into place",
      re.search(r'mv -f\s+"\$_env_bak_tmp"\s+"\$_env_bak"', code) is not None)
check("no chmod-after-copy glob over old backups",
      not re.search(r'chmod 600 "\$ENV_FILE\.bak-"\*', code),
      "the old chmod restyled every earlier backup as a side effect")

print()
print("=== %s ===" % ("ALL OK" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)