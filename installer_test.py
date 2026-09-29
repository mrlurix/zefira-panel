"""Regression guards for the BackPack-style installer CLI (install.sh).

The one-liner (`curl ... | sudo bash`) must never block, so the aftercare
menu has to be interactive-only, and the uninstall path has to work when $0
is "bash" (which is what it is under a pipe).
"""
import hashlib
import io
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"C:\Users\mrlurix\Desktop\laptop pro\zefira"
BASH = r"C:\Program Files\Git\bin\bash.exe"
sh = io.open(ROOT + r"\install.sh", encoding="utf-8").read()
# The shell source with comments removed. install.sh is heavily commented, and
# guards here have twice been fooled by a comment that quoted the very line they
# were checking - a pattern that matches prose is not a guard.
_sh_code = "\n".join(l for l in sh.splitlines() if not l.lstrip().startswith("#"))
# Comment lines stripped: a guard about code must not be satisfied - or
# broken - by the comment that explains the code.
sh_code = "\n".join(ln for ln in sh.splitlines()
                    if not ln.strip().startswith("#"))
readme = io.open(ROOT + r"\README.md", encoding="utf-8").read()
_tools_lock = io.open(ROOT + r"\tools_lock.py", encoding="utf-8").read()
fails = []


def check(name, cond, detail=""):
    ok = bool(cond)
    if not ok:
        fails.append((name, detail))
    print(("[PASS] " if ok else "[FAIL] ") + name + (f"  ({detail})" if detail and not ok else ""))


# ---- 1. it must parse -----------------------------------------------------
r = subprocess.run([BASH, "-c", "cd '/c/Users/mrlurix/Desktop/laptop pro/zefira' "
                                 "&& bash -n install.sh"],
                   capture_output=True, text=True)
check("install.sh parses under bash", r.returncode == 0, r.stderr.strip()[:120])

# The version-resolution block is EXERCISED, not read. A static check can
# compare the pinned literal against VERSION, but it cannot see the defect
# that actually shipped: `cat "$TARGET/VERSION"` looks like a harmless fallback
# and is the wrong answer on every server that already has Zefira installed,
# because it returns the version being replaced - so `curl | sudo bash` clones
# the old tag, reports success, and upgrades nothing.
_r = subprocess.run([BASH, "version_resolution_test.sh"], capture_output=True,
                    text=True, cwd=ROOT)
check("the one-liner installs the pinned release, not the one it replaces",
      _r.returncode == 0,
      (_r.stdout or "")[-300:] or (_r.stderr or "")[-300:])

_i = subprocess.run([BASH, "installer_interactive_test.sh"], capture_output=True,
                    text=True, cwd=ROOT)

# Two answers that silently did nothing, checked by RUNNING the logic. Both
# look correct in the source: the nginx question tested `[yY]*` while the four
# places acting on the answer tested `[yY]`, so typing "yes" asked for nginx and
# then did none of it; and the port preflight exited 1 on ANY listener while
# the service was not stopped for ~600 more lines, so `curl | sudo bash` on a
# running server always aborted on the panel's own installation.
_a = subprocess.run([BASH, "installer_answers_test.sh"], capture_output=True,
                    text=True, cwd=ROOT)
check("a 'yes' at the nginx prompt actually enables nginx, and a foreign port"
      " is distinguished from our own service",
      _a.returncode == 0,
      (_a.stdout or "")[-320:] or (_a.stderr or "")[-320:])

# ---- 2. the blocky wordmark ---------------------------------------------
art = re.search(r"ZEFIRA_ART=\(\n(.*?)\n\)", sh, re.S)
check("the banner carries a block-art wordmark array", art is not None)
if art:
    rows = [ln.strip().strip('"') for ln in art.group(1).splitlines() if ln.strip()]
    widths = {len(x) for x in rows}
    check("every art row is the same width (the letters line up)",
          len(rows) >= 5 and len(widths) == 1, f"widths={sorted(widths)}")
    check("the art is built from block glyphs, not spaced-out letters",
          all(("█" in x or "╗" in x or "╝" in x or "═" in x) for x in rows),
          rows[0][:40] if rows else "")
    check("the art fits an 80-column terminal",
          max(widths) <= 72, f"widest row={max(widths) if widths else '?'}")
    # THE bug this replaces: the glyphs were written with no gap between
    # letters, so the whole word came out as ONE cell and read as a smear
    # instead of ZEFIRA. Scan for columns that are blank in every row: there
    # must be exactly one cell per letter.
    w = max(widths)
    padded = [r.ljust(w) for r in rows]
    blank = [all(r[c] == " " for r in padded) for c in range(w)]
    cells, start = 0, None
    for c, is_blank in enumerate(blank + [True]):
        if not is_blank and start is None:
            start = c
        elif is_blank and start is not None:
            cells += 1
            start = None
    check("each letter is its own glyph cell (the word is legible)",
          cells == 6, f"{cells} cell(s) for 6 letters")

# ---- 3. the header lines, like the reference CLI ------------------------
check("the banner prints the product name and version",
      re.search(r'echo "\$\{C_BLD\}Zefira\$\{C_RST\}.*v\$\{ZEFIRA_VERSION\}', sh) is not None)
check("the banner prints a GitHub + Docs line", "GitHub : https://github.com/mrlurix" in sh
      and "Docs : https://mrlurix.github.io" in sh)
check("no invented Telegram handle is printed",
      "Telegram :" not in sh and "t.me/" not in sh,
      "the repo has no official channel - do not print one")

# ---- 4. the two-column numbered menu ------------------------------------
step = re.search(r"^step\(\)\s*\{(.*)$", sh, re.M)
check("step() prints the two-column 'N) Name  description' shape",
      step is not None and "%-16s" in step.group(1) and "$C_DIM" in step.group(1),
      step.group(1)[:80] if step else "not found")
check("the aftercare menu is numbered 1-7 and ends with the exit option",
      all(f"step {n} " in sh for n in range(1, 8)) and 'step 7 "Exit"' in sh)
check("the menu prompts exactly like the reference CLI",
      "Select an option:" in sh)
check("the menu loops until the operator leaves",
      "while true" in sh and re.search(r'7\|"\"\)\s*echo "Bye\."; return 0', sh) is not None)
check("an unknown answer warns and re-prompts instead of exiting",
      re.search(r'\*\)\s*warn "no option', sh) is not None)

# ---- 5. the pipe install must never block -------------------------------
check("the menu is interactive-only (a piped install has no TTY)",
      re.search(r"post_menu\(\)\s*\{\s*\n\s*\[\[ \$INTERACTIVE -eq 1 \]\] \|\| return 0", sh)
      is not None)
# Both EOF guards care that Ctrl+D returns rather than spins or crashes,
# not which reader is spelled, so they accept either: tty_read routes the
# read to the terminal and still returns non-zero at EOF, which is what
# the `|| { echo; return 0; }` guard is there for.
check("EOF on the prompt returns instead of spinning",
      re.search(r"(?:tty_)?read -e -r choice \|\| \{ echo; return 0; \}", sh) is not None)
check("the uninstall confirmation also survives EOF",
      re.search(r"printf 'Type yes to remove Zefira: ' ; (?:tty_)?read -r yes \|\| \{ echo; return 0; \}",
                sh) is not None)
check("the documented one-liner is untouched",
      "curl -fsSL https://raw.githubusercontent.com/mrlurix/zefira-panel/main/install.sh | sudo bash"
      in sh)
check("non-interactive installs still skip the wizard, and interactive ones do not",
   # The old check asserted the literal text "[[ -t 0 ]] && INTERACTIVE=1".
   # That tests the mechanism, not the behaviour, and it is the fifth time in
   # this repo that a restated implementation detail stood in for a guarantee
   # - the same shape as the hardcoded `|| echo 1.14.2` and the hand-written
   # data-i18n allowlist. It stayed green for the whole life of the bug it was
   # guarding: under `curl | sudo bash` stdin is the pipe carrying install.sh,
   # so `-t 0` is never true, INTERACTIVE is always 0, and the operator is
   # never asked for a port, a database or an admin account.
   #
   # installer_interactive_test.sh RUNS the gate and the reads instead: it
   # proves a prompt takes its answer from the terminal while stdin is carrying
   # script text, and that a session with no tty still falls back to defaults.
   _i.returncode == 0,
   (_i.stdout or "")[-320:] or (_i.stderr or "")[-320:])

# ---- 5b. the source-discovery escalation -------------------------------
# Under the documented pipe BASH_SOURCE[0] is EMPTY, so `dirname ""` is "."
# and the old "anchor to the script's own directory" rule silently became
# $PWD. `sudo bash install.sh` from /opt/zefira - a tree the service account
# owns - then had root pip install from a requirements.lock that account could
# rewrite (--require-hashes trusts the hashes in that same file).
check("a piped install never treats the working directory as its source",
      "HAVE_SELF_PATH=0" in sh_code
      and re.search(r'\[\[ -n "\$\{BASH_SOURCE\[0\]:-\}" \]\] && HAVE_SELF_PATH=1', sh)
      is not None
      and 'SCRIPT_DIR=""' in sh,
      "the guard needs the empty-BASH_SOURCE case")
check("the service-writable install dir is refused as a source",
      re.search(r'SCRIPT_DIR" != "\$TARGET_REAL', sh) is not None
      and re.search(r"refusing to install from \$TARGET_REAL", sh) is not None,
      "$TARGET must never be trusted as the installer's own source")
check("the clone ref is a real variable again, defaulting to the release tag",
      'REF="${ZEFIRA_INSTALL_REF:-v${ZEFIRA_VERSION}}"' in sh
      and '--branch "$REF"' in sh
      and "${ZEFIRA_INSTALL_REF:-main}" not in sh,
      "REF was assigned and never used; the clone followed a moving branch")
check("a clone can be pinned to an exact commit, and a mismatch aborts",
      "ZEFIRA_EXPECTED_SHA" in sh
      and 'CLONE_SHA" != "$ZEFIRA_EXPECTED_SHA"' in sh
      and "nothing was installed" in sh,
      "no expected-commit check")
# ---- the banner art must actually read as the product name --------------
# The art had drifted into a mixture of 7-, 8- and 9-wide glyphs whose columns
# no longer lined up, so the letters did not read as ZEFIRA at all. It is now
# generated from one font table, and these checks assert the LETTERS - which
# every earlier version of this test did not: it only counted cells, so a
# correctly-spaced picture of the wrong word passed.
_art = re.search(r"ZEFIRA_ART=\(\n(.*?)\n\)", sh, re.S)
_rows = ([ln.strip()[1:-1] for ln in _art.group(1).splitlines() if ln.strip()]
         if _art else [])
check("the banner art is present", bool(_rows), "ZEFIRA_ART not found in install.sh")
check("the banner spells the product name: zefira", len(_rows) == 5,
      f"expected 5 rows for a 5-row font, found {len(_rows)}")
check("every art row is the same width, so the columns line up",
      len({len(r) for r in _rows}) == 1,
      f"row widths {sorted({len(r) for r in _rows})}")
# Split each row on the single-space gaps between 5-wide glyphs and rebuild the
# letter each column spells. This reads the NAME, which is what was wrong.
_GLYPHS = {
    "Z": ["█████", "    █", "   █ ", "  █  ", "█████"],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"],
    "F": ["█████", "█    ", "████ ", "█    ", "█    "],
    "I": ["█████", "  █  ", "  █  ", "  █  ", "█████"],
    "R": ["█████", "█   █", "█████", "█   █", "█   █"],
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"],
}
_WANT = "ZEFIRA"


def _read_letters(rows):
    """Which letter does each column of glyphs spell?"""
    if not rows or len({len(r) for r in rows}) != 1:
        return None
    w = len(rows[0])
    letters = []
    for start in range(0, w, 6):          # 5-wide glyph + 1-space gap
        chunk = [r[start:start + 5] for r in rows]
        if any(len(c) != 5 for c in chunk):
            return None
        found = [ch for ch, g in _GLYPHS.items() if g == chunk]
        letters.append(found[0] if len(found) == 1 else "?")
    return "".join(letters)


_read = _read_letters(_rows) if _rows else None
check("each column of the art spells the right letter",
      _read == _WANT, f"the art reads {_read!r}, expected {_WANT!r}")
check("the letters are separated by exactly one space, never zero or two",
      len(_rows) == 5 and len(_rows[0]) == 5 * len(_WANT) + (len(_WANT) - 1),
      f"width {len(_rows[0]) if _rows else 0} for {len(_WANT)} letters "
      f"(5 cells + 1 gap each)")
_named = re.findall(r'\$\{C_BLD\}([A-Za-z0-9_.-]+)\$\{C_RST\}', sh)
check("the banner names the product under the art",
      any(n.lower() == "zefira" for n in _named),
      f"the name under the art is {_named}, expected zefira "
      f"(checked case-insensitively - a first version of this check demanded "
      f"both 'Zefira' and 'zefira' literally, which is not a thing)")
check("the art uses no escape sequences that bash would print literally",
      "\\x" not in (_art.group(1) if _art else "") and "\\033" not in sh.split("ZEFIRA_ART=(")[1][:400],
      "in double quotes \\x is not an escape, so it would print as text")
check("the read-it-first instructions use a private mktemp directory",
      re.search(r"mktemp -d", sh) is not None
      and "/tmp/zefira-inst" not in sh,
      "a predictable /tmp path can be pre-created by another local user")
# A regression I shipped and pushed, so these are permanent.
# `umask 077` makes every directory root creates mode 700 root-owned, so only a
# chown of $TARGET ITSELF lets `User=zefira` chdir into it. The .venv fix
# replaced the blanket `chown -R zefira "$TARGET"` with a `-mindepth 1` find
# that skipped the directory, and the service then failed every boot with
# status=200/CHDIR in a systemd restart loop - a dead panel that reported a
# successful install.
check("$TARGET itself is chowned to the service account",
   re.search(r'^chown zefira:zefira "\$TARGET"\s*$', _sh_code, re.M) is not None,
   "under umask 077 the directory stays root:root 700 and WorkingDirectory="
   "$TARGET cannot be entered by User=zefira. Matched against _sh_code, not "
   "sh: an earlier version of this guard matched the COMMENT quoting the same "
   "line, so a broken installer passed it")
check("the children walk still excludes .venv, so root keeps the venv",
   re.search(r'find "\$TARGET" -mindepth 1 -maxdepth 1 ! -name \'\.venv\'', _sh_code)
   is not None
   and 'chown -R zefira:zefira "$TARGET"' not in _sh_code,
   "chowning .venv to the service account hands back the root-executes-it "
   "escalation; a blanket -R over the tree would undo that guard too")
# Root-owned must not mean root-ONLY. Under `umask 077` a fresh venv is mode
# 700, and the first version of the venv hardening only stripped write bits
# (`chmod go-w`) - which nobody had - so `User=zefira` could not even ENTER
# .venv/bin and every boot died with status=203/EXEC "Failed to execute ...
# Permission denied". The mode check above it (`^[0-5][0-5]$`) passed 700,
# because it tested "not writable by others" while the failure needed
# "traversable by the service account". Same family of mistake as the
# hashes-per-package average: the right property, unchecked.
check("the root-owned venv stays readable and traversable by the service",
   re.search(r'chmod -R u=rwX,go=rX (["\']?)\.venv\1', _sh_code) is not None
   and re.search(r'chmod -R u=rwX,go=rX "\$TARGET/\.venv"', _sh_code) is not None,
   "dirs 755, files 644, executables keep x. A bare `go-w` preserves a 700 "
   "tree and only looks like a fix")
check("no bare go-w on a venv survives anywhere",
   re.search(r'chmod[^\n]*go-w[^\n]*venv', _sh_code) is None,
   "go-w on a umask-077 tree changes nothing - it is the spelling that "
   "shipped the 203/EXEC loop")
# gen_pass drew from 62 symbols with 10 digits, so ~6% of installs got a
# digit-less password: the unattended path then died blaming a variable the
# operator never set, and the interactive path printed a password the panel
# silently replaced. Every generation site must go through the function that
# loops on the panel's own bar - 300 executed draws, zero weak.
check("every generated password passes the panel's own strength bar",
   "strong_enough \"$p\"" in sh or 'strong_enough "$p"' in sh,
   "gen_pass must loop until strong_enough passes, or ~6% of installs get a "
   "password the panel rejects")
check("no inline password generator bypasses gen_pass",
   len(re.findall(r"head -c 18 /dev/urandom \| base64 \| tr -dc", sh))
   <= len(re.findall(r"gen_pass\(\)", sh)) + 1,
   "a second copy of the pipeline without the loop is the same 6% bug again")

# The literal is what a pipe install actually uses, so it has to equal VERSION.
# The previous version of this check restated the number itself
# (`|| echo 1\.14\.2`), which is why it stayed green for two releases while the
# one-liner silently installed v1.14.2: a test that hardcodes the value it is
# checking cannot notice that value going stale.
_repo_version = io.open(ROOT + os.sep + "VERSION", encoding="utf-8-sig").read().strip()
# Read the pin where it now lives. It is a named variable rather than an inline
# `|| echo <n>`, because the piped path must not be able to reach the installed
# tree at all - see version_resolution_test.sh, which runs that path.
_lit = re.search(r'^ZEFIRA_PINNED="([\d.]+)"', sh, re.M)
check("the installer's hardcoded release equals the VERSION file",
      _lit is not None and _lit.group(1) == _repo_version,
      f"install.sh is pinned to v{_lit.group(1) if _lit else '?'} but VERSION "
      f"says {_repo_version}; the pin is the ONLY value a piped install can use, "
      f"so if it drifts the one-liner silently installs a different release")
# And it must be a version that has an upstream tag, or the clone aborts.
check("the release the installer names is a plain dotted version",
      _lit is not None and re.fullmatch(r"\d+\.\d+\.\d+", _lit.group(1)) is not None,
      f"got {(_lit.group(1) if _lit else None)!r}, want x.y.z so the v-prefixed "
      f"tag can be built from it")

# The two checks above are two literals agreeing with each other. They stayed
# green while the pin named a release that no longer contained the code: v1.15.2
# predates the pre-auth DoS budget, the PATCH intent guard and the IP-prefix
# fix, so a FRESH one-liner install would have run today's installer over
# yesterday's application - the fixes would never reach a new server, and the
# one-liner would report success. The pin's whole purpose is reproducibility,
# and a pin that lags the fixes it was meant to ship reproduces the vulnerability.
#
# So the pin is compared against the CODE, not against another literal: the
# product files inside the named tag must be byte-identical to this tree's.
_PRODUCT_FILES = ("main.py", "protocols.py", "schemas.py", "database.py",
                  "security.py", "config.py", "static/app.js",
                  "templates/panel.html", "install.sh")
_pin = _lit.group(1) if _lit else ""
_tag = f"v{_pin}"


def _git(*args):
    try:
        r = subprocess.run(["git"] + list(args), cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=30)
        return r.returncode == 0, (r.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return False, ""


_tag_ok, _tag_sha = _git("rev-parse", "--verify", f"{_tag}^{{commit}}")
check(f"the pinned release {_tag} exists as a tag the clone can fetch",
      _tag_ok,
      f"no such tag. The one-liner runs `git clone --branch {_tag}`; with no "
      f"tag of that name the clone fails and the install dies at the last step")
# Compare blob ids, never bytes. The working tree is CRLF (core.autocrlf=true)
# and the stored blob is LF, so a byte comparison reports EVERY file as
# different and the check becomes a permanent lie. The id is computed here
# instead of shelling out to `git hash-object` once per file: nine subprocesses
# is nine chances to fail for reasons that have nothing to do with the code
# under test. A blob id is sha1("blob <len>\0" + content) with the checkin
# filter applied, which for this repository is exactly CRLF -> LF.
_ok_crlf, _crlf = _git("config", "--get", "core.autocrlf")
_AUTOCRLF = bool(_ok_crlf) and _crlf.strip().lower() == "true"


def _blob_id(rel):
    with io.open(ROOT + os.sep + rel.replace("/", os.sep), "rb") as fh:
        raw = fh.read()
    if _AUTOCRLF:
        raw = raw.replace(b"\r\n", b"\n")
    return hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()


_drifting = []
if _tag_ok:
    for f in _PRODUCT_FILES:
        _, ls = _git("ls-tree", _tag, "--", f)
        parts = ls.split()
        if len(parts) < 3:
            _drifting.append(f"{f} (absent from the tag)")
            continue
        try:
            live = _blob_id(f)
        except OSError as exc:
            _drifting.append(f"{f} (unreadable: {exc.strerror})")
            continue
        if parts[2] != live:
            _drifting.append(f)
if not _tag_ok:
    _drift_detail = (f"tag {_tag} does not exist yet, so there is nothing to "
                     f"compare. Commit first, then tag the release.")
else:
    _drift_detail = (
        f"differs in {len(_drifting)} file(s): {', '.join(_drifting[:4])}. The "
        f"installer clones the tag, so anything committed after it is NOT "
        f"installed - the fix is in the repository and missing from every fresh "
        f"install. Bump VERSION and ZEFIRA_PINNED together and tag the release.")
check(f"the pinned release {_tag} ships this tree's code, not older code",
      _tag_ok and not _drifting, _drift_detail)
# ---- the lock must be installable on the platform it ships to ------------
# It was not. tools_lock.py hashed whatever `pip download` found ON THE
# MACHINE THAT GENERATED IT and only asked PyPI when it found nothing, so a
# package with a wheel for the local interpreter (CPython 3.14 on Windows)
# got exactly one hash - the local one. 11 of 31 entries were uninstallable
# on Linux, and the reported failure was cffi: the lock held the cp314
# win_amd64 digest while the server downloads the cp312 manylinux wheel.
#
# This is a real security property, not cosmetics: a hash lock whose hashes do
# not match the artifacts the target fetches is either a broken install or a
# lock that verifies nothing.
_lock = io.open(ROOT + os.sep + "requirements.lock", encoding="utf-8").read()
_lock_entries = re.findall(
    r"^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?==(\S+)\s*\\?$", _lock, re.M)
_lock_hashes = re.findall(r"^\s*--hash=sha256:([0-9a-f]{64})", _lock, re.M)
check("the lock pins every package with a version", len(_lock_entries) >= 25,
      f"{len(_lock_entries)} pinned entries")
check("the lock is not empty and every entry has hashes",
      len(_lock_hashes) > 0
      and "# UNHASHED" not in _lock,
      "an entry with no hash means --require-hashes is theatre")
# The defect, stated as an invariant that a static check can actually see: a
# single hash per package IS a single-platform lock. Reducing one entry back to
# one hash removes ~99 of ~916, so an aggregate "hashes per package" average
# barely moves and the check passed - which is why the first version of this
# guard MISSED the very regression it was written for.
_per_entry = {}
for _m in re.finditer(
        r"^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?==(\S+)[^\n]*\n((?:\s*--hash=[^\n]*\n)+)",
        _lock, re.M):
    _per_entry[_m.group(1)] = len(re.findall(r"--hash=", _m.group(4)))
_single = [n for n, c in _per_entry.items() if c <= 1]
check("no lock entry is pinned to a single artifact",
      not _single and len(_per_entry) == len(_lock_entries),
      f"entries with only one hash (a single-platform lock): {_single[:6]}")
# "More than one" is the invariant, NOT "at least N". A pure-Python package
# legitimately publishes exactly two artifacts - one wheel, one sdist - and a
# first version of this check demanded four, so it failed on anyio,
# annotated-types and every other platform-independent package in the lock.
check("every lock entry covers at least the wheel and the sdist",
      _per_entry and min(_per_entry.values()) >= 2,
      f"thinnest entries: {sorted(_per_entry.items(), key=lambda kv: kv[1])[:4]}")
check("a package with platform wheels covers more than a pure-Python one",
      max(_per_entry.values()) >= 20,
      f"widest entry has {max(_per_entry.values()) if _per_entry else 0} hashes - "
      f"if nothing does, PyPI coverage is not being collected at all")
# And the generator must not be able to regress to local-only.
check("tools_lock.py unions the local artifacts with PyPI's, unconditionally",
      re.search(r"digests\s*=\s*\{hashes\[fn\]\s*for\s+fn\s+in\s+arts\}", _tools_lock)
  is not None
  and re.search(r"digests\.update\(pypi_hashes\(name, ver\)\)", _tools_lock)
  is not None,
      "the PyPI lookup must be part of the union, not a fallback for when the "
      "local download found nothing")
check("...and no `if not digests:` gate stands between them",
      re.search(r"if not digests:\s*\n\s*digests = pypi_hashes", _tools_lock) is None,
      "a conditional PyPI lookup is what produced the local-only lock")
check("a verifier exists, so the lock can be checked against PyPI",
      os.path.exists(ROOT + os.sep + "verify_lock_hashes.py"),
      "without this, a wrong hash is only found by a failed install on a "
      "machine that is not the one that generated it")
check("the README/install docs mention the verifier",
      "verify_lock_hashes" in readme,
      "regenerating the lock must be followed by verifying it")

check("the README's read-it-first block has the same fix",
      "mktemp -d" in readme
      # Mentioning the old path in prose is fine; USING it is not.
      and "mkdir -p /tmp/zefira-inst" not in readme
      and "-o /tmp/zefira-inst" not in readme,
      "the documented mitigation was a predictable /tmp path")

# ---- 6. uninstall must work from the menu ------------------------------
check("uninstall is a function both entry points call",
      re.search(r"^do_uninstall\(\) \{", sh, re.M) is not None
      and re.search(r'if \[\[ "\$\{1:-\}" == "--uninstall" \]\]; then\s*\n\s*do_uninstall',
                    sh) is not None
      and re.search(r'if \[\[ "\$yes" == "yes" \]\]; then\s*\n\s*do_uninstall', sh) is not None)
check("the menu never re-executes the script by path ($0 is bash under a pipe)",
      'exec bash "$0"' not in sh_code,
      're-running "bash bash --uninstall" silently does nothing')
check("option 2 reads the real .env keys",
      "ZEFIRA_ADMIN_(USERNAME|PASSWORD)" in sh_code)

# ---- 7. the summary keeps the facts an operator needs ------------------
# The labels are printf format strings (" %sPanel%s    : %s"), so match the
# label plus its colon rather than a plain substring.
for label in ("Panel", "Local", "Sub path", "Database", "SSL", "Service"):
    check(f"the summary still prints {label}",
          re.search(r"%s%s%s\s*:\s*%%s" % (re.escape(label), r"[^%]*%s", ""), sh_code)
          is not None or re.search(r"%s%s\s*:\s*%%s" % (re.escape(label), r"[^%]*"),
                                   sh_code) is not None,
          f"no printf line for {label}")
check("the password warning survives the restyle",
      "Change the admin password after the first login" in sh_code)

print(f"\n{'ALL OK' if not fails else str(len(fails)) + ' FAILURES'}")
sys.exit(1 if fails else 0)
