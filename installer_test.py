"""Regression guards for the BackPack-style installer CLI (install.sh).

The one-liner (`curl ... | sudo bash`) must never block, so the aftercare
menu has to be interactive-only, and the uninstall path has to work when $0
is "bash" (which is what it is under a pipe).
"""
import io
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = r"C:\Users\mrlurix\Desktop\laptop pro\zefira"
BASH = r"C:\Program Files\Git\bin\bash.exe"
sh = io.open(ROOT + r"\install.sh", encoding="utf-8").read()
# Comment lines stripped: a guard about code must not be satisfied - or
# broken - by the comment that explains the code.
sh_code = "\n".join(ln for ln in sh.splitlines()
                    if not ln.strip().startswith("#"))
readme = io.open(ROOT + r"\README.md", encoding="utf-8").read()
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
check("EOF on the prompt returns instead of spinning",
      re.search(r"read -e -r choice \|\| \{ echo; return 0; \}", sh) is not None)
check("the uninstall confirmation also survives EOF",
      re.search(r"printf 'Type yes to remove Zefira: ' ; read -r yes \|\| \{ echo; return 0; \}",
                sh) is not None)
check("the documented one-liner is untouched",
      "curl -fsSL https://raw.githubusercontent.com/mrlurix/zefira-panel/main/install.sh | sudo bash"
      in sh)
check("non-interactive installs still skip the wizard",
      "[[ -t 0 ]] && INTERACTIVE=1" in sh)

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
check("the version fallback names a tag that exists upstream",
      re.search(r'cat "\$TARGET/VERSION" 2>/dev/null \|\| echo 1\.14\.2', sh) is not None,
      "the pipe-install fallback version is stale")
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
