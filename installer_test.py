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
