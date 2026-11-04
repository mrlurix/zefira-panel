"""install.sh must refuse a symlinked .venv, and must not report success on a dead panel.

Both are guard-shaped problems found by auditing install.sh, and both had a
comment that read like a protection.

THE .venv SYMLINK
install.sh:531 opened with `if [[ -d .venv ]]`. `-d` FOLLOWS a symlink, so a
.venv pointing at a root-owned 0755 directory passes: the `stat` calls that
follow see owner=root and mode=755, the guard is satisfied, and the following
lines run as root INSIDE the directory the service account picked -
`python3 -m venv` creates directories there and
`chmod -R u=rwX,go=rX` relaxes its mode. The comment directly above the guard
names this exact threat ("Any RCE in the panel is therefore one
`curl | sudo bash` away from ROOT"); the guard did not implement it. The script
already refuses symlinks twice elsewhere, so this is the same check applied to
the third path.

THE SUCCESS BANNER
`fail()` is `echo`, so it returns 0, and nothing after the verification block
exited non-zero. A wedged panel printed "[x] Port not listening" and then a
green "Installed." with a URL on the next line. Verified by running both
shapes: before, the dead panel produced a green Installed; after, it says the
panel is NOT answering and prints the two commands to diagnose it.

THE UNBOUND VERIFY_FAILED
The script runs under `set -u`. `VERIFY_FAILED=0` was placed INSIDE the `else`
of the panel health check, so it only ran when the panel was DOWN. On a
HEALTHY install the assignment was skipped and the summary line
`if [[ "$VERIFY_FAILED" -eq 1 ]]` aborted with
"VERIFY_FAILED: unbound variable" - the installer failed at the last step
precisely when everything had worked. The old check only proved the string
`VERIFY_FAILED=0` existed somewhere; it passed with the assignment in the
wrong branch. It now (a) requires the initialisation BEFORE the health check
and (b) executes the real block under `set -u` with a stubbed healthy panel,
so moving the assignment back into the `else` turns the test red.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
INSTALL = os.path.join(ROOT, "install.sh")
BASH = r"C:\Program Files\Git\bin\bash.exe"


def read():
    with io.open(INSTALL, encoding="utf-8", newline="") as fh:
        return fh.read()


def checks(src):
    lines = src.split("\n")
    i = next((n for n, l in enumerate(lines) if l.strip() == "if [[ -d .venv ]]; then"), None)
    window = "\n".join(lines[max(0, i - 14):i]) if i is not None else ""
    # The banner, and whether it is conditional on the verification result.
    banner = next((n for n, l in enumerate(lines)
                   if l.startswith('echo "${C_GRN}${C_BLD}  Installed.${C_RST}')), None)
    # The verification flag must be initialised BEFORE the health check, not
    # inside its `else`: with `set -u`, a healthy panel skipped the assignment
    # and the summary died on "VERIFY_FAILED: unbound variable".
    health = next((n for n, l in enumerate(lines)
                   if l.strip().startswith('if curl -fsS "http://127.0.0.1:$PORT/login"')), None)
    init = next((n for n, l in enumerate(lines) if l.strip() == "VERIFY_FAILED=0"), None)
    # Search upward for the enclosing `if`, not a fixed offset: the fix put the
    # guard well above the echo, and a +/-10 window missed it and reported a
    # green banner as ungated when it is in fact gated.
    around = ""
    if banner is not None:
        for n in range(banner, max(-1, banner - 20), -1):
            around = lines[n] + "\n" + around
            if lines[n].strip().startswith("if [["):
                break
    return {
        # 1. the venv symlink refusal, and it must come BEFORE -d inspects it
        "a symlinked .venv is refused":
            "if [[ -L .venv ]]; then" in src,
        "the refusal precedes the -d test":
            i is not None and window.count("if [[ -L .venv ]]; then") >= 1,
        "the refusal removes the link, not the target":
            re.search(r"if \[\[ -L \.venv \]\]; then[\s\S]{0,400}?rm -f \.venv", src) is not None,
        # 2. the verification flag is set on both failure branches
        "verification records failure":
            src.count("VERIFY_FAILED=1") >= 2,
        "the flag is initialised before the health check":
            init is not None and health is not None and init < health,
        # 3. the success banner is conditional
        "the success banner is conditional on verification":
            'if [[ "$VERIFY_FAILED" -eq 1 ]]; then' in around,
        "a dead panel says so in words":
            "NOT answering" in src,
        "the failure tells the operator what to run":
            "systemctl status" in src and "journalctl" in src,
        # fail() must still not exit, or an unrelated early fail would abort a
        # good install; the point is that the BANNER is gated, not that fail()
        # exits.
        "fail() still only prints":
            re.search(r"fail\(\)\s*\{ echo", src) is not None,
        # 4. ownership/mode changes must not dereference a planted symlink.
        # chown follows each OPERAND unless -h is given, and find passes every
        # top-level entry as one, so a symlink at /opt/zefira/pwn would have its
        # target chowned. -R does not prevent this: it stops traversal at a
        # symlinked directory but still dereferences the link itself.
        "the tree chown passes -h":
            re.search(r"-exec chown -Rh zefira:zefira", src) is not None,
        "the tree chown has no bare -R form left":
            re.search(r"-exec chown -R zefira:zefira", src) is None,
        "the database chmod passes -h":
            re.search(r"chmod -h 600 \"\$TARGET/instance/zefira\.db\"", src) is not None,
    }


def bash_probe(script, cwd=None):
    if not os.path.exists(BASH):
        return None
    try:
        r = subprocess.run([BASH, script.replace("\\", "/")], capture_output=True,
                           text=True, timeout=90, cwd=cwd)
        return r.stdout + r.stderr
    except Exception:
        return None


def verify_parts(src):
    """The real verification block and the real banner guard, from install.sh.

    Extracting them (instead of copying a paraphrase) is what makes the probe
    below a regression test: if the source changes shape, this returns None and
    the test says so rather than silently testing a stale replica.
    """
    lines = src.split("\n")
    start = next((n for n, l in enumerate(lines)
                  if l.strip() == 'echo "==> Verifying..."'), None)
    if start is None:
        return None, None
    end = next((n for n in range(start, len(lines))
                if lines[n].startswith("ss -tlnp ")), None)
    guard = next((l.strip() for l in lines
                  if l.strip() == 'if [[ "$VERIFY_FAILED" -eq 1 ]]; then'), None)
    if end is None or guard is None:
        return None, None
    return "\n".join(lines[start:end + 1]), guard


def run_verify(block, guard, healthy):
    """Run the extracted block under `set -euo pipefail`, stubbing the probes.

    `curl` and `ss` are replaced so no socket is needed: a healthy panel is
    curl 0 plus an ss line that matches the `grep -q ":$PORT "`, a dead one is
    curl 7 plus empty ss output. The appended `guard` is the verbatim source
    line that reads VERIFY_FAILED, so this reproduces the real unbound-variable
    failure instead of an imitation of it.
    """
    if not os.path.exists(BASH):
        return None
    tmp = tempfile.mkdtemp(prefix="zefira_verify_")
    try:
        sh = os.path.join(tmp, "v.sh")
        with io.open(sh, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("set -euo pipefail\n")
            fh.write('ok()   { echo "[ok] $*"; }\n')
            fh.write('fail() { echo "[x] $*"; }\n')
            fh.write("PORT=8000\n")
            if healthy:
                fh.write("curl() { return 0; }\n")
                fh.write('ss() { echo "LISTEN 0 4096 0.0.0.0:$PORT 0.0.0.0:*"; }\n')
            else:
                fh.write("curl() { return 7; }\n")
                fh.write("ss() { return 1; }\n")
            fh.write(block + "\n")
            fh.write(guard + ' echo "GATED=1"; else echo "GATED=0"; fi\n')
            fh.write('echo "RESULT=${VERIFY_FAILED}"\n')
        r = subprocess.run([BASH, sh.replace("\\", "/")], capture_output=True,
                           text=True, timeout=90, cwd=tmp)
        return r.returncode, r.stdout + r.stderr
    except Exception:
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def move_init_into_else(block):
    """Put VERIFY_FAILED=0 back inside the health check's `else`.

    This is the exact regression: a healthy panel skips the assignment.
    """
    m = re.search(r"^VERIFY_FAILED=0\n", block, re.M)
    if not m:
        return block
    without = block[:m.start()] + block[m.end():]
    if "; else\n" not in without:
        return block
    return without.replace("; else\n", "; else\nVERIFY_FAILED=0\n", 1)


def main():
    failures = []
    src = read()
    base = checks(src)

    print("== 1. the two guards are in place ==")
    for name, ok in sorted(base.items()):
        print("   %-52s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2. `[[ -d ]]` really does follow a symlink, so `-L` is needed ==")
    tmp = tempfile.mkdtemp(prefix="zefira_dash_")
    try:
        probe = os.path.join(tmp, "p.sh")
        with io.open(probe, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(
                'mkdir -p "$1/decoy"\n'
                'mkdir -p "$1/holder"\n'
                'ln -s "$1/decoy" "$1/holder/.venv" 2>/dev/null\n'
                'cd "$1/holder" || exit 1\n'
                'if [[ -d .venv ]]; then echo "D_FOLLOWS=yes"; else echo "D_FOLLOWS=no"; fi\n'
                'if [[ -L .venv ]]; then echo "L_DETECTS=yes"; else echo "L_DETECTS=no"; fi\n')
        out = bash_probe(probe, cwd=tmp)
        if out is None:
            print("   SKIPPED: no bash on this host")
        else:
            follows = "D_FOLLOWS=yes" in out
            detects = "L_DETECTS=yes" in out
            print("   [[ -d .venv ]] follows a symlink : %s" % ("yes" if follows else "NO"))
            print("   [[ -L .venv ]] detects it        : %s" % ("yes" if detects else "NO"))
            if not follows:
                print("   -> -d does not follow here, so this platform cannot prove the bug")
            elif not detects:
                print("   FAIL: -d follows but -L does not detect; the guard is wrong")
                failures.append("symlink probe")
            else:
                print("   -> the old guard was blind to the link; the new one is not")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("== 3. the dead-panel banner: run both shapes ==")
    tmp2 = tempfile.mkdtemp(prefix="zefira_banner_")
    try:
        sh = os.path.join(tmp2, "b.sh")
        body = """
C_GRN=""; C_RED=""; C_DIM=""; C_BLD=""; C_RST=""
ok()   { echo "[ok] $*"; }
fail() { echo "[x] $*"; }
PORT=1; SERVICE=zefira; URL=http://x
verify() {
  local mode="$1"
  if [[ "$mode" == before ]]; then
    if curl -fsS "http://127.0.0.1:$PORT/login" >/dev/null 2>&1; then ok up; else
      fail "Panel not responding - logs:"; fi
    ss -tlnp 2>/dev/null | grep -q ":$PORT " && ok listening || fail "Port $PORT not listening"
    echo "${C_GRN}${C_BLD}  Installed.${C_RST}  ${C_DIM}${URL}${C_RST}"
  else
    VERIFY_FAILED=0
    if curl -fsS "http://127.0.0.1:$PORT/login" >/dev/null 2>&1; then ok up; else
      fail "Panel not responding - logs:"; VERIFY_FAILED=1; fi
    ss -tlnp 2>/dev/null | grep -q ":$PORT " && ok listening || { fail "Port $PORT not listening"; VERIFY_FAILED=1; }
    if [[ "$VERIFY_FAILED" -eq 1 ]]; then
      echo "${C_RED}${C_BLD}  Installed, but the panel is NOT answering.${C_RST}  ${C_DIM}${URL}${C_RST}"
      echo "${C_DIM}    systemctl status $SERVICE${C_RST}"
    else
      echo "${C_GRN}${C_BLD}  Installed.${C_RST}  ${C_DIM}${URL}${C_RST}"
    fi
  fi
}
verify "$1"
"""
        with io.open(sh, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
        before = bash_probe(sh + " before" if False else os.path.join(tmp2, "b.sh"))
        # run with an argument: write two wrappers
        w1 = os.path.join(tmp2, "r1.sh")
        w2 = os.path.join(tmp2, "r2.sh")
        with io.open(w1, "w", encoding="utf-8", newline="\n") as fh:
            fh.write('source "%s" before\n' % sh.replace("\\", "/"))
        with io.open(w2, "w", encoding="utf-8", newline="\n") as fh:
            fh.write('source "%s" after\n' % sh.replace("\\", "/"))
        b = bash_probe(w1)
        a = bash_probe(w2)
        if b is None or a is None:
            print("   SKIPPED: no bash on this host")
        else:
            print("   before: %s" % [l.strip() for l in b.splitlines()
                                   if "Installed" in l][:1])
            print("   after : %s" % [l.strip() for l in a.splitlines()
                                    if "Installed" in l][:1])
            if any(l.strip().startswith("Installed.") and "NOT answering" not in l
                   for l in b.splitlines()):
                print("   -> confirmed: the old shape prints a bare success banner")
            else:
                print("   FAIL: the 'before' shape did not reproduce a green banner")
                failures.append("banner repro")
            if any("NOT answering" in l for l in a.splitlines()):
                print("   -> confirmed: the new shape refuses to claim success")
            else:
                print("   FAIL: the new shape does not warn")
                failures.append("banner fix")
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)

    print()
    print("== 4. each guard can fail: undo it, it must go red ==")
    muts = [
        ("remove the -L refusal",
         lambda t: re.sub(r"if \[\[ -L \.venv \]\]; then\n(?:[^\n]*\n)*?fi\n\n", "", t, count=1),
         ["a symlinked .venv is refused", "the refusal precedes the -d test",
          "the refusal removes the link, not the target"]),
        ("un-gate the success banner",
         lambda t: t.replace('if [[ "$VERIFY_FAILED" -eq 1 ]]; then', "if false; then"),
         ["the success banner is conditional on verification"]),
        ("drop one VERIFY_FAILED=1",
         lambda t: t.replace("VERIFY_FAILED=1\n", "", 1),
         ["verification records failure"]),
        ("move the flag back into the else",
         lambda t: t.replace(
             'VERIFY_FAILED=0\nif curl -fsS "http://127.0.0.1:$PORT/login"'
             ' >/dev/null 2>&1; then ok "Panel running on port $PORT"; else\n',
             'if curl -fsS "http://127.0.0.1:$PORT/login"'
             ' >/dev/null 2>&1; then ok "Panel running on port $PORT"; else\n'
             'VERIFY_FAILED=0\n'),
         ["the flag is initialised before the health check"]),
        ("remove -h from the tree chown",
         lambda t: t.replace("-exec chown -Rh zefira:zefira", "-exec chown -R zefira:zefira"),
         ["the tree chown passes -h", "the tree chown has no bare -R form left"]),
        ("remove -h from the database chmod",
         lambda t: t.replace('chmod -h 600 "$TARGET/instance/zefira.db"',
                             'chmod 600 "$TARGET/instance/zefira.db"'),
         ["the database chmod passes -h"]),
    ]
    for name, fn, must in muts:
        mutated = fn(src)
        if mutated == src:
            print("   %-34s FAIL (mutation inert)" % name)
            failures.append(name + ": inert")
            continue
        after = checks(mutated)
        still = [g for g in must if after[g]]
        if still:
            print("   %-34s FAIL (stayed green: %s)" % (name, ", ".join(still)))
            failures.append(name + ": cannot fail")
        else:
            print("   %-34s ok (goes red: %s)" % (name, ", ".join(must)))

    print()
    print("== 5. a HEALTHY panel must survive `set -u` ==")
    block, guard = verify_parts(src)
    if block is None:
        print("   FAIL: could not extract the verification block / banner guard")
        failures.append("verify block extraction")
    else:
        healthy = run_verify(block, guard, healthy=True)
        dead = run_verify(block, guard, healthy=False)
        if healthy is None or dead is None:
            print("   SKIPPED: no bash on this host")
        else:
            hrc, hout = healthy
            drc, dout = dead
            ok_healthy = hrc == 0 and "GATED=0" in hout and "RESULT=0" in hout
            ok_dead = drc == 0 and "GATED=1" in dout and "RESULT=1" in dout
            print("   healthy panel: exit=%s result=%s" % (
                hrc, "0" if "RESULT=0" in hout else "MISSING"))
            print("   dead panel   : exit=%s result=%s" % (
                drc, "1" if "RESULT=1" in dout else "MISSING"))
            if ok_healthy:
                print("   -> a healthy install reaches the banner with the flag set")
            else:
                print("   FAIL: the healthy path did not complete")
                if "unbound variable" in hout:
                    print("      reproduced: %s" % next(
                        (l.strip() for l in hout.splitlines() if "unbound variable" in l), ""))
                failures.append("healthy path")
            if not ok_dead:
                print("   FAIL: the dead path did not record VERIFY_FAILED=1")
                failures.append("dead path")

            broken = move_init_into_else(block)
            if broken == block:
                print("   FAIL: could not move the initialisation back into the else")
                failures.append("unbound mutation: inert")
            else:
                m = run_verify(broken, guard, healthy=True)
                if m is None:
                    print("   SKIPPED: no bash on this host")
                else:
                    mrc, mout = m
                    if mrc != 0 and "unbound variable" in mout:
                        print("   -> regression confirmed: moving the flag back into")
                        print("      the else aborts a healthy install with")
                        print("      'VERIFY_FAILED: unbound variable'")
                    else:
                        print("   FAIL: the mutated block did not reproduce the crash")
                        failures.append("unbound mutation: no crash")

    print()
    if failures:
        print("FAIL: %d problem(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("PASS: both installer guards hold, and each can fail.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())