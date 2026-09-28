#!/usr/bin/env bash
# Does the one-liner actually ASK, or does it silently take every default?
#
# The defect this exists for: interactivity was decided by `[[ -t 0 ]]`, and
# under `curl ... | sudo bash` stdin is the pipe carrying install.sh itself, so
# that test is ALWAYS false. The installer therefore asked the operator for a
# port, a database, an admin account, a subscription path, Telegram and SSL,
# and then ignored every answer and used defaults. Reading the source cannot
# see that, because the prompts and the dead gate both look correct.
#
# Two things are checked here, by running the real code:
#   1. a prompt reads from the TERMINAL, not from stdin - proven by handing the
#      helper a "terminal" that is an ordinary file full of answers while stdin
#      is carrying more script. If any read still came from stdin it would eat
#      the script and return the wrong value.
#   2. the gate is a real tty probe with a working non-interactive escape, so
#      unattended installs keep taking defaults instead of hanging.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
SH="$HERE/install.sh"
rc=0

BLOCK="$(awk '/^# --- begin interactivity/{f=1;next} /^# --- end interactivity/{f=0} f{print}' "$SH")"
CODE="$(printf '%s\n' "$BLOCK" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$')"
if [[ -z "$CODE" ]]; then
    echo "could not find the interactivity block (markers missing?)" >&2
    exit 1
fi
LINES="$(printf '%s\n' "$CODE" | wc -l | tr -d ' ')"
if [[ "$LINES" -gt 60 ]]; then
    echo "interactivity slice is $LINES lines of code - markers are wrong" >&2
    exit 1
fi
if printf '%s' "$CODE" | grep -qE 'git clone|systemctl|apt-get|pip install|copy_tree|rm -rf'; then
    echo "the slice has installer side effects - refusing to source it" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- 1. prompts read the terminal, not stdin -------------------------------
# A "terminal" holding the operator's answers...
printf '9443\nChoose' > "$WORK/answers"
# ...and stdin carrying what a piped script would carry: MORE SCRIPT.
cat > "$WORK/script_on_stdin" <<'EOS'
echo "THIS LINE IS SCRIPT, NOT AN ANSWER"
EOS

out="$(ANSWERS="$WORK/answers" bash -c "$CODE
# The block above REASSIGNS TTY_PATH from its own probe, which is correct for a
# real install and useless for a test: exporting TTY_PATH before the block runs
# just gets overwritten. So the gate is exercised for what it is - deciding
# interactivity - and the read is then driven with a terminal we control.
# (ANSWERS must be exported BEFORE the bash -c below; an assignment placed
# after the input redirection is a command argument, not an environment var.)
TTY_PATH=\"\$ANSWERS\"
echo \"INTERACTIVE=\$INTERACTIVE\"
tty_read -r answer
echo \"GOT=\$answer\"" < "$WORK/script_on_stdin" 2>/dev/null | tail -3)"

echo "=== prompt sourcing ==="
printf '%s\n' "$out" | sed 's/^/  /'
if ! printf '%s' "$out" | grep -q "GOT=9443"; then
    echo "FAIL: the prompt did not read the terminal (expected GOT=9443)"
    echo "      a read from stdin would have returned the script text instead,"
    echo "      and then blocked forever on the next one."
    rc=1
else
    echo "  ok: the prompt took the operator's answer from the terminal"
fi

# ---- 2. the gate is a tty probe, with a working opt-out --------------------
# Comments are stripped first: the block's own explanation quotes the old
# `[[ -t 0 ]]` to explain why it was wrong, and grepping the file for that
# string finds the explanation. (The same trap caught a guard in installer_test
# that asserted the literal text of the mechanism instead of the behaviour.)
if printf '%s\n' "$CODE" | grep -q '\[\[ -t 0 \]\]'; then
    echo "FAIL: interactivity is still decided by '[[ -t 0 ]]' - under a pipe"
    echo "      that is never true, so the wizard is unreachable again."
    rc=1
else
    echo "  ok: interactivity no longer depends on stdin being a terminal"
fi
if ! grep -q 'ZEFIRA_NONINTERACTIVE' "$SH"; then
    echo "FAIL: no opt-out for unattended installs (systemd/cron/CI must not"
    echo "      block waiting for input that can never arrive)"
    rc=1
else
    echo "  ok: ZEFIRA_NONINTERACTIVE keeps unattended installs on defaults"
fi
if ! printf '%s\n' "$CODE" | grep -qE '\(:? *< */dev/tty\) *2>/dev/null'; then
    echo "FAIL: the tty probe must actually OPEN /dev/tty, quietly, or a"
    echo "      session with no controlling terminal hangs instead of falling back"
    rc=1
else
    echo "  ok: the probe opens /dev/tty, so a session with no controlling"
    echo "      terminal falls back instead of hanging"
fi

# ---- 3. every prompt goes through the helper --------------------------------
# Scanned OUTSIDE the interactivity block: the helper's own body reads from the
# tty file (or stdin when there is none) and is supposed to.
bare="$(awk '/^# --- begin interactivity/{skip=1;next} /^# --- end interactivity/{skip=0} !skip' "$SH" \
        | grep -vE '^[[:space:]]*#' \
        | grep -nE '(^|[^_[:alnum:]])read[[:space:]]+-[a-z]*[pr]' \
        | grep -v 'tty_read' || true)"
if [[ -n "$bare" ]]; then
    echo "FAIL: these reads still come from stdin:"
    printf '%s\n' "$bare" | sed 's/^/    /'
    rc=1
else
    echo "  ok: every prompt outside the helper reads through tty_read"
fi

[[ $rc -eq 0 ]] && echo "installer interactivity: ALL OK"
exit $rc
