#!/usr/bin/env bash
# Exercise install.sh's version resolution the way a real pipe install does.
#
# The bug this exists for: `cat "$TARGET/VERSION"` looks like a harmless
# fallback, but on a server that ALREADY has Zefira installed it succeeds and
# returns the version being replaced, so `curl | sudo bash` re-clones the old
# tag and upgrades nothing while printing a success message. Reading the source
# cannot see that; running it can.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
SH="$HERE/install.sh"

# The literal release the script is cut for, read from the script itself.
PINNED="$(grep -oE 'ZEFIRA_PINNED="[0-9.]+"' "$SH" | head -1 | grep -oE '[0-9.]+')"

# A fake previous install, holding an OLD version, as on the user's server.
FAKE="$(mktemp -d)"
trap 'rm -rf "$FAKE"' EXIT
printf '1.9.9\n' > "$FAKE/VERSION"

# Slice out just the resolution block, using the markers install.sh puts around
# it. The first version of this test sliced to the first `^fi$`, which meant
# that REMOVING the if/fi sent it to end-of-file - and it then executed the
# whole installer, which reported nothing wrong. So the slice is bounded by
# explicit markers, and it is checked for size and for anything that would
# touch the machine, rather than trusted.
BLOCK="$(awk '/^# --- begin version-resolution/{f=1;next} /^# --- end version-resolution/{f=0} f{print}' "$SH")"
# Comments do not execute, so they come out before the size check - otherwise
# the block's own explanation of the bug is counted as bloat.
CODE="$(printf '%s\n' "$BLOCK" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$')"
LINES="$(printf '%s\n' "$CODE" | wc -l | tr -d ' ')"
if [[ -z "$CODE" ]]; then
    echo "could not locate the version-resolution block (are the markers present?)" >&2
    exit 1
fi
if [[ "$LINES" -gt 20 ]]; then
    echo "the slice is $LINES lines of code - the markers are wrong, refusing" >&2
    exit 1
fi
if printf '%s' "$CODE" | grep -qE 'git clone|systemctl|apt-get|pip install|copy_tree'; then
    echo "the slice contains installer side effects - refusing to source it" >&2
    exit 1
fi

# The pipe install runs from wherever the user happens to be - `/root`, their
# home, a project directory - and there is no VERSION file there. That detail is
# the entire bug: with the repo's own VERSION still in the CWD, the FIRST
# `cat` succeeds and the test passes whether or not the code is right, which is
# how a first version of this test reported MISSED on the shipped defect.
resolve_piped() {   # how the one-liner runs: no script file, CWD has no VERSION
    local empty; empty="$(mktemp -d)"
    local out
    out="$(cd "$empty" && bash -c "TARGET='$FAKE'
$BLOCK
echo \"\$ZEFIRA_VERSION\"" < /dev/null | tail -1)"
    rm -rf "$empty"
    printf '%s\n' "$out"
}

resolve_from_checkout() {  # how a reviewed install runs: real file, own VERSION
    local d; d="$(mktemp -d)"
    printf '%s\n' "$PINNED" > "$d/VERSION"
    local out
    out="$(cd "$d" && bash -c "TARGET='$FAKE'
$BLOCK
echo \"\$ZEFIRA_VERSION\"" "$d/install.sh" < /dev/null | tail -1)"
    rm -rf "$d"
    printf '%s\n' "$out"
}

PIPED="$(resolve_piped)"
CHECKOUT="$(resolve_from_checkout)"

echo "script is pinned to        : $PINNED"
echo "previous install on disk   : $(cat "$FAKE/VERSION" | tr -d '\n')"
echo "piped (the one-liner) picks: $PIPED"
echo "from a checkout picks      : $CHECKOUT"

rc=0
if [[ "$PIPED" != "$PINNED" ]]; then
    echo "FAIL: piped install took its version from the install it is replacing"
    echo "      -> it would re-clone the old tag and upgrade nothing, silently."
    rc=1
fi
if [[ "$CHECKOUT" != "$PINNED" ]]; then
    echo "FAIL: a checkout with VERSION $PINNED resolved to '$CHECKOUT'"
    rc=1
fi
[[ $rc -eq 0 ]] && echo "version resolution: ALL OK"
exit $rc
