#!/usr/bin/env bash
# Do the two answers that silently did nothing now work?
#
# 1. `yes` at a [y/N] prompt. The question tested `[yY]*` and the four places
#    that act on the answer tested `[yY]`, so typing "yes" asked for nginx and
#    then did none of it - no vhost, the bind left on 0.0.0.0, the panel port
#    opened in the firewall, and a URL printed that resolves to nothing. The
#    installer looked like it had set nginx up.
#
# 2. Re-running the installer on a server where the service already holds the
#    port. The preflight exited 1 on ANY listener, and the service is not
#    stopped for ~600 lines after it, so the documented upgrade always aborted
#    on the panel's own installation.
#
# Both are checked by RUNNING the logic, because in both cases the code looks
# correct in the source and only the executed behaviour differs.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
SH="$HERE/install.sh"
rc=0

# ---- 1. the yes/no normalisation -----------------------------------------
# Slice the nginx/SSL block, then run it with a stubbed tty for each answer.
BLOCK="$(sed -n '/^# --- begin nginx\/ssl answers/,/^# --- end nginx\/ssl answers/p' "$SH")"
if [[ -z "$BLOCK" ]]; then
    echo "could not locate the nginx/SSL answer block" >&2
    exit 1
fi

for ans in y Y yes YES Yes n N no ""; do
    work="$(mktemp -d)"
    # Two lines: the nginx answer, then the SSL answer. Without the second the
    # SSL read hits EOF and USE_SSL comes back empty.
    printf '%s\nn\n' "$ans" > "$work/tty"
    # EMAIL and USE_SSL prompts are stubbed; ask() is stubbed to its default.
    out="$(cd "$work" && bash -c "
TTY_PATH=\"\$PWD/tty\"
DOMAIN=\"panel.example.com\"
EMAIL=\"\"
INTERACTIVE=1
ask() { echo \"\$2\"; }
tty_read() { read -r \"\$@\" < \"\$TTY_PATH\"; }
is_valid_email() { return 0; }
$BLOCK
echo \"NGINX=[\$SETUP_NGINX] SSL=[\${USE_SSL:-unset}]\"" 2>/dev/null | tail -1)"
    printf '  answer %-6s -> %s\n' "'$ans'" "$out"
    got="$(printf '%s' "$out" | sed -n 's/.*NGINX=\[\([^]]*\)\].*/\1/p')"
    case "$ans" in
      y|Y|yes|YES|Yes)
        # Accepted: after normalisation the value must satisfy [yY] on its own.
        if [[ ! "$got" =~ ^[yY]$ ]]; then
          echo "    FAIL: '$ans' should normalise to y or Y, got '$gt'"
          rc=1
        fi ;;
      "")
        # Empty means no, and must not be mistaken for yes at any site.
        if [[ "$got" =~ ^[yY]$ ]]; then
          echo "    FAIL: an empty answer became '$got'; [y/N] defaults to no"
          rc=1
        fi ;;
      n|N|no)
        if [[ ! "$got" =~ ^[nN]$ ]]; then
          echo "    FAIL: '$ans' should normalise to n or N, got '$got'"
          rc=1
        fi ;;
    esac
    # And whatever it is, the value must be ONE character: a multi-character
    # answer is what the [yY] vs [yY]* split used to disagree about.
    if [[ ${#got} -gt 1 ]]; then
      echo "    FAIL: '$ans' left a ${#got}-character value ('$got'); every"
      echo "           consumer tests [yY], which only matches one character"
      rc=1
    fi
    rm -rf "$work"
done

# ---- 2. the port preflight must not abort on our own service --------------
# Reproduce the decision with a stubbed `ss` reporting the panel's own listener.
pf="$(sed -n '/^# --- begin port preflight/,/^# --- end port preflight/p' "$SH")"
if [[ -z "$pf" ]]; then
    echo "could not locate the port preflight" >&2
    exit 1
fi

decide() {   # $1 = what ss reports
    local work; work="$(mktemp -d)"
    local PORT=8000 SERVICE=zefira   # the stub heredoc below expands these
    # Who holds the port: the panel's own service, or something else.
    local WHO="nginx"
    [[ "$1" == "self" ]] && WHO="$SERVICE"
    touch "$work/held"          # the listener is there to begin with
    cat > "$work/ss" <<EOS
#!/usr/bin/env bash
# stub: reports one listener for port $PORT
if [[ "\$1" == "-ltnp" ]]; then
  echo "LISTEN 0 128 0.0.0.0:$PORT 0.0.0.0:* users:((\"$WHO\",pid=900,fd=7))"
elif [[ "\$1" == "-ltn" ]]; then
  # Held only while the marker exists, so a `systemctl stop` frees the port -
  # which is what the installer's wait loop is checking for. A stub that always
  # reported it held would (correctly) trip the "did not release" guard.
  if [[ -f "\$HELD" ]]; then
    echo "LISTEN 0 128 0.0.0.0:$PORT 0.0.0.0:*"
  fi
fi
EOS
    chmod +x "$work/ss"
    ( cd "$work" && PATH="$work:$PATH" WHO="$WHO" PORT="$PORT" SERVICE="$SERVICE" HELD="$work/held" \
      bash -c "
ss() { command ss \"\$@\"; }
systemctl() { [[ "\$1" == "stop" ]] && rm -f "\$HELD"; return 0; }
$pf
echo REACHED_INSTALL" 2>&1 )
    local out; out="$?"
    rm -rf "$work"
    return $out
}

echo "  a listener held by ANOTHER process:"
o="$(decide other)"
printf '%s\n' "$o" | sed 's/^/    /'
if printf '%s' "$o" | grep -q REACHED_INSTALL; then
    echo "    FAIL: the installer continued past a foreign listener"
    rc=1
elif ! printf '%s' "$o" | grep -q "already in use"; then
    echo "    FAIL: no clear 'port in use' message"
    rc=1
else
    echo "    ok: refused, and it says who is holding it"
fi

echo "  a listener held by the panel's own service (an upgrade):"
o="$(ZEFIRA_TEST_STILL_HELD=1 decide self)"
printf '%s\n' "$o" | sed 's/^/    /'
if printf '%s' "$o" | grep -q REACHED_INSTALL; then
    echo "    ok: the upgrade proceeds after stopping the service"
else
    echo "    FAIL: the installer still aborts on its own running panel"
    rc=1
fi

[[ $rc -eq 0 ]] && echo "installer answers: ALL OK"
exit $rc
