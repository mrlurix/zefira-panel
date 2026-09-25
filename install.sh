#!/usr/bin/env bash
# ============================================================
#  ZEFIRA PANEL - Interactive Installer
#
#  Recommended (review before you run it as root):
#     curl -fsSL -o /tmp/zefira-install.sh \
#       https://raw.githubusercontent.com/mrlurix/zefira-panel/v1.13.9/install.sh
#     less /tmp/zefira-install.sh
#     sudo bash /tmp/zefira-install.sh
#
#  There is deliberately NO `curl | sudo bash` one-liner: piping a moving
#  branch straight into a root shell means whatever upstream serves at that
#  second runs as root unreviewed. Pin a tag (v1.13.9), read the file, then
#  run that exact copy.
#
#  Source selection: the installer's OWN directory is used when it sits next
#  to main.py + requirements.txt; otherwise it clones ZEFIRA_INSTALL_REF
#  (defaults to the `main` branch - set it to a tag or commit SHA for a
#  reproducible install).
#
#  Non-interactive (pipe): uses defaults, no prompts
#  Uninstall: sudo bash install.sh --uninstall
# ============================================================
set -euo pipefail

# ---------- pretty output (defined first: used by the REPO_URL check below) ----------
if [[ -t 1 ]]; then
    C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
    C_BLU=$'\e[34m'; C_BLD=$'\e[1m';  C_DIM=$'\e[2m'; C_RST=$'\e[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_DIM=""; C_RST=""
fi
ok()    { echo "${C_GRN}[ok]${C_RST} $*"; }
warn()  { echo "${C_YEL}[!]${C_RST} $*"; }
fail()  { echo "${C_RED}[x]${C_RST} $*"; }

REPO_URL="${ZEFIRA_REPO_URL:-https://github.com/mrlurix/zefira-panel.git}"
if [[ "$REPO_URL" != "https://github.com/mrlurix/zefira-panel.git" ]]; then
    warn "Custom REPO_URL in use ($REPO_URL) — only use mirrors you trust; the panel runtime stays pinned regardless."
fi
TARGET="/opt/zefira"
SERVICE="zefira"
# Single source of truth is the VERSION file; keep the literal as fallback
# for pipe-installs where no checkout exists yet.
ZEFIRA_VERSION="$(cat VERSION 2>/dev/null || cat "$TARGET/VERSION" 2>/dev/null || echo 1.13.1)"

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service"
    rm -f "/etc/nginx/sites-enabled/zefira" "/etc/nginx/sites-available/zefira" "/etc/nginx/conf.d/zefira.conf"
    rm -f /etc/cron.d/zefira-ssl-renew
    rm -f /etc/sudoers.d/zefira
    systemctl daemon-reload 2>/dev/null || true
    # Drop the vhost so a stale proxy doesn't stay live, and release the
    # firewall ports this installer opened (ufw + firewalld).
    systemctl reload nginx 2>/dev/null || true
    command -v ufw >/dev/null && ufw delete allow 80/tcp 2>/dev/null || true
    command -v ufw >/dev/null && ufw delete allow 443/tcp 2>/dev/null || true
    command -v firewall-cmd >/dev/null && firewall-cmd --remove-port=80/tcp --permanent 2>/dev/null || true
    command -v firewall-cmd >/dev/null && firewall-cmd --remove-port=443/tcp --permanent 2>/dev/null || true
    command -v firewall-cmd >/dev/null && firewall-cmd --reload 2>/dev/null || true
    rm -rf "$TARGET"
    echo "[zefira] uninstalled (system user 'zefira' kept for safety; userdel zefira to remove)."
    echo "[zefira] manual leftovers, if applicable: certbot delete --cert-name <domain> ; ufw delete allow <port>/tcp ; journalctl --vacuum-time=1s (logs)."
    exit 0
fi

if [[ $EUID -ne 0 ]]; then echo "[!] Run as root (sudo)."; exit 1; fi

# Every file this installer creates (source tree, .env with the admin password
# and DB credentials, secret.key, vhost backups) must be private from the moment
# it exists. Without this, a partial write or an interrupted run leaves a
# mode-644 .env readable by every local account.
umask 077

INTERACTIVE=0
[[ -t 0 ]] && INTERACTIVE=1

# ---------- banner ----------
banner() {
    echo "${C_RED}${C_BLD}███████ ███████ ███████ ███████ ██████   ███${C_RST}"
    echo "${C_RED}${C_BLD}     ██ ██ ██   ███   ██   ██  ██ ██${C_RST}"
    echo "${C_RED}${C_BLD}    ██  ██ ██   ███   ██   ██ ██   ██${C_RST}"
    echo "${C_RED}${C_BLD}   ██   ██████ ██████   ███   ██████ ███████${C_RST}"
    echo "${C_RED}${C_BLD}  ██   ██ ██   ███   ██ ██  ██   ██ ██   ██${C_RST}"
    echo "${C_RED}${C_BLD} ██    ██ ██   ███   ██  ██ ██   ██ ██   ██${C_RST}"
    echo "${C_RED}${C_BLD}███████ ███████ ██ ███████ ██   ██ ██   ██${C_RST}"
    echo "${C_BLD}Zefira${C_RST} ${C_RED}v${ZEFIRA_VERSION}${C_RST}"
    echo "${C_DIM}GitHub : https://github.com/mrlurix/zefira-panel${C_RST}"
    echo "${C_DIM}────────────────────────────────────────${C_RST}"
}
step()  { echo; echo " ${C_RED}$1)${C_RST} ${C_BLD}$2${C_RST}  ${C_DIM}$3${C_RST}"; }

# ---------- helpers ----------
ask() {
    local prompt="$1" def="$2" var
    if [[ $INTERACTIVE -eq 0 ]]; then echo "$def"; return; fi
    read -rp "$prompt [$def]: " var; echo "${var:-$def}"
}
# NOTE: every read below uses -r so backslashes survive verbatim. Without it,
# a password like My\Pass1 would silently lose the backslash and the operator
# could never log in with what they typed.
ask_secret() {
    local prompt="$1" var
    if [[ $INTERACTIVE -eq 0 ]]; then echo ""; return; fi
    read -r -sp "$prompt (empty=random): " var; echo >&2; printf "%s" "$var"
}
# The value arrives on STDIN, never as argv: any local user can read another
# process's command line (`ps`, /proc/*/cmdline) while it runs.
urlencode() { python3 -c "import sys,urllib.parse; sys.stdout.write(urllib.parse.quote(sys.stdin.read()))"; }
is_valid_domain() { [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] && [[ "$1" != *".."* ]]; }
is_valid_email() { [[ "$1" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; }
is_valid_dbident() { [[ "$1" =~ ^[A-Za-z0-9_.-]{1,253}$ ]]; }
# Quote a value for systemd EnvironmentFile (double quotes + escape \, ", $, `).
# CR/LF are stripped: they would break the KEY=VALUE line and silently corrupt
# secrets (e.g. a password with $ would be variable-expanded by systemd).
env_escape() {
    local v="$1"
    v=${v//$'\r'/}; v=${v//$'\n'/}
    v=${v//\\/\\\\}; v=${v//\"/\\\"}; v=${v//\$/\\\$}; v=${v//\`/\\\`}
    printf '"%s"' "$v"
}
is_valid_subpath() { [[ "$1" =~ ^/[a-zA-Z0-9/_-]*$ ]] && [[ "$1" != *".."* ]]; }
is_valid_username() { [[ "$1" =~ ^[a-zA-Z0-9_]{3,32}$ ]]; }

banner
echo "Detected OS: $(grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"' || uname -s)"

# ---------- Step 1/7 · Port ----------
step 1 "Panel port" "local port the panel listens on"
PORT=$(ask "Panel port" "8000")
if [[ ! "$PORT" =~ ^[0-9]{1,5}$ ]]; then
    echo "[!] Port must be digits only (got: $PORT)"; exit 1
fi
PORT=$(echo "$PORT" | tr -cd '0-9')
if ((PORT < 1 || PORT > 65535)); then echo "[!] Invalid port: $PORT"; exit 1; fi
# Preflight: uvicorn will die with a cryptic bind error otherwise.
if command -v ss >/dev/null && ss -ltn 2>/dev/null | grep -q ":$PORT[[:space:]]"; then
    echo "[!] Port $PORT is already in use. Stop that process or choose another port."; exit 1
fi

# ---------- Step 2/7 · Domain ----------
step 2 "Domain (for links and SSL)" "empty = server IP, no SSL"
DOMAIN=""
if [[ $INTERACTIVE -eq 1 ]]; then
    read -rp "Domain (empty = use server IP, no SSL) []: " DOMAIN
    DOMAIN=$(echo "$DOMAIN" | xargs)
    if [[ -n "$DOMAIN" ]] && ! is_valid_domain "$DOMAIN"; then echo "[!] Invalid domain: $DOMAIN"; exit 1; fi
else
    DOMAIN="${ZEFIRA_DOMAIN:-}"
fi
if [[ -n "$DOMAIN" ]] && ! is_valid_domain "$DOMAIN"; then echo "[!] Invalid ZEFIRA_DOMAIN: $DOMAIN"; exit 1; fi

# ---------- Step 3/7 · Admin ----------
step 3 "Admin account" "username + strong password"
gen_pass() { head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16; }
# The panel strips surrounding whitespace at login, so normalize here too —
# otherwise a trailing space locks the operator out with no error message.
trim() { local v="$1"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"; printf '%s' "$v"; }
# Same bar as the panel itself: 10+ chars with letters AND digits.
strong_enough() { local p="$1"; (( ${#p} >= 10 )) && [[ "$p" =~ [A-Za-z] ]] && [[ "$p" =~ [0-9] ]]; }
if [[ $INTERACTIVE -eq 1 ]]; then
    ADMIN_USER=$(ask "Admin username" "admin")
    if ! is_valid_username "$ADMIN_USER"; then echo "[!] Invalid admin username (a-z, 0-9, _ , 3-32 chars)"; exit 1; fi
    ADMIN_PASS=""
    for _try in 1 2 3; do
        ADMIN_PASS=$(trim "$(ask_secret "Admin password (empty=random, min 10 chars + letters & digits)")")
        if [[ -z "$ADMIN_PASS" ]]; then
            ADMIN_PASS=$(gen_pass)
            echo "[*] Generated password: $ADMIN_PASS"
            break
        fi
        if ! strong_enough "$ADMIN_PASS"; then
            echo "[!] Too weak (need 10+ chars with letters AND digits) — try again"
            ADMIN_PASS=""
            continue
        fi
        read -rsp "Confirm password: " CONFIRM; echo
        CONFIRM=$(trim "$CONFIRM")
        if [[ "$ADMIN_PASS" != "$CONFIRM" ]]; then echo "[!] Passwords do not match — try again"; ADMIN_PASS=""; continue; fi
        break
    done
    if [[ -z "$ADMIN_PASS" ]]; then echo "[!] No valid password given"; exit 1; fi
else
    ADMIN_USER="${ZEFIRA_ADMIN_USERNAME:-admin}"
    ADMIN_PASS=$(trim "${ZEFIRA_ADMIN_PASSWORD:-}")
    if [[ -z "$ADMIN_PASS" ]]; then ADMIN_PASS=$(gen_pass); fi
    if ! strong_enough "$ADMIN_PASS"; then echo "[!] ZEFIRA_ADMIN_PASSWORD must be 10+ chars with letters AND digits"; exit 1; fi
fi

# ---------- Step 4/7 · Database ----------
step 4 "Database" "SQLite default, or MySQL / MariaDB / PostgreSQL"
DB_CHOICE=1; DB_URL=""
if [[ $INTERACTIVE -eq 1 ]]; then
    echo "  1) SQLite (default, no setup)"
    echo "  2) MySQL"
    echo "  3) MariaDB"
    echo "  4) PostgreSQL"
    DB_CHOICE=$(ask "Choose" "1")
    if [[ ! "$DB_CHOICE" =~ ^[1-4]$ ]]; then
        echo "[!] Choose 1-4 (got: $DB_CHOICE)"; exit 1
    fi
fi
if [[ "$DB_CHOICE" == "2" || "$DB_CHOICE" == "3" ]]; then
    DB_HOST=$(ask "DB host" "127.0.0.1")
    DB_PORT=$(ask "DB port" "3306")
    DB_NAME=$(ask "DB name" "zefira")
    DB_USER=$(ask "DB user" "zefira")
    DB_PASS=$(ask_secret "DB password")
    DB_PASS_ENC=$(printf '%s' "$DB_PASS" | urlencode)
    DB_URL="mysql+pymysql://$DB_USER:$DB_PASS_ENC@$DB_HOST:$DB_PORT/$DB_NAME"
elif [[ "$DB_CHOICE" == "4" ]]; then
    DB_HOST=$(ask "DB host" "127.0.0.1")
    DB_PORT=$(ask "DB port" "5432")
    DB_NAME=$(ask "DB name" "zefira")
    DB_USER=$(ask "DB user" "zefira")
    DB_PASS=$(ask_secret "DB password")
    DB_PASS_ENC=$(printf '%s' "$DB_PASS" | urlencode)
    DB_URL="postgresql+psycopg2://$DB_USER:$DB_PASS_ENC@$DB_HOST:$DB_PORT/$DB_NAME"
fi
[[ -n "${DATABASE_URL:-}" ]] && DB_URL="$DATABASE_URL"
if [[ -n "$DB_URL" && "$DB_URL" != sqlite* ]]; then
    # DB_URL is operator-influenced (host/user/name/port prompts); reject
    # metacharacters so a typo fails fast here instead of a broken panel later.
    if [[ "$DB_CHOICE" == "2" || "$DB_CHOICE" == "3" || "$DB_CHOICE" == "4" ]]; then
        if ! is_valid_dbident "$DB_HOST" || ! is_valid_dbident "$DB_USER" || ! is_valid_dbident "$DB_NAME"; then
            echo "[!] Invalid DB host/user/name (letters, digits, _ . - only)"; exit 1
        fi
        if ! [[ "$DB_PORT" =~ ^[0-9]{1,5}$ ]] || ((DB_PORT < 1 || DB_PORT > 65535)); then
            echo "[!] Invalid DB port: $DB_PORT"; exit 1
        fi
    fi
fi

# ---------- Step 5/7 · Subscription path ----------
step 5 "Subscription path" "URL prefix for user links"
if [[ $INTERACTIVE -eq 1 ]]; then
    SUB_PATH=$(ask "Subscription path" "/sub")
    [[ "$SUB_PATH" != /* ]] && SUB_PATH="/$SUB_PATH"
else
    SUB_PATH="${SUBSCRIPTION_PATH:-/sub}"
fi
if ! is_valid_subpath "$SUB_PATH" || [[ "$SUB_PATH" == "/" ]]; then echo "[!] Invalid subscription path (use /sub or /my-path, a-z 0-9 / _ -)"; exit 1; fi
if ! is_valid_username "$ADMIN_USER"; then echo "[!] Invalid admin username"; exit 1; fi

# ---------- Step 6/7 · Telegram ----------
step 6 "Telegram notifications (optional)" "bot token + chat ID"
TG_TOKEN=""; TG_CHAT=""
if [[ $INTERACTIVE -eq 1 ]]; then
    read -rp "Telegram bot token (empty to skip) []: " TG_TOKEN
    if [[ -n "$TG_TOKEN" ]]; then
        read -rp "Telegram chat ID []: " TG_CHAT
        # Same patterns the panel enforces, so a typo fails here instead of
        # as a silent "no notifications" after install.
        if ! [[ "$TG_TOKEN" =~ ^[0-9]{1,15}:[A-Za-z0-9_-]{1,100}$ ]]; then
            echo "[!] Invalid bot token format (expected 123456:ABC-DEF...)"; exit 1
        fi
        if ! [[ "$TG_CHAT" =~ ^@[A-Za-z0-9_]{4,64}$ || "$TG_CHAT" =~ ^-?[0-9]{3,25}$ ]]; then
            echo "[!] Invalid chat ID (numeric id or @channelname)"; exit 1
        fi
    fi
else
    TG_TOKEN="${TG_BOT_TOKEN:-}"; TG_CHAT="${TG_CHAT_ID:-}"
fi

# ---------- Step 7/7 · Nginx + SSL certificate ----------
step 7 "Nginx reverse proxy + SSL certificate" "needs a domain, port 80 free"
SETUP_NGINX="n"; USE_SSL="n"; EMAIL=""
if [[ -z "$DOMAIN" ]]; then
    echo "No domain given — skipping Nginx and SSL (panel will run on http://SERVER_IP:$PORT)."
elif [[ $INTERACTIVE -eq 1 ]]; then
    read -rp "Setup Nginx reverse proxy for $DOMAIN ? [y/N]: " SETUP_NGINX
    if [[ "$SETUP_NGINX" == [yY]* ]]; then
        EMAIL=$(ask "Email for Let's Encrypt" "admin@$DOMAIN")
        if ! is_valid_email "$EMAIL"; then echo "[!] Invalid email: $EMAIL"; exit 1; fi
        read -rp "Issue SSL certificate now? (needs port 80 free) [y/N]: " USE_SSL
    fi
else
    SETUP_NGINX="${ZEFIRA_SETUP_NGINX:-n}"
    USE_SSL="${ZEFIRA_USE_SSL:-n}"
    EMAIL="${ZEFIRA_SSL_EMAIL:-}"
fi

# ---------- System packages ----------
echo "==> [1/6] Installing system packages..."
if command -v apt-get >/dev/null; then
    apt-get update -y
    apt-get install -y python3 python3-venv python3-pip python3-dev build-essential git curl rsync nginx certbot 2>/dev/null || apt-get install -y python3 python3-venv python3-pip git curl rsync
elif command -v dnf >/dev/null; then
    dnf install -y python3 python3-pip python3-devel gcc git curl rsync nginx certbot 2>/dev/null || dnf install -y python3 git curl
elif command -v yum >/dev/null; then
    yum install -y python3 python3-pip python3-devel gcc git curl rsync 2>/dev/null || yum install -y python3 git curl
fi
# The app uses PEP 604 unions (`str | None`) and current FastAPI/SQLAlchemy,
# which need 3.10+. Failing here beats a stack trace on first boot.
_PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 10) else 0)' 2>/dev/null || echo 0)"
if [[ "$_PY_OK" != "1" ]]; then
    fail "Python 3.10+ is required (found: $(python3 -V 2>&1))."
    fail "Install a newer python3 (e.g. `apt install python3.11 python3.11-venv`) and re-run."
    exit 1
fi

# ---------- Fetch ----------
echo "==> [2/6] Fetching Zefira..."
# Copy WITHOUT the runtime state. A plain `cp -r` fallback used to drag
# instance/secret.key along: anyone who could seed that file with a key they
# knew could mint a valid admin session cookie. Never copy secrets or state.
copy_tree() {
    local src="$1" dst="$2"
    mkdir -p "$dst"
    # shellcheck disable=SC2164
    ( cd "$src" && tar -cf - \
        --exclude='./.venv' --exclude='./instance' --exclude='./.git' \
        --exclude='./.env' --exclude='./__pycache__' . ) | ( cd "$dst" && tar -xf - )
}
# Source discovery: anchor to the SCRIPT'S OWN directory, never to $PWD.
# Using $(pwd) meant that any directory containing main.py + requirements.txt
# became the root installer's input - including the service-writable
# /opt/zefira itself. A foothold as the `zefira` user could edit that tree and
# wait for the next `sudo bash install.sh` to run its code as root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -f "$SCRIPT_DIR/main.py" && -f "$SCRIPT_DIR/requirements.txt" ]]; then
    SRC="$SCRIPT_DIR"
    # Re-running from inside the install dir: copying a tree onto itself is a
    # no-op at best and an infinite read at worst. Nothing to do.
    if [[ "$SRC" != "$(cd "$TARGET" 2>/dev/null && pwd -P || echo "$TARGET")" ]]; then
        copy_tree "$SRC" "$TARGET"
    else
        echo "[*] Already running from $TARGET - keeping the existing tree"
    fi
else
    # No source next to the installer: clone the pinned tag/commit, never a
    # moving branch. A floating `main` means whoever controls upstream (or a
    # MITM on the fetch) chooses code that runs as root here.
    REF="${ZEFIRA_INSTALL_REF:-$REPO_URL}"
    rm -rf "$TARGET.tmp"
    git clone --depth 1 --branch "${ZEFIRA_INSTALL_REF:-main}" "$REPO_URL" "$TARGET.tmp" \
        || { rm -rf "$TARGET.tmp"; echo "[!] clone failed (ref: ${ZEFIRA_INSTALL_REF:-main})"; exit 1; }
    # Pin the commit that was actually checked out so a re-run is reproducible.
    if CLONE_SHA="$(cd "$TARGET.tmp" && git rev-parse HEAD 2>/dev/null)"; then
        echo "[*] Installing commit ${CLONE_SHA:0:12}"
    fi
    copy_tree "$TARGET.tmp" "$TARGET"
    rm -rf "$TARGET.tmp"
fi
cd "$TARGET"

# ---------- Python env ----------
echo "==> [3/6] Python environment..."
python3 -m venv .venv
# Install from the hash-locked set, not from requirements.txt. Exact
# top-level pins never pinned the TRANSITIVE graph: `uvicorn[standard]` alone
# drags in a dozen version ranges, so two installs of the same file could
# execute different code - and pip runs whatever it downloads. --require-hashes
# aborts on any artifact that is not the exact one we hashed.
LOCKFILE="$TARGET/requirements.lock"
if [[ -f "$LOCKFILE" ]]; then
    echo "[*] Installing from the hash-locked requirements.lock"
    ".venv/bin/pip" install --require-hashes --no-deps -r "$LOCKFILE" -q
else
    echo "[!] requirements.lock missing - refusing an unlocked install"
    echo "    (regenerate with: python3 tools_lock.py)"
    exit 1
fi

# ---------- .env ----------
echo "==> [4/6] Writing .env ..."
ENV_FILE="$TARGET/.env"
# $TARGET is owned by the service user (the updater needs write access), so a
# foothold as `zefira` can plant a symlink at .env pointing at /etc/shadow (or
# any root file) and wait for the next root install. Write through a fresh
# temp file and rename over the path: rename(2) replaces the SYMLINK itself,
# never its target.
if [[ -L "$ENV_FILE" ]]; then
    echo "[!] $ENV_FILE is a symlink - refusing to write through it"
    echo "    (remove it first if this is expected: rm -f $ENV_FILE)"
    exit 1
fi
# Re-run safety: never silently destroy the operator's env (secrets, custom
# DATABASE_URL). The panel scrubs the admin password on first boot, so a
# backup is the only surviving copy of any hand-set values.
if [[ -f "$ENV_FILE" ]]; then
    cp -a "$ENV_FILE" "$ENV_FILE.bak-$(date +%Y%m%d%H%M%S)"
    # cp -a preserves the source mode: a legacy 0644 .env would leave a
    # world-readable copy of the admin password + DB credentials behind.
    chmod 600 "$ENV_FILE.bak-"* 2>/dev/null || true
    echo "[*] Existing .env backed up to $ENV_FILE.bak-<timestamp>"
    if [[ -z "${ADMIN_PASS:-}" ]]; then ADMIN_PASS=$(gen_pass); fi
fi
ENV_TMP="$(mktemp "$TARGET/.env.XXXXXX")"
chmod 600 "$ENV_TMP"
if [[ -z "${ADMIN_PASS:-}" ]]; then ADMIN_PASS=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16); fi
{
    echo "ZEFIRA_ADMIN_USERNAME=$(env_escape "$ADMIN_USER")"
    echo "ZEFIRA_ADMIN_PASSWORD=$(env_escape "$ADMIN_PASS")"
    echo "ZEFIRA_DOMAIN=$(env_escape "$DOMAIN")"
    echo "ZEFIRA_PORT=$(env_escape "$PORT")"
    echo "SUBSCRIPTION_PATH=$(env_escape "$SUB_PATH")"
    if [[ "$SETUP_NGINX" == [yY] ]]; then
        # Without this every request looks like it came from 127.0.0.1: the
        # audit log records the proxy instead of the customer, and all visitors
        # share ONE login rate-limit bucket (so one attacker locks out
        # everyone). Only the exact loopback proxy is trusted - never 0.0.0.0/0.
        echo "ZEFIRA_TRUSTED_PROXIES=127.0.0.1"
    fi
    [[ -n "$DB_URL" ]] && echo "DATABASE_URL=$(env_escape "$DB_URL")"
    [[ -n "$TG_TOKEN" ]] && echo "TG_BOT_TOKEN=$(env_escape "$TG_TOKEN")"
    [[ -n "$TG_CHAT" ]] && echo "TG_CHAT_ID=$(env_escape "$TG_CHAT")"
    echo "# NOTE: ZEFIRA_ADMIN_PASSWORD is one-time: the panel scrubs it from"
    echo "# this file on first boot (lifespan _scrub_env_password). Keep 0600."
} > "$ENV_TMP"
chmod 600 "$ENV_TMP"
mv -f "$ENV_TMP" "$ENV_FILE"

# ---------- unprivileged service user ----------
# The panel never runs as root: a compromised GitHub upstream (via
# /api/update/apply) or RCE would otherwise mean instant root.
if ! id zefira >/dev/null 2>&1; then
    useradd --system --no-log-init --home-dir "$TARGET" --no-create-home --shell /usr/sbin/nologin zefira 2>/dev/null || \
    useradd --system --home-dir "$TARGET" --no-create-home --shell /usr/sbin/nologin zefira
    ok "Created system user 'zefira'"
fi
chown -R zefira:zefira "$TARGET"
# ProtectSystem=strict bind-mounts ReadWritePaths when the namespace is
# set up — BEFORE the app (which creates instance/ itself) ever runs.
# A missing dir = 226/NAMESPACE and a dead service, so create it here.
# Same symlink trap for the secret directory: a service-user foothold can
# replace instance/ with a symlink to /etc, and then `chown`/`chmod` below run
# as root against the REFERENT. Refuse instead of escalating.
if [[ -L "$TARGET/instance" ]]; then
    echo "[!] $TARGET/instance is a symlink - refusing to install over it"
    echo "    (a real instance dir is a directory owned by 'zefira', mode 700)"
    exit 1
fi
mkdir -p "$TARGET/instance" || { echo "[!] cannot create $TARGET/instance"; exit 1; }
chown zefira:zefira "$TARGET/instance"
chmod 700 "$TARGET/instance"
chmod 600 "$TARGET/instance/zefira.db" 2>/dev/null || true
chmod 600 "$ENV_FILE"
# Allow the unprivileged service to restart ONLY itself after an update.
# No other sudo rights: `sudo -n systemctl restart zefira` from main.py.
# Resolve the binary path (merged-/usr systems keep /bin as a symlink,
# but never assume it): the rule names one exact binary + unit.
_SYSCTL="$(command -v systemctl 2>/dev/null || echo /bin/systemctl)"
# Least privilege: the updater only ever runs `restart`. `reload` was never
# used and would have doubled the allowed root commands.
echo "zefira ALL=(root) NOPASSWD: $_SYSCTL restart $SERVICE" > /etc/sudoers.d/zefira
chmod 440 /etc/sudoers.d/zefira
visudo -c >/dev/null 2>&1 || { rm -f /etc/sudoers.d/zefira; warn "sudoers check failed, update restart will need manual systemctl restart"; }

# ---------- systemd ----------
echo "==> [5/6] systemd service (non-root)..."
# Bind decision: with the nginx reverse proxy in front, the panel must listen on
# loopback only. A wildcard bind would keep serving plain HTTP straight to the
# internet on $PORT, bypassing the TLS redirect, HSTS and Secure cookies, and
# exposing the admin login to passive observers.
BIND_HOST="0.0.0.0"
[[ "$SETUP_NGINX" == [yY] ]] && BIND_HOST="127.0.0.1"
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=Zefira Proxy Sales Panel
After=network.target

[Service]
Type=simple
User=zefira
Group=zefira
WorkingDirectory=$TARGET
EnvironmentFile=-$ENV_FILE
# NOTE: there are deliberately NO privileged ExecStartPre=+ helpers here.
# A `+` command runs as full root while inheriting the service environment and
# the service-writable working tree, so a compromised panel could drop
# LD_PRELOAD=/opt/zefira/x.so into its own .env and get root code execution the
# next time the unit started. instance/ is created by the installer and, if it
# ever goes missing, re-created by the app itself as the unprivileged user
# (/opt/zefira is writable by zefira for the updater).
UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PYTHONHOME
# SINGLE WORKER ONLY. Rate limiters, the restore/update locks, the node
# monitor loop and the settings cache are process-local: --workers N would
# multiply limit budgets, interleave restores and fork monitor loops.
ExecStart=$TARGET/.venv/bin/python -m uvicorn main:app --host $BIND_HOST --port $PORT --no-server-header --no-proxy-headers --no-access-log
Restart=always
RestartSec=3
# Least privilege + filesystem lockdown (update still works: /opt/zefira
# is owned by zefira, pip installs into its own .venv).
# NOTE: no NoNewPrivileges=true here on purpose: the in-panel updater
# restarts the service via the sudoers-scoped `sudo -n systemctl restart
# zefira`, and NoNewPrivileges would neuter setuid sudo (silent failure).
# The sudoers rule below is already scoped to that single command.
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true
RestrictSUIDSGID=true
LockPersonality=true
UMask=0077
# The whole tree must be writable (not just instance/ + .venv): the
# in-panel updater runs git fetch/reset here, and pip installs into .venv.
# System dirs (/usr, /boot, /etc) stay read-only via ProtectSystem=strict.
ReadWritePaths=$TARGET
# Network is required (panel + probes + AI). No extra caps.
AmbientCapabilities=
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$SERVICE"

# ---------- Nginx + SSL ----------
SSL_CERT=""; SSL_KEY=""; SSL_DONE="no"
# Debian/Ubuntu read sites-enabled/*, RHEL-family only conf.d/*.conf:
# write the vhost where THIS nginx actually loads it from.
NGINX_CONF=""
if [[ "$SETUP_NGINX" == [yY] ]]; then
    if [[ -d /etc/nginx/sites-enabled ]]; then
        NGINX_CONF="/etc/nginx/sites-available/zefira"
    else
        NGINX_CONF="/etc/nginx/conf.d/zefira.conf"
    fi
fi
if [[ -n "$NGINX_CONF" ]]; then
    echo "==> Setting up Nginx for $DOMAIN ..."
    # Re-run safety: back up a hand-edited vhost before overwriting it.
    VHOST_BAK=""
    if [[ -f "$NGINX_CONF" ]]; then
        cp -a "$NGINX_CONF" "$NGINX_CONF.bak-$(date +%Y%m%d%H%M%S)"
        VHOST_BAK="$NGINX_CONF.bak-$(date +%Y%m%d%H%M%S)"
        echo "[*] Existing vhost backed up to $VHOST_BAK"
    fi
    # Fail closed: a broken/rejected vhost must never be reported as a
    # successful install. The previous file (or "no vhost") is restored and
    # nginx is put back in a running state before we abort.
    nginx_apply() {
        if ! nginx -t >/dev/null 2>&1; then
            warn "nginx rejected the configuration - restoring the previous vhost"
            if [[ -n "$VHOST_BAK" && -f "$VHOST_BAK" ]]; then
                cp -a "$VHOST_BAK" "$NGINX_CONF" || true
            else
                rm -f "$NGINX_CONF"
            fi
            nginx -t >/dev/null 2>&1 || true
            systemctl start nginx 2>/dev/null || systemctl reload nginx 2>/dev/null || true
            fail "nginx configuration is invalid. Nothing was deployed; fix nginx and re-run."
            nginx -t 2>&1 | tail -n 5 || true
            exit 1
        fi
        systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || {
            warn "nginx refused to reload/restart - restoring the previous vhost"
            if [[ -n "$VHOST_BAK" && -f "$VHOST_BAK" ]]; then
                cp -a "$VHOST_BAK" "$NGINX_CONF" || true
            else
                rm -f "$NGINX_CONF"
            fi
            systemctl start nginx 2>/dev/null || true
            fail "nginx could not be started. Nothing was deployed."
            exit 1
        }
    }
    # access_log is off on purpose: nginx's default format records the full
    # request line, and /sub/<token> IS a bearer credential for that customer's
    # config. The panel keeps its own audit log instead. Re-enable with a
    # redacting log_format if you need web-server access logs.
    cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    access_log off;
    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    if [[ "$NGINX_CONF" == "/etc/nginx/sites-available/zefira" ]]; then
        ln -sf /etc/nginx/sites-available/zefira /etc/nginx/sites-enabled/zefira 2>/dev/null || true
    fi
    nginx_apply
    if [[ "$USE_SSL" == [yY] ]]; then
        echo "==> Issuing SSL certificate for $DOMAIN ..."
        # Standalone certbot needs :80 free but nginx (just configured
        # above) holds it: stop it for the issuance, restart on ALL paths
        # below so nginx is never left stopped.
        systemctl stop nginx 2>/dev/null || true
        if certbot certonly --standalone --non-interactive --agree-tos -m "$EMAIL" -d "$DOMAIN" 2>&1 | tail -n 15; then
            if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
                SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
                SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                {
                    echo "ZEFIRA_SSL_CERT=$(env_escape "$SSL_CERT")"
                    echo "ZEFIRA_SSL_KEY=$(env_escape "$SSL_KEY")"
                    echo "ZEFIRA_SSL_DOMAIN=$(env_escape "$DOMAIN")"
                } >> "$ENV_FILE"
                # Deploy the cert: without a 443 block the panel would stay
                # plain HTTP behind nginx (false HTTPS: no Secure cookies, no
                # HSTS, plaintext logins). Terminate TLS in nginx and tell
                # the panel the real scheme via X-Forwarded-Proto.
                cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    server_tokens off;
    access_log off;
    # HSTS on the redirect itself; app responses carry the panel's own HSTS.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    location / {
        return 301 https://\$host\$request_uri;
    }
}
server {
    listen 443 ssl;
    server_name $DOMAIN;
    server_tokens off;
    access_log off;
    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
                nginx_apply
                # Standalone renewals need :80 free, but nginx now holds it:
                # stop/start around renew (3am, seconds of downtime).
                echo "0 3 * * * root certbot renew --quiet --pre-hook 'systemctl stop nginx' --post-hook 'systemctl start nginx' --deploy-hook 'systemctl reload nginx'" > /etc/cron.d/zefira-ssl-renew
                SSL_DONE="yes"
                ok "SSL issued and deployed for $DOMAIN (https)"
                openssl x509 -in "$SSL_CERT" -noout -enddate 2>/dev/null || true
            else
                systemctl start nginx 2>/dev/null || true
                warn "certbot finished but certificate files not found — run it manually later"
            fi
        else
            systemctl start nginx 2>/dev/null || true
            warn "certbot failed (check DNS points to this server) — run it manually later"
        fi
    fi
fi

# ---------- Firewall ----------
echo "==> [6/6] Firewall ..."
if [[ "$SETUP_NGINX" == [yY] ]]; then
    # nginx terminates TLS on 80/443 and proxies to 127.0.0.1:$PORT, which is
    # now loopback-only. Opening $PORT here would publish a second, unencrypted
    # copy of the admin login that bypasses the redirect, HSTS and Secure
    # cookies - so the port stays closed.
    command -v ufw >/dev/null && ufw allow 80/tcp 2>/dev/null && ufw allow 443/tcp 2>/dev/null || true
    ok "Panel port $PORT kept private (nginx handles 80/443)"
else
    command -v ufw >/dev/null && ufw allow "$PORT/tcp" 2>/dev/null || true
    command -v firewall-cmd >/dev/null && firewall-cmd --add-port="$PORT/tcp" --permanent 2>/dev/null && firewall-cmd --reload 2>/dev/null || true
    warn "No reverse proxy: the panel answers plain HTTP on $PORT. Put it behind TLS before using real accounts."
fi

sleep 3
echo "==> Verifying..."
if curl -fsS "http://127.0.0.1:$PORT/login" >/dev/null 2>&1; then ok "Panel running on port $PORT"; else
    fail "Panel not responding - logs:"; journalctl -u "$SERVICE" -n 40 --no-pager 2>&1 | tail -n 30 || true
fi
ss -tlnp 2>/dev/null | grep -q ":$PORT " && ok "Port $PORT listening" || fail "Port $PORT not listening"

IP=$(curl -fsS4 https://api.ipify.org 2>/dev/null || echo SERVER_IP)
if [[ "$SSL_DONE" == "yes" ]]; then URL="https://$DOMAIN"; elif [[ -n "$DOMAIN" && "$SETUP_NGINX" == [yY]* ]]; then URL="http://$DOMAIN"; else URL="http://$IP:$PORT"; fi
echo
echo "${C_BLD}${C_GRN}╔════════════════════════════════════════════╗${C_RST}"
echo "${C_BLD}${C_GRN}║${C_RST}          ${C_BLD}${C_RED}ZEFIRA INSTALLED${C_RST}              ${C_BLD}${C_GRN}║${C_RST}"
echo "${C_BLD}${C_GRN}╚════════════════════════════════════════════╝${C_RST}"
echo "  URL      : $URL"
echo "  Local    : http://127.0.0.1:$PORT"
echo "  Login    : cat $ENV_FILE"
echo "  Service  : systemctl status $SERVICE"
echo "  Logs     : journalctl -u $SERVICE -n 100 --no-pager"
echo "  Sub path : $SUB_PATH"
if [[ "$SSL_DONE" == "yes" ]]; then echo "  SSL      : $SSL_CERT (auto-renew cron installed)"; fi
if [[ -n "$DB_URL" ]]; then echo "  DB       : $DB_CHOICE"; else echo "  DB       : SQLite (instance/zefira.db)"; fi
echo "  !! Change the password after first login !!"
echo "============================================================"
