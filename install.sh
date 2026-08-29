#!/usr/bin/env bash
# ============================================================
#  ZEFIRA PANEL - Interactive Installer (6 steps)
#  One-line:  bash <(curl -fsSL https://raw.githubusercontent.com/mrlurix/zefira/main/install.sh)
#  Local:     sudo bash install.sh
#  Non-interactive (pipe): uses defaults, no prompts
#  Uninstall: sudo bash install.sh --uninstall
# ============================================================
set -euo pipefail

REPO_URL="${ZEFIRA_REPO_URL:-https://github.com/mrlurix/zefira.git}"
TARGET="/opt/zefira"
SERVICE="zefira"

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service"
    rm -f "/etc/nginx/sites-enabled/zefira" "/etc/nginx/sites-available/zefira"
    systemctl daemon-reload 2>/dev/null || true
    rm -rf "$TARGET"
    echo "[zefira] uninstalled."
    exit 0
fi

if [[ $EUID -ne 0 ]]; then echo "[!] Run as root (sudo)."; exit 1; fi

INTERACTIVE=0
[[ -t 0 ]] && INTERACTIVE=1

# ---------- helpers ----------
ask() {
    local prompt="$1" def="$2" var
    if [[ $INTERACTIVE -eq 0 ]]; then echo "$def"; return; fi
    read -rp "$prompt [$def]: " var; echo "${var:-$def}"
}
ask_secret() {
    local prompt="$1" var
    if [[ $INTERACTIVE -eq 0 ]]; then echo ""; return; fi
    read -rsp "$prompt (empty=random): " var; echo; echo "$var"
}
urlencode() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1"; }

# ---------- 1. Port ----------
PORT=$(ask "Panel port" "8000")
PORT=$(echo "$PORT" | tr -cd '0-9'); [[ -z "$PORT" ]] && PORT=8000

# ---------- helpers (validation) ----------
is_valid_domain() { [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; }
is_valid_subpath() { [[ "$1" =~ ^/[a-zA-Z0-9/_-]*$ ]] && [[ "$1" != *".."* ]]; }
is_valid_username() { [[ "$1" =~ ^[a-zA-Z0-9_]{3,32}$ ]]; }

# ---------- 2. Domain + SSL ----------
DOMAIN=""
EMAIL=""
USE_SSL="n"
if [[ $INTERACTIVE -eq 1 ]]; then
    read -rp "Domain for SSL (empty = use IP, no SSL) []: " DOMAIN
    DOMAIN=$(echo "$DOMAIN" | xargs)
    if [[ -n "$DOMAIN" ]]; then
        if ! is_valid_domain "$DOMAIN"; then echo "[!] Invalid domain: $DOMAIN"; exit 1; fi
        EMAIL=$(ask "Email for Let's Encrypt" "admin@$DOMAIN")
        read -rp "Issue SSL certificate now? (needs port 80 free) [y/N]: " USE_SSL
    fi
else
    DOMAIN="${ZEFIRA_DOMAIN:-}"
    EMAIL="${ZEFIRA_SSL_EMAIL:-}"
fi
if [[ -n "$DOMAIN" ]] && ! is_valid_domain "$DOMAIN"; then echo "[!] Invalid ZEFIRA_DOMAIN: $DOMAIN"; exit 1; fi

# ---------- 3. Admin ----------
if [[ $INTERACTIVE -eq 1 ]]; then
    ADMIN_USER=$(ask "Admin username" "admin")
    if ! is_valid_username "$ADMIN_USER"; then echo "[!] Invalid admin username (a-z, 0-9, _ , 3-32 chars)"; exit 1; fi
    ADMIN_PASS=$(ask_secret "Admin password")
    if [[ -z "$ADMIN_PASS" ]]; then
        ADMIN_PASS=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
        echo "[*] Generated password: $ADMIN_PASS"
    fi
    read -rsp "Confirm password: " CONFIRM; echo
    if [[ "$ADMIN_PASS" != "$CONFIRM" ]]; then echo "[!] Passwords do not match"; exit 1; fi
else
    ADMIN_USER="${ZEFIRA_ADMIN_USERNAME:-admin}"
    ADMIN_PASS="${ZEFIRA_ADMIN_PASSWORD:-}"
fi

# ---------- 4. Database ----------
DB_CHOICE=1; DB_URL=""
if [[ $INTERACTIVE -eq 1 ]]; then
    echo "Database:"
    echo "  1) SQLite (default, no setup)"
    echo "  2) MySQL"
    echo "  3) MariaDB"
    echo "  4) PostgreSQL"
    DB_CHOICE=$(ask "Choose" "1")
fi
if [[ "$DB_CHOICE" == "2" || "$DB_CHOICE" == "3" ]]; then
    DB_HOST=$(ask "DB host" "127.0.0.1")
    DB_PORT=$(ask "DB port" "3306")
    DB_NAME=$(ask "DB name" "zefira")
    DB_USER=$(ask "DB user" "zefira")
    DB_PASS=$(ask_secret "DB password")
    DB_PASS_ENC=$(urlencode "$DB_PASS")
    DB_URL="mysql+pymysql://$DB_USER:$DB_PASS_ENC@$DB_HOST:$DB_PORT/$DB_NAME"
elif [[ "$DB_CHOICE" == "4" ]]; then
    DB_HOST=$(ask "DB host" "127.0.0.1")
    DB_PORT=$(ask "DB port" "5432")
    DB_NAME=$(ask "DB name" "zefira")
    DB_USER=$(ask "DB user" "zefira")
    DB_PASS=$(ask_secret "DB password")
    DB_PASS_ENC=$(urlencode "$DB_PASS")
    DB_URL="postgresql+psycopg2://$DB_USER:$DB_PASS_ENC@$DB_HOST:$DB_PORT/$DB_NAME"
fi
[[ -n "${DATABASE_URL:-}" ]] && DB_URL="$DATABASE_URL"

# ---------- 5. Subscription path ----------
if [[ $INTERACTIVE -eq 1 ]]; then
    SUB_PATH=$(ask "Subscription path" "/sub")
    [[ "$SUB_PATH" != /* ]] && SUB_PATH="/$SUB_PATH"
else
    SUB_PATH="${SUBSCRIPTION_PATH:-/sub}"
fi
if ! is_valid_subpath "$SUB_PATH"; then echo "[!] Invalid subscription path (use /sub or /my-path, a-z 0-9 / _ -)"; exit 1; fi
if ! is_valid_username "$ADMIN_USER"; then echo "[!] Invalid admin username"; exit 1; fi
if ((PORT < 1 || PORT > 65535)); then echo "[!] Invalid port: $PORT"; exit 1; fi

# ---------- 6. Telegram + Nginx ----------
TG_TOKEN=""; TG_CHAT=""
if [[ $INTERACTIVE -eq 1 ]]; then
    read -rp "Telegram bot token (empty to skip) []: " TG_TOKEN
    if [[ -n "$TG_TOKEN" ]]; then read -rp "Telegram chat ID []: " TG_CHAT; fi
    if [[ -n "$DOMAIN" ]]; then
        read -rp "Setup Nginx reverse proxy for $DOMAIN ? [y/N]: " SETUP_NGINX
    else
        SETUP_NGINX="n"
    fi
else
    TG_TOKEN="${TG_BOT_TOKEN:-}"; TG_CHAT="${TG_CHAT_ID:-}"; SETUP_NGINX="n"
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

# ---------- Fetch ----------
echo "==> [2/6] Fetching Zefira..."
if [[ -f "main.py" && -f "requirements.txt" ]]; then
    SRC="$(pwd)"; mkdir -p "$TARGET"
    rsync -a --exclude .venv --exclude instance --exclude .git "$SRC"/ "$TARGET"/ 2>/dev/null || cp -r "$SRC"/. "$TARGET"/
else
    rm -rf "$TARGET.tmp"; git clone --depth 1 "$REPO_URL" "$TARGET.tmp" || { echo "[!] clone failed"; exit 1; }
    mkdir -p "$TARGET"; cp -r "$TARGET.tmp"/. "$TARGET"/; rm -rf "$TARGET.tmp"
fi
cd "$TARGET"

# ---------- Python env ----------
echo "==> [3/6] Python environment..."
python3 -m venv .venv
".venv/bin/pip" install --upgrade pip -q
".venv/bin/pip" install -r requirements.txt -q
if [[ "$DB_CHOICE" == "2" || "$DB_CHOICE" == "3" ]]; then ".venv/bin/pip" install -q pymysql 2>/dev/null || true; fi
if [[ "$DB_CHOICE" == "4" ]]; then ".venv/bin/pip" install -q psycopg2-binary 2>/dev/null || true; fi

# ---------- .env ----------
echo "==> [4/6] Writing .env ..."
ENV_FILE="$TARGET/.env"
if [[ -z "${ADMIN_PASS:-}" ]]; then ADMIN_PASS=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16); fi
cat > "$ENV_FILE" <<EOF
ZEFIRA_ADMIN_USERNAME=$ADMIN_USER
ZEFIRA_ADMIN_PASSWORD=$ADMIN_PASS
ZEFIRA_DOMAIN=$DOMAIN
ZEFIRA_PORT=$PORT
SUBSCRIPTION_PATH=$SUB_PATH
EOF
[[ -n "$DB_URL" ]] && echo "DATABASE_URL=$DB_URL" >> "$ENV_FILE"
[[ -n "$TG_TOKEN" ]] && echo "TG_BOT_TOKEN=$TG_TOKEN" >> "$ENV_FILE"
[[ -n "$TG_CHAT" ]] && echo "TG_CHAT_ID=$TG_CHAT" >> "$ENV_FILE"
chmod 600 "$ENV_FILE"

# ---------- systemd ----------
echo "==> [5/6] systemd service..."
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=Zefira Proxy Sales Panel
After=network.target

[Service]
WorkingDirectory=$TARGET
EnvironmentFile=-$ENV_FILE
ExecStart=$TARGET/.venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port $PORT --no-server-header --no-proxy-headers
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$SERVICE"

# ---------- Nginx + SSL ----------
if [[ "$SETUP_NGINX" == "y" || "$SETUP_NGINX" == "Y" ]]; then
    echo "==> Setting up Nginx for $DOMAIN ..."
    cat > "/etc/nginx/sites-available/zefira" <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    ln -sf /etc/nginx/sites-available/zefira /etc/nginx/sites-enabled/zefira 2>/dev/null || true
    nginx -t && systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
    if [[ "$USE_SSL" == "y" || "$USE_SSL" == "Y" ]]; then
        echo "==> Issuing SSL for $DOMAIN ..."
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect 2>&1 | tail -n 20 || echo "[!] certbot failed - you can run it manually later"
        # Tell panel the real domain for links
        grep -q ZEFIRA_DOMAIN "$ENV_FILE" || echo "ZEFIRA_DOMAIN=$DOMAIN" >> "$ENV_FILE"
        systemctl restart "$SERVICE"
    fi
fi

# ---------- Firewall ----------
echo "==> [6/6] Firewall ..."
command -v ufw >/dev/null && ufw allow "$PORT/tcp" 2>/dev/null || true
command -v firewall-cmd >/dev/null && firewall-cmd --add-port="$PORT/tcp" --permanent 2>/dev/null && firewall-cmd --reload 2>/dev/null || true
if [[ "$SETUP_NGINX" == "y" ]]; then
    command -v ufw >/dev/null && ufw allow 80/tcp 2>/dev/null && ufw allow 443/tcp 2>/dev/null || true
fi

sleep 3
echo "==> Verifying..."
if curl -fsS "http://127.0.0.1:$PORT/login" >/dev/null 2>&1; then echo "[ok] Panel running on port $PORT"; else
    echo "[!] Panel not responding - logs:"; journalctl -u "$SERVICE" -n 40 --no-pager 2>&1 | tail -n 30 || true
fi
ss -tlnp 2>/dev/null | grep -q ":$PORT " && echo "[ok] Port $PORT listening" || echo "[!] Port $PORT not listening"

IP=$(curl -fsS4 https://api.ipify.org 2>/dev/null || echo SERVER_IP)
if [[ -n "$DOMAIN" && "$SETUP_NGINX" == "y" ]]; then URL="https://$DOMAIN"; else URL="http://$IP:$PORT"; fi
echo
echo "============================================================"
echo "  ZEFIRA INSTALLED"
echo "  URL      : $URL"
echo "  Local    : http://127.0.0.1:$PORT"
echo "  Login    : cat $ENV_FILE"
echo "  Service  : systemctl status $SERVICE"
echo "  Logs     : journalctl -u $SERVICE -n 100 --no-pager"
echo "  Sub path : $SUB_PATH"
if [[ -n "$DB_URL" ]]; then echo "  DB       : $DB_CHOICE"; else echo "  DB       : SQLite (instance/zefira.db)"; fi
echo "  !! Change password + enable 2FA after first login !!"
echo "============================================================"
