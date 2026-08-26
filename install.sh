#!/usr/bin/env bash
# ============================================================
#  ZEFIRA PANEL - one-command Linux installer
#
#  Fresh server :
#      bash <(curl -fsSL https://raw.githubusercontent.com/mrlurix/zefira/main/install.sh)
#  Inside a cloned repo :
#      sudo bash install.sh
#  Uninstall :
#      sudo bash install.sh --uninstall
# ============================================================
set -uo pipefail

REPO_URL="${ZEFIRA_REPO_URL:-https://github.com/mrlurix/zefira.git}"
TARGET="/opt/zefira"
SERVICE="zefira"
PORT="${ZEFIRA_PORT:-8000}"

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE.service"
    systemctl daemon-reload
    rm -rf "$TARGET"
    echo "[zefira] uninstalled."
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "[!] Please run as root (sudo)."; exit 1
fi

echo "==> [1/6] Installing system packages..."
if command -v apt-get >/dev/null; then
    apt-get update -y && apt-get install -y python3 python3-venv python3-pip git curl
elif command -v dnf >/dev/null; then
    dnf install -y python3 python3-pip git curl
elif command -v yum >/dev/null; then
    yum install -y python3 python3-pip git curl
else
    echo "[!] Unsupported distro: install python3 + venv + git manually."; exit 1
fi

echo "==> [2/6] Fetching Zefira..."
if [[ -f "main.py" && -f "requirements.txt" ]]; then
    SRC="$(pwd)"
    mkdir -p "$TARGET"
    rsync -a --exclude .venv --exclude instance --exclude .git "$SRC"/ "$TARGET"/ 2>/dev/null \
        || cp -r "$SRC"/." "$TARGET"/
else
    rm -rf "$TARGET.tmp"
    git clone --depth 1 "$REPO_URL" "$TARGET.tmp" || { echo "[!] clone failed"; exit 1; }
    mkdir -p "$TARGET"
    cp -r "$TARGET.tmp"/. "$TARGET"/
    rm -rf "$TARGET.tmp"
fi
cd "$TARGET"

echo "==> [3/6] Python environment..."
python3 -m venv .venv
".venv/bin/pip" install --upgrade pip -q
".venv/bin/pip" install -r requirements.txt -q

echo "==> [4/6] Admin credentials..."
ENV_FILE="$TARGET/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    ADMIN_USER="${ZEFIRA_ADMIN_mrlurix:-admin}"
    ADMIN_PASS="${ZEFIRA_ADMIN_PASSWORD:-$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)}"
    cat > "$ENV_FILE" <<EOF
ZEFIRA_ADMIN_mrlurix=$ADMIN_USER
ZEFIRA_ADMIN_PASSWORD=$ADMIN_PASS
EOF
    chmod 600 "$ENV_FILE"
fi

echo "==> [5/6] systemd service..."
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=Zefira Proxy Sales Panel
After=network.target

[Service]
WorkingDirectory=$TARGET
EnvironmentFile=$ENV_FILE
ExecStart=$TARGET/.venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port $PORT --no-server-header --no-proxy-headers
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$SERVICE"

echo "==> [6/6] Firewall (best effort)..."
command -v ufw >/dev/null && ufw allow "$PORT/tcp" 2>/dev/null || true
command -v firewall-cmd >/dev/null && firewall-cmd --add-port="$PORT/tcp" --permanent 2>/dev/null && firewall-cmd --reload 2>/dev/null || true

sleep 2
IP=$(curl -fsS4 https://api.ipify.org 2>/dev/null || echo SERVER_IP)
echo
echo "============================================================"
echo "  ZEFIRA INSTALLED"
echo "  URL      : http://$IP:$PORT"
echo "  Login    : see $ENV_FILE"
echo "  Service  : systemctl status $SERVICE"
echo "  Logs     : journalctl -u $SERVICE -f"
echo "  !! Change the admin password + enable 2FA now !!"
echo "============================================================"
