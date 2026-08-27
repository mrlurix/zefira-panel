import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(mode=0o700, exist_ok=True)
try:
    os.chmod(INSTANCE_DIR, 0o700)
except OSError:
    pass


def _load_or_create_secret() -> str:
    path = INSTANCE_DIR / "secret.key"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(48)
    path.write_text(key, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


SECRET_KEY = _load_or_create_secret()
SESSION_TTL = int(os.environ.get("ZEFIRA_SESSION_TTL", "28800"))
DOMAIN = os.environ.get("ZEFIRA_DOMAIN", "zefira.example.com")
SUB_PORT = os.environ.get("ZEFIRA_SUB_PORT", "443")
WG_PORT = os.environ.get("ZEFIRA_WG_PORT", "51820")
HY2_PORT = os.environ.get("ZEFIRA_HY2_PORT", "8443")
DNS = os.environ.get("ZEFIRA_DNS", "1.1.1.1")
OVPN_PORT_DEFAULT = os.environ.get("ZEFIRA_OVPN_PORT", "1194")
OVPN_PROTO = os.environ.get("ZEFIRA_OVPN_PROTO", "udp")
