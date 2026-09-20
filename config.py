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
        try:
            existing = path.read_text(encoding="utf-8").strip()
        except OSError:
            existing = ""
        # Refuse short/empty keys: HS256/Fernet with a guessable key would let
        # anyone forge sessions or decrypt secrets (e.g. operator created an
        # empty file by accident). Fall through and generate a real one.
        if len(existing) >= 32:
            return existing
    key = secrets.token_hex(48)
    path.write_text(key, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


SECRET_KEY = _load_or_create_secret()


def _session_ttl() -> int:
    try:
        return max(300, min(86400 * 7, int(os.environ.get("ZEFIRA_SESSION_TTL", "28800"))))
    except (TypeError, ValueError):
        return 28800


SESSION_TTL = _session_ttl()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
_SUB_RAW = (os.environ.get("SUBSCRIPTION_PATH", "/sub") or "").strip() or "/sub"
if not _SUB_RAW.startswith("/"):
    _SUB_RAW = "/" + _SUB_RAW
# Route patterns are operator-controlled env: a crafted value (e.g. with
# "..", "{token}" tricks or absurd length) must never alter routing.
# Fall back to /sub on anything but a plain path prefix.
import re as _re

if (
    _SUB_RAW == "/"
    or ".." in _SUB_RAW
    or len(_SUB_RAW) > 64
    or not _re.fullmatch(r"/[a-zA-Z0-9/_-]*", _SUB_RAW)
):
    SUBSCRIPTION_PATH = "/sub"
else:
    SUBSCRIPTION_PATH = _SUB_RAW.rstrip("/") or "/sub"
DOMAIN = os.environ.get("ZEFIRA_DOMAIN", "zefira.example.com").strip() or "zefira.example.com"
SUB_PORT = os.environ.get("ZEFIRA_SUB_PORT", "443")
WG_PORT = os.environ.get("ZEFIRA_WG_PORT", "51820")
HY2_PORT = os.environ.get("ZEFIRA_HY2_PORT", "8443")
DNS = os.environ.get("ZEFIRA_DNS", "1.1.1.1")
OVPN_PORT_DEFAULT = os.environ.get("ZEFIRA_OVPN_PORT", "1194")
OVPN_PROTO = os.environ.get("ZEFIRA_OVPN_PROTO", "udp")
