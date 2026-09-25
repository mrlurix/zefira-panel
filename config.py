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
        # FAIL CLOSED on an existing but unusable key. Regenerating silently
        # signed every session out and made every Fernet blob (REALITY key,
        # Telegram token, AI key) permanently undecryptable - with no message
        # explaining why. A wrong key is an operator decision, not ours.
        try:
            existing = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemExit(
                f"Cannot read {path}: {exc}. Refusing to start: replacing the "
                "master key would sign out every session and make every "
                "encrypted setting undecryptable. Restore the file from a "
                "backup, or delete it to intentionally start a fresh instance."
            ) from exc
        if len(existing) < 32:
            raise SystemExit(
                f"{path} is too short ({len(existing)} chars) to be a valid "
                "master key. Refusing to start: generating a new one would "
                "sign out every session and make every encrypted setting "
                "undecryptable. Restore the file from a backup, or delete it "
                "to intentionally start a fresh instance."
            )
        try:
            st = os.stat(path)
            # A world/group-readable master key lets any local user forge an
            # admin session cookie, so tighten it on every start.
            if st.st_mode & 0o077:
                os.chmod(path, 0o600)
        except OSError:
            pass
        return existing
    key = secrets.token_hex(48)
    # Create exclusively with the final mode: no window where the key is
    # world-readable, and no chance of following a planted symlink.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError:
        # Another worker won the race; use its key.
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"Cannot create {path}: {exc}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key)
        fh.flush()
        os.fsync(fh.fileno())
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


def _detect_outbound_ipv4() -> str:
    """Best-effort primary outbound IPv4 (no packets are sent).

    install.sh explicitly supports "empty domain = use server IP", so the
    panel has to know its own address: without this the generated configs
    pointed at the zefira.example.com placeholder.
    """
    try:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("1.1.1.1", 53))
            ip = sock.getsockname()[0]
        finally:
            sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


_raw_domain = os.environ.get("ZEFIRA_DOMAIN")
if _raw_domain is None:
    # Unset: keep the documented placeholder default.
    DOMAIN = "zefira.example.com"
else:
    # Explicitly empty (IP mode): resolve the server's own address instead of
    # shipping every link to the placeholder domain.
    DOMAIN = _raw_domain.strip() or _detect_outbound_ipv4()
SUB_PORT = os.environ.get("ZEFIRA_SUB_PORT", "443")
WG_PORT = os.environ.get("ZEFIRA_WG_PORT", "51820")
HY2_PORT = os.environ.get("ZEFIRA_HY2_PORT", "8443")
DNS = os.environ.get("ZEFIRA_DNS", "1.1.1.1")
OVPN_PORT_DEFAULT = os.environ.get("ZEFIRA_OVPN_PORT", "1194")
OVPN_PROTO = os.environ.get("ZEFIRA_OVPN_PROTO", "udp")
