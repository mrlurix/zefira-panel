import base64
import hashlib
import hmac
import os
import struct
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import SECRET_KEY, SESSION_TTL

COOKIE_NAME = "zefira_session"
_ALGO = "HS256"
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${dk.hex()}"


_DUMMY_HASH = hash_password("zefira-dummy-password-for-timing")


def verify_password(password: str, stored: str | None) -> bool:
    try:
        if not password or len(password) > 128 or not stored:
            return False
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = bytes.fromhex(parts[4])
        expected = bytes.fromhex(parts[5])
        dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


def dummy_verify(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def create_session(admin_id: int, version: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(admin_id),
        "ver": version,
        "iat": now,
        "exp": now + timedelta(seconds=SESSION_TTL),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=_ALGO)


def decode_session(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[_ALGO])
    except jwt.PyJWTError:
        return None


class SlidingWindowLimiter:
    MAX_KEYS = 20000

    def __init__(self, max_events: int, window_seconds: float):
        self.max = max_events
        self.window = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)

    def _evict_if_needed(self) -> None:
        if len(self._events) <= self.MAX_KEYS:
            return
        now = time.monotonic()
        for k in [k for k, q in self._events.items() if not q or now - q[-1] > self.window]:
            del self._events[k]
        overflow = len(self._events) - self.MAX_KEYS // 2
        if overflow > 0:
            for k in list(self._events.keys())[:overflow]:
                del self._events[k]

    def hit(self, key: str) -> bool:
        self._evict_if_needed()
        now = time.monotonic()
        q = self._events[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max:
            return False
        q.append(now)
        return True

    def reset(self, key: str) -> None:
        self._events.pop(key, None)


login_limiter = SlidingWindowLimiter(max_events=8, window_seconds=900)
login_user_limiter = SlidingWindowLimiter(max_events=25, window_seconds=900)

_HKDF = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"zefira-static-salt", info=b"totp-encryption")
_FERNET = Fernet(base64.urlsafe_b64encode(_HKDF.derive(SECRET_KEY.encode())))


def encrypt_text(plain: str) -> str:
    return _FERNET.encrypt(plain.encode()).decode()


def decrypt_text(token: str | None) -> str:
    if not token:
        return ""
    try:
        return _FERNET.decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return ""


def gen_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def totp_now(secret: str, offset: int = 0) -> str:
    pad = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret.upper() + pad)
    counter = struct.pack(">Q", int(time.time() // 30) + offset)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code = (int.from_bytes(digest[o : o + 4], "big") & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    if not secret or not code or not code.isdigit() or len(code) != 6:
        return False
    for offset in range(-window, window + 1):
        if hmac.compare_digest(totp_now(secret, offset), code):
            return True
    return False


def otpauth_uri(username: str, secret: str) -> str:
    return f"otpauth://totp/Zefira:{username}?secret={secret}&issuer=Zefira&algorithm=SHA1&digits=6&period=30"
