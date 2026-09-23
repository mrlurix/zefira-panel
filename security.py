import base64
import hashlib
import hmac
import os
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
        if not (2**10 <= n <= 2**20 and 1 <= r <= 32 and 1 <= p <= 32):
            return False
        # Cost cap: scrypt memory is ~128*n*r*p bytes. A crafted hash with
        # maxed params (2^20/32/32) would OOM the worker on every login
        # attempt for that user. Production hashes are 2^14/8/1 (2^17);
        # anything above 2^20 total cost is rejected outright.
        if n * r * p > 2**20:
            return False
        salt = bytes.fromhex(parts[4])
        expected = bytes.fromhex(parts[5])
        if not (16 <= len(expected) <= 64 and len(salt) <= 64):
            return False
        dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError, MemoryError, OverflowError):
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
# Global per-username bucket: intentionally loose. The tight per-IP bucket above
# stops single-source brute force; this one only slows distributed sprays.
# Too low a value lets anyone lock the real admin out (account-lockout DoS).
login_user_limiter = SlidingWindowLimiter(max_events=100, window_seconds=900)

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
