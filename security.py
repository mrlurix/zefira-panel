import base64
import hashlib
import hmac
import html
import logging
import os
import threading
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

# scrypt allocates ~16 MiB per call and login runs in uvicorn's thread pool,
# so 40 parallel guesses would reserve ~640 MiB from an unauthenticated
# request. Cap concurrent hashing at 4. The gate is NON-BLOCKING on purpose:
# blocking would let a flood park dozens of pool threads waiting for their
# turn and starve every other endpoint. Instead an over-subscribed caller gets
# ScryptBusy, which the API turns into 429 - the request never reaches the
# hash, so it costs nothing.
_SCRYPT_MAX_CONCURRENCY = 4
_SCRYPT_SEMAPHORE = threading.BoundedSemaphore(_SCRYPT_MAX_CONCURRENCY)


class ScryptBusy(Exception):
    """Raised when the concurrent-hashing gate is saturated."""


class _ScryptGate:
    def __enter__(self):
        if not _SCRYPT_SEMAPHORE.acquire(blocking=False):
            raise ScryptBusy("too many concurrent password operations")
        return self

    def __exit__(self, *exc):
        _SCRYPT_SEMAPHORE.release()
        return False


_SCRYPT_GATE = _ScryptGate()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    with _SCRYPT_GATE:
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
        with _SCRYPT_GATE:
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
    # Absolute ceiling. Between MAX_KEYS and HARD_CAP a saturated bucket is
    # never evicted (see _evict_if_needed); past HARD_CAP memory safety wins
    # and the oldest saturated buckets go, with a warning in the log.
    HARD_CAP = 200000

    def __init__(self, max_events: int, window_seconds: float):
        self.max = max_events
        self.window = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)
        # Sync endpoints run on uvicorn's thread pool: concurrent hit()
        # calls race on the dict (over-admit + "dictionary changed size"
        # RuntimeError during eviction). One lock serializes them.
        self._lock = threading.Lock()

    def _evict_if_needed(self) -> None:
        if len(self._events) <= self.MAX_KEYS:
            return
        now = time.monotonic()
        # 1) Fully expired buckets are always safe to drop.
        for k in [k for k, q in self._events.items() if not q or now - q[-1] > self.window]:
            self._events.pop(k, None)
        if len(self._events) <= self.MAX_KEYS:
            return
        # 2) Buckets that are NOT currently throttled can be rebuilt by the
        #    next hit, so dropping them costs nothing. A SATURATED bucket is
        #    the security state itself: evicting it would let an attacker
        #    clear a locked-out account with a flood of throwaway keys
        #    (the old code deleted the oldest keys unconditionally).
        for k in [k for k, q in self._events.items() if len(q) < self.max]:
            self._events.pop(k, None)
            if len(self._events) <= self.MAX_KEYS // 2:
                break
        if len(self._events) > self.HARD_CAP:
            logging.getLogger("zefira").warning(
                "rate limiter %s over hard cap (%d keys) - dropping oldest buckets",
                self.max, len(self._events),
            )
            overflow = len(self._events) - self.HARD_CAP // 2
            for k in list(self._events.keys())[:overflow]:
                self._events.pop(k, None)

    def hit(self, key: str) -> bool:
        with self._lock:
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
        with self._lock:
            self._events.pop(key, None)


login_limiter = SlidingWindowLimiter(max_events=8, window_seconds=900)
# Global per-username bucket: intentionally loose. The tight per-IP bucket above
# stops single-source brute force; this one only slows distributed sprays.
# Too low a value lets anyone lock the real admin out (account-lockout DoS).
login_user_limiter = SlidingWindowLimiter(max_events=100, window_seconds=900)
# Per-source-IP budget that does NOT depend on the submitted username. Both
# buckets above are keyed by username, so an unauthenticated attacker can mint
# a fresh 8-attempt bucket per guess and make every request pay a full scrypt
# (~16 MiB) plus an audit write: an unauthenticated memory/CPU amplifier.
# This one is checked before any hashing, so one source can never trigger more
# than 100 scrypt operations per 15 minutes no matter how it varies the
# username. It is only reset by a *successful* login, so guessing can never
# clear it. (100 is deliberately generous for a human - a mistyped password is
# capped at 8 tries by the per-(ip|user) bucket above - while still bounding
# an anonymous client's CPU, memory and audit-write usage to a trickle.)
login_ip_limiter = SlidingWindowLimiter(max_events=100, window_seconds=900)

_HKDF = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"zefira-static-salt", info=b"totp-encryption")
_FERNET = Fernet(base64.urlsafe_b64encode(_HKDF.derive(SECRET_KEY.encode())))


def tg_message(fmt: str, *untrusted: object) -> str:
    """Build a Telegram HTML message from trusted markup + escaped values.

    Telegram notifications are sent with parse_mode=HTML so the panel can
    bold names. Any value interpolated into that markup must therefore be
    HTML-escaped first, or a request-controlled string (e.g. the username on
    a failed login) becomes a clickable phishing link in the operator's chat.
    `fmt` is trusted, module-owned markup; every dynamic value is escaped
    here. Returns the body in `text` form ready for the API call.
    """
    body = fmt.format(*(html.escape(str(v), quote=True) for v in untrusted)) if untrusted else fmt
    return body[:500]


def encrypt_text(plain: str) -> str:
    return _FERNET.encrypt(plain.encode()).decode()


def decrypt_text(token: str | None) -> str:
    if not token:
        return ""
    try:
        return _FERNET.decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return ""
