import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy import event
from sqlalchemy.orm import Session, declarative_base

Base = declarative_base()

# A subscription token is exactly 32 lowercase hex characters (secrets.token_hex(16)).
# Anything else in the token column is a Fernet blob, which is how the two shapes
# are told apart - the same trick parse_secret_map uses for the credential bundle.
TOKEN_PLAIN_RE = re.compile(r"\A[a-f0-9]{32}\Z")


def token_is_sealed(value: str | None) -> bool:
    """True when the stored value is encrypted rather than bare hex."""
    return bool(value) and TOKEN_PLAIN_RE.fullmatch(value) is None


def token_digest(token: str) -> str:
    """The indexed lookup key for a subscription token.

    HMAC, not a bare SHA-256: the input space is only 128 bits of a CSPRNG, but
    an HMAC also means a stolen token_sha column cannot be attacked with a
    precomputed table the way a plain hash of a low-entropy value could be.
    """
    import hashlib
    import hmac

    from config import SECRET_KEY

    return hmac.new(SECRET_KEY.encode("utf-8"), token.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def seal_token(plain: str) -> tuple[str, str]:
    """-> (ciphertext for the token column, digest for the lookup index)."""
    from security import encrypt_text

    return encrypt_text(plain), token_digest(plain)


def parse_token(value: str | None) -> str:
    """The plaintext token, whether it is stored bare or encrypted.

    Both shapes must keep working: a row written before this change is bare hex
    and stays that way until it is rewritten, and a backup exported by an older
    panel carries the bare form too. Unreadable input yields "", because the
    correct response is to re-provision the customer, not to 500 the
    subscription endpoint.
    """
    if not value:
        return ""
    if TOKEN_PLAIN_RE.fullmatch(value):
        return value
    from security import decrypt_text

    return decrypt_text(value)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def safe_text(value):
    """Read-path sanitizer for strings leaving the database.

    Two ways a stored TEXT column can break response encoding:
      * SQLite accepted a lone surrogate (U+D800-U+DFFF), e.g. from a
        hand-edited DB or an old import. It reads back as a valid `str` but
        cannot be re-encoded to UTF-8.
      * SQLite stores raw bytes that are not valid UTF-8 at all; pysqlite then
        hands them back as `bytes`, and JSON encoding blows up on `.decode()`.
    Either way a single bad row 500s the entire collection endpoint, which is
    a panel-wide DoS. Writes are blocked at the HTTP edge; this keeps
    pre-existing rows readable.
    """
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    if type(value) is str and not value.isascii():
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            value = value.encode("utf-8", "replace").decode("utf-8")
    return value


class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    token_version = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    def to_backup_dict(self) -> dict:
        # A hand-edited NULL created_at used to raise AttributeError here and
        # 500 the whole backup download.
        created = self.created_at or utcnow()
        return {
            "username": safe_text(self.username),
            "password_hash": safe_text(self.password_hash),
            "token_version": self.token_version,
            "created_at": created.isoformat(timespec="seconds"),
        }


class VpnUser(Base):
    __tablename__ = "vpn_users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    protocol = Column(String(16), nullable=False, default="vless")
    protocols = Column(Text, nullable=False, default="")
    note = Column(Text, nullable=False, default="")
    volume_gb = Column(Float, nullable=False)
    used_gb = Column(Float, nullable=False, default=0.0)
    token = Column(Text, unique=True, nullable=False, index=True)
    # Indexed lookup key for the subscription token. The token itself is stored
    # encrypted (see seal_token), so the database file cannot be searched with
    # the value a customer actually presents - but /sub/{token} has to stay an
    # indexed equality lookup, not a decrypt-every-row scan. This is that
    # index: an HMAC under the panel key, so it cannot be brute-forced back
    # into a token without the key either.
    token_sha = Column(String(64), unique=True, nullable=True, index=True)
    secret_data = Column(Text, nullable=False, default="")
    is_active = Column(Boolean, nullable=False, default=True)
    start_on_first_use = Column(Boolean, nullable=False, default=False)
    duration_days = Column(Integer, nullable=True)
    device_limit = Column(Integer, nullable=True)
    last_fetch_at = Column(DateTime, nullable=True)
    last_fetch_ip = Column(String(64), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    expires_at = Column(DateTime, nullable=False)

    def is_pending_start(self) -> bool:
        return bool(self.start_on_first_use) and self.expires_at is not None and self.expires_at.year >= 2098

    def to_dict(self) -> dict:
        # 4 decimals, not 2: the raw gate compares used >= volume, so rounding
        # 1.233/1.234 down to 1.23 made the panel say "out of volume" for an
        # account the server was still serving (and the subscription header
        # reported download == total).
        return {
            "id": self.id,
            "username": safe_text(self.username),
            "protocols": self.protocols_list(),
            "note": safe_text(self.note),
            "volume_gb": round(self.volume_gb or 0, 4),
            "used_gb": round(self.used_gb or 0, 4),
            "token": parse_token(self.token),
            "is_active": self.is_active,
            "device_limit": self.device_limit,
            "start_on_first_use": self.start_on_first_use,
            "pending_start": self.is_pending_start(),
            "last_fetch_at": (
                self.last_fetch_at.isoformat(timespec="seconds") + "Z" if self.last_fetch_at else None
            ),
            "last_fetch_ip": safe_text(self.last_fetch_ip) or None,
            "created_at": (
                self.created_at.isoformat(timespec="seconds") + "Z" if self.created_at else None
            ),
            "expires_at": (
                self.expires_at.isoformat(timespec="seconds") + "Z" if self.expires_at else None
            ),
        }

    def protocols_list(self) -> list:
        raw = (self.protocols or "").strip()
        if raw:
            return [safe_text(p) for p in raw.split(",") if p]
        return [safe_text(self.protocol or "vless")]

    def to_full_dict(self) -> dict:
        data = self.to_dict()
        data["secret_map"] = parse_secret_map(self.secret_data)
        return data

    def to_backup_dict(self) -> dict:
        # None-tolerant: a hand-edited NULL must degrade the backup, never 500
        # it. Last-seen metadata rides along so a restore does not wipe the
        # customer's history.
        #
        # expires_at is written as-is, INCLUDING null. The old code substituted
        # utcnow() for a NULL, which wrote a lie into the operator's
        # disaster-recovery file: restoring it later gave that customer an
        # expiry of "the moment you restored", so they were instantly expired
        # and their subscription 404'd. The restore re-derives a sane expiry
        # from duration_days instead.
        created = self.created_at or utcnow()
        return {
            "username": safe_text(self.username),
            "protocol": safe_text(self.protocol),
            "protocols": safe_text(self.protocols),
            "note": safe_text(self.note),
            "volume_gb": self.volume_gb,
            "used_gb": self.used_gb,
            # The RAW column, deliberately. This is the export, and the token
            # column now holds a Fernet blob - so an unencrypted backup carries
            # ciphertext, exactly like secret_data beside it, and cannot be
            # replayed as a working subscription URL by itself. Restore calls
            # parse_token, which accepts this shape and the bare-hex shape an
            # older panel exported.
            "token": safe_text(self.token),
            "secret_data": safe_text(self.secret_data),
            "is_active": self.is_active,
            "device_limit": self.device_limit,
            "start_on_first_use": self.start_on_first_use,
            "duration_days": self.duration_days,
            "last_fetch_at": (
                self.last_fetch_at.isoformat(timespec="seconds") + "Z" if self.last_fetch_at else None
            ),
            "last_fetch_ip": safe_text(self.last_fetch_ip) or None,
            "created_at": created.isoformat(timespec="seconds"),
            "expires_at": (
                self.expires_at.isoformat(timespec="seconds") + "Z" if self.expires_at else None
            ),
        }


class UserTemplate(Base):
    __tablename__ = "user_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(40), unique=True, nullable=False)
    protocols = Column(Text, nullable=False)
    volume_gb = Column(Float, nullable=False)
    days = Column(Integer, nullable=False)
    start_on_first_use = Column(Boolean, nullable=False, default=False)
    device_limit = Column(Integer, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": safe_text(self.name),
            "protocols": [safe_text(p) for p in (self.protocols or "").split(",") if p],
            "volume_gb": self.volume_gb,
            "days": self.days,
            "start_on_first_use": self.start_on_first_use,
            "device_limit": self.device_limit,
        }


def parse_secret_map(secret_data: str) -> dict:
    """Read the per-customer credential bundle, encrypted or not.

    This column holds what a customer CANNOT regenerate: a WireGuard private
    key, an OpenVPN client keypair, the L2TP PSK. It was stored as bare
    json.dumps output, so anyone who could read the database file - a stolen
    backup, a mis-set filesystem permission, an operator who pastes a
    support file - read every customer's connection credentials at a glance.
    Fernet with the panel's own SECRET_KEY now wraps it; the same key already
    protects the AI key, the Telegram bot token and the REALITY private key,
    so this is wiring up an existing mechanism, not inventing one.

    BOTH shapes must keep working. A row written before this change is bare
    JSON and stays that way until it is rewritten, and the panel will be
    upgraded in place from any earlier version, so the plaintext branch is not
    legacy to be deleted later - it is the format every existing row has. A
    row that is neither shape returns {} rather than raising, because the
    caller's correct response is to re-provision the customer, not to 500 the
    subscription endpoint.
    """
    if not secret_data:
        return {}
    if secret_data.startswith("{"):
        import json

        try:
            return json.loads(secret_data)
        except ValueError:
            return {}
    # Encrypted since v1.15.27. decrypt_text returns "" on any failure -
    # a rotated key, a truncated token, a value that was never ours - so this
    # degrades to "re-provision", never to an exception.
    try:
        from security import decrypt_text

        plain = decrypt_text(secret_data)
    except Exception:  # noqa: BLE001 - an unreadable bundle is re-provisioned
        return {}
    if not plain:
        return {}
    import json

    try:
        parsed = json.loads(plain)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


@event.listens_for(VpnUser, "before_insert")
# One hook rather than edits at the four call sites that mint a token, because
# that is what makes the rotation paths safe too: "reset token" assigns a fresh
# plaintext value and the old digest would otherwise survive beside it, so
# /sub/{new token} would 404 while the database still held the old index. Any
# bare token is re-sealed and re-digested here; an already-sealed one is left
# alone, so writing a row does not churn its ciphertext.
@event.listens_for(VpnUser, "before_insert")
@event.listens_for(VpnUser, "before_update")
def _seal_token_on_write(mapper, connection, target):
    if target.token and not token_is_sealed(target.token):
        target.token, target.token_sha = seal_token(target.token)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False, default="")


class Inbound(Base):
    __tablename__ = "inbounds"

    id = Column(Integer, primary_key=True)
    name = Column(String(40), unique=True, nullable=False)
    protocol = Column(String(16), nullable=False)
    port = Column(Integer, nullable=False)
    host = Column(String(253), nullable=False, default="")
    enabled = Column(Boolean, nullable=False, default=True)
    node_id = Column(Integer, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": safe_text(self.name),
            "protocol": safe_text(self.protocol),
            "port": self.port,
            "host": safe_text(self.host),
            "enabled": self.enabled,
            "node_id": self.node_id,
        }


class ServerNode(Base):
    __tablename__ = "server_nodes"

    id = Column(Integer, primary_key=True)
    name = Column(String(40), unique=True, nullable=False)
    address = Column(String(253), nullable=False)
    check_port = Column(Integer, nullable=False, default=443)
    note = Column(Text, nullable=False, default="")
    enabled = Column(Boolean, nullable=False, default=True)
    status = Column(String(12), nullable=False, default="unknown")
    latency_ms = Column(Integer, nullable=True)
    success_count = Column(Integer, nullable=False, default=0)
    fail_count = Column(Integer, nullable=False, default=0)
    last_check = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    def uptime_pct(self) -> int | None:
        total = (self.success_count or 0) + (self.fail_count or 0)
        if not total:
            return None
        return round(100 * (self.success_count or 0) / total)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": safe_text(self.name),
            "address": safe_text(self.address),
            "check_port": self.check_port,
            "note": safe_text(self.note),
            "enabled": self.enabled,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "uptime_pct": self.uptime_pct(),
            "last_check": (
                self.last_check.isoformat(timespec="seconds") + "Z" if self.last_check else None
            ),
            # Guarded like VpnUser.to_dict: a hand-edited or migrated row with
            # a NULL created_at raised AttributeError here, and that took out
            # /api/server-nodes, its check endpoint and the monitor loop with
            # a 500. safe_text's own docstring calls it a panel-wide DoS.
            "created_at": (
                self.created_at.isoformat(timespec="seconds") + "Z" if self.created_at else None
            ),
        }


class BlockedSite(Base):
    __tablename__ = "blocked_sites"

    id = Column(Integer, primary_key=True)
    domain = Column(String(253), unique=True, nullable=False, index=True)
    category = Column(String(20), nullable=False, default="custom")
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": safe_text(self.domain),
            "category": safe_text(self.category),
            "enabled": self.enabled,
            # A hand-edited or migrated row with a NULL created_at raised
            # AttributeError here and took out the whole list endpoint with a
            # 500. The sibling serialisers guard this; this one did not.
            "created_at": (
                self.created_at.isoformat(timespec="seconds") + "Z" if self.created_at else None
            ),
        }


def _int_or(value, default: int) -> int:
    """An INTEGER column that may hold text, as a SQLite row edited by hand can.

    The guide formats these with %d, which raises on a string - so one mangled
    row would turn a tunnel's setup guide into a 500 instead of showing the
    tunnel with its limit unset.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class TunnelNode(Base):
    __tablename__ = "tunnel_nodes"

    id = Column(Integer, primary_key=True)
    name = Column(String(40), unique=True, nullable=False)
    transport = Column(String(20), nullable=False, default="tcp")
    iran_ip = Column(String(253), nullable=False)
    kharej_ip = Column(String(253), nullable=False)
    tunnel_port = Column(Integer, nullable=False)
    forwarded_ports = Column(Text, nullable=False, default="")
    udp_forward = Column(Boolean, nullable=False, default=False)
    token_enc = Column(Text, nullable=False)
    status = Column(String(12), nullable=False, default="unknown")
    # BackPack v1.8.5 options. Defaults match upstream's own defaults, so a row
    # written before this release behaves exactly as it did.
    preset = Column(String(16), nullable=False, default="turbo")
    traffic_limit_gb = Column(Integer, nullable=False, default=0)
    restart_hours = Column(Integer, nullable=False, default=0)
    backup_hosts = Column(Text, nullable=False, default="")
    last_check = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": safe_text(self.name),
            "transport": safe_text(self.transport),
            "iran_ip": safe_text(self.iran_ip),
            "kharej_ip": safe_text(self.kharej_ip),
            "tunnel_port": self.tunnel_port,
            "forwarded_ports": safe_text(self.forwarded_ports),
            "udp_forward": self.udp_forward,
            "preset": safe_text(self.preset or "turbo"),
            # int() rather than the raw column: a hand-edited row can hold text
            # in an INTEGER column on SQLite, and the guide formats these with
            # %d, which would raise on a string instead of showing the tunnel.
            "traffic_limit_gb": _int_or(self.traffic_limit_gb, 0),
            "restart_hours": _int_or(self.restart_hours, 0),
            "backup_hosts": safe_text(self.backup_hosts or ""),
            "status": self.status,
            "last_check": (
                self.last_check.isoformat(timespec="seconds") + "Z" if self.last_check else None
            ),
            # Same NULL guard as last_check above: a NULL created_at 500'd the
            # whole /api/nodes list instead of degrading one row.
            "created_at": (
                self.created_at.isoformat(timespec="seconds") + "Z" if self.created_at else None
            ),
        }


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, nullable=False, default=utcnow, index=True)
    event = Column(String(32), nullable=False)
    detail = Column(Text, nullable=False, default="")
    ip = Column(String(64), nullable=False, default="")
    ok = Column(Boolean, nullable=False, default=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            # Same NULL guard as the other rows: the audit log is read by the
            # panel's own dashboard, and one legacy row without a timestamp
            # 500'd /api/audit.
            "ts": self.ts.isoformat(timespec="seconds") + "Z" if self.ts else None,
            "event": safe_text(self.event),
            "detail": safe_text(self.detail[:200] if self.detail else None),
            "ip": safe_text(self.ip),
            "ok": self.ok,
        }


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True)
    name = Column(String(40), unique=True, nullable=False)
    prefix = Column(String(12), nullable=False, default="")
    # SHA-256 of the raw token (256-bit random: unbrute-forceable even if the
    # DB leaks). The raw value is shown once at creation and never stored.
    token_sha = Column(String(64), unique=True, nullable=False, index=True)
    admin_id = Column(Integer, nullable=True)
    # Scope: "full" (all endpoints) or "bot" (reseller-bot safe subset:
    # GET /api/me, GET /api/stats, GET /api/users, POST /api/users,
    # GET /api/templates). Bot tokens can create users (including
    # start_on_first_use) but can never delete, patch, backup/restore,
    # change settings, or manage tokens/update.
    scopes = Column(String(16), nullable=False, default="full")
    created_at = Column(DateTime, nullable=False, default=utcnow)
    # NULL = never expires (the operator's explicit choice at creation). A
    # token with no expiry at all is indistinguishable from a leaked one a
    # year later, so the default is a bounded life.
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": safe_text(self.name),
            "prefix": safe_text(self.prefix),
            "scopes": self.scopes or "full",
            # Same NULL guard as expires_at/last_used_at below: to_backup_dict
            # in this same class already uses `self.created_at or utcnow()`,
            # so the unguarded to_dict was an oversight, not a policy.
            "created_at": (
                self.created_at.isoformat(timespec="seconds") + "Z" if self.created_at else None
            ),
            "expires_at": (
                self.expires_at.isoformat(timespec="seconds") + "Z" if self.expires_at else None
            ),
            "last_used_at": (
                self.last_used_at.isoformat(timespec="seconds") + "Z" if self.last_used_at else None
            ),
        }

    def to_backup_dict(self) -> dict:
        created = self.created_at or utcnow()
        return {
            "name": safe_text(self.name),
            "prefix": safe_text(self.prefix),
            "token_sha": safe_text(self.token_sha),
            "scopes": self.scopes or "full",
            "created_at": created.isoformat(timespec="seconds"),
            "last_used_at": (
                self.last_used_at.isoformat(timespec="seconds") if self.last_used_at else None
            ),
        }


# Migration steps, each run in its own transaction - see init(). Built once at
# import so the statements live in one place instead of inline in the caller.
# `bool_ddl`/`text_ddl`/`dt_ddl` were computed from `conn.engine.dialect.name`;
# the engine is the same object whichever connection it hands out.
def _migration_steps(dialect_name):
    bool_ddl = ("BOOLEAN NOT NULL DEFAULT FALSE" if dialect_name == "postgresql"
                else "BOOLEAN NOT NULL DEFAULT 0")
    text_ddl = "TEXT NULL" if dialect_name == "mysql" else "TEXT NOT NULL DEFAULT ''"
    dt_ddl = "DATETIME" if dialect_name == "mysql" else "TIMESTAMP"

    def _drop(table, column):
        return lambda self, conn: self._drop_column(conn, table, column)

    def _add(table, column, ddl):
        return lambda self, conn: self._add_column(conn, table, column, ddl)

    def _index(table, column, name):
        """A migration step that creates an index. Same shape as _add above.

        ALTER TABLE ADD COLUMN cannot create an index, and
        Base.metadata.create_all() emits indexes only for the tables it builds -
        so a column added by migration arrives unindexed. On a table built this
        way, measured, PRAGMA index_list returned [] and EXPLAIN planned SCAN
        for /sub/{token} - the anonymous subscription lookup, once per poll.
        Unique as well as indexed: token_digest() is an HMAC and the ORM column
        already declares unique=True.

        A pre-existing duplicate value, or a dialect that spells it differently,
        must not stop the panel booting - the column and its data are already
        correct and this is only the index. So it warns and moves on, unlike
        _add_column below which deliberately lets a failed ALTER do the same.
        """
        def _run(self, conn):
            try:
                conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (%s)"
                                  % (name, table, column)))
            except Exception:
                logging.getLogger(__name__).warning(
                    "could not create index %s on %s(%s)", name, table, column,
                    exc_info=True)
        return _run

    def _blank_backfill(column):
        def _run(self, conn):
            try:
                conn.execute(text("UPDATE vpn_users SET %s = '' "
                                  "WHERE %s IS NULL" % (column, column)))
            except Exception:
                pass
        return _run

    def _scopes_backfill(self, conn):
        try:
            conn.execute(text("UPDATE api_tokens SET scopes='full' "
                              "WHERE scopes IS NULL"))
        except Exception:
            pass

    def _protocols_backfill(self, conn):
        conn.execute(text("UPDATE vpn_users SET protocols = protocol "
                          "WHERE protocols IS NULL OR protocols = ''"))

    def _token_seal(self, conn):
        """Encrypt every subscription token still stored in the clear.

        The token column held the bearer credential itself, so reading
        instance/zefira.db - or an unencrypted backup exported from it - handed
        over working VPN access for every customer at once. Measured before
        this ran: a token read straight out of the file answered /sub/{token}
        with 200 and the customer's WireGuard private key, no credentials of any
        kind.

        token_sha is the backfill marker: a row whose digest is still NULL was
        written before the column existed and still holds bare hex. Each is
        sealed and given its digest here, so an existing panel upgrades in place
        and nobody's subscription URL changes. If a single row cannot be sealed
        the transaction is left to fail loudly rather than half-migrated - a
        row that stayed bare would look migrated while still leaking.
        """
        rows = conn.execute(
            text("SELECT id, token FROM vpn_users WHERE token_sha IS NULL")
        ).fetchall()
        for rid, raw in rows:
            if not raw:
                conn.execute(text("UPDATE vpn_users SET token_sha = :d "
                                  "WHERE id = :i"),
                             {"d": token_digest(secrets.token_hex(16)), "i": rid})
                continue
            plain = parse_token(raw)
            if not plain:
                # Encrypted under a key this panel does not hold: leave it
                # alone rather than overwrite the only copy of the value.
                continue
            cipher, digest = seal_token(plain)
            conn.execute(text("UPDATE vpn_users SET token = :t, token_sha = :d "
                              "WHERE id = :i"),
                         {"t": cipher, "d": digest, "i": rid})
            self._tokens_sealed = True

    return [
        _drop("admins", "totp_enabled"),
        _drop("admins", "totp_secret"),
        _drop("admins", "totp_pending"),
        _add("vpn_users", "protocol", "protocol VARCHAR(16) NOT NULL DEFAULT 'vless'"),
        _add("vpn_users", "secret_data", f"secret_data {text_ddl}"),
        _add("vpn_users", "protocols", f"protocols {text_ddl}"),
        _add("vpn_users", "start_on_first_use", f"start_on_first_use {bool_ddl}"),
        _add("vpn_users", "duration_days", "duration_days INTEGER"),
        _add("vpn_users", "device_limit", "device_limit INTEGER"),
        _add("vpn_users", "last_fetch_at", f"last_fetch_at {dt_ddl}"),
        _add("vpn_users", "last_fetch_ip", "last_fetch_ip VARCHAR(64)"),
        _add("vpn_users", "token_sha", "token_sha VARCHAR(64)"),
        # create_all() emits this index for a FRESH table and does nothing
        # for an existing one, so every UPGRADED install resolved
        # /sub/{token} with a full scan of vpn_users. Measured on a table
        # built the migration way: PRAGMA index_list returned [] and
        # EXPLAIN said SCAN, not SEARCH. Unique as well as indexed -
        # token_digest() is an HMAC and the ORM column already declares
        # unique=True, so the database should enforce it.
        _index("vpn_users", "token_sha", "ix_vpn_users_token_sha"),
        _add("inbounds", "node_id", "node_id INTEGER"),
        _add("user_templates", "device_limit", "device_limit INTEGER"),
        _add("api_tokens", "scopes", "scopes VARCHAR(16) NOT NULL DEFAULT 'full'"),
        _add("api_tokens", "expires_at", f"expires_at {dt_ddl}"),
        # BackPack v1.8.5 per-tunnel options. Each defaults to the value
        # upstream itself defaults to, so an existing tunnel keeps its meaning:
        # turbo, no limit, no restart schedule, no backup addresses.
        _add("tunnel_nodes", "preset", "preset VARCHAR(16) NOT NULL DEFAULT 'turbo'"),
        _add("tunnel_nodes", "traffic_limit_gb",
             "traffic_limit_gb INTEGER NOT NULL DEFAULT 0"),
        _add("tunnel_nodes", "restart_hours", "restart_hours INTEGER NOT NULL DEFAULT 0"),
        _add("tunnel_nodes", "backup_hosts", f"backup_hosts {text_ddl}"),
        _blank_backfill("secret_data"),
        _blank_backfill("protocols"),
        _scopes_backfill,
        _protocols_backfill,
        _token_seal,
    ]

class Database:
    def __init__(self, path: Path):
        import os

        db_url = os.environ.get("DATABASE_URL", "").strip()
        if db_url:
            self.engine = create_engine(db_url, future=True, pool_pre_ping=True)
            self._external_db = True
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.engine = create_engine(
                f"sqlite:///{path}",
                connect_args={"check_same_thread": False},
                future=True,
            )
            self._external_db = False

        if not self._external_db:
            from sqlalchemy import event

            @event.listens_for(self.engine, "connect")
            def _set_sqlite_pragma(dbapi_connection, _):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                # Writers collide (sub-fetch presence writes, token touches,
                # monitor loop, admin ops): block up to 30s instead of
                # failing fast with "database is locked".
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.close()

    _tokens_sealed = False

    def init(self) -> None:
        Base.metadata.create_all(self.engine)
        if not getattr(self, "_external_db", False):
            try:
                import os

                # WAL mode keeps the most recently written rows in the -wal
                # sidecar, so hardening only the main file leaves the freshest
                # data readable by anyone the umask allows. That matters more
                # since secret_data became encrypted: the sidecar is where a
                # just-provisioned customer's bundle sits before a checkpoint.
                # install.sh sets umask 077, but a panel started by hand
                # (uvicorn, start.bat) inherits umask 022 and creates these 0644.
                for suffix in ("", "-wal", "-shm"):
                    try:
                        os.chmod(self.engine.url.database + suffix, 0o600)
                    except OSError:
                        pass
            except (OSError, AttributeError):
                pass
        # Each step gets its OWN transaction.
        #
        # These eighteen used to share one `engine.begin()`. Both column helpers
        # are idempotent, but _add_column deliberately lets a failed ALTER
        # propagate, as does the backfill below - so one failure raised out of
        # the block and rolled back every step before it. On SQLite and
        # PostgreSQL, where DDL is transactional, that discarded steps 1..k-1:
        # the panel started against the old schema, the ORM's SELECTs named
        # columns that did not exist, and the panel was dead - identically dead
        # on every later boot because the same step kept failing.
        #
        # MySQL was never affected: its DDL implies a COMMIT, so each step
        # autocommitted and the outer `with` was decorative. Moving the boundary
        # is therefore a no-op there.
        #
        # With a boundary per step, a failure leaves a well-defined prefix
        # applied and the next boot resumes from it instead of from nothing.
        # Statements and their order are copied verbatim from the block this
        # replaces; only the transaction changed.
        for _step in _migration_steps(self.engine.dialect.name):
            with self.engine.begin() as _conn:
                _step(self, _conn)

        # Encrypting a column does not erase the old bytes. SQLite frees the
        # pages the plaintext occupied and leaves them on the freelist, so a
        # stolen zefira.db still contained every pre-upgrade subscription token
        # in raw form - measured, not assumed: 242 of 330 pages still held the
        # bytes after the rewrite while zero rows referenced them. VACUUM
        # rebuilds the file, which is the only thing that actually removes them.
        #
        # Only when the token step really sealed something, so a normal boot
        # never pays for it, and never inside a transaction (SQLite refuses).
        if self._tokens_sealed and not getattr(self, "_external_db", False):
            try:
                # Deliberately NOT through the engine. An earlier version used
                # engine.connect() with isolation_level=AUTOCOMMIT and the
                # bytes were still there afterwards - measured, with the row
                # holding ciphertext, the freelist empty and the plaintext
                # still readable in the file. A plain sqlite3 connection in
                # autocommit mode is unambiguous about transaction boundaries,
                # and this runs once, at upgrade, before serving anything.
                self.engine.dispose()
                import sqlite3

                _con = sqlite3.connect(self.engine.url.database,
                                       isolation_level=None)
                try:
                    _con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    _con.execute("VACUUM")
                    _con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                finally:
                    _con.close()
            except Exception as exc:
                # Not fatal: the tokens are encrypted from here on either way,
                # and refusing to start over a cosmetic VACUUM would be worse.
                import logging
                logging.getLogger(__name__).warning(
                    "post-migration VACUUM skipped: %s", exc)
            finally:
                self._tokens_sealed = False

    @staticmethod
    def _drop_column(conn, table: str, name: str) -> None:
        # Only drops columns this app once created; identifiers are internal
        # literals. A dialect that cannot DROP COLUMN (SQLite < 3.35) must
        # not take the whole panel down at startup: the leftover TOTP columns
        # are simply ignored by the ORM.
        from sqlalchemy import inspect as sa_inspect

        insp = sa_inspect(conn)
        if not insp.has_table(table):
            return
        if name not in {c["name"] for c in insp.get_columns(table)}:
            return
        try:
            conn.execute(text(f"ALTER TABLE {table} DROP COLUMN {name}"))
        except Exception:
            pass

    @staticmethod
    def _add_column(conn, table: str, name: str, ddl: str) -> None:
        # Dialect-agnostic introspection (works on SQLite, MySQL, PostgreSQL).
        # Table/column identifiers below are always internal literals.
        from sqlalchemy import inspect as sa_inspect

        insp = sa_inspect(conn)
        if not insp.has_table(table):
            return
        cols = {c["name"] for c in insp.get_columns(table)}
        if name not in cols:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {ddl}"))

    def s(self) -> Session:
        return Session(self.engine, future=True)
