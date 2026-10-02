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
from sqlalchemy.orm import Session, declarative_base

Base = declarative_base()


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
    token = Column(String(64), unique=True, nullable=False, index=True)
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
            "token": self.token,
            "is_active": self.is_active,
            "device_limit": self.device_limit,
            "start_on_first_use": self.start_on_first_use,
            "pending_start": self.is_pending_start(),
            "last_fetch_at": (
                self.last_fetch_at.isoformat(timespec="seconds") + "Z" if self.last_fetch_at else None
            ),
            "last_fetch_ip": self.last_fetch_ip or None,
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
    if not secret_data:
        return {}
    if secret_data.startswith("{"):
        import json

        try:
            return json.loads(secret_data)
        except ValueError:
            return {}
    return {}


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
            "detail": safe_text(self.detail[:200]),
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
        _add("inbounds", "node_id", "node_id INTEGER"),
        _add("user_templates", "device_limit", "device_limit INTEGER"),
        _add("api_tokens", "scopes", "scopes VARCHAR(16) NOT NULL DEFAULT 'full'"),
        _add("api_tokens", "expires_at", f"expires_at {dt_ddl}"),
        _blank_backfill("secret_data"),
        _blank_backfill("protocols"),
        _scopes_backfill,
        _protocols_backfill,
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

    def init(self) -> None:
        Base.metadata.create_all(self.engine)
        if not getattr(self, "_external_db", False):
            try:
                import os

                os.chmod(self.engine.url.database, 0o600)
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
