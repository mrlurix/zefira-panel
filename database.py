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


class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    token_version = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    totp_enabled = Column(Boolean, nullable=False, default=False)
    totp_secret = Column(Text, nullable=True)
    totp_pending = Column(Text, nullable=True)

    def to_backup_dict(self) -> dict:
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "token_version": self.token_version,
            "totp_enabled": self.totp_enabled,
            "totp_secret": self.totp_secret,
            "created_at": self.created_at.isoformat(timespec="seconds"),
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
    created_at = Column(DateTime, nullable=False, default=utcnow)
    expires_at = Column(DateTime, nullable=False)

    def is_pending_start(self) -> bool:
        return bool(self.start_on_first_use) and self.expires_at is not None and self.expires_at.year >= 2098

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "protocols": self.protocols_list(),
            "note": self.note,
            "volume_gb": round(self.volume_gb, 2),
            "used_gb": round(self.used_gb, 2),
            "token": self.token,
            "is_active": self.is_active,
            "start_on_first_use": self.start_on_first_use,
            "pending_start": self.is_pending_start(),
            "created_at": self.created_at.isoformat(timespec="seconds") + "Z",
            "expires_at": (
                self.expires_at.isoformat(timespec="seconds") + "Z" if self.expires_at else None
            ),
        }

    def protocols_list(self) -> list:
        raw = (self.protocols or "").strip()
        if raw:
            return [p for p in raw.split(",") if p]
        return [self.protocol or "vless"]

    def to_full_dict(self) -> dict:
        data = self.to_dict()
        data["secret_map"] = parse_secret_map(self.secret_data)
        return data

    def to_backup_dict(self) -> dict:
        return {
            "username": self.username,
            "protocol": self.protocol,
            "protocols": self.protocols,
            "note": self.note,
            "volume_gb": self.volume_gb,
            "used_gb": self.used_gb,
            "token": self.token,
            "secret_data": self.secret_data,
            "is_active": self.is_active,
            "start_on_first_use": self.start_on_first_use,
            "duration_days": self.duration_days,
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "expires_at": self.expires_at.isoformat(timespec="seconds"),
        }


class UserTemplate(Base):
    __tablename__ = "user_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(40), unique=True, nullable=False)
    protocols = Column(Text, nullable=False)
    volume_gb = Column(Float, nullable=False)
    days = Column(Integer, nullable=False)
    start_on_first_use = Column(Boolean, nullable=False, default=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "protocols": [p for p in (self.protocols or "").split(",") if p],
            "volume_gb": self.volume_gb,
            "days": self.days,
            "start_on_first_use": self.start_on_first_use,
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

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "protocol": self.protocol,
            "port": self.port,
            "host": self.host,
            "enabled": self.enabled,
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
            "name": self.name,
            "transport": self.transport,
            "iran_ip": self.iran_ip,
            "kharej_ip": self.kharej_ip,
            "tunnel_port": self.tunnel_port,
            "forwarded_ports": self.forwarded_ports,
            "udp_forward": self.udp_forward,
            "status": self.status,
            "last_check": (
                self.last_check.isoformat(timespec="seconds") + "Z" if self.last_check else None
            ),
            "created_at": self.created_at.isoformat(timespec="seconds") + "Z",
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
            "ts": self.ts.isoformat(timespec="seconds") + "Z",
            "event": self.event,
            "detail": self.detail[:200],
            "ip": self.ip,
            "ok": self.ok,
        }


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            f"sqlite:///{path}",
            connect_args={"check_same_thread": False},
            future=True,
        )

        from sqlalchemy import event

        @event.listens_for(self.engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    def init(self) -> None:
        Base.metadata.create_all(self.engine)
        with self.engine.begin() as conn:
            self._add_column(conn, "admins", "totp_enabled", "totp_enabled BOOLEAN NOT NULL DEFAULT 0")
            self._add_column(conn, "admins", "totp_secret", "totp_secret TEXT")
            self._add_column(conn, "admins", "totp_pending", "totp_pending TEXT")
            self._add_column(conn, "vpn_users", "protocol", "protocol VARCHAR(16) NOT NULL DEFAULT 'vless'")
            self._add_column(conn, "vpn_users", "secret_data", "secret_data TEXT NOT NULL DEFAULT ''")
            self._add_column(conn, "vpn_users", "protocols", "protocols TEXT NOT NULL DEFAULT ''")
            self._add_column(conn, "vpn_users", "start_on_first_use", "start_on_first_use BOOLEAN NOT NULL DEFAULT 0")
            self._add_column(conn, "vpn_users", "duration_days", "duration_days INTEGER")
            conn.execute(text("UPDATE vpn_users SET protocols = protocol WHERE protocols IS NULL OR protocols = ''"))

    @staticmethod
    def _add_column(conn, table: str, name: str, ddl: str) -> None:
        tables = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name=:t"),
            {"t": table},
        ).fetchall()
        if not tables:
            return
        cols = [row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))]
        if name not in cols:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {ddl}"))

    def s(self) -> Session:
        return Session(self.engine, future=True)
