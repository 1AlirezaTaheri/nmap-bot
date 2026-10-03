"""SQLAlchemy models — the canonical data model for NetSentinel.

Portable types only (no PostgreSQL-specific constructs) so the same models
run against SQLite in tests and PostgreSQL in production.

Both the Telegram bot and the FastAPI admin service import from here. Do
not duplicate these definitions per service; extend them in this module.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Core scanning domain (shared by bot and admin)
# ---------------------------------------------------------------------------


class Target(Base):
    """A named, reusable scan target — replaces free-form typed strings."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    value: Mapped[str] = mapped_column(String(255))
    group_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )

    scans: Mapped[list["Scan"]] = relationship(back_populates="target")
    schedules: Mapped[list["Schedule"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class Scan(Base):
    """One execution of a scan against a target."""

    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_target_profile", "target_id", "profile"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    profile: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="running")
    # Which trigger produced this scan: manual, scheduled, or retention.
    source: Mapped[str] = mapped_column(String(16), default="manual")
    # Who requested it: NULL for scheduled runs, telegram id for manual.
    # BigInteger: Telegram IDs overflow 32-bit INTEGER.
    requested_by: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    host_count: Mapped[int] = mapped_column(Integer, default=0)
    service_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")
    hosts: Mapped[list["Host"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    # ChangeEvent.scan_id AND .previous_scan_id both point at scans.id,
    # so the ORM must be told which one owns this relationship.
    changes: Mapped[list["ChangeEvent"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        foreign_keys="[ChangeEvent.scan_id]",
    )


class Host(Base):
    """A host observed in a scan, with its open ports."""

    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("scan_id", "address"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    address: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="up")

    scan: Mapped[Scan] = relationship(back_populates="hosts")
    services: Mapped[list["Service"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )


class Service(Base):
    """A port/service on a host within a scan."""

    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("host_id", "port", "protocol"),
        Index("ix_services_lookup", "port", "protocol"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(16), default="open")
    service_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)

    host: Mapped[Host] = relationship(back_populates="services")


class ChangeEvent(Base):
    """A difference between two scans of the same target+profile."""

    __tablename__ = "change_events"
    __table_args__ = (Index("ix_changes_scan", "scan_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    previous_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id"), nullable=True
    )
    change_type: Mapped[str] = mapped_column(String(32))
    host: Mapped[str] = mapped_column(String(64))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(8), nullable=True)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )

    scan: Mapped[Scan] = relationship(
        back_populates="changes", foreign_keys="[ChangeEvent.scan_id]"
    )


class Schedule(Base):
    """A recurring scan for a target (V1)."""

    __tablename__ = "schedules"
    __table_args__ = (UniqueConstraint("target_id",),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    profile: Mapped[str] = mapped_column(String(32))
    interval_hours: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )

    target: Mapped[Target] = relationship(back_populates="schedules")


class OperatorChat(Base):
    """Where scheduled alerts are delivered (V1).

    Populated by the first allowed user who runs ``/start``. Scheduled runs
    have no originating chat, so they need a remembered destination.
    """

    __tablename__ = "operator_chats"

    id: Mapped[int] = mapped_column(primary_key=True)
    # BigInteger: Telegram chat and user ids overflow 32-bit INTEGER.
    chat_id: Mapped[int] = mapped_column(
        BigInteger, unique=True, index=True
    )
    user_id: Mapped[int] = mapped_column(BigInteger)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )


# ---------------------------------------------------------------------------
# Admin panel (V2)
# ---------------------------------------------------------------------------


class AdminUser(Base):
    """A web-panel administrator.

    Deliberately *not* the same table as Telegram users: an admin has a
    password and web role, a Telegram user has a numeric ID and a chat role.
    Linking them would mean one compromise grants both surfaces.
    """

    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # bcrypt hash; never the plaintext.
    password_hash: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # superadmin | admin | viewer
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )


class AuditLog(Base):
    """Append-only record of every consequential action.

    Rows are never updated or deleted by application code. ``success`` is
    stored explicitly so failed attempts (a rejected login, a refused
    scan) are as visible as successful ones.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_created_at", "created_at"),
        Index("ix_audit_actor_id", "actor_id"),
        Index("ix_audit_action", "action"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # admin | telegram_user | system
    actor_type: Mapped[str] = mapped_column(String(24))
    # BigInteger: holds Telegram ids, which exceed 32-bit INTEGER.
    actor_id: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    actor_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # JSON-encoded string: portable across SQLite and PostgreSQL.
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), index=True
    )


class SystemSetting(Base):
    """Runtime-tunable configuration, editable from the web panel.

    Values override the environment at runtime so an operator can change a
    limit without editing ``.env`` and restarting the bot.
    """

    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class TelegramUser(Base):
    """A Telegram user known to the system, with role and preferences.

    Distinct from ``operator_chats``: that table only remembers *which chat
    receives scheduled alerts*, while this one holds the full access
    record and survives the alert destination changing.
    """

    __tablename__ = "telegram_users"

    # BigInteger: Telegram IDs overflow 32-bit INTEGER.
    telegram_user_id: Mapped[int] = mapped_column(
        BigInteger, primary_key=True
    )
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # viewer | operator | admin
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # fa | en
    language: Mapped[str] = mapped_column(String(4), default="fa")
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )


# Canonical change_type vocabulary — keep in sync with core/change_detector.
CHANGE_TYPES = (
    "new_host",
    "closed_host",
    "new_port",
    "closed_port",
    "service_change",
)

# Canonical admin/web role vocabulary — weakest to strongest.
ADMIN_ROLES = ("viewer", "admin", "superadmin")

# Canonical Telegram role vocabulary — weakest to strongest.
TELEGRAM_ROLES = ("viewer", "operator", "admin")

# Supported bot languages.
LANGUAGES = ("fa", "en")