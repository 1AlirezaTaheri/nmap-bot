"""SQLAlchemy models — the canonical data model for NetSentinel.

Portable types only (no PostgreSQL-specific constructs) so the same models
run against SQLite in tests and PostgreSQL in production.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
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


class Scan(Base):
    """One execution of a scan against a target."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_target_profile", "target_id", "profile"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    profile: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="running")
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


# Canonical change_type vocabulary — keep in sync with core/change_detector.
CHANGE_TYPES = (
    "new_host",
    "closed_host",
    "new_port",
    "closed_port",
    "service_change",
)