"""Audit logging.

Every consequential action — admin or bot — writes a row. The helper is
deliberately forgiving: an audit failure must never abort the operation it
was describing, so exceptions are logged and swallowed. Losing an audit
line is bad; losing the user's action is worse.

Rows are append-only. Nothing in the application updates or deletes them.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from database.models import AuditLog

log = logging.getLogger(__name__)

# Canonical action names. Keeping them in one place stops the admin panel
# and the bot from inventing near-duplicates that make filtering useless.
ACTIONS = (
    "auth.login",
    "auth.login_failed",
    "auth.logout",
    "user.add",
    "user.update",
    "user.delete",
    "settings.update",
    "target.add",
    "target.delete",
    "target.purge",
    "scan.requested",
    "scan.completed",
    "scan.failed",
    "schedule.add",
    "schedule.remove",
    "schedule.pause",
    "schedule.resume",
    "schedule.pause_all",
    "schedule.resume_all",
    "retention.run",
    "export.run",
    "report.run",
    "rule.create",
    "rule.update",
    "rule.delete",
    "rule.reorder",
    "rule.import",
    "rule.denied",
    "rule.hit_cap",
    "miniapp.auth",
    "miniapp.auth_failed",
    "miniapp.scan_requested",
    "miniapp.target_add",
    "miniapp.settings_update",
)

ACTOR_ADMIN = "admin"
ACTOR_TELEGRAM = "telegram_user"
ACTOR_SYSTEM = "system"


@dataclass
class AuditEntry:
    action: str
    actor_type: str = ACTOR_SYSTEM
    actor_id: int | None = None
    actor_username: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    ip_address: str | None = None
    user_agent: str | None = None
    success: bool = True


def record(session: Session, entry: AuditEntry) -> AuditLog | None:
    """Append one audit row.

    Returns the row on success, ``None`` if persistence failed. Never
    raises — see the module docstring.
    """
    try:
        payload = None
        if entry.details:
            payload = json.dumps(entry.details, default=str, ensure_ascii=False)
        row = AuditLog(
            actor_type=entry.actor_type,
            actor_id=entry.actor_id,
            actor_username=(entry.actor_username or None),
            action=entry.action,
            target_type=entry.target_type,
            target_id=(str(entry.target_id) if entry.target_id is not None else None),
            details=payload,
            ip_address=entry.ip_address,
            user_agent=(entry.user_agent or None),
            success=bool(entry.success),
        )
        session.add(row)
        session.flush()
        return row
    except Exception:
        log.warning("Could not write audit entry %s", entry.action, exc_info=True)
        return None


def record_standalone(database, entry: AuditEntry) -> None:
    """Append one audit row using its own session.

    Used by the bot, which has no ambient transaction to join.
    """
    try:
        with database.session() as session:
            record(session, entry)
    except Exception:
        log.warning("Could not write audit entry %s", entry.action, exc_info=True)


@dataclass
class AuditQuery:
    actor_id: int | None = None
    actor_type: str | None = None
    action: str | None = None
    success: bool | None = None
    since: datetime | None = None
    until: datetime | None = None
    page: int = 1
    page_size: int = 50


def query(session: Session, q: AuditQuery) -> tuple[list[AuditLog], int]:
    """Return one page of audit rows plus the total match count."""
    stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)

    if q.actor_id is not None:
        stmt = stmt.where(AuditLog.actor_id == q.actor_id)
        count_stmt = count_stmt.where(AuditLog.actor_id == q.actor_id)
    if q.actor_type:
        stmt = stmt.where(AuditLog.actor_type == q.actor_type)
        count_stmt = count_stmt.where(AuditLog.actor_type == q.actor_type)
    if q.action:
        stmt = stmt.where(AuditLog.action == q.action)
        count_stmt = count_stmt.where(AuditLog.action == q.action)
    if q.success is not None:
        stmt = stmt.where(AuditLog.success.is_(q.success))
        count_stmt = count_stmt.where(AuditLog.success.is_(q.success))
    if q.since is not None:
        stmt = stmt.where(AuditLog.created_at >= q.since)
        count_stmt = count_stmt.where(AuditLog.created_at >= q.since)
    if q.until is not None:
        stmt = stmt.where(AuditLog.created_at <= q.until)
        count_stmt = count_stmt.where(AuditLog.created_at <= q.until)

    total = int(session.scalar(count_stmt) or 0)
    page = max(1, q.page)
    size = max(1, min(200, q.page_size))
    rows = list(
        session.scalars(
            stmt.order_by(desc(AuditLog.created_at), desc(AuditLog.id))
            .offset((page - 1) * size)
            .limit(size)
        )
    )
    return rows, total


def to_csv(rows: list[AuditLog]) -> str:
    """Serialize audit rows to CSV, including parsed details."""
    import csv
    import io

    header = [
        "id",
        "created_at",
        "actor_type",
        "actor_id",
        "actor_username",
        "action",
        "target_type",
        "target_id",
        "success",
        "ip_address",
        "details",
    ]
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(header)

    for row in rows:
        details = row.details or ""
        # Keep the cell readable while preserving the full payload.
        details = details.replace("\n", " ")
        writer.writerow(
            [
                row.id,
                row.created_at.isoformat() if row.created_at else "",
                row.actor_type,
                row.actor_id if row.actor_id is not None else "",
                row.actor_username or "",
                row.action,
                row.target_type or "",
                row.target_id or "",
                "true" if row.success else "false",
                row.ip_address or "",
                details,
            ]
        )
    return out.getvalue()


def prune(session: Session, older_than: datetime) -> int:
    """Delete audit rows older than a cutoff. Returns the row count.

    Not exposed in the UI — audit history is meant to be kept. Provided for
    an operator to call deliberately.
    """
    result = session.execute(
        AuditLog.__table__.delete().where(AuditLog.created_at < older_than)
    )
    return int(result.rowcount or 0)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)