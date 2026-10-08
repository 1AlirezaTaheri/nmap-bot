"""Dashboard statistics and target overview queries."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from database.models import (
    AuditLog,
    ChangeEvent,
    OperatorChat,
    Scan,
    Target,
    TelegramUser,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class DashboardStats:
    targets: int = 0
    scans: int = 0
    scans_24h: int = 0
    scans_24h_failed: int = 0
    changes: int = 0
    changes_24h: int = 0
    telegram_users: int = 0
    admins: int = 0
    hosts: int = 0
    services: int = 0
    last_scan_at: datetime | None = None
    series: list = field(default_factory=list)


def dashboard(session: Session, days: int = 7) -> DashboardStats:
    """Aggregate the numbers behind the dashboard."""
    stats = DashboardStats()

    stats.targets = int(session.scalar(select(func.count()).select_from(Target)) or 0)
    stats.scans = int(session.scalar(select(func.count()).select_from(Scan)) or 0)
    stats.changes = int(
        session.scalar(select(func.count()).select_from(ChangeEvent)) or 0
    )
    stats.telegram_users = int(
        session.scalar(select(func.count()).select_from(TelegramUser)) or 0
    )
    from database.models import AdminUser

    stats.admins = int(
        session.scalar(select(func.count()).select_from(AdminUser)) or 0
    )

    cutoff_24h = _utcnow() - timedelta(hours=24)
    stats.scans_24h = int(
        session.scalar(
            select(func.count())
            .select_from(Scan)
            .where(Scan.started_at >= cutoff_24h)
        )
        or 0
    )
    stats.scans_24h_failed = int(
        session.scalar(
            select(func.count())
            .select_from(Scan)
            .where(Scan.started_at >= cutoff_24h, Scan.status == "failed")
        )
        or 0
    )
    stats.changes_24h = int(
        session.scalar(
            select(func.count())
            .select_from(ChangeEvent)
            .where(ChangeEvent.created_at >= cutoff_24h)
        )
        or 0
    )

    from database.models import Host, Service

    stats.hosts = int(session.scalar(select(func.count()).select_from(Host)) or 0)
    stats.services = int(
        session.scalar(select(func.count()).select_from(Service)) or 0
    )

    latest = session.scalar(select(Scan).order_by(desc(Scan.finished_at)).limit(1))
    stats.last_scan_at = getattr(latest, "finished_at", None)

    stats.series = daily_series(session, days=days)
    return stats


def daily_series(session: Session, days: int = 7) -> list[dict]:
    """Scans and changes per day for the last ``days`` days.

    Bucketed in Python rather than SQL so the same code produces the same
    shape on SQLite and PostgreSQL (``date_trunc`` is Postgres-only).
    """
    cutoff = _utcnow() - timedelta(days=days - 1)
    cutoff = cutoff.replace(hour=0, minute=0, second=0, microsecond=0)

    scan_rows = session.execute(
        select(Scan.started_at, Scan.status).where(Scan.started_at >= cutoff)
    ).all()
    change_rows = session.execute(
        select(ChangeEvent.created_at).where(ChangeEvent.created_at >= cutoff)
    ).all()

    buckets: dict[str, dict] = {}
    day = cutoff
    today = _utcnow().date()
    for _ in range(days):
        key = day.date().isoformat()
        buckets[key] = {"date": key, "scans": 0, "failed": 0, "changes": 0}
        day += timedelta(days=1)

    for started_at, status in scan_rows:
        if started_at is None:
            continue
        key = started_at.date().isoformat()
        if key in buckets:
            buckets[key]["scans"] += 1
            if status == "failed":
                buckets[key]["failed"] += 1

    for (created_at,) in change_rows:
        if created_at is None:
            continue
        key = created_at.date().isoformat()
        if key in buckets:
            buckets[key]["changes"] += 1

    # Guard against a bucket whose date is in the future (clock skew).
    return [v for k, v in sorted(buckets.items()) if k <= today.isoformat()]


def targets_with_counts(session: Session) -> list[dict]:
    """Every target with its scan totals and most recent scan time."""
    # cast() keeps the conditional sum portable: PostgreSQL rejects
    # sum(boolean) while SQLite tolerates it.
    from sqlalchemy import Integer, cast

    scan_stats: dict[int, tuple] = {}
    for target_id, total, succeeded, last in session.execute(
        select(
            Scan.target_id,
            func.count(Scan.id),
            func.sum(cast(Scan.status == "succeeded", Integer)),
            func.max(Scan.started_at),
        ).group_by(Scan.target_id)
    ).all():
        scan_stats[target_id] = (total, succeeded, last)

    from database.repository import ScheduleRepository

    schedules = {
        s.target_id: s for s in ScheduleRepository(session).all()
    }

    rows = []
    for target in session.scalars(select(Target).order_by(Target.name)):
        total, succeeded, last = scan_stats.get(
            target.id, (0, 0, None)
        )
        schedule = schedules.get(target.id)
        rows.append(
            {
                "id": target.id,
                "name": target.name,
                "value": target.value,
                "group": target.group_name,
                "enabled": target.enabled,
                "created_at": target.created_at,
                "scan_count": int(total or 0),
                "succeeded_count": int(succeeded or 0),
                "failed_count": int(total or 0) - int(succeeded or 0),
                "last_scan_at": last,
                "schedule": (
                    {
                        "id": schedule.id,
                        "profile": schedule.profile,
                        "interval_hours": schedule.interval_hours,
                        "enabled": schedule.enabled,
                        "next_run_at": schedule.next_run_at,
                    }
                    if schedule is not None
                    else None
                ),
            }
        )
    return rows


def target_scans(session: Session, target_id: int, limit: int = 25) -> list[dict]:
    from database.repository import ScanRepository

    scans = ScanRepository(session).recent(target_id, limit=limit)
    return [
        {
            "id": s.id,
            "profile": s.profile,
            "status": s.status,
            "source": s.source,
            "started_at": s.started_at,
            "finished_at": s.finished_at,
            "duration_ms": s.duration_ms,
            "host_count": s.host_count,
            "service_count": s.service_count,
            "error": s.error,
        }
        for s in scans
    ]


def target_changes(session: Session, target_id: int, limit: int = 100) -> list[dict]:
    rows = session.execute(
        select(ChangeEvent)
        .join(Scan, ChangeEvent.scan_id == Scan.id)
        .where(Scan.target_id == target_id)
        .order_by(desc(ChangeEvent.id))
        .limit(limit)
    ).scalars()
    return [
        {
            "id": c.id,
            "scan_id": c.scan_id,
            "previous_scan_id": c.previous_scan_id,
            "change_type": c.change_type,
            "host": c.host,
            "port": c.port,
            "protocol": c.protocol,
            "old_value": c.old_value,
            "new_value": c.new_value,
            "created_at": c.created_at,
        }
        for c in rows
    ]


def change_breakdown(session: Session, days: int = 7) -> dict[str, int]:
    """Change events grouped by type over a window."""
    cutoff = _utcnow() - timedelta(days=days)
    rows = session.execute(
        select(ChangeEvent.change_type, func.count())
        .where(ChangeEvent.created_at >= cutoff)
        .group_by(ChangeEvent.change_type)
    ).all()
    return {str(k): int(v) for k, v in rows}


def recent_audit(session: Session, limit: int = 10) -> list[dict]:
    rows = session.scalars(
        select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
    )
    return [
        {
            "id": r.id,
            "created_at": r.created_at,
            "actor_type": r.actor_type,
            "actor_username": r.actor_username,
            "action": r.action,
            "success": r.success,
        }
        for r in rows
    ]


def operator_chat(session: Session) -> dict | None:
    row = session.scalars(select(OperatorChat).order_by(OperatorChat.id).limit(1)).first()
    if row is None:
        return None
    return {
        "chat_id": row.chat_id,
        "user_id": row.user_id,
        "username": row.username,
        "last_seen_at": row.last_seen_at,
    }


def top_changed_targets(session: Session, days: int = 7,
                        limit: int = 5) -> list[dict]:
    """Targets with the most change events in a window, worst first.

    ``ChangeEvent`` has no ``target_id``; it reaches a target through its scan.
    The join is on the scan's own target, which is already indexed via
    ``Scan.target_id``, so this stays cheap enough to run on a 15s refresh.

    Returns an empty list when nothing changed in the window, which is a normal
    state rather than an error.
    """
    cutoff = _utcnow() - timedelta(days=days)
    rows = session.execute(
        select(
            Target.id,
            Target.name,
            Target.value,
            func.count(ChangeEvent.id).label("changes"),
            func.max(ChangeEvent.created_at).label("last_change_at"),
        )
        .join(Scan, Scan.target_id == Target.id)
        .join(ChangeEvent, ChangeEvent.scan_id == Scan.id)
        .where(ChangeEvent.created_at >= cutoff)
        .group_by(Target.id, Target.name, Target.value)
        .order_by(func.count(ChangeEvent.id).desc(), Target.name)
        .limit(limit)
    ).all()
    return [
        {
            "id": int(target_id),
            "name": name,
            "value": value,
            "changes": int(changes),
            "last_change_at": last_change_at,
        }
        for target_id, name, value, changes, last_change_at in rows
    ]


def schedule_status(store: Any) -> dict:
    """The scheduler switch and its interval.

    Takes the ``SettingsStore`` rather than opening one: the store is already
    constructed and loaded on the app context, and there is no module-level
    singleton to reach for. Building a second one here would mean a second
    database read on every 15s refresh.

    Deliberately does not synthesise a ``next_run``. There is no stored value
    for one, and deriving it from the interval would be a guess about the
    scheduler's actual cadence -- a number on a dashboard that looks precise
    and is not. It reports what is genuinely known and flags the gap so the UI
    can say so rather than implying certainty.
    """
    # SettingsStore.get() already falls back to the compiled default from
    # SETTING_SPECS, so no default argument is passed here. Passing one is a
    # TypeError: get() takes a single positional key.
    enabled = bool(store.get("schedule_enabled"))
    interval = store.get("schedule_interval_hours")
    return {
        "enabled": enabled,
        "interval_hours": (
            int(interval) if isinstance(interval, (int, float)) else None
        ),
        "next_run_at": None,
        "next_run_known": False,
    }


def worker_status(worker: object | None) -> dict:
    """Live view of the admin process's own scan worker.

    Reads the counters the ScanWorker already keeps. The worker is absent when
    the admin process did not start one, which is the normal case: scans are
    queued by the *bot* process, which runs its own worker instance. So this
    reports the admin's view and says whether it has one, rather than
    presenting a zero as if it meant "idle".

    Synchronous by design. The underlying counters are guarded by an asyncio
    lock, but reading an int under the GIL cannot tear, and this handler is
    sync, so awaiting is not available. The lock protects multi-step
    invariants, not single reads.
    """
    if worker is None:
        return {
            "available": False,
            "running": False,
            "queue_depth": None,
            "active": None,
            "pending": None,
            "max_concurrency": None,
        }

    queue = getattr(worker, "_queue", None)
    jobs = getattr(worker, "_jobs", {})
    statuses = list(jobs.values()) if isinstance(jobs, dict) else []

    def count(state: str) -> int:
        return sum(1 for j in statuses if getattr(j, "state", None) == state)

    return {
        "available": True,
        "running": bool(getattr(worker, "is_running", False)),
        # qsize() is the queue's own counter, so no lock is needed for it.
        "queue_depth": queue.qsize() if queue is not None else None,
        "active": count("running"),
        "pending": count("queued") + count("running"),
        "max_concurrency": getattr(worker, "max_concurrency", None),
    }


def target_detail(session: Session, target_id: int) -> dict | None:
    """One target's identity and counts, or None if it does not exist."""
    from database.repository import TargetRepository

    row = TargetRepository(session).get(target_id)
    if row is None:
        return None

    scan_count = TargetRepository(session).scan_count(target_id)
    return {
        "id": row.id,
        "name": row.name,
        "value": row.value,
        # The column is `group_name`; the API field is `group` because that is
        # what /api/targets already returns and the two must agree.
        "group": row.group_name,
        "enabled": bool(row.enabled),
        "created_at": row.created_at,
        "scan_count": scan_count,
        "schedule": _target_schedule(session, target_id),
    }


def _target_schedule(session: Session, target_id: int) -> dict | None:
    """The target's schedule row, or None when it has none.

    Unlike the global scheduler -- which has no stored next-run time and so
    reports it as unknown -- a schedule row does persist `next_run_at`, so the
    detail page can show a real value here.
    """
    from database.repository import ScheduleRepository

    row = ScheduleRepository(session).for_target(target_id)
    if row is None:
        return None
    return {
        "id": row.id,
        "profile": row.profile,
        "enabled": bool(row.enabled),
        "interval_hours": row.interval_hours,
        "last_run_at": row.last_run_at,
        "next_run_at": row.next_run_at,
    }


def target_timeline(session: Session, target_id: int,
                    days: int = 30) -> list[dict]:
    """Daily scan and change counts for one target, oldest first.

    Bucketed in Python rather than SQL so SQLite and PostgreSQL produce the
    same shape, matching `daily_series`. Buckets with no activity are emitted
    as zeros on purpose: a gap in the data and a gap on the chart are different
    things, and a line that skips a day implies the former.
    """
    cutoff = _utcnow() - timedelta(days=days - 1)
    cutoff = cutoff.replace(hour=0, minute=0, second=0, microsecond=0)

    scan_rows = session.execute(
        select(Scan.started_at, Scan.status, Scan.id).where(
            Scan.target_id == target_id, Scan.started_at >= cutoff
        )
    ).all()

    change_rows = session.execute(
        select(ChangeEvent.created_at)
        .join(Scan, ChangeEvent.scan_id == Scan.id)
        .where(Scan.target_id == target_id, ChangeEvent.created_at >= cutoff)
    ).all()

    buckets: dict[str, dict] = {}
    day = cutoff
    today = _utcnow().date()
    for _ in range(days):
        key = day.date().isoformat()
        buckets[key] = {
            "date": key, "scans": 0, "failed": 0, "changes": 0,
        }
        day += timedelta(days=1)

    for started_at, status, _scan_id in scan_rows:
        if started_at is None:
            continue
        key = started_at.date().isoformat()
        if key in buckets:
            buckets[key]["scans"] += 1
            if status == "failed":
                buckets[key]["failed"] += 1

    for (created_at,) in change_rows:
        if created_at is None:
            continue
        key = created_at.date().isoformat()
        if key in buckets:
            buckets[key]["changes"] += 1

    return [v for k, v in sorted(buckets.items()) if k <= today.isoformat()]


def scan_hosts(session: Session, scan_id: int) -> dict | None:
    """Hosts and services for one scan, plus a port distribution.

    Returns None when the scan does not exist, so the route can 404 rather
    than return an empty result that reads as "this scan found nothing".

    The port distribution is counted from the same rows the table renders, so
    the chart and the table cannot drift apart.
    """
    from sqlalchemy import select as sa_select

    from database.models import Host as HostModel
    from database.models import Scan as ScanModel
    from database.models import Service as ServiceModel

    scan = session.get(ScanModel, scan_id)
    if scan is None:
        return None

    hosts = session.scalars(
        sa_select(HostModel)
        .where(HostModel.scan_id == scan_id)
        .order_by(HostModel.address)
    ).all()

    host_ids = [h.id for h in hosts]
    services: dict[int, list[ServiceModel]] = {}
    if host_ids:
        for svc in session.scalars(
            sa_select(ServiceModel).where(ServiceModel.host_id.in_(host_ids))
        ):
            services.setdefault(svc.host_id, []).append(svc)

    host_rows = [
        {
            "id": h.id,
            "address": h.address,
            "hostname": h.hostname,
            "state": h.state,
            "services": sorted(
                (
                    {
                        "id": s.id,
                        "port": s.port,
                        "protocol": s.protocol,
                        "state": s.state,
                        "service_name": s.service_name,
                        "product": s.product,
                        "version": s.version,
                    }
                    for s in services.get(h.id, [])
                ),
                key=lambda s: (s["port"], s["protocol"]),
            ),
        }
        for h in hosts
    ]

    # Port distribution across every service on the scan, open or not.
    counts: dict[int, int] = {}
    for rows in services.values():
        for s in rows:
            counts[s.port] = counts.get(s.port, 0) + 1

    return {
        "scan": {
            "id": scan.id,
            "profile": scan.profile,
            "status": scan.status,
            "source": scan.source,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "duration_ms": scan.duration_ms,
            "host_count": scan.host_count,
            "service_count": scan.service_count,
            "error": scan.error,
        },
        "hosts": host_rows,
        "port_distribution": [
            {"port": port, "count": count}
            for port, count in sorted(counts.items(), key=lambda kv: -kv[1])[:20]
        ],
    }
