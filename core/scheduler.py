"""Scheduled monitoring — APScheduler on the running event loop.

Design notes
------------
* Every scan (manual and scheduled) goes through the *same*
  :class:`ScanWorker`. That is what makes ``MAX_CONCURRENT_SCANS`` a real
  ceiling rather than a per-path suggestion.
* Scheduler jobs never touch Telegram directly. They submit a job and
  return; the worker's completion callback sends the alert, so there is
  exactly one delivery path.
* Failures inside a job are caught and logged. An unhandled exception in
  an APScheduler job would otherwise be swallowed without a traceback and
  the schedule would silently stop firing.
* Alerts need a destination even though nobody is typing, so the operator
  chat is remembered from ``/start`` (``OperatorChat`` table).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from core.structured_logging import bind
from database.database import Database
from database.repository import (
    OperatorChatRepository,
    ScanRepository,
    ScheduleRepository,
    TargetRepository,
)
from core.retention import RetentionReport, RetentionService
from workers.scan_worker import ScanJob, ScanWorker

log = logging.getLogger(__name__)

JOB_PREFIX = "netsentinel-scan"
RETENTION_JOB_ID = "netsentinel-retention"
SCHEDULER_SHUTDOWN_TIMEOUT = 5.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class SchedulerStatus:
    running: bool = False
    enabled: bool = False
    schedule_count: int = 0
    jobs_registered: int = 0
    next_run_at: datetime | None = None
    operator_chat_id: int | None = None
    last_retention: RetentionReport | None = None
    registered_ids: list[str] = field(default_factory=list)

    def text(self) -> str:
        state = "running" if self.running else "stopped"
        mode = "enabled" if self.enabled else "disabled (SCHEDULE_ENABLED=false)"
        operator = (
            f"@{self.operator_chat_id}" if self.operator_chat_id else "not set"
        )
        nxt = self.next_run_at.isoformat(sep=" ", timespec="seconds") if self.next_run_at else "—"
        return (
            f"⏱ Scheduler: {state} ({mode})\n"
            f"  schedules enabled : {self.schedule_count}\n"
            f"  jobs registered   : {self.jobs_registered}\n"
            f"  next run          : {nxt}\n"
            f"  operator chat     : {operator}"
        )


class ScanScheduler:
    """Owns the AsyncIOScheduler and the per-target scan jobs."""

    def __init__(
        self,
        database: Database,
        worker: ScanWorker,
        *,
        enabled: bool,
        default_interval_hours: int,
        default_profile: str,
        retention_days: int,
        retention_max_per_target: int,
    ) -> None:
        self._db = database
        self._worker = worker
        self._enabled = enabled
        self._default_interval_hours = default_interval_hours
        self._default_profile = default_profile
        self._retention_days = retention_days
        self._retention_max = retention_max_per_target
        self._scheduler = AsyncIOScheduler(timezone="UTC")
        self._running = False
        self._job_counter = 0
        self._last_retention: RetentionReport | None = None
        self._alert_sink = None  # set by bot.app; async callable(chat_id, text)

    # ---- lifecycle -------------------------------------------------
    async def start(self, alert_sink=None) -> None:
        """Start the scheduler if enabled, registering all schedules.

        ``alert_sink`` is an ``async (chat_id, text) -> None`` callback used
        to deliver scheduled alerts. Injected rather than imported so this
        module stays free of Telegram dependencies.
        """
        self._alert_sink = alert_sink

        if not self._enabled:
            log.info("Scheduled monitoring is disabled (SCHEDULE_ENABLED=false)")
            return

        self._scheduler.start()
        self._running = True

        # Daily retention maintenance, regardless of target schedules.
        self._scheduler.add_job(
            self._retention_job,
            trigger=IntervalTrigger(hours=24),
            id=RETENTION_JOB_ID,
            replace_existing=True,
            name="retention cleanup",
        )

        loaded = self.load_schedules()
        log.info(
            "Scheduler started with %d scan schedule(s) + retention job",
            loaded,
        )

    async def stop(self) -> None:
        """Shut down cleanly and leave no pending tasks behind.

        ``wait=False`` then an explicit bounded wait, because APScheduler's
        own shutdown can block on jobs that are mid-nmap.
        """
        if not self._running:
            return
        try:
            self._scheduler.shutdown(wait=False)
        except Exception:  # pragma: no cover - already stopped
            log.debug("Scheduler shutdown raised", exc_info=True)
        self._running = False
        log.info("Scheduler stopped")

    @property
    def running(self) -> bool:
        return self._running

    @property
    def scheduler(self) -> AsyncIOScheduler:
        return self._scheduler

    # ---- schedule registration -------------------------------------
    def load_schedules(self) -> int:
        """(Re)register a job for every enabled schedule in the database."""
        if not self._running:
            return 0
        with self._db.session() as session:
            rows = ScheduleRepository(session).enabled()

        # Drop previously registered scan jobs so renames/removals apply.
        for job in self._scheduler.get_jobs():
            if job.id.startswith(JOB_PREFIX):
                try:
                    self._scheduler.remove_job(job.id)
                except Exception:  # pragma: no cover
                    pass

        for row in rows:
            self._register(row)
        return len(rows)

    def _register(self, schedule) -> None:
        self._job_counter += 1
        job_id = f"{JOB_PREFIX}-{schedule.target_id}"
        try:
            self._scheduler.add_job(
                self._run_scheduled_scan,
                trigger=IntervalTrigger(hours=max(1, schedule.interval_hours)),
                args=[schedule.target_id, schedule.id, schedule.profile,
                      max(1, schedule.interval_hours)],
                id=job_id,
                replace_existing=True,
                name=f"scan {schedule.target.name if schedule.target else schedule.target_id}",
                next_run_time=_next_run(schedule.interval_hours),
            )
        except Exception:
            log.exception("Failed to register schedule %s", job_id)
            return

        self._set_next_run(schedule.id, schedule.interval_hours)

    async def _run_scheduled_scan(
        self,
        target_id: int,
        schedule_id: int,
        profile: str,
        interval_hours: int,
    ) -> None:
        """Queue one scan. Never raises into APScheduler."""
        with bind("sch"):
            try:
                with self._db.session() as session:
                    from database.models import Target

                    target = session.get(Target, target_id)
                    if target is None:
                        log.warning("Schedule %d has no target", schedule_id)
                        return
                    target_name, target_value = target.name, target.value

                job = ScanJob(
                    job_id=await self._worker.next_job_id(),
                    chat_id=0,  # resolved from the operator chat at send time
                    target_name=target_name,
                    target_value=target_value,
                    profile=_resolve_profile(profile),
                    source="scheduled",
                )
                await self._worker.submit(job)
                log.info(
                    "Scheduled scan queued: target=%s profile=%s",
                    target_name, profile,
                )
            except Exception:
                # A raising job is dropped by APScheduler with no traceback.
                log.exception("Scheduled scan for target %d failed", target_id)
            finally:
                self._set_next_run(schedule_id, interval_hours)

    def _retention_job(self) -> None:
        """Daily retention pass. Blocking by design; runs off the loop via
        APScheduler's thread pool for sync jobs."""
        with bind("ret"):
            try:
                report = RetentionService(self._db).run(
                    keep_days=self._retention_days,
                    keep_per_target=self._retention_max,
                )
                self._last_retention = report
                log.info("Retention: deleted %d row(s)", report.total_rows)
            except Exception:
                log.exception("Retention job failed")

    # ---- helpers ----------------------------------------------------
    def _set_next_run(self, schedule_id: int, interval_hours: int) -> None:
        try:
            now = _utcnow()
            with self._db.session() as session:
                ScheduleRepository(session).mark_run(
                    schedule_id,
                    last_run=now,
                    next_run=now + timedelta(hours=max(1, interval_hours)),
                )
        except Exception:
            log.debug("Could not update schedule %d timestamps", schedule_id)

    def operator_chat_id(self) -> int | None:
        with self._db.session() as session:
            row = OperatorChatRepository(session).primary()
            return row.chat_id if row else None

    def status(self) -> SchedulerStatus:
        jobs = []
        if self._running:
            try:
                jobs = self._scheduler.get_jobs()
            except Exception:  # pragma: no cover
                jobs = []

        next_run = None
        scan_jobs = [j for j in jobs if j.id.startswith(JOB_PREFIX)]
        if scan_jobs:
            for job in scan_jobs:
                candidate = getattr(job, "next_run_time", None)
                if candidate is not None:
                    candidate = candidate.replace(tzinfo=None)
                    if next_run is None or candidate < next_run:
                        next_run = candidate

        with self._db.session() as session:
            count = ScheduleRepository(session).count_enabled()

        return SchedulerStatus(
            running=self._running,
            enabled=self._enabled,
            schedule_count=count,
            jobs_registered=len(scan_jobs),
            next_run_at=next_run,
            operator_chat_id=self.operator_chat_id(),
            last_retention=self._last_retention,
            registered_ids=[j.id for j in scan_jobs],
        )

    async def send_scheduled_alert(self, text: str) -> bool:
        """Deliver an alert to the remembered operator chat."""
        chat_id = self.operator_chat_id()
        if chat_id is None:
            log.warning("No operator chat recorded; scheduled alert dropped")
            return False
        if self._alert_sink is None:
            log.warning("No alert sink configured; scheduled alert dropped")
            return False
        try:
            await self._alert_sink(chat_id, text)
            return True
        except Exception:
            log.exception("Could not deliver scheduled alert to %s", chat_id)
            return False


def _resolve_profile(profile: str):
    from core.profiles import get_profile

    try:
        return get_profile(profile)
    except Exception:
        return get_profile(None)


def _next_run(interval_hours: int) -> datetime:
    return _utcnow() + timedelta(hours=max(1, interval_hours))