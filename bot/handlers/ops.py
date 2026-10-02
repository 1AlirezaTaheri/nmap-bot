"""``/health`` and ``/cleanup`` — operational commands."""

from __future__ import annotations

import asyncio
import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce, authorizer
from bot.messages import reports
from core.retention import RetentionService
from security.authorization import AuthorizationError

log = logging.getLogger(__name__)


async def health(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Report DB connectivity, scheduler, queue depth, last scan per target.

    Deliberately does not require operator role — any authenticated user
    may check that the bot is alive.
    """
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    database = context.application.bot_data["database"]
    scheduler = context.application.bot_data.get("scheduler")
    worker = context.application.bot_data.get("scan_worker")

    db_ok = True
    db_error = ""
    last_successful = []
    scheduler_text = None

    try:
        from sqlalchemy import text

        with database.session() as session:
            session.execute(text("SELECT 1"))
            if scheduler is not None:
                try:
                    status = scheduler.status()
                    scheduler_text = {
                        "running": status.running,
                        "schedule_count": status.schedule_count,
                    }
                except Exception:  # pragma: no cover - status is best-effort
                    scheduler_text = {"running": False, "schedule_count": 0}

            from database.repository import ScanRepository

            for scan in ScanRepository(session).last_successful_per_target():
                finished = getattr(scan, "finished_at", None)
                target = getattr(scan, "target", None)
                last_successful.append(
                    {
                        "target": getattr(target, "name", "?")
                        if target is not None
                        else "?",
                        "finished_at": (
                            finished.strftime("%Y-%m-%d %H:%M")
                            if finished is not None
                            else None
                        ),
                    }
                )
    except Exception as exc:  # noqa: BLE001 — health must never raise
        db_ok = False
        db_error = f"{type(exc).__name__}: {exc}"
        log.warning("Health check: database unreachable: %s", db_error)

    queue_depth = 0
    active_jobs = 0
    pending_jobs = 0
    if worker is not None:
        try:
            queue_depth = await worker.queue_depth()
            active_jobs = await worker.active_count()
            pending_jobs = await worker.pending_count()
        except Exception:  # pragma: no cover
            pass

    await update.message.reply_text(
        reports.health_report(
            {
                "db_ok": db_ok,
                "db_error": db_error,
                "scheduler": scheduler_text,
                "queue_depth": queue_depth,
                "active_jobs": active_jobs,
                "pending_jobs": pending_jobs,
                "last_successful": last_successful,
            }
        )
    )


async def cleanup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Run the retention pass on demand (operator only)."""
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    try:
        authorizer(context).require_role(principal, "run retention cleanup")
    except AuthorizationError as exc:
        await update.message.reply_text(f"⛔ {exc}")
        return

    settings = context.application.bot_data["settings"]
    database = context.application.bot_data["database"]

    try:
        report = await asyncio.to_thread(
            RetentionService(database).run,
            keep_days=settings.retention_days,
            keep_per_target=settings.retention_max_scans_per_target,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("/cleanup failed")
        await update.message.reply_text(
            f"⚠️ Cleanup failed: {type(exc).__name__}. "
            "Nothing was deleted — the operator should check the bot logs."
        )
        return

    await update.message.reply_text(
        report.text()
        + f"\n  policy       : keep {settings.retention_days}d, "
        f"max {settings.retention_max_scans_per_target}/target"
    )