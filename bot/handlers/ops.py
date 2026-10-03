"""``/health``, ``/cleanup``, ``/language`` — operational commands."""

from __future__ import annotations

import asyncio
import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import (
    audit,
    authenticate_or_denounce,
    authorizer,
    database,
    lang_of_update,
    settings_store,
)
from bot.messages import reports
from core.retention import RetentionService
from security.authorization import AuthorizationError

log = logging.getLogger(__name__)


async def health(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Report DB connectivity, scheduler, queue depth, last scan per target.

    Deliberately does not require operator role — any authenticated user
    may check that the bot is alive.
    """
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    db = database(context)
    scheduler = context.application.bot_data.get("scheduler")
    worker = context.application.bot_data.get("scan_worker")

    db_ok = True
    db_error = ""
    last_successful = []
    scheduler_text = None

    try:
        from sqlalchemy import text

        from database.repository import ScanRepository

        with db.session() as session:
            session.execute(text("SELECT 1"))
            if scheduler is not None:
                try:
                    status = scheduler.status()
                    scheduler_text = {
                        "running": status.running,
                        "schedule_count": status.schedule_count,
                    }
                except Exception:  # pragma: no cover - best effort
                    scheduler_text = {"running": False, "schedule_count": 0}

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

    queue_depth = active_jobs = pending_jobs = 0
    if worker is not None:
        try:
            queue_depth = await worker.queue_depth()
            active_jobs = await worker.active_count()
            pending_jobs = await worker.pending_count()
        except Exception:  # pragma: no cover
            pass

    store = settings_store(context)
    bot_language = normalize(store.get("bot_language") if store else None)

    await update.message.reply_text(
        reports.health_report(
            lang,
            {
                "db_ok": db_ok,
                "db_error": db_error,
                "scheduler": scheduler_text,
                "queue_depth": queue_depth,
                "active_jobs": active_jobs,
                "pending_jobs": pending_jobs,
                "last_successful": last_successful,
            },
        )
        + f"\n\n🌐 bot language: {bot_language}"
    )


def normalize(value: str | None) -> str:
    from core.i18n import normalize_lang

    return normalize_lang(value)


async def cleanup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Run the retention pass on demand (operator only)."""
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    try:
        authorizer(context).require_role(principal, "run retention cleanup")
    except AuthorizationError as exc:
        await update.message.reply_text(reports.forbidden(lang, str(exc)))
        return

    settings = context.application.bot_data["settings"]
    store = settings_store(context)

    # Runtime-overridable values, falling back to the boot configuration.
    keep_days = int(store.get("retention_days") or settings.retention_days)
    keep_per_target = int(
        store.get("retention_max_scans_per_target")
        or settings.retention_max_scans_per_target
    )

    try:
        report = await asyncio.to_thread(
            RetentionService(database(context)).run,
            keep_days=keep_days,
            keep_per_target=keep_per_target,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("/cleanup failed")
        await update.message.reply_text(
            reports.cleanup_failed(lang, type(exc).__name__)
        )
        audit(
            context, "retention.run",
            actor_id=principal.user_id, actor_username=principal.username,
            details={"error": type(exc).__name__}, success=False,
        )
        return

    audit(
        context, "retention.run",
        actor_id=principal.user_id, actor_username=principal.username,
        details={
            "scans": report.scans_deleted,
            "hosts": report.hosts_deleted,
            "services": report.services_deleted,
            "changes": report.change_events_deleted,
        },
    )
    await update.message.reply_text(
        reports.cleanup_report(lang, report)
        + f"\n  policy       : keep {keep_days}d, max {keep_per_target}/target"
    )