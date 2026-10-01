"""Scan history and job status commands: ``/scans``, ``/status``."""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce
from bot.messages import reports


async def history(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    registry = context.application.bot_data["target_registry"]
    reference = context.args[0] if context.args else None

    if reference is None:
        await update.message.reply_text(
            "Usage: /scans <target>  — show history for a target"
        )
        return

    target = registry.resolve(reference)
    if target is None:
        await update.message.reply_text(f"❌ Unknown target '{reference}'.")
        return

    database = context.application.bot_data["database"]
    with database.session() as session:
        from database.repository import ScanRepository, TargetRepository

        repo = TargetRepository(session)
        row = repo.get_by_name(target.name)
        rows = ScanRepository(session).recent(row.id, limit=10) if row else []

    await update.message.reply_text(reports.scan_history(rows))


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    worker = context.application.bot_data["scan_worker"]
    jobs = await worker.statuses()
    await update.message.reply_text(reports.status_report(jobs))