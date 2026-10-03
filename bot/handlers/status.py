"""``/scans`` and ``/status`` — history and job state."""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import (
    authenticate_or_denounce,
    database,
    lang_of_update,
)
from bot.messages import reports


async def history(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    reference = context.args[0] if context.args else None
    if reference is None:
        await update.message.reply_text(reports.history_usage(lang))
        return

    registry = context.application.bot_data["target_registry"]
    target = registry.resolve(reference)
    if target is None:
        await update.message.reply_text(reports.history_unknown_target(lang, reference))
        return

    from database.repository import ScanRepository, TargetRepository

    with database(context).session() as session:
        row = TargetRepository(session).get_by_name(target.name)
        rows = ScanRepository(session).recent(row.id, limit=10) if row else []

    await update.message.reply_text(reports.scan_history(lang, rows))


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    worker = context.application.bot_data["scan_worker"]
    jobs = await worker.statuses()
    await update.message.reply_text(reports.status_report(lang, jobs))