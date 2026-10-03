"""``/export`` and ``/report`` — data extraction commands."""

from __future__ import annotations

import logging
from collections import defaultdict

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import (
    audit,
    authenticate_or_denounce,
    database,
    lang_of_update,
)
from bot.messages import reports
from core.exporters import build_scan_rows, render
from core.reporter import REPORT_WINDOW_DAYS, build_summary
from database.repository import ChangeRepository, ScanRepository

log = logging.getLogger(__name__)

SUPPORTED_FORMATS = ("json", "csv")
MAX_EXPORT_BYTES = 45 * 1024 * 1024


async def export(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text(
            reports.export_usage(lang, SUPPORTED_FORMATS)
        )
        return

    reference = context.args[0]
    fmt = (context.args[1] if len(context.args) > 1 else "json").lower()

    if fmt not in SUPPORTED_FORMATS:
        await update.message.reply_text(
            reports.export_bad_format(lang, fmt, SUPPORTED_FORMATS)
        )
        return

    registry = context.application.bot_data["target_registry"]
    target = registry.get(reference)
    if target is None:
        await update.message.reply_text(reports.export_unknown_target(lang, reference))
        return

    settings = context.application.bot_data["settings"]
    store = context.application.bot_data.get("settings_store")
    max_scans = int(
        (store.get("export_max_scans") if store else None)
        or settings.export_max_scans
    )
    db = database(context)

    try:
        from database.repository import TargetRepository

        with db.session() as session:
            row = TargetRepository(session).get_by_name(target.name)
            if row is None:  # pragma: no cover - race
                await update.message.reply_text(
                    reports.target_not_found(lang, reference)
                )
                return
            target_id = row.id

            scans = ScanRepository(session).recent(target_id, limit=max_scans)
            changes = ChangeRepository(session).for_scans([s.id for s in scans])

        if not scans:
            await update.message.reply_text(reports.export_no_scans(lang, target.name))
            return

        by_scan = defaultdict(list)
        for change in changes:
            scan_id = getattr(change, "scan_id", None)
            if scan_id is not None:
                by_scan[scan_id].append(change)

        rows = build_scan_rows(scans, by_scan)
        content, suffix, _mime = render(rows, fmt)
    except Exception as exc:  # noqa: BLE001 — always answer
        log.exception("/export failed for %s", reference)
        await update.message.reply_text(
            reports.handler_failed(lang, "/export", type(exc).__name__)
        )
        audit(
            context, "export.run",
            actor_id=principal.user_id, actor_username=principal.username,
            target_type="target", target_id=target.name,
            details={"error": type(exc).__name__}, success=False,
        )
        return

    audit(
        context, "export.run",
        actor_id=principal.user_id, actor_username=principal.username,
        target_type="target", target_id=target.name,
        details={"format": suffix, "scans": len(rows)},
    )

    filename = f"netsentinel_{_safe_filename(target.name)}.{suffix}"
    payload = content.encode("utf-8")

    # Telegram caps documents at 50 MB; guard before spending the upload.
    if len(payload) > MAX_EXPORT_BYTES:
        await update.message.reply_text(
            reports.export_too_large(
                lang, len(payload) // 1024, max_scans
            )
        )
        return

    await update.message.reply_document(
        document=payload,
        filename=filename,
        caption=reports.export_caption(lang, target.name, len(rows), suffix),
    )


async def report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text(reports.report_usage(lang, REPORT_WINDOW_DAYS))
        return

    reference = context.args[0]
    registry = context.application.bot_data["target_registry"]
    target = registry.get(reference)
    if target is None:
        await update.message.reply_text(reports.report_unknown_target(lang, reference))
        return

    db = database(context)
    try:
        from database.repository import TargetRepository

        with db.session() as session:
            row = TargetRepository(session).get_by_name(target.name)
            if row is None:  # pragma: no cover - race
                await update.message.reply_text(
                    reports.target_not_found(lang, reference)
                )
                return
            target_id = row.id

            scans = ScanRepository(session).in_window(
                target_id, days=REPORT_WINDOW_DAYS
            )
            changes = ChangeRepository(session).for_target_window(
                target_id, days=REPORT_WINDOW_DAYS
            )

        summary = build_summary(target.name, target.value, scans, changes)
    except Exception as exc:  # noqa: BLE001
        log.exception("/report failed for %s", reference)
        await update.message.reply_text(
            reports.handler_failed(lang, "/report", type(exc).__name__)
        )
        return

    audit(
        context, "report.run",
        actor_id=principal.user_id, actor_username=principal.username,
        target_type="target", target_id=target.name, details={},
    )
    await update.message.reply_text(reports.report_text(lang, summary))


def _safe_filename(name: str) -> str:
    """Strip anything that could confuse a filesystem or a file header."""
    return "".join(c for c in name if c.isalnum() or c in "-_.")[:64] or "export"