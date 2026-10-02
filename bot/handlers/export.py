"""``/export`` and ``/report`` — data extraction commands."""

from __future__ import annotations

import logging
from collections import defaultdict

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce
from core.exporters import build_scan_rows, render
from core.reporter import REPORT_WINDOW_DAYS, build_summary
from database.repository import ChangeRepository, ScanRepository

log = logging.getLogger(__name__)

SUPPORTED_FORMATS = ("json", "csv")


def _registry(context):
    return context.application.bot_data["target_registry"]


def _database(context):
    return context.application.bot_data["database"]


def _safe_filename(name: str) -> str:
    """Strip anything that could confuse a filesystem or a file header."""
    return "".join(c for c in name if c.isalnum() or c in "-_.")[:64] or "export"


async def export(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text(
            "Usage: /export <target> [format]\n"
            f"Formats: {', '.join(SUPPORTED_FORMATS)} (default json)"
        )
        return

    reference = context.args[0]
    fmt = (context.args[1] if len(context.args) > 1 else "json").lower()

    if fmt not in SUPPORTED_FORMATS:
        await update.message.reply_text(
            f"❌ Unsupported format '{fmt}'.\n"
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
        return

    target = _registry(context).get(reference)
    if target is None:
        await update.message.reply_text(
            f"❌ No target named '{reference}'.\n"
            "Register it first: /addtarget <name> <value>"
        )
        return

    max_scans = context.application.bot_data["settings"].export_max_scans
    database = _database(context)

    try:
        with database.session() as session:
            from database.repository import TargetRepository

            row = TargetRepository(session).get_by_name(target.name)
            if row is None:  # pragma: no cover - race
                await update.message.reply_text(f"❌ Target '{reference}' vanished.")
                return
            target_id = row.id

            scans = ScanRepository(session).recent(target_id, limit=max_scans)
            changes = ChangeRepository(session).for_scans([s.id for s in scans])

        if not scans:
            await update.message.reply_text(
                f"❌ No scans recorded for '{target.name}' yet.\n"
                f"Run /scan {target.name} first."
            )
            return

        by_scan = defaultdict(list)
        for change in changes:
            scan_id = getattr(change, "scan_id", None)
            if scan_id is not None:
                by_scan[scan_id].append(change)

        rows = build_scan_rows(scans, by_scan)
        content, suffix, mime = render(rows, fmt)
    except Exception as exc:  # noqa: BLE001 — always answer
        log.exception("/export failed for %s", reference)
        await update.message.reply_text(
            f"⚠️ Export failed: {type(exc).__name__}. "
            "The operator should check the bot logs."
        )
        return

    filename = f"netsentinel_{_safe_filename(target.name)}.{suffix}"

    # Telegram caps documents at 50 MB; guard before spending the upload.
    payload = content.encode("utf-8")
    if len(payload) > 45 * 1024 * 1024:
        await update.message.reply_text(
            f"❌ Export too large ({len(payload) // 1024} KB). "
            f"Try a smaller EXPORT_MAX_SCANS (currently {max_scans})."
        )
        return

    await update.message.reply_document(
        document=payload,
        filename=filename,
        caption=(
            f"📦 Export of '{target.name}' — {len(rows)} scan(s), "
            f"format {suffix.upper()}"
        ),
    )


async def report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text(
            f"Usage: /report <target>\n"
            f"Shows the last {REPORT_WINDOW_DAYS} days."
        )
        return

    reference = context.args[0]
    target = _registry(context).get(reference)
    if target is None:
        await update.message.reply_text(f"❌ No target named '{reference}'.")
        return

    database = _database(context)
    try:
        with database.session() as session:
            from database.repository import TargetRepository

            row = TargetRepository(session).get_by_name(target.name)
            if row is None:  # pragma: no cover - race
                await update.message.reply_text(f"❌ Target '{reference}' vanished.")
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
            f"⚠️ Report failed: {type(exc).__name__}. "
            "The operator should check the bot logs."
        )
        return

    await update.message.reply_text(summary.text())