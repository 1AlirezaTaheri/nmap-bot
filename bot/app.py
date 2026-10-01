"""Composition root for the Telegram application.

Wires configuration, database, security, target registry, scan pipeline
and the background worker in exactly one place. Handlers reach shared
objects through ``bot_data`` rather than importing globals, which keeps
the wiring swappable and testable.
"""

from __future__ import annotations

import logging

from telegram.ext import ApplicationBuilder, CommandHandler

from bot.handlers import scan as scan_handlers
from bot.handlers import status as status_handlers
from bot.handlers import start as start_handlers
from bot.handlers import target as target_handlers
from bot.messages import reports
from config.settings import Settings
from core.scan_manager import ScanManager
from core.target_manager import TargetRegistry
from database.database import Database
from parser.nmap_runner import NmapRunner
from security.authentication import Authenticator
from security.authorization import Authorizer
from workers.scan_worker import ScanJob, ScanWorker

log = logging.getLogger(__name__)


async def _on_scan_complete(app, job: ScanJob, outcome, error: str | None) -> None:
    """Send the finished report — and any change alerts — to the chat."""
    try:
        if error:
            await app.bot.send_message(
                chat_id=job.chat_id, text=f"❌ Scan failed: {error}"
            )
            return
        if outcome is None:  # pragma: no cover - defensive
            return

        await app.bot.send_message(
            chat_id=job.chat_id, text=reports.scan_completed(outcome)
        )
        change_text = reports.change_report(outcome)
        if change_text:
            await app.bot.send_message(chat_id=job.chat_id, text=change_text)
    except Exception:  # pragma: no cover - network failure
        log.exception("Failed to deliver scan result to chat %s", job.chat_id)


async def _post_init(app) -> None:
    worker: ScanWorker = app.bot_data["scan_worker"]

    async def handler(job, outcome, error):
        await _on_scan_complete(app, job, outcome, error)

    await worker.start(handler)
    log.info("Background scan worker started")


async def _post_shutdown(app) -> None:
    await app.bot_data["scan_worker"].stop()


def build_application(settings: Settings):
    """Construct and configure the ``Application``."""
    database = Database(settings.database_url)
    database.create_all()

    authenticator = Authenticator(settings)
    authorizer = Authorizer(settings.allowed_cidrs)
    registry = TargetRegistry(database, authorizer)
    runner = NmapRunner(settings.nmap_binary, settings.scan_timeout_seconds)
    scan_manager = ScanManager(database, runner)
    worker = ScanWorker(
        scan_manager=scan_manager,
        max_concurrency=settings.max_concurrent_scans,
    )

    app = (
        ApplicationBuilder()
        .token(settings.telegram_bot_token)
        .post_init(_post_init)
        .post_shutdown(_post_shutdown)
        .build()
    )

    app.bot_data["settings"] = settings
    app.bot_data["database"] = database
    app.bot_data["authenticator"] = authenticator
    app.bot_data["authorizer"] = authorizer
    app.bot_data["target_registry"] = registry
    app.bot_data["scan_manager"] = scan_manager
    app.bot_data["scan_worker"] = worker

    app.add_handler(CommandHandler("start", start_handlers.start))
    app.add_handler(CommandHandler("help", start_handlers.help_command))
    app.add_handler(CommandHandler("scan", scan_handlers.scan))
    app.add_handler(CommandHandler("addtarget", target_handlers.addtarget))
    app.add_handler(CommandHandler("targets", target_handlers.listtargets))
    app.add_handler(CommandHandler("deltarget", target_handlers.deltarget))
    app.add_handler(CommandHandler("scans", status_handlers.history))
    app.add_handler(CommandHandler("status", status_handlers.status))

    return app