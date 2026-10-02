"""Scheduled monitoring commands — all operator-only.

Shape: ``/schedule <subcommand> ...``. Every exit path replies; a silent
handler is indistinguishable from a dead bot.
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce, authorizer
from bot.messages import reports
from core.profiles import UnknownProfileError, PROFILES
from database.repository import RepositoryError, ScheduleRepository
from security.authorization import AuthorizationError

log = logging.getLogger(__name__)

USAGE = (
    "⏱ Scheduled monitoring\n"
    "/schedule list — show all schedules\n"
    "/schedule add <target> <profile> <hours>\n"
    "/schedule remove <target>\n"
    "/schedule pause <target>\n"
    "/schedule resume <target>\n"
    "/schedule pause-all\n"
    "/schedule resume-all"
)


def _registry(context):
    return context.application.bot_data["target_registry"]


def _scheduler(context):
    return context.application.bot_data["scheduler"]


def _database(context):
    return context.application.bot_data["database"]


async def schedule(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    try:
        authorizer(context).require_role(principal, "manage schedules")
    except AuthorizationError as exc:
        await update.message.reply_text(f"⛔ {exc}")
        return

    if not context.args:
        await update.message.reply_text(USAGE)
        return

    subcommand = context.args[0].lower()
    args = context.args[1:]

    handlers = {
        "list": _list,
        "add": _add,
        "remove": _remove,
        "pause": _pause,
        "resume": _resume,
        "pause-all": _pause_all,
        "resume-all": _resume_all,
    }
    handler = handlers.get(subcommand)
    if handler is None:
        await update.message.reply_text(
            f"❌ Unknown subcommand '{subcommand}'.\n\n{USAGE}"
        )
        return

    try:
        await handler(update, context, args)
    except Exception as exc:  # noqa: BLE001 — always answer
        log.exception("/schedule %s failed", subcommand)
        await update.message.reply_text(
            f"⚠️ /schedule {subcommand} failed: {type(exc).__name__}. "
            "The operator should check the bot logs."
        )


def _resolve_target(context, reference: str):
    """Return (TargetRow, name) or raise ValueError with a user message."""
    target = _registry(context).get(reference)
    if target is None:
        raise ValueError(f"No target named '{reference}'. Add it with /addtarget.")
    database = _database(context)
    with database.session() as session:
        row = ScheduleRepository(session)  # touch to ensure session works
        from database.repository import TargetRepository

        record = TargetRepository(session).get_by_name(target.name)
        if record is None:  # pragma: no cover - race
            raise ValueError(f"Target '{reference}' vanished.")
        return record.id, record.name


async def _list(update: Update, context, args) -> None:
    database = _database(context)
    with database.session() as session:
        rows = ScheduleRepository(session).all()
    scheduler = _scheduler(context)
    header = reports.schedules_list(rows)
    if scheduler is not None and not scheduler.running:
        header += "\n\n(Scheduler is not running — SCHEDULE_ENABLED=false)"
    await update.message.reply_text(header)


async def _add(update: Update, context, args) -> None:
    if len(args) < 2:
        await update.message.reply_text(
            "Usage: /schedule add <target> <profile> <hours>\n"
            f"Profiles: {', '.join(sorted(PROFILES))}\n"
            "Example: /schedule add home service 6"
        )
        return

    reference = args[0]
    profile = args[1].lower()

    try:
        PROFILES[profile]
    except KeyError:
        await update.message.reply_text(
            f"❌ Unknown profile '{profile}'.\n"
            f"Available: {', '.join(sorted(PROFILES))}"
        )
        return

    hours_raw = args[2] if len(args) > 2 else None
    if hours_raw is None:
        # Default interval comes from configuration, never a literal here.
        hours = context.application.bot_data["settings"].schedule_interval_hours
    else:
        try:
            hours = int(hours_raw)
        except ValueError:
            await update.message.reply_text(
                f"❌ Interval must be a whole number of hours, got '{hours_raw}'."
            )
            return

    if hours < 1:
        await update.message.reply_text("❌ Interval must be at least 1 hour.")
        return

    try:
        target_id, name = _resolve_target(context, reference)
    except ValueError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return

    database = _database(context)
    with database.session() as session:
        ScheduleRepository(session).upsert(target_id, profile, hours)

    scheduler = _scheduler(context)
    registered = 0
    if scheduler is not None:
        registered = scheduler.load_schedules()

    suffix = (
        ""
        if scheduler is not None and scheduler.running
        else "\n\n⚠️ Scheduler is disabled (SCHEDULE_ENABLED=false); "
        "the schedule is saved but will not fire."
    )
    await update.message.reply_text(
        f"✅ Schedule saved: {name} [{profile}] every {hours}h "
        f"({registered} active job(s)).{suffix}"
    )


async def _remove(update: Update, context, args) -> None:
    if not args:
        await update.message.reply_text("Usage: /schedule remove <target>")
        return

    try:
        target_id, name = _resolve_target(context, args[0])
    except ValueError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return

    database = _database(context)
    with database.session() as session:
        removed = ScheduleRepository(session).delete_for_target(target_id)

    if not removed:
        await update.message.reply_text(
            f"❌ No schedule for '{name}'. Use /schedule add to create one."
        )
        return

    scheduler = _scheduler(context)
    if scheduler is not None:
        scheduler.load_schedules()
    await update.message.reply_text(f"🗑 Schedule removed for '{name}'.")


async def _pause(update: Update, context, args) -> None:
    await _set_enabled(update, context, args, False)


async def _resume(update: Update, context, args) -> None:
    await _set_enabled(update, context, args, True)


async def _set_enabled(update: Update, context, args, enabled: bool) -> None:
    action = "resume" if enabled else "pause"
    if not args:
        await update.message.reply_text(f"Usage: /schedule {action} <target>")
        return

    try:
        target_id, name = _resolve_target(context, args[0])
    except ValueError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return

    database = _database(context)
    with database.session() as session:
        row = ScheduleRepository(session).set_enabled(target_id, enabled)

    if row is None:
        await update.message.reply_text(
            f"❌ No schedule for '{name}'. Use /schedule add to create one."
        )
        return

    scheduler = _scheduler(context)
    if scheduler is not None:
        scheduler.load_schedules()
    verb = "resumed" if enabled else "paused"
    await update.message.reply_text(f"{'▶️' if enabled else '⏸'} Schedule {verb} for '{name}'.")


async def _pause_all(update: Update, context, args) -> None:
    database = _database(context)
    with database.session() as session:
        count = ScheduleRepository(session).set_all_enabled(False)
    scheduler = _scheduler(context)
    if scheduler is not None:
        scheduler.load_schedules()
    await update.message.reply_text(
        f"⏸ Paused {count} schedule(s)."
        if count
        else "No schedules to pause."
    )


async def _resume_all(update: Update, context, args) -> None:
    database = _database(context)
    with database.session() as session:
        count = ScheduleRepository(session).set_all_enabled(True)
    scheduler = _scheduler(context)
    if scheduler is not None:
        scheduler.load_schedules()
    await update.message.reply_text(
        f"▶️ Resumed {count} schedule(s)."
        if count
        else "No schedules to resume."
    )