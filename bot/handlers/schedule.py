"""Scheduled monitoring commands — all operator-only.

Shape: ``/schedule <subcommand> ...``. Every exit path replies; a silent
handler is indistinguishable from a dead bot.
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import (
    audit,
    authenticate_or_denounce,
    authorizer,
    database,
    lang_of_update,
)
from bot.messages import reports
from core.profiles import PROFILES
from database.repository import RepositoryError, ScheduleRepository
from security.authorization import AuthorizationError

log = logging.getLogger(__name__)


def _registry(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data["target_registry"]


def _scheduler(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data.get("scheduler")


async def schedule(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    try:
        authorizer(context).require_role(principal, "manage schedules")
    except AuthorizationError as exc:
        await update.message.reply_text(reports.forbidden(lang, str(exc)))
        return

    if not context.args:
        await update.message.reply_text(reports.schedule_usage(lang))
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
            reports.schedule_unknown(lang, subcommand)
        )
        return

    try:
        await handler(update, context, args, lang, principal)
    except Exception as exc:  # noqa: BLE001 — always answer
        log.exception("/schedule %s failed", subcommand)
        await update.message.reply_text(
            reports.handler_failed(lang, f"/schedule {subcommand}", type(exc).__name__)
        )


def _resolve_target(context: ContextTypes.DEFAULT_TYPE, reference: str, lang: str):
    """Return ``(target_id, name)`` or raise ValueError carrying a user message."""
    target = _registry(context).get(reference)
    if target is None:
        raise ValueError(reports.target_not_found(lang, reference))

    from database.repository import TargetRepository

    with database(context).session() as session:
        record = TargetRepository(session).get_by_name(target.name)
        if record is None:  # pragma: no cover - race
            raise ValueError(reports.target_not_found(lang, reference))
        return record.id, record.name


async def _list(update, context, args, lang, principal) -> None:
    with database(context).session() as session:
        rows = ScheduleRepository(session).all()
    scheduler = _scheduler(context)
    running = bool(scheduler is not None and scheduler.running)
    await update.message.reply_text(reports.schedules_list(lang, rows, running))


async def _add(update, context, args, lang, principal) -> None:
    if len(args) < 2:
        await update.message.reply_text(
            reports.schedule_add_usage(lang, list(PROFILES))
        )
        return

    reference, profile = args[0], args[1].lower()

    if profile not in PROFILES:
        await update.message.reply_text(
            reports.schedule_bad_profile(lang, profile, list(PROFILES))
        )
        return

    hours_raw = args[2] if len(args) > 2 else None
    if hours_raw is None:
        # Default interval comes from configuration, never a literal here.
        store = context.application.bot_data.get("settings_store")
        hours = int(
            (store.get("schedule_interval_hours") if store else None)
            or context.application.bot_data["settings"].schedule_interval_hours
        )
    else:
        try:
            hours = int(hours_raw)
        except ValueError:
            await update.message.reply_text(
                reports.schedule_bad_interval(lang, hours_raw)
            )
            return

    if hours < 1:
        await update.message.reply_text(reports.schedule_min_interval(lang))
        return

    try:
        target_id, name = _resolve_target(context, reference)
    except ValueError as exc:
        await update.message.reply_text(str(exc))
        return

    with database(context).session() as session:
        ScheduleRepository(session).upsert(target_id, profile, hours)

    scheduler = _scheduler(context)
    registered = 0
    if scheduler is not None:
        registered = scheduler.load_schedules()

    audit(
        context, "schedule.add",
        actor_id=principal.user_id, actor_username=principal.username,
        target_type="target", target_id=name,
        details={"profile": profile, "hours": hours},
    )
    await update.message.reply_text(
        reports.schedule_saved(
            lang, name, profile, hours, registered,
            enabled=bool(scheduler is not None and scheduler.running),
        )
    )


async def _remove(update, context, args, lang, principal) -> None:
    if not args:
        await update.message.reply_text("/schedule remove <target>")
        return
    try:
        target_id, name = _resolve_target(context, args[0], lang)
    except ValueError as exc:
        await update.message.reply_text(str(exc))
        return

    with database(context).session() as session:
        removed = ScheduleRepository(session).delete_for_target(target_id)

    if not removed:
        await update.message.reply_text(reports.schedule_no_schedule(lang, name))
        return

    scheduler = _scheduler(context)
    if scheduler is not None:
        scheduler.load_schedules()

    audit(
        context, "schedule.remove",
        actor_id=principal.user_id, actor_username=principal.username,
        target_type="target", target_id=name, details={},
    )
    await update.message.reply_text(reports.schedule_removed(lang, name))


async def _pause(update, context, args, lang, principal) -> None:
    await _set_enabled(update, context, args, False, lang, principal, "schedule.pause")


async def _resume(update, context, args, lang, principal) -> None:
    await _set_enabled(update, context, args, True, lang, principal, "schedule.resume")


async def _set_enabled(update, context, args, enabled, lang, principal, action) -> None:
    verb = "resume" if enabled else "pause"
    if not args:
        await update.message.reply_text(f"/schedule {verb} <target>")
        return
    try:
        target_id, name = _resolve_target(context, args[0], lang)
    except ValueError as exc:
        await update.message.reply_text(str(exc))
        return

    with database(context).session() as session:
        row = ScheduleRepository(session).set_enabled(target_id, enabled)

    if row is None:
        await update.message.reply_text(reports.schedule_no_schedule(lang, name))
        return

    scheduler = _scheduler(context)
    if scheduler is not None:
        scheduler.load_schedules()

    audit(
        context, action,
        actor_id=principal.user_id, actor_username=principal.username,
        target_type="target", target_id=name,
        details={"enabled": enabled},
    )
    if enabled:
        await update.message.reply_text(reports.schedule_resumed(lang, name))
    else:
        await update.message.reply_text(reports.schedule_paused(lang, name))


async def _pause_all(update, context, args, lang, principal) -> None:
    with database(context).session() as session:
        count = ScheduleRepository(session).set_all_enabled(False)
    scheduler = _scheduler(context)
    if scheduler is not None:
        scheduler.load_schedules()
    audit(
        context, "schedule.pause_all",
        actor_id=principal.user_id, actor_username=principal.username,
        details={"count": count},
    )
    await update.message.reply_text(reports.schedule_pause_all(lang, count))


async def _resume_all(update, context, args, lang, principal) -> None:
    with database(context).session() as session:
        count = ScheduleRepository(session).set_all_enabled(True)
    scheduler = _scheduler(context)
    if scheduler is not None:
        scheduler.load_schedules()
    audit(
        context, "schedule.resume_all",
        actor_id=principal.user_id, actor_username=principal.username,
        details={"count": count},
    )
    await update.message.reply_text(reports.schedule_resume_all(lang, count))