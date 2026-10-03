"""Target Registry commands: /addtarget, /targets, /deltarget, /purge."""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import (
    audit,
    authenticate_or_denounce,
    authorizer,
    lang_of_update,
)
from bot.messages import reports
from database.repository import RepositoryError
from security.authorization import AuthorizationError, TargetNotAllowedError

log = logging.getLogger(__name__)

CONFIRM_WORD = "confirm"
MAX_NAME_LENGTH = 64
MAX_VALUE_LENGTH = 255
# Names become filenames and CLI-ish identifiers; keep them boring.
_NAME_ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789-_."
)


def _registry(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data["target_registry"]


def validate_name(name: str) -> str | None:
    """Return an error message, or None when the name is acceptable."""
    if not name:
        return "target.name_required"
    if len(name) > MAX_NAME_LENGTH:
        return "target.name_too_long"
    if set(name) - _NAME_ALLOWED:
        return "target.name_bad_chars"
    if name.startswith(".") or name.endswith("."):
        return "target.name_dot_edge"
    return None


async def addtarget(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if len(context.args) < 2:
        await update.message.reply_text(reports.target_usage_add(lang))
        return

    name, value = context.args[0], context.args[1]
    group = context.args[2] if len(context.args) > 2 else None

    problem = validate_name(name)
    if problem:
        await update.message.reply_text(_render_name_error(problem, lang, name))
        return

    if len(value) > MAX_VALUE_LENGTH:
        await update.message.reply_text(
            reports.target_invalid(
                lang, f"target value too long ({len(value)} > {MAX_VALUE_LENGTH})"
            )
        )
        return

    try:
        authorizer(context).require_role(principal, "add a target")
        target = _registry(context).add(name, value, group)
    except AuthorizationError as exc:
        await update.message.reply_text(reports.forbidden(lang, str(exc)))
        return
    except TargetNotAllowedError as exc:
        await update.message.reply_text(reports.target_rejected(lang, str(exc)))
        return
    except ValueError as exc:
        await update.message.reply_text(reports.target_invalid(lang, str(exc)))
        return
    except Exception as exc:  # duplicate name, DB error
        await update.message.reply_text(reports.target_invalid(lang, str(exc)))
        audit(
            context, "target.add",
            actor_id=principal.user_id, actor_username=principal.username,
            target_type="target", target_id=name,
            details={"error": str(exc)}, success=False,
        )
        return

    audit(
        context, "target.add",
        actor_id=principal.user_id, actor_username=principal.username,
        target_type="target", target_id=target.name,
        details={"value": target.value, "group": group},
    )
    await update.message.reply_text(reports.target_added(lang, target.name, target.value))


def _render_name_error(problem: str, lang: str, name: str) -> str:
    from core.i18n import t

    if problem == "target.name_required":
        return t("target.name_required", lang)
    if problem == "target.name_too_long":
        return t("target.name_too_long", lang, length=len(name), max=MAX_NAME_LENGTH)
    if problem == "target.name_dot_edge":
        return t("target.name_dot_edge", lang)
    bad = "".join(sorted(set(name) - _NAME_ALLOWED))
    return t("target.name_bad_chars", lang, chars=bad)


async def listtargets(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return
    await update.message.reply_text(
        reports.targets_list(lang, _registry(context).list())
    )


async def deltarget(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Delete a target. Refuses when scan history exists.

    Every exit path replies: a silent handler is indistinguishable from an
    unresponsive bot, and this one previously swallowed IntegrityErrors.
    """
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text(reports.target_usage_del(lang))
        return

    try:
        authorizer(context).require_role(principal, "delete a target")
    except AuthorizationError as exc:
        await update.message.reply_text(reports.forbidden(lang, str(exc)))
        return

    name = context.args[0]
    try:
        removed = _registry(context).delete(name)
    except RepositoryError as exc:
        await update.message.reply_text(reports.target_delete_blocked(lang, str(exc)))
        audit(
            context, "target.delete",
            actor_id=principal.user_id, actor_username=principal.username,
            target_type="target", target_id=name,
            details={"error": str(exc)}, success=False,
        )
        return
    except Exception as exc:  # noqa: BLE001 — always answer the user
        log.exception("deltarget failed for %s", name)
        await update.message.reply_text(reports.delete_failed(lang, name, type(exc).__name__))
        audit(
            context, "target.delete",
            actor_id=principal.user_id, actor_username=principal.username,
            target_type="target", target_id=name,
            details={"error": type(exc).__name__}, success=False,
        )
        return

    if removed:
        audit(
            context, "target.delete",
            actor_id=principal.user_id, actor_username=principal.username,
            target_type="target", target_id=name, details={},
        )
        await update.message.reply_text(reports.target_deleted(lang, name))
    else:
        await update.message.reply_text(reports.target_not_found(lang, name))


async def purge(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Delete a target AND its entire scan history. Requires confirmation.

    Two-step so scan history — the security record — cannot be destroyed by
    a mistyped command.
    """
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text(reports.purge_usage(lang))
        return

    try:
        authorizer(context).require_role(principal, "purge a target and its history")
    except AuthorizationError as exc:
        await update.message.reply_text(reports.forbidden(lang, str(exc)))
        return

    name = context.args[0]
    registry = _registry(context)

    confirmed = len(context.args) > 1 and context.args[1].lower() == CONFIRM_WORD
    if not confirmed:
        target = registry.get(name)
        if target is None:
            await update.message.reply_text(reports.target_not_found(lang, name))
            return
        try:
            pending = registry.history_count(name)
        except Exception:
            pending = {"scans": 0, "hosts": 0, "services": 0,
                       "change_events": 0, "schedules": 0}
        await update.message.reply_text(
            reports.purge_confirm_prompt(lang, target.name, target.value, pending)
        )
        return

    try:
        counts = registry.purge(name)
    except RepositoryError as exc:
        await update.message.reply_text(reports.target_not_found(lang, str(exc)))
        return
    except Exception as exc:  # noqa: BLE001
        log.exception("purge failed for %s", name)
        await update.message.reply_text(reports.purge_failed(lang, name, type(exc).__name__))
        audit(
            context, "target.purge",
            actor_id=principal.user_id, actor_username=principal.username,
            target_type="target", target_id=name,
            details={"error": type(exc).__name__}, success=False,
        )
        return

    audit(
        context, "target.purge",
        actor_id=principal.user_id, actor_username=principal.username,
        target_type="target", target_id=name, details=counts,
    )
    await update.message.reply_text(reports.purge_done(lang, name, counts))