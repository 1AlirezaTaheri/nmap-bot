"""Target Registry commands: /addtarget, /targets, /deltarget, /purge."""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce, authorizer
from bot.messages import reports
from database.repository import RepositoryError
from security.authorization import AuthorizationError, TargetNotAllowedError

log = logging.getLogger(__name__)

CONFIRM_WORD = "confirm"
MAX_NAME_LENGTH = 64
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
        return "Target name is required."
    if len(name) > MAX_NAME_LENGTH:
        return (
            f"Target name too long ({len(name)} > {MAX_NAME_LENGTH} characters)."
        )
    bad = sorted(set(name) - _NAME_ALLOWED)
    if bad:
        return (
            f"Target name contains unsupported characters: {''.join(bad)}. "
            "Use letters, digits, dash, underscore or dot."
        )
    if name.startswith(".") or name.endswith("."):
        return "Target name may not start or end with a dot."
    return None


async def addtarget(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if len(context.args) < 2:
        await update.message.reply_text(
            "Usage: /addtarget <name> <value> [group]\n"
            "Example: /addtarget home 192.168.174.0/24 core"
        )
        return

    name, value = context.args[0], context.args[1]
    group = context.args[2] if len(context.args) > 2 else None

    problem = validate_name(name)
    if problem:
        await update.message.reply_text(f"❌ {problem}")
        return

    if len(value) > 255:
        await update.message.reply_text(
            f"❌ Target value too long ({len(value)} > 255 characters)."
        )
        return

    try:
        authorizer(context).require_role(principal, "add a target")
        target = _registry(context).add(name, value, group)
    except AuthorizationError as exc:
        await update.message.reply_text(f"⛔ {exc}")
        return
    except TargetNotAllowedError as exc:
        await update.message.reply_text(f"⛔ Target rejected: {exc}")
        return
    except ValueError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return
    except Exception as exc:  # duplicate name, DB error
        await update.message.reply_text(f"❌ {exc}")
        return

    await update.message.reply_text(
        f"✅ Target '{target.name}' added successfully.\n"
        f"Value: {target.value}"
    )


async def listtargets(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return
    await update.message.reply_text(
        reports.targets_list(_registry(context).list())
    )


async def deltarget(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Delete a target. Refuses when scan history exists.

    Every exit path replies: a silent handler is indistinguishable from an
    unresponsive bot, and this one previously swallowed IntegrityErrors.
    """
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text("Usage: /deltarget <name>")
        return

    try:
        authorizer(context).require_role(principal, "delete a target")
    except AuthorizationError as exc:
        await update.message.reply_text(f"⛔ {exc}")
        return

    name = context.args[0]
    try:
        removed = _registry(context).delete(name)
    except RepositoryError as exc:
        await update.message.reply_text(f"⛔ {exc}")
        return
    except Exception as exc:  # noqa: BLE001 — always answer the user
        log.exception("deltarget failed for %s", name)
        await update.message.reply_text(
            f"⚠️ Could not delete '{name}': {type(exc).__name__}. "
            "The operator should check the bot logs."
        )
        return

    if removed:
        await update.message.reply_text(f"🗑 Target '{name}' removed.")
    else:
        await update.message.reply_text(f"❌ No target named '{name}'.")


async def purge(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Delete a target AND its entire scan history. Requires confirmation.

    Two-step so scan history — the security record — cannot be destroyed by
    a mistyped command.
    """
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text(
            "Usage: /purge <name> confirm\n"
            "⚠️ This deletes the target and ALL of its scan history."
        )
        return

    try:
        authorizer(context).require_role(principal, "purge a target and its history")
    except AuthorizationError as exc:
        await update.message.reply_text(f"⛔ {exc}")
        return

    name = context.args[0]
    registry = _registry(context)

    confirmed = len(context.args) > 1 and context.args[1].lower() == CONFIRM_WORD
    if not confirmed:
        target = registry.get(name)
        if target is None:
            await update.message.reply_text(f"❌ No target named '{name}'.")
            return
        pending = registry.history_count(name)
        await update.message.reply_text(
            f"⚠️ This will permanently delete target '{target.name}' "
            f"({target.value}) and its history:\n"
            f"  • {pending['scans']} scan(s)\n"
            f"  • {pending['hosts']} host(s)\n"
            f"  • {pending['services']} service(s)\n"
            f"  • {pending['change_events']} change event(s)\n"
            f"  • {pending['schedules']} schedule(s)\n\n"
            f"To proceed: /purge {target.name} {CONFIRM_WORD}"
        )
        return

    try:
        counts = registry.purge(name)
    except RepositoryError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return
    except Exception as exc:  # noqa: BLE001
        log.exception("purge failed for %s", name)
        await update.message.reply_text(
            f"⚠️ Purge failed for '{name}': {type(exc).__name__}. "
            "Nothing was deleted — the operator should check the bot logs."
        )
        return

    await update.message.reply_text(
        f"🗑 Purged '{name}':\n"
        f"  • {counts['scans']} scan(s)\n"
        f"  • {counts['hosts']} host(s)\n"
        f"  • {counts['services']} service(s)\n"
        f"  • {counts['change_events']} change event(s)\n"
        f"  • {counts['schedules']} schedule(s)\n"
        f"  • 1 target"
    )