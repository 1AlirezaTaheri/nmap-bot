"""Target Registry commands: ``/addtarget``, ``/targets``, ``/deltarget``."""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce, authorizer
from bot.messages import reports
from security.authorization import AuthorizationError, TargetNotAllowedError


def _registry(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data["target_registry"]


async def addtarget(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if len(context.args) < 2:
        await update.message.reply_text(
            "Usage: /addtarget <name> <value> [group]\n"
            "Example: /addtarget lab 192.168.1.0/24 core"
        )
        return

    name, value = context.args[0], context.args[1]
    group = context.args[2] if len(context.args) > 2 else None

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
    if _registry(context).delete(name):
        await update.message.reply_text(f"🗑 Target '{name}' removed.")
    else:
        await update.message.reply_text(f"❌ No target named '{name}'.")