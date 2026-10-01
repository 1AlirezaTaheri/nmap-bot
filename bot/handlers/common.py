"""Shared helpers for Telegram command handlers."""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from security.authentication import Authenticator, Principal
from security.authorization import Authorizer


def authenticator(context: ContextTypes.DEFAULT_TYPE) -> Authenticator:
    return context.application.bot_data["authenticator"]


def authorizer(context: ContextTypes.DEFAULT_TYPE) -> Authorizer:
    return context.application.bot_data["authorizer"]


async def authenticate_or_denounce(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> Principal | None:
    """Return the caller's Principal, or reply with a denial and return None.

    Every privileged handler starts with this one guard clause — a single
    choke point for authentication instead of ad-hoc checks per command.
    """
    user = update.effective_user
    if user is None:
        return None

    principal = authenticator(context).authenticate(user.id, user.username)
    if principal is None:
        await update.message.reply_text(
            "⛔ شناسایی نشدید. دسترسی فقط برای کاربران مجاز است.\n"
            "If you are the operator, add your numeric user ID to "
            "ALLOWED_USER_IDS and restart the bot."
        )
        return None
    return principal
