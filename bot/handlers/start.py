"""`/start` — greet an authenticated user."""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    await update.message.reply_text(
        "سلام! من ربات اسکنر nmap هستم.\n"
        "برای اسکن: /scan <IP or domain>\n"
        "مثال: /scan scanme.nmap.org\n\n"
        "دستورات: /start /scan /help"
    )


async def help_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    await update.message.reply_text(
        "دستورات:\n"
        "/scan <target> — اجرای اسکن\n"
        "/help — راهنما\n\n"
        "نقش شما: " + principal.role
    )
