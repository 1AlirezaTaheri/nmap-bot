"""`/start` and `/help` — greet an authenticated user."""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce
from core.profiles import PROFILES


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    await update.message.reply_text(
        "سلام! من NetSentinel هستم — دستیار پایش امنیت شبکه.\n\n"
        "دستورات:\n"
        "/addtarget <name> <value> — ثبت هدف\n"
        "/targets — فهرست هدف‌ها\n"
        "/scan <name> [profile] — اجرای اسکن\n"
        "/scans <name> — تاریخچه\n"
        "/status — وضعیت اسکن‌های در حال اجرا\n"
        "/help — راهنما"
    )


async def help_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    lines = ["دستورات:", "/addtarget <name> <value> [group]", "/targets",
             "/deltarget <name>", "/scan <target|name> [profile]",
             "/scans <name>", "/status", "", "پروفایل‌های اسکن:"]
    for name, profile in sorted(PROFILES.items()):
        lines.append(f"• {name} — {profile.description}")
    lines += ["", f"نقش شما: {principal.role}"]
    await update.message.reply_text("\n".join(lines))