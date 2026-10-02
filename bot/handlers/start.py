"""`/start` and `/help` — greet an authenticated user.

``/start`` also records the caller's chat as the operator chat, which is
where scheduled alerts are delivered: a scheduled run has no originating
conversation, so the destination has to be remembered from somewhere.
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce
from core.profiles import PROFILES

log = logging.getLogger(__name__)

COMMANDS = [
    "/addtarget <name> <value> [group]",
    "/targets",
    "/deltarget <name>",
    "/purge <name> confirm",
    "/scan <target|name> [profile]",
    "/scans <name>",
    "/status",
    "/health",
    "/cleanup",
    "/export <target> [json|csv]",
    "/report <target>",
    "/schedule list|add|remove|pause|resume|pause-all|resume-all",
]


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    # Remember where scheduled alerts should go.
    try:
        from database.repository import OperatorChatRepository

        database = context.application.bot_data["database"]
        chat = update.effective_chat
        with database.session() as session:
            OperatorChatRepository(session).remember(
                chat_id=chat.id,
                user_id=principal.user_id,
                username=principal.username,
            )
    except Exception:
        # Never let bookkeeping stop the greeting.
        log.warning("Could not record operator chat", exc_info=True)

    await update.message.reply_text(
        "سلام! من NetSentinel هستم — دستیار پایش امنیت شبکه.\n"
        "Know what changed, and what deserves your attention.\n\n"
        "دستورات اصلی:\n"
        "/addtarget <name> <value> — ثبت هدف\n"
        "/scan <name> [profile] — اجرای اسکن\n"
        "/report <name> — گزارش ۷ روز اخیر\n"
        "/schedule add <name> <profile> <hours> — اسکن زمان‌بندی‌شده\n"
        "/help — همه دستورات"
    )


async def help_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    lines = ["همه دستورات:", *COMMANDS, "", "پروفایل‌های اسکن:"]
    for name, profile in sorted(PROFILES.items()):
        lines.append(f"• {name} — {profile.description}")
    lines += ["", f"نقش شما: {principal.role}"]
    await update.message.reply_text("\n".join(lines))