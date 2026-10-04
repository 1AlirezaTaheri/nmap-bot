"""`/start`, `/help`, and `/lang` — greet an authenticated user.

``/start`` also records the caller's chat as the operator chat, which is
where scheduled alerts are delivered: a scheduled run has no originating
conversation, so the destination has to be remembered from somewhere.
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import (
    authenticate_or_denounce,
    database,
    lang_of_update,
)
from bot import miniapp as miniapp_ui
from bot.messages import reports
from core.i18n import available_languages, normalize_lang, t
from core.profiles import PROFILES

log = logging.getLogger(__name__)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    settings = context.application.bot_data.get("settings")

    # Remember where scheduled alerts should go.
    try:
        from database.repository import OperatorChatRepository

        chat = update.effective_chat
        with database(context).session() as session:
            OperatorChatRepository(session).remember(
                chat_id=chat.id,
                user_id=principal.user_id,
                username=principal.username,
            )
    except Exception:
        # Never let bookkeeping stop the greeting.
        log.warning("Could not record operator chat", exc_info=True)

    await update.message.reply_text(
        reports.start_greeting(lang),
        reply_markup=miniapp_ui.inline_keyboard(settings),
    )
    await update.message.reply_text(t("start.hint", lang))


async def help_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return
    await update.message.reply_text(
        reports.help_text(lang, principal.role, PROFILES)
    )


async def set_language(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """`/lang` — show or change this user's language."""
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    supported = available_languages() or ["fa", "en"]

    if not context.args:
        names = ", ".join(
            f"{code} ({t('lang.name', code)})" for code in supported
        )
        await update.message.reply_text(
            f"🌐 {t('lang.name', lang)} / language:\n"
            f"{names}\n\n/tlang <{' | '.join(supported)}>"
        )
        return

    wanted = normalize_lang(context.args[0])
    if wanted not in supported:
        await update.message.reply_text(
            f"❌ /tlang <{' | '.join(supported)}>"
        )
        return

    try:
        from admin.services.users import update_telegram_user

        with database(context).session() as session:
            update_telegram_user(session, principal.user_id, language=wanted)
    except Exception as exc:
        # The handler must always answer; a preference write is not worth
        # silence.
        log.exception("Could not save language preference")
        await update.message.reply_text(
            reports.handler_failed(lang, "/tlang", type(exc).__name__)
        )
        return

    # Reply in the language the user just chose, to confirm it took effect.
    await update.message.reply_text(t("start.greeting", wanted))


async def open_app(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """`/app` — open the Telegram Mini App.

    Replies on every path: with a button when the Mini App is configured, and
    with an explanation when it is not. Never silent, because a user who typed
    /app and got nothing has no way to tell a bug from a missing setting.
    """
    lang = lang_of_update(update, context)
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    settings = context.application.bot_data.get("settings")
    keyboard = miniapp_ui.inline_keyboard(settings, text=t("app.button", lang))

    if keyboard is None:
        await update.message.reply_text(t("app.unavailable", lang))
        return

    await update.message.reply_text(
        t("app.title", lang),
        reply_markup=keyboard,
    )
