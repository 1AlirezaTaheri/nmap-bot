"""Mini App affordances for the Telegram bot.

All of it lives here so ``/start``, ``/app`` and the menu button cannot drift
apart on what "configured" means.

Telegram only loads a Mini App over HTTPS, so :func:`is_configured` rejects a
plain-HTTP URL rather than publishing a button that opens a blank WebView.
"""

from __future__ import annotations

import logging

from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    MenuButtonWebApp,
    WebAppInfo,
)

from core.miniapp_auth import is_miniapp_enabled, mini_app_url

log = logging.getLogger(__name__)


def is_configured(settings) -> bool:
    """Whether Mini App affordances should be shown at all."""
    return is_miniapp_enabled(getattr(settings, "miniapp_url", ""))


def app_url(settings, start_param: str | None = None) -> str:
    """The Mini App URL, or "" when not configured."""
    if not is_configured(settings):
        return ""
    return mini_app_url(settings.miniapp_url, start_param)


def web_app_info(settings) -> WebAppInfo | None:
    url = app_url(settings)
    return WebAppInfo(url=url) if url else None


def menu_button(settings, text: str = "Open app") -> MenuButtonWebApp | None:
    info = web_app_info(settings)
    return MenuButtonWebApp(text=text, web_app=info) if info else None


def inline_keyboard(
    settings, text: str = "📱 Open the dashboard"
) -> InlineKeyboardMarkup | None:
    """A one-button keyboard for /start and /app, or None when disabled."""
    info = web_app_info(settings)
    if info is None:
        return None
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton(text=text, web_app=info)]]
    )


async def set_menu_button(bot, settings) -> bool:
    """Point the chat menu button at the Mini App, or clear it.

    Returns True when the button is live. Never raises: a failure here must
    not stop the bot from starting, and Telegram tolerates a missing menu
    button perfectly well.
    """
    try:
        button = menu_button(settings)
        await bot.set_chat_menu_button(menu_button=button)
        if button is not None:
            log.info("Mini App menu button set: %s", button.web_app.url)
        else:
            log.info("Mini App not configured; menu button cleared")
        return button is not None
    except Exception:
        log.warning("Could not set the Mini App menu button", exc_info=True)
        return False


async def publish_commands(bot, settings) -> None:
    """Register /app in the Telegram command list, when configured.

    Replaces the whole list rather than appending, because the command set is
    defined in bot/app.py and a partial update would leave /app listed after
    it was disabled.
    """
    try:
        from telegram import BotCommand

        from bot.handlers import start as start_handlers
        from core.profiles import profile_names

        commands = [
            BotCommand("start", "Open the dashboard / شروع"),
            BotCommand("help", "What this bot can do"),
        ]
        if is_configured(settings):
            commands.append(BotCommand("app", "Open the dashboard"))
        commands.extend(
            [
                BotCommand("scan", "Scan a target"),
                BotCommand("addtarget", "Register a target"),
                BotCommand("targets", "List targets"),
                BotCommand("status", "Current activity"),
                BotCommand("tlang", "Change language"),
            ]
        )
        await bot.set_my_commands(commands)
        del profile_names, start_handlers
    except Exception:
        log.warning("Could not publish the command list", exc_info=True)
