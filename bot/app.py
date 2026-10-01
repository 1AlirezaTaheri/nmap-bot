"""Composition root for the Telegram application.

Wires configuration, security and handlers together in one place — the
only module that knows how the pieces connect. Handlers retrieve shared
objects from ``bot_data`` rather than importing a global singleton.
"""

from __future__ import annotations

from telegram.ext import ApplicationBuilder, CommandHandler

from bot.handlers import scan as scan_handlers
from bot.handlers import start as start_handlers
from config.settings import Settings
from security.authentication import Authenticator
from security.authorization import Authorizer


def build_application(settings: Settings):
    """Construct and configure the ``Application``."""
    app = (
        ApplicationBuilder()
        .token(settings.telegram_bot_token)
        .build()
    )

    app.bot_data["settings"] = settings
    app.bot_data["authenticator"] = Authenticator(settings)
    app.bot_data["authorizer"] = Authorizer(settings.allowed_cidrs)

    app.add_handler(CommandHandler("start", start_handlers.start))
    app.add_handler(CommandHandler("help", start_handlers.help_command))
    app.add_handler(CommandHandler("scan", scan_handlers.scan))

    return app
