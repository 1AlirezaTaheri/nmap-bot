"""Shared helpers for Telegram command handlers.

Adds two things the MVP did not have: per-user language resolution and
audit logging, so every command records what it did.
"""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from admin.services import audit as audit_service
from core.i18n import DEFAULT_LANG, normalize_lang, t
from security.authentication import Authenticator, Principal
from security.authorization import Authorizer


def authenticator(context: ContextTypes.DEFAULT_TYPE) -> Authenticator:
    return context.application.bot_data["authenticator"]


def authorizer(context: ContextTypes.DEFAULT_TYPE) -> Authorizer:
    return context.application.bot_data["authorizer"]


def settings_store(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data.get("settings_store")


def database(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data["database"]


def language_of(context: ContextTypes.DEFAULT_TYPE, user_id: int | None) -> str:
    """Resolve a user's language: per-user row, then global setting, then fa.

    The per-user preference wins so one operator can read Persian while the
    default is English.
    """
    if user_id is not None:
        try:
            from admin.services.users import get_telegram_user

            with database(context).session() as session:
                row = get_telegram_user(session, user_id)
            if row is not None and row.enabled:
                return normalize_lang(row.language)
        except Exception:
            # Never fail a message over a preference lookup.
            pass

    store = settings_store(context)
    if store is not None:
        return normalize_lang(store.get("bot_language"))
    return DEFAULT_LANG


def lang_of_update(update: Update, context: ContextTypes.DEFAULT_TYPE) -> str:
    user = update.effective_user
    return language_of(context, user.id if user else None)


def audit(context: ContextTypes.DEFAULT_TYPE, action: str, **kwargs) -> None:
    """Write an audit row for a bot-side action.

    Never raises: losing an audit line must not break the command.
    """
    db = context.application.bot_data.get("database")
    if db is None:
        return
    entry = audit_service.AuditEntry(
        action=action,
        actor_type=audit_service.ACTOR_TELEGRAM,
        **kwargs,
    )
    audit_service.record_standalone(db, entry)


async def authenticate_or_denounce(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> Principal | None:
    """Return the caller's Principal, or reply with a denial and return None.

    Every privileged handler starts with this one guard clause — a single
    choke point for authentication instead of ad-hoc checks per command.

    A user disabled in the panel is refused here, so ``enabled=False``
    takes effect immediately without touching ``ALLOWED_USER_IDS``.
    """
    user = update.effective_user
    lang = lang_of_update(update, context)

    if user is None:
        return None

    try:
        from admin.services.users import get_telegram_user

        with database(context).session() as session:
            row = get_telegram_user(session, user.id)
        if row is not None and not row.enabled:
            await update.message.reply_text(t("auth.disabled", lang))
            return None
    except Exception:
        # Preference lookup failure must not grant or deny access; the
        # allow-list below is the real gate.
        pass

    principal = authenticator(context).authenticate(user.id, user.username)
    if principal is None:
        await update.message.reply_text(t("auth.denied", lang))
        return None

    # Track the user so the panel can show them before they run /start.
    try:
        from admin.services.users import upsert_telegram_user

        with database(context).session() as session:
            upsert_telegram_user(session, user.id, username=user.username)
    except Exception:
        pass

    return principal