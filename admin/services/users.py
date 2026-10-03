"""Repository-style access to admin users and Telegram users.

SQL lives here so the route handlers stay thin and testable.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from database.models import (
    ADMIN_ROLES,
    LANGUAGES,
    TELEGRAM_ROLES,
    AdminUser,
    Scan,
    TelegramUser,
)


class UserError(ValueError):
    """User-management failure; message is user-facing."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Admin users
# ---------------------------------------------------------------------------


def admin_count(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(AdminUser)) or 0)


def get_admin(session: Session, admin_id: int) -> AdminUser | None:
    return session.get(AdminUser, admin_id)


def get_admin_by_username(session: Session, username: str) -> AdminUser | None:
    return session.scalar(
        select(AdminUser).where(AdminUser.username == username)
    )


def list_admins(session: Session) -> list[AdminUser]:
    return list(session.scalars(select(AdminUser).order_by(AdminUser.username)))


def create_admin(
    session: Session,
    username: str,
    password_hash: str,
    *,
    email: str | None = None,
    role: str = "viewer",
) -> AdminUser:
    username = (username or "").strip()
    if not username:
        raise UserError("Username is required.")
    if len(username) > 64:
        raise UserError("Username is too long (max 64 characters).")
    if role not in ADMIN_ROLES:
        raise UserError(f"Role must be one of {', '.join(ADMIN_ROLES)}.")
    if get_admin_by_username(session, username) is not None:
        raise UserError(f"Username '{username}' is already taken.")

    row = AdminUser(
        username=username,
        password_hash=password_hash,
        email=(email or None),
        role=role,
        enabled=True,
    )
    session.add(row)
    session.flush()
    return row


def set_password(session: Session, admin_id: int, password_hash: str) -> AdminUser:
    row = get_admin(session, admin_id)
    if row is None:
        raise UserError("Admin not found.")
    row.password_hash = password_hash
    session.flush()
    return row


def touch_login(session: Session, admin_id: int) -> None:
    row = get_admin(session, admin_id)
    if row is not None:
        row.last_login_at = _utcnow()
        session.flush()


def count_admins_with_role(session: Session, role: str) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(AdminUser)
            .where(AdminUser.role == role, AdminUser.enabled.is_(True))
        )
        or 0
    )


# ---------------------------------------------------------------------------
# Telegram users
# ---------------------------------------------------------------------------


def get_telegram_user(session: Session, telegram_user_id: int) -> TelegramUser | None:
    return session.get(TelegramUser, telegram_user_id)


def upsert_telegram_user(
    session: Session,
    telegram_user_id: int,
    *,
    username: str | None = None,
    role: str | None = None,
    language: str | None = None,
) -> TelegramUser:
    """Create the row if absent, otherwise refresh the volatile fields.

    ``role`` and ``language`` are only applied on creation or when
    explicitly passed, so a panel-set role is not silently reset by the bot
    noticing a user online.
    """
    row = get_telegram_user(session, telegram_user_id)
    if row is None:
        row = TelegramUser(
            telegram_user_id=telegram_user_id,
            username=username,
            role=role if role in TELEGRAM_ROLES else "viewer",
            language=language if language in LANGUAGES else "fa",
            enabled=True,
            last_seen_at=_utcnow(),
        )
        session.add(row)
        session.flush()
        return row

    if username:
        row.username = username
    if role in TELEGRAM_ROLES:
        row.role = role
    if language in LANGUAGES:
        row.language = language
    row.last_seen_at = _utcnow()
    session.flush()
    return row


def list_telegram_users(session: Session) -> list[dict]:
    """Telegram users with their scan counts, newest activity first."""
    scan_counts = dict(
        session.execute(
            select(Scan.requested_by, func.count())
            .where(Scan.requested_by.isnot(None))
            .group_by(Scan.requested_by)
        ).all()
    )
    rows = list(
        session.scalars(select(TelegramUser).order_by(desc(TelegramUser.last_seen_at)))
    )
    return [
        {
            "telegram_user_id": r.telegram_user_id,
            "username": r.username,
            "role": r.role,
            "enabled": r.enabled,
            "language": r.language,
            "timezone": r.timezone,
            "notifications_enabled": r.notifications_enabled,
            "first_seen_at": r.first_seen_at,
            "last_seen_at": r.last_seen_at,
            "scan_count": int(scan_counts.get(r.telegram_user_id, 0)),
        }
        for r in rows
    ]


def update_telegram_user(
    session: Session,
    telegram_user_id: int,
    *,
    role: str | None = None,
    language: str | None = None,
    enabled: bool | None = None,
    notifications_enabled: bool | None = None,
    timezone: str | None = None,
) -> TelegramUser:
    row = get_telegram_user(session, telegram_user_id)
    if row is None:
        raise UserError(f"Telegram user {telegram_user_id} not found.")

    if role is not None:
        if role not in TELEGRAM_ROLES:
            raise UserError(f"Role must be one of {', '.join(TELEGRAM_ROLES)}.")
        row.role = role
    if language is not None:
        if language not in LANGUAGES:
            raise UserError(f"Language must be one of {', '.join(LANGUAGES)}.")
        row.language = language
    if enabled is not None:
        row.enabled = bool(enabled)
    if notifications_enabled is not None:
        row.notifications_enabled = bool(notifications_enabled)
    if timezone is not None:
        row.timezone = timezone.strip() or None

    session.flush()
    return row


def delete_telegram_user(session: Session, telegram_user_id: int) -> bool:
    row = get_telegram_user(session, telegram_user_id)
    if row is None:
        return False
    session.delete(row)
    session.flush()
    return True


def sync_from_allowed(
    database, telegram_user_ids: tuple[int, ...], default_role: str = "operator"
) -> int:
    """Ensure every ID in the allow-list has a row. Returns rows created.

    Runs at bot startup so the panel shows configured users even before
    anyone has run ``/start``. Takes the ``Database`` rather than a session
    because the caller owns no ambient transaction here.
    """
    created = 0
    for telegram_user_id in telegram_user_ids:
        with database.session() as session:
            if get_telegram_user(session, telegram_user_id) is None:
                upsert_telegram_user(
                    session, telegram_user_id, role=default_role
                )
                created += 1
    return created