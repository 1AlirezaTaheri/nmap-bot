"""Authentication: *is this caller allowed to talk to the bot at all?*

Maps to the "Authentication & Authorization → Allowed users" block of the
architecture. This module answers only the identity question; permission
questions (what may they do?) belong to :mod:`security.authorization`.
"""

from __future__ import annotations

from dataclasses import dataclass

from config.settings import Settings


@dataclass(frozen=True)
class Principal:
    """An authenticated Telegram user, with their assigned role."""

    user_id: int
    username: str | None
    role: str = "operator"


class Authenticator:
    """Checks a Telegram user against the configured allow-list."""

    def __init__(self, settings: Settings) -> None:
        self._allowed: frozenset[int] = frozenset(settings.allowed_user_ids)

    @property
    def allowed_user_ids(self) -> frozenset[int]:
        return self._allowed

    def authenticate(
        self, user_id: int, username: str | None = None
    ) -> Principal | None:
        """Return a Principal if allowed, otherwise ``None``.

        Returning ``None`` rather than raising keeps call sites simple: a
        handler can write one guard clause instead of wrapping every
        command in try/except.
        """
        if user_id not in self._allowed:
            return None
        return Principal(user_id=user_id, username=username)