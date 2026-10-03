"""Database-backed runtime settings.

``config/settings.py`` reads the environment once at startup. These
settings layer on top so an operator can change a limit from the web panel
without editing ``.env`` and restarting the bot.

Precedence: database value → environment value → compiled-in default.

The bot re-reads on demand (with a short TTL) rather than subscribing to
notifications, which would need a new external service.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import SystemSetting

log = logging.getLogger(__name__)

# key -> (default, kind, description)
# "kind" drives coercion and validation on write.
SETTING_SPECS: dict[str, tuple[Any, str, str]] = {
    "bot_language": ("fa", "choice:fa,en", "Language used by the Telegram bot"),
    "default_profile": ("service", "choice:quick,service,deep", "Profile used when none given"),
    "rate_limit_seconds": (30, "int:1:3600", "Min seconds between scans of one target"),
    "retention_days": (30, "int:1:3650", "Delete scans older than this"),
    "retention_max_scans_per_target": (100, "int:1:10000", "Cap on scans kept per target"),
    "schedule_enabled": (False, "bool", "Master switch for scheduled monitoring"),
    "schedule_interval_hours": (6, "int:1:720", "Default schedule interval"),
    "schedule_profile": ("service", "choice:quick,service,deep", "Profile for scheduled scans"),
    "scan_timeout_seconds": (60, "int:5:3600", "Per-scan timeout"),
    "max_concurrent_scans": (2, "int:1:16", "Worker concurrency"),
    "export_max_scans": (20, "int:1:500", "Scans per /export"),
    "allowed_cidrs": ("", "str", "Comma-separated CIDRs scans may target"),
}


class SettingError(ValueError):
    """Raised when a value fails validation; message is user-facing."""


def seed(session: Session, actor: str | None = None) -> int:
    """Insert any missing settings at their defaults."""
    existing = set(session.scalars(select(SystemSetting.key)))
    added = 0
    for key, (default, _kind, _desc) in SETTING_SPECS.items():
        if key in existing:
            continue
        session.add(
            SystemSetting(key=key, value=_stringify(default), updated_by=actor)
        )
        added += 1
    if added:
        session.flush()
    return added


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def coerce(key: str, raw: Any) -> Any:
    """Validate and convert ``raw`` for ``key``.

    Raises :class:`SettingError` with a message safe to show an admin.
    """
    if key not in SETTING_SPECS:
        raise SettingError(f"Unknown setting: {key}")

    _default, kind, _desc = SETTING_SPECS[key]

    if isinstance(raw, bool):
        # Already a bool (e.g. from JSON) — accept, but honour the kind.
        if kind == "bool":
            return raw
        raw = "true" if raw else "false"

    text = str(raw).strip()

    if kind == "bool":
        if text.lower() in ("1", "true", "yes", "on"):
            return True
        if text.lower() in ("0", "false", "no", "off"):
            return False
        raise SettingError(f"{key} must be a boolean, got {text!r}")

    if kind.startswith("int:"):
        _kind, low, high = kind.split(":")
        try:
            value = int(text)
        except ValueError as exc:
            raise SettingError(f"{key} must be an integer, got {text!r}") from exc
        if not (int(low) <= value <= int(high)):
            raise SettingError(
                f"{key} must be between {low} and {high}, got {value}"
            )
        return value

    if kind.startswith("choice:"):
        allowed = kind.split(":", 1)[1].split(",")
        if text not in allowed:
            raise SettingError(
                f"{key} must be one of {', '.join(allowed)}, got {text!r}"
            )
        return text

    return text


@dataclass
class SettingsStore:
    """Reads settings from the database with a short-lived cache."""

    database: Any
    ttl_seconds: float = 5.0
    _cache: dict[str, Any] = field(default_factory=dict)
    _cached_at: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def get(self, key: str) -> Any:
        """Return one setting, falling back to its compiled default."""
        with self._lock:
            self._ensure_loaded()
            if key in self._cache:
                return self._cache[key]
        return SETTING_SPECS.get(key, (None, "str", ""))[0]

    def all(self) -> dict[str, Any]:
        with self._lock:
            self._ensure_loaded()
            return dict(self._cache)

    def _ensure_loaded(self) -> None:
        """Load when the cache is empty *or* stale.

        Two distinct conditions: an empty cache must always be populated,
        and a populated one must be refreshed once the TTL lapses.
        """
        if not self._cache or not self._fresh():
            self._load_locked()

    def set(self, session: Session, key: str, value: Any, actor: str | None) -> Any:
        """Validate, persist and invalidate the cache."""
        coerced = coerce(key, value)
        row = session.scalar(
            select(SystemSetting).where(SystemSetting.key == key)
        )
        if row is None:
            row = SystemSetting(key=key, value="")
            session.add(row)
        row.value = _stringify(coerced)
        row.updated_by = actor
        session.flush()
        self.invalidate()
        return coerced

    def set_many(
        self, session: Session, values: dict[str, Any], actor: str | None
    ) -> dict[str, Any]:
        """Apply several settings atomically.

        Validation happens first for every key so a bad value in the batch
        rejects the whole request rather than applying it halfway.
        """
        validated = {key: coerce(key, value) for key, value in values.items()}
        for key, coerced in validated.items():
            row = session.scalar(
                select(SystemSetting).where(SystemSetting.key == key)
            )
            if row is None:
                row = SystemSetting(key=key, value="")
                session.add(row)
            row.value = _stringify(coerced)
            row.updated_by = actor
        session.flush()
        self.invalidate()
        return validated

    def invalidate(self) -> None:
        with self._lock:
            self._cached_at = 0.0
            self._cache.clear()

    def _fresh(self) -> bool:
        """True when the cache is populated and within its TTL."""
        if not self._cache:
            return False
        return (time.monotonic() - self._cached_at) < self.ttl_seconds

    def _load_locked(self) -> None:
        try:
            with self.database.session() as session:
                rows = {r.key: r.value for r in session.scalars(select(SystemSetting))}
        except Exception:
            # A database blip must not stop the bot answering messages;
            # fall back to compiled defaults instead.
            log.warning("Could not read system settings; using defaults", exc_info=True)
            rows = {}

        resolved: dict[str, Any] = {}
        for key, (default, kind, _desc) in SETTING_SPECS.items():
            raw = rows.get(key)
            if raw is None:
                resolved[key] = default
                continue
            try:
                resolved[key] = coerce(key, raw)
            except SettingError:
                # A stored value that no longer validates (profile renamed,
                # range tightened) must not poison every read.
                log.warning("Stored value for %s is invalid; using default", key)
                resolved[key] = default

        self._cache = resolved
        self._cached_at = time.monotonic()