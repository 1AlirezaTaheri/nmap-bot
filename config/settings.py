"""NetSentinel — application configuration.

All runtime configuration is read from environment variables and validated
here, in one place. Nothing else in the codebase should touch ``os.environ``
directly — that keeps secrets and tunables in a single, auditable module.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(
            f"Missing required environment variable: {name}. "
            f"See .env.example for the expected format."
        )
    return value


def _optional(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


def _int(name: str, default: str) -> int:
    raw = _optional(name, default)
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _csv_ints(name: str) -> tuple[int, ...]:
    """Parse a comma-separated list of Telegram user IDs."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return ()
    ids: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.append(int(part))
        except ValueError as exc:
            raise ConfigError(
                f"{name} contains a non-numeric entry: {part!r}"
            ) from exc
    return tuple(ids)


def _csv_strs(name: str) -> tuple[str, ...]:
    """Parse a comma-separated list of strings."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    """Immutable snapshot of the runtime configuration."""

    telegram_bot_token: str
    allowed_user_ids: tuple[int, ...]
    allowed_cidrs: tuple[str, ...]
    database_url: str
    nmap_binary: str
    scan_timeout_seconds: int
    max_concurrent_scans: int
    default_profile: str

    @classmethod
    def from_env(cls) -> "Settings":
        allowed = _csv_ints("ALLOWED_USER_IDS")
        if not allowed:
            # Fail closed: an empty allow-list would otherwise mean
            # "let everyone scan", which is exactly the risk this
            # project exists to eliminate.
            raise ConfigError(
                "ALLOWED_USER_IDS is empty. Refusing to start with an "
                "open bot — set it to a comma-separated list of your "
                "Telegram numeric user IDs, or delete the variable only "
                "if you understand that startup will fail."
            )
        return cls(
            telegram_bot_token=_require("TELEGRAM_BOT_TOKEN"),
            allowed_user_ids=allowed,
            allowed_cidrs=_csv_strs("ALLOWED_CIDRS"),
            database_url=_optional(
                "DATABASE_URL",
                "postgresql+psycopg://netsentinel:netsentinel@db:5432/netsentinel",
            ),
            nmap_binary=_optional("NMAP_BINARY", "nmap"),
            scan_timeout_seconds=_int("SCAN_TIMEOUT_SECONDS", "300"),
            max_concurrent_scans=_int("MAX_CONCURRENT_SCANS", "2"),
            default_profile=_optional("DEFAULT_PROFILE", "service"),
        )