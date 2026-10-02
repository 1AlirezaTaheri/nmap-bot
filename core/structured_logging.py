"""Structured logging with a correlation id.

A scan spans queue -> worker thread -> parser -> database -> Telegram, so
its log lines are otherwise impossible to stitch together. Every entry
point mints a short id and puts it in a :class:`contextvars.ContextVar`,
which the formatter renders alongside the message.

``contextvars`` rather than thread-locals because the scan runs in a worker
thread via ``asyncio.to_thread``; a context var copied into that thread
keeps the id attached to the work itself.
"""

from __future__ import annotations

import contextvars
import logging
import uuid

REQUEST_ID: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default="-"
)


def new_id(prefix: str = "req") -> str:
    """Mint a short correlation id, e.g. ``req-4f9a2b71``."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def set_request_id(value: str):
    return REQUEST_ID.set(value)


def get_request_id() -> str:
    return REQUEST_ID.get()


def bind(prefix: str = "req"):
    """Context manager that assigns an id for the duration of a unit of work."""

    class _Binder:
        def __enter__(self) -> str:
            self._value = new_id(prefix)
            self._token = REQUEST_ID.set(self._value)
            return self._value

        def __exit__(self, *exc) -> None:
            REQUEST_ID.reset(self._token)

    return _Binder()


class RequestIdFilter(logging.Filter):
    """Ensures every record has a request_id attribute."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = REQUEST_ID.get()  # type: ignore[attr-defined]
        return True


class RequestIdFormatter(logging.Formatter):
    """Formatter that surfaces the correlation id and extra context."""

    def __init__(self, fmt: str | None = None) -> None:
        super().__init__(fmt or "%(message)s")

    def format(self, record: logging.LogRecord) -> str:
        rid = getattr(record, "request_id", "-")
        base = super().format(record)
        if rid and rid != "-":
            return f"[{rid}] {base}"
        return base