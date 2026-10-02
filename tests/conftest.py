"""Pytest configuration for NetSentinel.

``pytest-asyncio`` is configured in strict mode so async tests must be
marked explicitly — an unmarked coroutine test would otherwise be silently
skipped rather than run.
"""

from __future__ import annotations

import pytest

pytest_plugins = ("pytest_asyncio",)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"