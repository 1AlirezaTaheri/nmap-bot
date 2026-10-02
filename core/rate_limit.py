"""Per-target rate limiting.

Stops a user from queueing the same scan repeatedly, which would burn
nmap processes and fill the queue. Implemented as a small in-memory
token bucket keyed by target name — deliberately *not* persisted, because
a restart should not hand out a fresh allowance while the host is still
recovering.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# Below this, timestamps are pruned so the map cannot grow without bound
# on a long-lived process.
_MAX_TRACKED = 512


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after: float = 0.0
    reason: str = ""


class RateLimiter:
    def __init__(self, min_interval_seconds: float, *, clock=time.monotonic) -> None:
        self._interval = float(min_interval_seconds)
        self._clock = clock
        self._last: dict[str, float] = {}

    @property
    def min_interval_seconds(self) -> float:
        return self._interval

    def check(self, key: str) -> RateLimitDecision:
        """Record an attempt for ``key``; report whether it is allowed."""
        if self._interval <= 0:
            return RateLimitDecision(allowed=True)

        now = self._clock()
        previous = self._last.get(key)

        if previous is not None:
            elapsed = now - previous
            if elapsed < self._interval:
                return RateLimitDecision(
                    allowed=False,
                    retry_after=self._interval - elapsed,
                    reason=(
                        f"Rate limited: '{key}' was scanned "
                        f"{elapsed:.0f}s ago. Wait "
                        f"{self._interval - elapsed:.0f}s more."
                    ),
                )

        self._record(key, now)
        return RateLimitDecision(allowed=True)

    def peek(self, key: str) -> float | None:
        """Seconds since the last accepted attempt, or None."""
        previous = self._last.get(key)
        if previous is None:
            return None
        return self._clock() - previous

    def forget(self, key: str) -> None:
        self._last.pop(key, None)

    def reset(self) -> None:
        self._last.clear()

    def _record(self, key: str, now: float) -> None:
        if len(self._last) >= _MAX_TRACKED:
            oldest = min(self._last, key=self._last.get)  # type: ignore[arg-type]
            self._last.pop(oldest, None)
        self._last[key] = now