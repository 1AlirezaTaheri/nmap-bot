"""Background scan execution with bounded concurrency.

The legacy handler called ``subprocess.run`` directly inside the Telegram
coroutine, blocking the event loop for the whole scan. Here the queue
decouples submission from execution, a semaphore caps how many nmap
processes run at once, and the blocking call is pushed to a thread so the
bot keeps answering ``/status`` while scans are in flight.

Manual *and* scheduled scans share this single worker, so
``MAX_CONCURRENT_SCANS`` bounds total load rather than each path
separately.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from core.change_detector import Change
from core.profiles import ScanProfile
from core.scan_manager import ScanManager, ScanOutcome
from core.structured_logging import bind

log = logging.getLogger(__name__)

# Callback signature: (job, outcome | None, error | None) -> Awaitable[None]
CompletionHandler = Callable[
    ["ScanJob", "ScanOutcome | None", str | None], Awaitable[None]
]


@dataclass
class ScanJob:
    job_id: int
    chat_id: int
    target_name: str
    target_value: str
    profile: ScanProfile
    # "manual" or "scheduled" — stored on the scan row for provenance.
    source: str = "manual"
    # Who asked. None for scheduled runs.
    requested_by: int | None = None
    actor_username: str | None = None
    # Language for the completion message; None falls back to the global
    # setting at delivery time.
    lang: str | None = None
    # Per-job nmap timeout resolved by the rule engine. None means the
    # runner's configured default applies.
    scan_timeout: int | None = None


@dataclass
class JobStatus:
    job_id: int
    target_name: str
    profile: str
    state: str  # queued | running | done | failed
    detail: str = ""
    source: str = "manual"


@dataclass
class ScanWorker:
    scan_manager: ScanManager
    max_concurrency: int = 2
    _queue: asyncio.Queue = field(default_factory=asyncio.Queue, init=False)
    _jobs: dict[int, JobStatus] = field(default_factory=dict, init=False)
    _jobs_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    _tasks: list[asyncio.Task] = field(default_factory=list, init=False)
    _next_id: int = field(default=1, init=False)
    _running: bool = field(default=False, init=False)
    _on_complete: CompletionHandler | None = field(default=None, init=False)

    async def start(self, on_complete: CompletionHandler) -> None:
        """Start ``max_concurrency`` consumer tasks."""
        self._on_complete = on_complete
        self._running = True
        self._tasks = [
            asyncio.create_task(self._consume(), name=f"scan-worker-{i}")
            for i in range(max(1, self.max_concurrency))
        ]
        log.info(
            "ScanWorker started with %d slot(s)", max(1, self.max_concurrency)
        )

    async def stop(self) -> None:
        """Cancel consumers and await them, leaving no pending tasks."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    @property
    def task_count(self) -> int:
        return len(self._tasks)

    @property
    def is_running(self) -> bool:
        return self._running

    async def submit(self, job: ScanJob) -> None:
        async with self._jobs_lock:
            self._jobs[job.job_id] = JobStatus(
                job_id=job.job_id,
                target_name=job.target_name,
                profile=job.profile.name,
                state="queued",
                source=job.source,
            )
        await self._queue.put(job)

    async def next_job_id(self) -> int:
        async with self._jobs_lock:
            job_id = self._next_id
            self._next_id += 1
            return job_id

    async def statuses(self) -> list[JobStatus]:
        async with self._jobs_lock:
            return sorted(
                self._jobs.values(), key=lambda j: j.job_id, reverse=True
            )

    async def queue_depth(self) -> int:
        """Jobs waiting, not yet picked up by a consumer."""
        return self._queue.qsize()

    async def active_count(self) -> int:
        """Jobs currently executing on a consumer slot."""
        async with self._jobs_lock:
            return sum(1 for j in self._jobs.values() if j.state == "running")

    async def pending_count(self) -> int:
        async with self._jobs_lock:
            return sum(
                1 for j in self._jobs.values() if j.state in ("queued", "running")
            )

    async def _set_state(self, job_id: int, state: str, detail: str = "") -> None:
        async with self._jobs_lock:
            if job_id in self._jobs:
                self._jobs[job_id].state = state
                self._jobs[job_id].detail = detail

    async def _consume(self) -> None:
        """Consumer loop: pull a job, run it off-loop, report the outcome."""
        while self._running:
            try:
                job = await self._queue.get()
            except asyncio.CancelledError:
                return

            with bind("job"):
                await self._set_state(job.job_id, "running")
                outcome: ScanOutcome | None = None
                error: str | None = None
                try:
                    outcome = await asyncio.to_thread(
                        self.scan_manager.execute,
                        job.target_value,
                        job.profile,
                        source=job.source,
                        requested_by=job.requested_by,
                        scan_timeout=job.scan_timeout,
                    )
                except Exception as exc:  # noqa: BLE001 — report, never crash
                    log.exception("Scan job %d failed", job.job_id)
                    error = str(exc)

                await self._set_state(
                    job.job_id, "failed" if error else "done", error or ""
                )

                if self._on_complete is not None:
                    try:
                        await self._on_complete(job, outcome, error)
                    except Exception:  # pragma: no cover - Telegram failure
                        log.exception("Completion notification failed")
                self._queue.task_done()