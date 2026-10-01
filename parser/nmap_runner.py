"""Run nmap with XML output.

Security invariants enforced here:
- the target is re-validated immediately before exec;
- arguments are never assembled from user input — they come from the
  fixed :mod:`core.profiles` catalog;
- ``subprocess`` is called with a list (no shell), so metacharacters in a
  target cannot be interpreted by a shell even if validation were bypassed.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

from security.targets import validate_target


class ScanExecutionError(RuntimeError):
    """Raised when nmap cannot be executed or exits non-zero."""


@dataclass(frozen=True)
class ScanResult:
    xml: str
    returncode: int
    duration_ms: int
    stderr: str


class NmapRunner:
    def __init__(self, nmap_binary: str = "nmap", timeout_seconds: int = 300) -> None:
        self._binary = nmap_binary
        self._timeout = timeout_seconds

    def run(self, target: str, args: list[str]) -> ScanResult:
        """Execute nmap and return its XML document.

        ``args`` must come from a profile, never from a chat message.
        """
        safe_target = validate_target(target)

        if any(a.startswith("-") and a == "-" for a in args):  # pragma: no cover
            raise ScanExecutionError("Invalid profile arguments.")

        command = [self._binary, *args, "-oX", "-", safe_target]

        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanExecutionError(
                f"Scan timed out after {self._timeout}s."
            ) from exc
        except FileNotFoundError as exc:
            raise ScanExecutionError(
                f"nmap binary not found: {self._binary}"
            ) from exc

        duration_ms = int((time.monotonic() - started) * 1000)

        if completed.returncode != 0:
            raise ScanExecutionError(
                f"nmap exited with {completed.returncode}: "
                f"{completed.stderr.strip() or 'no details'}"
            )
        if not completed.stdout.strip():
            raise ScanExecutionError("nmap produced no XML output.")

        return ScanResult(
            xml=completed.stdout,
            returncode=completed.returncode,
            duration_ms=duration_ms,
            stderr=completed.stderr,
        )