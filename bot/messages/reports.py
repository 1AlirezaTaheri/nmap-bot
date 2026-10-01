"""Telegram message formatting.

Kept separate from handlers so message shape is testable without a
Telegram connection, and so wording stays consistent across commands.
"""

from __future__ import annotations

from core.change_detector import (
    CLOSED_HOST,
    CLOSED_PORT,
    LABELS,
    NEW_HOST,
    NEW_PORT,
    SERVICE_CHANGE,
    Change,
)
from core.scan_manager import ScanOutcome

# Telegram rejects messages longer than 4096 characters.
MAX_MESSAGE = 4000
MAX_CHANGE_LINES = 30


def scan_started(target_name: str, target_value: str, profile_name: str) -> str:
    return (
        "🔍 Scan Started\n"
        f"Target: {target_name} ({target_value})\n"
        f"Profile: {profile_name}\n"
        "Status: Running…"
    )


def scan_completed(outcome: ScanOutcome) -> str:
    lines = [
        "✅ Scan Completed",
        f"Target: {outcome.target_name} ({outcome.target_value})",
        f"Profile: {outcome.profile}",
        f"Hosts discovered: {outcome.host_count}",
        f"Open services: {outcome.service_count}",
        f"Scan duration: {outcome.duration_ms / 1000:.1f}s",
        f"Scan ID: {outcome.scan_id}",
    ]
    return "\n".join(lines)


def _change_line(c: Change) -> str:
    if c.change_type == NEW_HOST:
        return f"New host: {c.host}"
    if c.change_type == CLOSED_HOST:
        return f"Closed host: {c.host}"
    if c.change_type == NEW_PORT:
        return f"New port: {c.host}:{c.port}"
    if c.change_type == CLOSED_PORT:
        return f"Closed port: {c.host}:{c.port}"
    if c.change_type == SERVICE_CHANGE:
        return (
            f"Service changed: {c.host}:{c.port} "
            f"({c.old_value} → {c.new_value})"
        )
    return f"{LABELS.get(c.change_type, c.change_type)}: {c.host}"


def change_report(outcome: ScanOutcome) -> str | None:
    """The alert block, or ``None`` when there is nothing to report."""
    if not outcome.changes:
        return None

    header = (
        "🚨 NETWORK CHANGES DETECTED"
        if not outcome.is_first_scan
        else "ℹ️ BASELINE ESTABLISHED (first scan)"
    )

    lines = [header, ""]
    for change in outcome.changes[:MAX_CHANGE_LINES]:
        lines.append(_change_line(change))
    hidden = len(outcome.changes) - MAX_CHANGE_LINES
    if hidden > 0:
        lines.append(f"… and {hidden} more change(s)")

    lines.append("")
    lines.append(f"Summary: {', '.join(_summary_pieces(outcome))}")
    lines.append(f"Previous scan: {outcome.baseline_scan_id or 'none'}")
    return "\n".join(lines)


def _summary_pieces(outcome: ScanOutcome) -> list[str]:
    counts = outcome.counts
    pieces: list[str] = []
    if counts.get(NEW_HOST):
        pieces.append(f"+{counts[NEW_HOST]} host")
    if counts.get(NEW_PORT):
        pieces.append(f"+{counts[NEW_PORT]} port")
    if counts.get(SERVICE_CHANGE):
        pieces.append(f"+{counts[SERVICE_CHANGE]} service change")
    if counts.get(CLOSED_PORT):
        pieces.append(f"-{counts[CLOSED_PORT]} port")
    if counts.get(CLOSED_HOST):
        pieces.append(f"-{counts[CLOSED_HOST]} host")
    return pieces or ["no changes"]


def targets_list(rows: list) -> str:
    if not rows:
        return (
            "Targets: (none)\n"
            "Add one with: /addtarget <name> <value>"
        )
    lines = ["Registered targets:"]
    for t in rows:
        group = f"  [{t.group}]" if t.group else ""
        lines.append(f"• {t.name} → {t.value}{group}")
    return "\n".join(lines)


def scan_history(rows: list) -> str:
    if not rows:
        return "No scans recorded yet."
    lines = ["Scan history:"]
    for s in rows:
        mark = {"succeeded": "✅", "failed": "❌", "running": "⏳"}.get(
            s.status, "•"
        )
        when = s.started_at.strftime("%Y-%m-%d %H:%M") if s.started_at else "?"
        lines.append(
            f"{mark} #{s.id} {s.target.name if s.target else '?'} "
            f"[{s.profile}] {when} — {s.host_count}h/{s.service_count}s"
        )
    return "\n".join(lines)


def status_report(jobs: list) -> str:
    if not jobs:
        return "No active scans."
    lines = ["Active scans:"]
    for j in jobs:
        icon = {"queued": "🕐", "running": "⚙️", "done": "✅", "failed": "❌"}.get(
            j.state, "•"
        )
        detail = f" — {j.detail}" if j.detail else ""
        lines.append(
            f"{icon} #{j.job_id} {j.target_name} [{j.profile}] "
            f"{j.state}{detail}"
        )
    return "\n".join(lines)


def profile_help(names: list[str]) -> str:
    return "Profiles: " + ", ".join(names)