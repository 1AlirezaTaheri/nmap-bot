"""Telegram message formatting.

Kept separate from handlers so message shape is testable without a
Telegram connection, and so wording stays consistent across commands.

Every attribute read from a persisted row goes through :func:`_attr`.
Report rows are routinely rendered after their SQLAlchemy session has
closed, so any relationship access may raise ``DetachedInstanceError``.
Note that ``getattr(obj, name, default)`` does **not** help here:
DetachedInstanceError is not an AttributeError, so getattr would still
propagate it. An explicit try/except is required.
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


def _attr(obj: object, name: str, default: object = None) -> object:
    """Read ``name`` from ``obj``, tolerating detached instances.

    Catches DetachedInstanceError (relationship not loaded and the session
    is gone) as well as AttributeError (attribute simply absent).
    """
    try:
        value = getattr(obj, name)
    except Exception:  # noqa: BLE001 — detached ORM rows raise broadly
        return default
    return default if value is None else value


def _target_name(row: object) -> str:
    """Human-readable target name for a scan row, never raising."""
    target = _attr(row, "target")
    if target is None:
        return "?"
    name = _attr(target, "name")
    return str(name) if name else "?"


def scan_started(target_name: str, target_value: str, profile_name: str) -> str:
    return (
        "🔍 Scan Started\n"
        f"Target: {target_name} ({target_value})\n"
        f"Profile: {profile_name}\n"
        "Status: Running…"
    )


def scheduled_scan_notice(target_name: str, profile_name: str) -> str:
    return (
        "⏰ Scheduled scan completed\n"
        f"Target: {target_name}\n"
        f"Profile: {profile_name}"
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


def scheduled_alert(outcome: ScanOutcome) -> str | None:
    """Alert body for a scheduled run.

    Quiet when nothing changed: an unchanged network is the common case, and
    an alert every cycle would train the operator to ignore the bot.
    """
    if not outcome.changes:
        return (
            "⏰ Scheduled check — no changes\n"
            f"Target: {outcome.target_name} ({outcome.target_value})\n"
            f"Hosts: {outcome.host_count}  Services: {outcome.service_count}"
        )

    body = change_report(outcome) or ""
    return "⏰ " + body


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


def schedules_list(rows: list) -> str:
    if not rows:
        return (
            "⏱ No schedules configured.\n"
            "Add one with: /schedule add <target> <profile> <hours>"
        )
    lines = ["⏱ Scheduled monitoring:"]
    for s in rows:
        target = _attr(s, "target")
        name = _attr(target, "name", "?")
        enabled = bool(_attr(s, "enabled", False))
        interval = _attr(s, "interval_hours", "?")
        next_run = _attr(s, "next_run_at")
        last_run = _attr(s, "last_run_at")
        icon = "🟢" if enabled else "⏸"
        next_text = (
            next_run.strftime("%Y-%m-%d %H:%M")
            if next_run is not None and hasattr(next_run, "strftime")
            else "—"
        )
        last_text = (
            last_run.strftime("%Y-%m-%d %H:%M")
            if last_run is not None and hasattr(last_run, "strftime")
            else "never"
        )
        lines.append(
            f"{icon} {name} [{_attr(s, 'profile', '?')}] every {interval}h\n"
            f"     next: {next_text}   last: {last_text}"
        )
    return "\n".join(lines)


def scan_history(rows: list) -> str:
    """Render scan history. Safe for rows from a closed session."""
    if not rows:
        return "No scans recorded yet."

    lines = ["Scan history:"]
    for row in rows:
        mark = {
            "succeeded": "✅",
            "failed": "❌",
            "running": "⏳",
        }.get(_attr(row, "status", ""), "•")

        started = _attr(row, "started_at")
        when = (
            started.strftime("%Y-%m-%d %H:%M")
            if started is not None and hasattr(started, "strftime")
            else "?"
        )

        source = _attr(row, "source", "manual")
        tag = " ⏰" if source == "scheduled" else ""

        scan_id = _attr(row, "id", "?")
        profile = _attr(row, "profile", "?")
        hosts = _attr(row, "host_count", "?")
        services = _attr(row, "service_count", "?")

        lines.append(
            f"{mark} #{scan_id} {_target_name(row)} "
            f"[{profile}] {when} — {hosts}h/{services}s{tag}"
        )
    return "\n".join(lines)


def status_report(jobs: list) -> str:
    if not jobs:
        return "No active scans."
    lines = ["Active scans:"]
    for j in jobs:
        icon = {"queued": "🕐", "running": "⚙️", "done": "✅", "failed": "❌"}.get(
            _attr(j, "state", ""), "•"
        )
        detail = _attr(j, "detail", "")
        suffix = f" — {detail}" if detail else ""
        source = _attr(j, "source", "manual")
        tag = " ⏰" if source == "scheduled" else ""
        lines.append(
            f"{icon} #{_attr(j, 'job_id', '?')} {_attr(j, 'target_name', '?')} "
            f"[{_attr(j, 'profile', '?')}] {_attr(j, 'state', '?')}{suffix}{tag}"
        )
    return "\n".join(lines)


def health_report(data: dict) -> str:
    """Render the /health payload.

    ``data`` carries db_ok, db_error, scheduler text, queue depth and the
    last successful scan per target.
    """
    db_line = "✅ reachable" if data.get("db_ok") else f"❌ {data.get('db_error')}"
    lines = [
        "🩺 NetSentinel health",
        "",
        f"  database    : {db_line}",
    ]

    scheduler = data.get("scheduler") or {}
    lines.append(
        f"  scheduler   : {'running' if scheduler.get('running') else 'stopped'}"
        f" ({scheduler.get('schedule_count', 0)} schedule(s) enabled)"
    )
    lines.append(
        f"  worker queue: depth {data.get('queue_depth', 0)}, "
        f"active {data.get('active_jobs', 0)}, "
        f"pending {data.get('pending_jobs', 0)}"
    )

    last = data.get("last_successful") or []
    lines += ["", "  last successful scan per target:"]
    if not last:
        lines.append("    (none)")
    else:
        for item in last:
            lines.append(
                f"    • {item['target']} — {item['finished_at'] or 'unknown'}"
            )
    return "\n".join(lines)


def profile_help(names: list[str]) -> str:
    return "Profiles: " + ", ".join(names)