"""Telegram message formatting.

All user-visible bot text is routed through the i18n layer so it can be
served in Persian or English. Two shapes coexist here:

* **localised** messages call ``t(key, lang, **placeholders)``;
* **data-heavy** messages (scan reports, diffs) stay built in Python and
  are wrapped by a translated header, because localising every field label
  while keeping the tabular layout readable is not worth the coupling.

Every attribute read from a persisted row goes through :func:`_attr`.
Report rows are routinely rendered after their SQLAlchemy session has
closed, so any relationship access may raise ``DetachedInstanceError``.
Note ``getattr(obj, name, default)`` does **not** help: that exception is
not an ``AttributeError``, so getattr would still propagate it.
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
from core.i18n import t
from core.scan_manager import ScanOutcome

# Telegram rejects messages longer than 4096 characters.
MAX_MESSAGE = 4000
MAX_CHANGE_LINES = 30


def _attr(obj: object, name: str, default: object = None) -> object:
    """Read ``name`` from ``obj``, tolerating detached instances."""
    try:
        value = getattr(obj, name)
    except Exception:  # noqa: BLE001 — detached ORM rows raise broadly
        return default
    return default if value is None else value


def _target_name(row: object) -> str:
    target = _attr(row, "target")
    if target is None:
        return "?"
    name = _attr(target, "name")
    return str(name) if name else "?"


# ---------------------------------------------------------------------------
# Localised bot chrome
# ---------------------------------------------------------------------------


def start_greeting(lang: str = "fa") -> str:
    return t("start.greeting", lang)


def help_text(lang: str, role: str, profiles: dict) -> str:
    lines = [t("help.title", lang)]
    for key in (
        "help.cmd.addtarget", "help.cmd.targets", "help.cmd.deltarget",
        "help.cmd.purge", "help.cmd.scan", "help.cmd.scans", "help.cmd.status",
        "help.cmd.health", "help.cmd.cleanup", "help.cmd.export",
        "help.cmd.report", "help.cmd.schedule",
    ):
        lines.append(t(key, lang))
    lines += ["", t("help.profiles", lang)]
    for name in sorted(profiles):
        lines.append(f"• {name} — {profiles[name].description}")
    lines += ["", t("help.role", lang, role=role)]
    return "\n".join(lines)


def denied(lang: str = "fa") -> str:
    return t("auth.denied", lang)


def disabled_account(lang: str = "fa") -> str:
    return t("auth.disabled", lang)


def forbidden(lang: str, error: str) -> str:
    return t("auth.forbidden", lang, error=error)


def scan_usage(lang: str, profiles: list[str]) -> str:
    return t("scan.usage", lang, profiles=", ".join(sorted(profiles)))


def scan_reference_too_long(lang: str, length: int, maximum: int) -> str:
    return t("scan.ref_too_long", lang, length=length, max=maximum)


def scan_value_too_long(lang: str, length: int, maximum: int) -> str:
    return t("scan.value_too_long", lang, length=length, max=maximum)


def scan_unknown_target(lang: str, target: str) -> str:
    return t("scan.unknown_target", lang, target=target)


def scan_rate_limited(lang: str, reason: str) -> str:
    return t("scan.rate_limited", lang, reason=reason)


def scan_blocked_by_rule(
    lang: str, reason: str, rule_name: str | None = None
) -> str:
    """A scan refused by policy. ``rule_name`` is shown when known so the
    operator can go change that rule rather than guess.
    """
    return t(
        "scan.blocked_by_rule", lang, reason=reason, rule=rule_name or "-"
    )


def scan_started(lang: str, target: str, value: str, profile: str) -> str:
    return t(
        "scan.started", lang,
        target=target, value=value, profile=profile,
    )


def scan_failed(lang: str, error: str) -> str:
    return t("scan.failed", lang, error=error)


def unhandled_error(lang: str, error: str) -> str:
    return t("error.unhandled", lang, error=error)


def handler_failed(lang: str, action: str, error: str) -> str:
    return t("error.handler_failed", lang, action=action, error=error)


# ---------------------------------------------------------------------------
# Target registry
# ---------------------------------------------------------------------------


def target_usage_add(lang: str) -> str:
    return t("target.usage_add", lang)


def target_usage_del(lang: str) -> str:
    return t("target.usage_del", lang)


def target_added(lang: str, name: str, value: str) -> str:
    return t("target.added", lang, name=name, value=value)


def target_rejected(lang: str, error: str) -> str:
    return t("target.rejected", lang, error=error)


def target_invalid(lang: str, error: str) -> str:
    return t("target.invalid", lang, error=error)


def target_deleted(lang: str, name: str) -> str:
    return t("target.deleted", lang, name=name)


def target_not_found(lang: str, name: str) -> str:
    return t("target.not_found", lang, name=name)


def target_delete_blocked(lang: str, error: str) -> str:
    return t("target.delete_blocked", lang, error=error)


def targets_list(lang: str, rows: list) -> str:
    if not rows:
        return t("target.list_empty", lang)
    lines = [t("target.list_header", lang)]
    for row in rows:
        group = f"  [{row.group}]" if row.group else ""
        lines.append(t("target.list_item", lang, name=row.name, value=row.value, group=group))
    return "\n".join(lines)


def purge_usage(lang: str) -> str:
    return t("purge.usage", lang)


def purge_confirm_prompt(
    lang: str, name: str, value: str, pending: dict
) -> str:
    return t(
        "purge.confirm_prompt", lang,
        name=name, value=value,
        scans=pending["scans"], hosts=pending["hosts"],
        services=pending["services"], changes=pending["change_events"],
        schedules=pending["schedules"],
        command=f"/purge {name} confirm",
    )


def purge_done(lang: str, name: str, counts: dict) -> str:
    return t(
        "purge.done", lang,
        name=name, scans=counts["scans"], hosts=counts["hosts"],
        services=counts["services"], changes=counts["change_events"],
        schedules=counts["schedules"],
    )


def purge_failed(lang: str, name: str, error: str) -> str:
    return t("error.purge_failed", lang, target=name, error=error)


def delete_failed(lang: str, name: str, error: str) -> str:
    return t("error.delete_failed", lang, target=name, error=error)


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------


def schedule_usage(lang: str) -> str:
    return t("schedule.usage", lang)


def schedule_unknown(lang: str, subcommand: str) -> str:
    return t("schedule.unknown", lang, subcommand=subcommand, usage=schedule_usage(lang))


def schedule_add_usage(lang: str, profiles: list[str]) -> str:
    return t("schedule.add_usage", lang, profiles=", ".join(sorted(profiles)))


def schedule_bad_interval(lang: str, value: str) -> str:
    return t("schedule.bad_interval", lang, value=value)


def schedule_bad_profile(lang: str, profile: str, profiles: list[str]) -> str:
    return t("schedule.bad_profile", lang, profile=profile, profiles=", ".join(sorted(profiles)))


def schedule_min_interval(lang: str) -> str:
    return t("schedule.min_interval", lang)


def schedule_saved(lang: str, name: str, profile: str, hours: int, jobs: int,
                   enabled: bool) -> str:
    suffix = "" if enabled else t("schedule.disabled_suffix", lang)
    return t(
        "schedule.saved", lang,
        name=name, profile=profile, hours=hours, jobs=jobs, suffix=suffix,
    )


def schedule_removed(lang: str, name: str) -> str:
    return t("schedule.removed", lang, name=name)


def schedule_paused(lang: str, name: str) -> str:
    return t("schedule.paused", lang, name=name)


def schedule_resumed(lang: str, name: str) -> str:
    return t("schedule.resumed", lang, name=name)


def schedule_no_schedule(lang: str, name: str) -> str:
    return t("schedule.no_schedule", lang, name=name)


def schedule_pause_all(lang: str, count: int) -> str:
    return t("schedule.pause_all", lang, count=count) if count else t("schedule.nothing_pause", lang)


def schedule_resume_all(lang: str, count: int) -> str:
    return t("schedule.resume_all", lang, count=count) if count else t("schedule.nothing_resume", lang)


def schedules_list(lang: str, rows: list, scheduler_running: bool = True) -> str:
    if not rows:
        return t("schedule.list_empty", lang)

    lines = [t("schedule.list_header", lang)]
    for row in rows:
        target = _attr(row, "target")
        name = _attr(target, "name", "?")
        enabled = bool(_attr(row, "enabled", False))
        next_run = _attr(row, "next_run_at")
        last_run = _attr(row, "last_run_at")
        icon = "🟢" if enabled else "⏸"
        lines.append(
            t(
                "schedule.list_item", lang,
                icon=icon,
                name=name,
                profile=_attr(row, "profile", "?"),
                hours=_attr(row, "interval_hours", "?"),
                next=(
                    next_run.strftime("%Y-%m-%d %H:%M")
                    if next_run is not None and hasattr(next_run, "strftime")
                    else "—"
                ),
                last=(
                    last_run.strftime("%Y-%m-%d %H:%M")
                    if last_run is not None and hasattr(last_run, "strftime")
                    else t("schedule.never", lang)
                ),
            )
        )
    if not scheduler_running:
        lines.append(t("schedule.list_not_running", lang))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scan results (data-heavy, header localised)
# ---------------------------------------------------------------------------


def scan_completed(outcome: ScanOutcome, lang: str = "fa") -> str:
    return t(
        "scan.completed", lang,
        target=outcome.target_name,
        value=outcome.target_value,
        profile=outcome.profile,
        hosts=outcome.host_count,
        services=outcome.service_count,
        duration=f"{outcome.duration_ms / 1000:.1f}s",
        scan_id=outcome.scan_id,
    )


def _change_line(c: Change, lang: str) -> str:
    if c.change_type == NEW_HOST:
        return t("change.new_host", lang, host=c.host)
    if c.change_type == CLOSED_HOST:
        return t("change.closed_host", lang, host=c.host)
    if c.change_type == NEW_PORT:
        return t("change.new_port", lang, host=c.host, port=c.port)
    if c.change_type == CLOSED_PORT:
        return t("change.closed_port", lang, host=c.host, port=c.port)
    if c.change_type == SERVICE_CHANGE:
        return t(
            "change.service_changed", lang,
            host=c.host, port=c.port, old=c.old_value, new=c.new_value,
        )
    return f"{LABELS.get(c.change_type, c.change_type)}: {c.host}"


def change_report(outcome: ScanOutcome, lang: str = "fa") -> str | None:
    """The alert block, or None when there is nothing to report."""
    if not outcome.changes:
        return None

    header = (
        t("change.header", lang)
        if not outcome.is_first_scan
        else t("change.header_first", lang)
    )

    lines = [header, ""]
    for change in outcome.changes[:MAX_CHANGE_LINES]:
        lines.append(_change_line(change, lang))
    hidden = len(outcome.changes) - MAX_CHANGE_LINES
    if hidden > 0:
        lines.append(t("change.more", lang, count=hidden))

    lines.append("")
    lines.append(t("change.summary", lang, summary=", ".join(_summary_pieces(outcome))))
    lines.append(t("change.previous_scan", lang, scan_id=outcome.baseline_scan_id or "none"))
    return "\n".join(lines)


def scheduled_alert(outcome: ScanOutcome, lang: str = "fa") -> str | None:
    """Alert body for a scheduled run.

    Quiet when nothing changed: an unchanged network is the common case,
    and an alert every cycle would train the operator to ignore the bot.
    """
    if not outcome.changes:
        return t(
            "scheduled.unchanged", lang,
            target=outcome.target_name,
            value=outcome.target_value,
            hosts=outcome.host_count,
            services=outcome.service_count,
        )
    return "⏰ " + (change_report(outcome, lang) or "")


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


# ---------------------------------------------------------------------------
# History / status / health / cleanup
# ---------------------------------------------------------------------------


def scan_history(lang: str, rows: list) -> str:
    if not rows:
        return t("history.empty", lang)

    lines = [t("history.header", lang)]
    for row in rows:
        mark = {
            "succeeded": "✅", "failed": "❌", "running": "⏳",
        }.get(_attr(row, "status", ""), "•")
        started = _attr(row, "started_at")
        when = (
            started.strftime("%Y-%m-%d %H:%M")
            if started is not None and hasattr(started, "strftime")
            else "?"
        )
        source = _attr(row, "source", "manual")
        tag = " ⏰" if source == "scheduled" else ""
        lines.append(
            f"{mark} #{_attr(row, 'id', '?')} {_target_name(row)} "
            f"[{_attr(row, 'profile', '?')}] {when} — "
            f"{_attr(row, 'host_count', '?')}h/{_attr(row, 'service_count', '?')}s{tag}"
        )
    return "\n".join(lines)


def history_usage(lang: str) -> str:
    return t("history.usage", lang)


def history_unknown_target(lang: str, target: str) -> str:
    return t("history.unknown_target", lang, target=target)


def status_report(lang: str, jobs: list) -> str:
    if not jobs:
        return t("status.empty", lang)
    lines = [t("status.header", lang)]
    for j in jobs:
        icon = {"queued": "🕐", "running": "⚙️", "done": "✅", "failed": "❌"}.get(
            _attr(j, "state", ""), "•"
        )
        detail = _attr(j, "detail", "")
        source = _attr(j, "source", "manual")
        lines.append(
            t(
                "status.item", lang,
                icon=icon,
                job_id=_attr(j, "job_id", "?"),
                target=_attr(j, "target_name", "?"),
                profile=_attr(j, "profile", "?"),
                state=_attr(j, "state", "?"),
                detail=f" — {detail}" if detail else "",
                scheduled=" ⏰" if source == "scheduled" else "",
            )
        )
    return "\n".join(lines)


def health_report(lang: str, data: dict) -> str:
    db_line = (
        t("health.db_ok", lang)
        if data.get("db_ok")
        else t("health.db_fail", lang, error=data.get("db_error", "?"))
    )
    scheduler = data.get("scheduler") or {}
    lines = [
        t("health.title", lang),
        "",
        db_line,
        t(
            "health.scheduler", lang,
            state=t("health.running", lang) if scheduler.get("running") else t("health.stopped", lang),
            count=scheduler.get("schedule_count", 0),
        ),
        t(
            "health.queue", lang,
            depth=data.get("queue_depth", 0),
            active=data.get("active_jobs", 0),
            pending=data.get("pending_jobs", 0),
        ),
        "",
        t("health.last_scan", lang),
    ]

    last = data.get("last_successful") or []
    if not last:
        lines.append(t("health.none", lang))
    else:
        for item in last:
            lines.append(
                t("health.item", lang, target=item["target"], finished=item["finished_at"] or "—")
            )
    return "\n".join(lines)


def cleanup_report(lang: str, report) -> str:
    return t(
        "cleanup.title", lang
    ) + "\n" + t(
        "cleanup.targets", lang, targets=report.targets_scanned
    ) + "\n" + t(
        "cleanup.scans", lang, scans=report.scans_deleted
    ) + "\n" + t(
        "cleanup.hosts", lang, hosts=report.hosts_deleted
    ) + "\n" + t(
        "cleanup.services", lang, services=report.services_deleted
    ) + "\n" + t(
        "cleanup.changes", lang, changes=report.change_events_deleted
    ) + "\n" + t(
        "cleanup.total", lang, total=report.total_rows
    )


def cleanup_failed(lang: str, error: str) -> str:
    return t("error.cleanup_failed", lang, error=error)


# ---------------------------------------------------------------------------
# Export / report
# ---------------------------------------------------------------------------


def export_usage(lang: str, formats: tuple) -> str:
    return t("export.usage", lang, formats=", ".join(formats))


def export_bad_format(lang: str, fmt: str, formats: tuple) -> str:
    return t("export.bad_format", lang, format=fmt, formats=", ".join(formats))


def export_unknown_target(lang: str, target: str) -> str:
    return t("export.unknown_target", lang, target=target)


def export_no_scans(lang: str, target: str) -> str:
    return t("export.no_scans", lang, target=target)


def export_caption(lang: str, target: str, scans: int, fmt: str) -> str:
    return t("export.caption", lang, target=target, scans=scans, format=fmt.upper())


def export_too_large(lang: str, size_kb: int, maximum: int) -> str:
    return t("export.too_large", lang, size=size_kb, max=maximum)


def report_usage(lang: str, days: int) -> str:
    return t("report.usage", lang, days=days)


def report_unknown_target(lang: str, target: str) -> str:
    return t("report.unknown_target", lang, target=target)


def report_text(lang: str, summary) -> str:
    """Render a :class:`core.reporter.ReportSummary` with translated labels."""
    lines = [
        t("report.title", lang, target=summary.target_name),
        t("report.range", lang, value=summary.target_value),
        t("report.window", lang, days=summary.window_days),
        "",
        t("report.scans", lang),
        t("report.total", lang, value=summary.total_scans),
        t("report.succeeded", lang, value=summary.succeeded),
        t("report.failed", lang, value=summary.failed),
        t("report.running", lang, value=summary.running),
        t("report.ratio", lang, value=summary.success_ratio),
        "",
        t("report.assets", lang),
        t("report.unique_hosts", lang, value=summary.unique_hosts),
        t("report.unique_services", lang, value=summary.unique_services),
        "",
        t("report.changes", lang),
    ]

    if not summary.change_counts:
        lines.append(t("report.no_changes", lang))
    else:
        for change_type, count in summary.change_counts.items():
            lines.append(f"  {change_type:16}: {count}")

    lines += ["", t("report.top_hosts", lang)]
    if not summary.top_changed_hosts:
        lines.append(t("report.no_hosts", lang))
    else:
        for address, count in summary.top_changed_hosts:
            lines.append(f"  {address:20} {count} change(s)")

    return "\n".join(lines)


def profile_help(lang: str, names: list[str]) -> str:
    return ", ".join(names)