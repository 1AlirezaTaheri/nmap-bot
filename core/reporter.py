"""Human-readable scan reports for ``/report <target>``.

Pure aggregation over already-loaded rows — no database access, no
Telegram. Given the same input it always renders the same text.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from core.change_detector import ORDER as CHANGE_ORDER
from core.change_detector import LABELS as CHANGE_LABELS

REPORT_WINDOW_DAYS = 7
TOP_HOSTS = 10


def _get(obj, name, default=None):
    if obj is None:
        return default
    try:
        value = getattr(obj, name)
    except Exception:  # noqa: BLE001 — detached ORM rows
        return default
    return default if value is None else value


@dataclass
class ReportSummary:
    target_name: str
    target_value: str
    window_days: int
    total_scans: int = 0
    succeeded: int = 0
    failed: int = 0
    running: int = 0
    unique_hosts: int = 0
    unique_services: int = 0
    change_counts: dict[str, int] = field(default_factory=dict)
    top_changed_hosts: list[tuple[str, int]] = field(default_factory=list)

    @property
    def success_ratio(self) -> str:
        if not self.total_scans:
            return "n/a"
        return f"{self.succeeded}/{self.total_scans} ({self.succeeded * 100 // self.total_scans}%)"

    def text(self) -> str:
        lines = [
            f"📊 Report — {self.target_name}",
            f"Range: {self.target_value}",
            f"Window: last {self.window_days} days",
            "",
            "── Scans ──",
            f"  total          : {self.total_scans}",
            f"  succeeded      : {self.succeeded}",
            f"  failed         : {self.failed}",
            f"  running        : {self.running}",
            f"  success ratio  : {self.success_ratio}",
            "",
            "── Assets discovered ──",
            f"  unique hosts   : {self.unique_hosts}",
            f"  unique services: {self.unique_services}",
            "",
            "── Change events ──",
        ]

        if not self.change_counts:
            lines.append("  (no change events recorded)")
        else:
            for change_type in CHANGE_ORDER:
                count = self.change_counts.get(change_type, 0)
                if count:
                    lines.append(f"  {CHANGE_LABELS[change_type]:16}: {count}")
            extra = set(self.change_counts) - set(CHANGE_ORDER)
            for change_type in sorted(extra):
                lines.append(
                    f"  {change_type:16}: {self.change_counts[change_type]}"
                )

        lines += ["", "── Top changed hosts ──"]
        if not self.top_changed_hosts:
            lines.append("  (none)")
        else:
            for address, count in self.top_changed_hosts:
                lines.append(f"  {address:20} {count} change(s)")

        return "\n".join(lines)


def build_summary(target_name: str, target_value: str, scans, changes) -> ReportSummary:
    """Aggregate scans and change events into a report.

    ``scans`` should be the window returned by
    :meth:`ScanRepository.in_window`; ``changes`` the matching change
    events. Both may be detached ORM rows.
    """
    summary = ReportSummary(
        target_name=target_name,
        target_value=target_value,
        window_days=REPORT_WINDOW_DAYS,
    )

    summary.total_scans = len(scans)
    statuses = Counter(str(_get(s, "status", "?")) for s in scans)
    summary.succeeded = statuses.get("succeeded", 0)
    summary.failed = statuses.get("failed", 0)
    summary.running = statuses.get("running", 0)

    hosts: set[str] = set()
    services: set[tuple] = set()
    for scan in scans:
        for host in _get(scan, "hosts", []) or []:
            address = _get(host, "address")
            if address:
                hosts.add(str(address))
            for svc in _get(host, "services", []) or []:
                port = _get(svc, "port")
                proto = _get(svc, "protocol", "tcp")
                name = _get(svc, "service_name")
                if port is not None:
                    services.add((str(name), int(port), str(proto)))

    summary.unique_hosts = len(hosts)
    summary.unique_services = len(services)

    type_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    for change in changes:
        change_type = str(_get(change, "change_type", "?"))
        host = _get(change, "host")
        type_counts[change_type] += 1
        if host:
            host_counts[str(host)] += 1

    summary.change_counts = dict(type_counts)
    summary.top_changed_hosts = host_counts.most_common(TOP_HOSTS)
    return summary