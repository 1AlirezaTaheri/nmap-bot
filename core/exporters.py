"""Export serializers — turn persisted scans into JSON or CSV.

Pure functions over detached-friendly plain dicts, so they are directly
unit-testable and carry no database or Telegram dependency.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass, field


def _iso(value) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat(sep=" ", timespec="seconds")
    return str(value)


@dataclass
class ServiceRow:
    port: int | None
    protocol: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None


@dataclass
class HostRow:
    address: str
    hostname: str | None
    state: str
    services: list[ServiceRow] = field(default_factory=list)


@dataclass
class ChangeRow:
    change_type: str
    host: str
    port: int | None
    protocol: str | None
    old_value: str | None
    new_value: str | None


@dataclass
class ScanRow:
    id: int
    target: str
    target_value: str | None
    profile: str
    status: str
    source: str
    started_at: str | None
    finished_at: str | None
    duration_ms: int | None
    host_count: int
    service_count: int
    error: str | None
    hosts: list[HostRow] = field(default_factory=list)
    changes: list[ChangeRow] = field(default_factory=list)


def build_scan_rows(scans, changes_by_scan) -> list[ScanRow]:
    """Normalize ORM scan rows into plain dict-friendly structures.

    Accepts detached ORM objects: only already-loaded attributes are read,
    and relationships are accessed defensively.
    """
    rows: list[ScanRow] = []
    for scan in scans:
        target = _get(scan, "target")
        row = ScanRow(
            id=_get(scan, "id", 0),
            target=str(_get(target, "name", "?")),
            target_value=_get(target, "value"),
            profile=str(_get(scan, "profile", "?")),
            status=str(_get(scan, "status", "?")),
            source=str(_get(scan, "source", "manual")),
            started_at=_iso(_get(scan, "started_at")),
            finished_at=_iso(_get(scan, "finished_at")),
            duration_ms=_get(scan, "duration_ms"),
            host_count=_get(scan, "host_count", 0),
            service_count=_get(scan, "service_count", 0),
            error=_get(scan, "error"),
        )

        for host in _get(scan, "hosts", []) or []:
            host_row = HostRow(
                address=str(_get(host, "address", "?")),
                hostname=_get(host, "hostname"),
                state=str(_get(host, "state", "?")),
            )
            for svc in _get(host, "services", []) or []:
                host_row.services.append(
                    ServiceRow(
                        port=_get(svc, "port"),
                        protocol=str(_get(svc, "protocol", "tcp")),
                        state=str(_get(svc, "state", "?")),
                        service_name=_get(svc, "service_name"),
                        product=_get(svc, "product"),
                        version=_get(svc, "version"),
                    )
                )
            row.hosts.append(host_row)

        for change in changes_by_scan.get(row.id, []):
            row.changes.append(
                ChangeRow(
                    change_type=str(_get(change, "change_type", "?")),
                    host=str(_get(change, "host", "?")),
                    port=_get(change, "port"),
                    protocol=_get(change, "protocol"),
                    old_value=_get(change, "old_value"),
                    new_value=_get(change, "new_value"),
                )
            )

        rows.append(row)
    return rows


def _get(obj, name, default=None):
    """Read an attribute tolerating detached instances."""
    if obj is None:
        return default
    try:
        value = getattr(obj, name)
    except Exception:  # noqa: BLE001
        return default
    return default if value is None else value


def to_json(rows: list[ScanRow], *, indent: int = 2) -> str:
    """Full structured dump: scans, hosts, services, change events."""
    payload = {
        "generated_at": _iso(__import__("datetime").datetime.now()),
        "scan_count": len(rows),
        "scans": [asdict(r) for r in rows],
    }
    return json.dumps(payload, indent=indent, default=str)


CSV_HEADER = [
    "record_type",
    "scan_id",
    "target",
    "profile",
    "status",
    "started_at",
    "host",
    "hostname",
    "port",
    "protocol",
    "state",
    "service_name",
    "product",
    "version",
    "change_type",
    "old_value",
    "new_value",
]


def to_csv(rows: list[ScanRow]) -> str:
    """One row per service per scan, plus one row per change event.

    Two record shapes share a header; ``record_type`` distinguishes them
    so the file stays a single, spreadsheet-friendly table.
    """
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_HEADER)

    for row in rows:
        if row.hosts:
            for host in row.hosts:
                for svc in host.services:
                    writer.writerow(
                        [
                            "service",
                            row.id,
                            row.target,
                            row.profile,
                            row.status,
                            row.started_at,
                            host.address,
                            host.hostname or "",
                            svc.port,
                            svc.protocol,
                            svc.state,
                            svc.service_name or "",
                            svc.product or "",
                            svc.version or "",
                            "",
                            "",
                            "",
                        ]
                    )
                if not host.services:
                    writer.writerow(
                        [
                            "host",
                            row.id,
                            row.target,
                            row.profile,
                            row.status,
                            row.started_at,
                            host.address,
                            host.hostname or "",
                            "",
                            "",
                            host.state,
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                        ]
                    )
        else:
            # A scan that found nothing still deserves a row.
            writer.writerow(
                [
                    "scan",
                    row.id,
                    row.target,
                    row.profile,
                    row.status,
                    row.started_at,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )

        for change in row.changes:
            writer.writerow(
                [
                    "change",
                    row.id,
                    row.target,
                    row.profile,
                    row.status,
                    row.started_at,
                    change.host,
                    "",
                    change.port if change.port is not None else "",
                    change.protocol or "",
                    "",
                    "",
                    "",
                    "",
                    change.change_type,
                    change.old_value or "",
                    change.new_value or "",
                ]
            )

    return out.getvalue()


def render(rows: list[ScanRow], fmt: str) -> tuple[str, str, str]:
    """Return ``(content, filename_suffix, mime_type)`` for a format."""
    if fmt == "csv":
        return to_csv(rows), "csv", "text/csv"
    if fmt == "json":
        return to_json(rows), "json", "application/json"
    raise ValueError(f"Unsupported export format: {fmt}")