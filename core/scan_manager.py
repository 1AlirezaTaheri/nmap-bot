"""Scan Manager — the Facade over the whole scan pipeline.

One call drives: nmap → XML parse → normalize → persist → change-detect.
Callers (handlers, worker) never touch the individual stages, so the
sequence stays in one reviewable place.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.change_detector import Change, detect, summarize
from core.profiles import ScanProfile
from database.database import Database
from database.models import ChangeEvent
from database.repository import (
    ChangeRepository,
    ScanRepository,
    TargetRepository,
)
from parser import normalizer, xml_parser
from parser.nmap_runner import NmapRunner

log = logging.getLogger(__name__)


@dataclass
class ScanOutcome:
    scan_id: int
    target_name: str
    target_value: str
    profile: str
    host_count: int
    service_count: int
    duration_ms: int
    changes: list[Change] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    baseline_scan_id: int | None = None
    is_first_scan: bool = False


class ScanManager:
    def __init__(self, database: Database, runner: NmapRunner) -> None:
        self._db = database
        self._runner = runner

    def execute(
        self,
        target_value: str,
        profile: ScanProfile,
        source: str = "manual",
        requested_by: int | None = None,
    ) -> ScanOutcome:
        """Run one scan end-to-end and persist the result.

        The target row is resolved here so callers never manage ids —
        every scan gets a valid foreign key, including ad-hoc targets.

        ``source`` records provenance ("manual" / "scheduled") and
        ``requested_by`` the Telegram id behind it, so the panel can show
        per-user scan counts and attribute history.
        """
        # Commit the "running" row first, so a crash mid-scan still leaves
        # a durable record instead of losing the attempt entirely.
        with self._db.session() as session:
            target_row = TargetRepository(session).get_or_create_by_value(
                target_value
            )
            target_id = target_row.id
            target_name = target_row.name
            scan_id = ScanRepository(session).create(
                target_id, profile.name, source=source,
                requested_by=requested_by,
            ).id

        with self._db.session() as session:
            scans = ScanRepository(session)
            changes_repo = ChangeRepository(session)
            # Re-fetch inside this session: the instance created above was
            # committed and detached when its session closed, and updating
            # a detached object would be silently dropped (leaving the scan
            # stuck at "running" forever).
            scan = scans.get(scan_id)

            try:
                result = self._runner.run(target_value, list(profile.args))
                parsed = xml_parser.parse(result.xml)
                snapshot = normalizer.normalize(parsed)
            except Exception as exc:
                scans.complete(
                    scan, host_count=0, service_count=0,
                    duration_ms=0, error=str(exc),
                )
                log.warning("Scan failed for %s: %s", target_value, exc)
                return ScanOutcome(
                    scan_id=scan.id, target_name=target_name,
                    target_value=target_value, profile=profile.name,
                    host_count=0, service_count=0, duration_ms=0,
                )

            baseline = scans.latest_succeeded(
                target_id, profile.name, exclude_id=scan.id
            )
            previous = _snapshot_of(baseline) if baseline is not None else None

            scans.store_snapshot(
                scan, snapshot["hosts"], snapshot["services"]
            )

            service_count = sum(len(v) for v in snapshot["services"].values())
            scans.complete(
                scan, host_count=len(snapshot["hosts"]),
                service_count=service_count, duration_ms=result.duration_ms,
            )

            changes = detect(previous, snapshot)
            if changes:
                changes_repo.add_all(
                    [
                        ChangeEvent(
                            scan_id=scan.id,
                            previous_scan_id=baseline.id if baseline else None,
                            change_type=c.change_type,
                            host=c.host,
                            port=c.port,
                            protocol=c.protocol,
                            old_value=c.old_value,
                            new_value=c.new_value,
                        )
                        for c in changes
                    ]
                )

            return ScanOutcome(
                scan_id=scan.id,
                target_name=target_name,
                target_value=target_value,
                profile=profile.name,
                host_count=len(snapshot["hosts"]),
                service_count=service_count,
                duration_ms=result.duration_ms,
                changes=changes,
                counts=summarize(changes),
                baseline_scan_id=baseline.id if baseline else None,
                is_first_scan=previous is None,
            )


def _snapshot_of(scan) -> dict:
    """Rebuild a normalized snapshot from persisted rows for comparison."""
    hosts = [
        {
            "address": h.address,
            "hostname": h.hostname,
            "state": h.state,
        }
        for h in scan.hosts
    ]
    services = {
        h.address: [
            {
                "port": s.port,
                "protocol": s.protocol,
                "state": s.state,
                "service_name": s.service_name,
                "product": s.product,
                "version": s.version,
            }
            for s in h.services
        ]
        for h in scan.hosts
    }
    return {"hosts": hosts, "services": services}