"""Retention policy — prune old scans without destroying the baseline.

Pure selection lives in :meth:`ScanRepository.deletable_ids`; this module
performs the deletes in FK order and returns a report. Kept separate from
the scheduler so it can be unit-tested and triggered on demand by
``/cleanup``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import delete

from database.database import Database
from database.models import ChangeEvent, Host, Scan, Service
from database.repository import ScanRepository, TargetRepository

log = logging.getLogger(__name__)


@dataclass
class RetentionReport:
    targets_scanned: int = 0
    scans_deleted: int = 0
    hosts_deleted: int = 0
    services_deleted: int = 0
    change_events_deleted: int = 0

    @property
    def total_rows(self) -> int:
        return (
            self.scans_deleted
            + self.hosts_deleted
            + self.services_deleted
            + self.change_events_deleted
        )

    def text(self) -> str:
        return (
            "🧹 Cleanup complete\n"
            f"  targets checked : {self.targets_scanned}\n"
            f"  scans deleted   : {self.scans_deleted}\n"
            f"  hosts deleted   : {self.hosts_deleted}\n"
            f"  services deleted: {self.services_deleted}\n"
            f"  change events   : {self.change_events_deleted}\n"
            f"  total rows      : {self.total_rows}"
        )


class RetentionService:
    def __init__(self, database: Database) -> None:
        self._db = database

    def run(self, *, keep_days: int, keep_per_target: int) -> RetentionReport:
        """Delete scans outside the retention window, per target.

        Always preserves the newest successful scan for each target even if
        older than ``keep_days``: it is the baseline for change detection,
        and losing it would make the next scan report every host as new.
        """
        report = RetentionReport()

        with self._db.session() as session:
            target_ids = [t.id for t in TargetRepository(session).list()]

        for target_id in target_ids:
            with self._db.session() as session:
                doomed = ScanRepository(session).deletable_ids(
                    target_id,
                    keep_days=keep_days,
                    keep_per_target=keep_per_target,
                )
                if not doomed:
                    report.targets_scanned += 1
                    continue

                host_ids = list(
                    session.query(Host.id)
                    .filter(Host.scan_id.in_(doomed))
                    .all()
                )
                host_id_list = [h[0] for h in host_ids]

                # Children first: services -> hosts -> change_events -> scans
                if host_id_list:
                    report.services_deleted += session.execute(
                        delete(Service).where(Service.host_id.in_(host_id_list))
                    ).rowcount
                report.change_events_deleted += session.execute(
                    delete(ChangeEvent).where(ChangeEvent.scan_id.in_(doomed))
                ).rowcount
                if host_id_list:
                    report.hosts_deleted += session.execute(
                        delete(Host).where(Host.id.in_(host_id_list))
                    ).rowcount
                report.scans_deleted += session.execute(
                    delete(Scan).where(Scan.id.in_(doomed))
                ).rowcount

            report.targets_scanned += 1

        log.info(
            "Retention: %d target(s), deleted %d scan(s), %d row(s) total",
            report.targets_scanned,
            report.scans_deleted,
            report.total_rows,
        )
        return report