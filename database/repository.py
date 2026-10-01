"""Repository pattern — SQL lives here and nowhere else.

Callers depend on these classes, never on the ORM directly, so the change
detector and scan manager can be unit-tested against an in-memory SQLite
database with no stubbing.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from database.models import ChangeEvent, Host, Scan, Service, Target


class RepositoryError(RuntimeError):
    pass


class TargetRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def add(self, name: str, value: str, group_name: str | None = None) -> Target:
        if self.get_by_name(name) is not None:
            raise RepositoryError(f"Target '{name}' already exists.")
        target = Target(name=name, value=value, group_name=group_name)
        self._s.add(target)
        self._s.flush()
        return target

    def get_by_name(self, name: str) -> Target | None:
        return self._s.scalar(select(Target).where(Target.name == name))

    def get_or_create_by_value(self, value: str) -> Target:
        """Find a target by its scan value, creating an implicit one if needed.

        Lets ad-hoc values (``/scan 8.8.8.8``) still get a row, so every
        scan has a valid foreign key and history stays queryable per target.
        """
        row = self._s.scalar(select(Target).where(Target.value == value))
        if row is not None:
            return row
        name = value
        if self.get_by_name(name) is not None:
            # Name collision with an explicit target: suffix deterministically.
            suffix = 1
            while self.get_by_name(f"{value}#{suffix}") is not None:
                suffix += 1
            name = f"{value}#{suffix}"
        row = Target(name=name, value=value, group_name=None, enabled=1)
        self._s.add(row)
        self._s.flush()
        return row

    def delete(self, name: str) -> bool:
        target = self.get_by_name(name)
        if target is None:
            return False
        self._s.delete(target)
        self._s.flush()
        return True

    def list(self) -> list[Target]:
        return list(self._s.scalars(select(Target).order_by(Target.name)))


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def create(self, target_id: int, profile: str) -> Scan:
        scan = Scan(target_id=target_id, profile=profile, status="running")
        self._s.add(scan)
        self._s.flush()
        return scan

    def get(self, scan_id: int) -> Scan | None:
        return self._s.scalar(
            select(Scan).where(Scan.id == scan_id).options(
                joinedload(Scan.hosts).joinedload(Host.services)
            )
        )

    def latest_succeeded(
        self, target_id: int, profile: str, exclude_id: int | None = None
    ) -> Scan | None:
        """Most recent successful scan of this target+profile — the baseline."""
        stmt = (
            select(Scan)
            .where(
                Scan.target_id == target_id,
                Scan.profile == profile,
                Scan.status == "succeeded",
            )
            .options(joinedload(Scan.hosts).joinedload(Host.services))
            .order_by(desc(Scan.id))
        )
        if exclude_id is not None:
            stmt = stmt.where(Scan.id != exclude_id)
        return self._s.scalar(stmt.limit(1))

    def recent(self, target_id: int, limit: int = 10) -> list[Scan]:
        return list(
            self._s.scalars(
                select(Scan)
                .where(Scan.target_id == target_id)
                .order_by(desc(Scan.id))
                .limit(limit)
            )
        )

    def complete(
        self,
        scan: Scan,
        *,
        host_count: int,
        service_count: int,
        duration_ms: int,
        error: str | None = None,
    ) -> None:
        scan.status = "failed" if error else "succeeded"
        scan.host_count = host_count
        scan.service_count = service_count
        scan.duration_ms = duration_ms
        scan.error = error
        scan.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
        self._s.flush()

    def store_snapshot(
        self, scan: Scan, hosts: list[dict], services_by_host: dict[str, list[dict]]
    ) -> None:
        """Persist a normalized snapshot into Host/Service rows."""
        for h in hosts:
            host = Host(
                scan_id=scan.id,
                address=h["address"],
                hostname=h.get("hostname"),
                state=h.get("state", "up"),
            )
            self._s.add(host)
            self._s.flush()
            for svc in services_by_host.get(h["address"], []):
                self._s.add(
                    Service(
                        host_id=host.id,
                        port=svc["port"],
                        protocol=svc.get("protocol", "tcp"),
                        state=svc.get("state", "open"),
                        service_name=svc.get("service_name"),
                        product=svc.get("product"),
                        version=svc.get("version"),
                    )
                )
        self._s.flush()


class ChangeRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def add_all(self, events: list[ChangeEvent]) -> None:
        self._s.add_all(events)
        self._s.flush()

    def for_scan(self, scan_id: int) -> list[ChangeEvent]:
        return list(
            self._s.scalars(
                select(ChangeEvent)
                .where(ChangeEvent.scan_id == scan_id)
                .order_by(ChangeEvent.change_type, ChangeEvent.host)
            )
        )