"""Tests for the deletion policy: block by default, purge is explicit."""

from __future__ import annotations

import pytest

from core.target_manager import TargetRegistry
from database.database import Database
from database.repository import (
    ChangeRepository,
    RepositoryError,
    ScanRepository,
    TargetRepository,
)


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/t.db")
    database.create_all()
    yield database
    database.dispose()


def make_target(db: Database, name: str = "lab", value: str = "192.168.1.0/24"):
    with db.session() as s:
        return TargetRepository(s).add(name, value)


def make_scan(db: Database, target_id: int, profile: str = "quick") -> int:
    with db.session() as s:
        scan = ScanRepository(s).create(target_id, profile)
        scan_id = scan.id
        scan.status = "succeeded"
    return scan_id


class TestDeleteBlockedByDefault:
    def test_delete_without_history_succeeds(self, db):
        make_target(db)
        with db.session() as s:
            assert TargetRepository(s).delete("lab") is True

    def test_delete_with_history_raises_clear_error(self, db):
        row = make_target(db)
        make_scan(db, row.id)

        with db.session() as s:
            with pytest.raises(RepositoryError) as exc:
                TargetRepository(s).delete("lab")

        msg = str(exc.value)
        assert "Cannot delete target 'lab'" in msg
        assert "1 scan(s) reference it" in msg
        assert "/purge" in msg

    def test_scan_count_in_message_is_accurate(self, db):
        row = make_target(db)
        for _ in range(3):
            make_scan(db, row.id)

        with db.session() as s:
            with pytest.raises(RepositoryError) as exc:
                TargetRepository(s).delete("lab")
        assert "3 scan(s)" in str(exc.value)

    def test_delete_nonexistent_returns_false(self, db):
        with db.session() as s:
            assert TargetRepository(s).delete("ghost") is False

    def test_history_survives_a_blocked_delete(self, db):
        """The bug being fixed: no UPDATE ... SET NULL, no data loss."""
        row = make_target(db)
        for _ in range(3):
            make_scan(db, row.id)

        with db.session() as s:
            with pytest.raises(RepositoryError):
                TargetRepository(s).delete("lab")

        with db.session() as s:
            scans = ScanRepository(s).recent(row.id, limit=10)
            assert len(scans) == 3
            assert all(sc.target_id == row.id for sc in scans)


class TestPendingCounts:
    def test_counts_are_reported(self, db):
        row = make_target(db)
        for _ in range(2):
            make_scan(db, row.id)

        with db.session() as s:
            counts = TargetRepository(s).pending_counts(row.id)

        assert counts["targets"] == 1
        assert counts["scans"] == 2

    def test_zero_history_target(self, db):
        row = make_target(db)
        with db.session() as s:
            counts = TargetRepository(s).pending_counts(row.id)
        assert counts["scans"] == 0
        assert counts["hosts"] == 0


class TestPurge:
    def test_purge_removes_target_and_scans(self, db):
        row = make_target(db)
        ids = [make_scan(db, row.id) for _ in range(3)]

        with db.session() as s:
            counts = TargetRepository(s).purge("lab")

        assert counts["scans"] == 3
        assert counts["targets"] == 1

        with db.session() as s:
            assert TargetRepository(s).get_by_name("lab") is None
            for scan_id in ids:
                assert ScanRepository(s).get(scan_id) is None

    def test_purge_removes_hosts_services_and_changes(self, db):
        row = make_target(db)
        scan_id = make_scan(db, row.id)

        with db.session() as s:
            scans = ScanRepository(s)
            scan = scans.get(scan_id)
            scans.store_snapshot(
                scan,
                [{"address": "10.0.0.1", "state": "up"}],
                {"10.0.0.1": [{"port": 22, "protocol": "tcp", "state": "open",
                               "service_name": "ssh"}]},
            )
            from database.models import ChangeEvent

            ChangeRepository(s).add_all([
                ChangeEvent(scan_id=scan_id, change_type="new_host",
                            host="10.0.0.1")
            ])

        with db.session() as s:
            counts = TargetRepository(s).purge("lab")

        assert counts["hosts"] == 1
        assert counts["services"] == 1
        assert counts["change_events"] == 1

        with db.session() as s:
            assert ScanRepository(s).get(scan_id) is None

    def test_purge_nonexistent_raises(self, db):
        with db.session() as s:
            with pytest.raises(RepositoryError):
                TargetRepository(s).purge("ghost")


class TestRegistrySurface:
    def test_registry_delete_raises_on_history(self, db):
        registry = TargetRegistry(db)
        view = registry.add("lab", "192.168.1.0/24")
        row_id = None
        with db.session() as s:
            row_id = TargetRepository(s).get_by_name(view.name).id
        make_scan(db, row_id)

        with pytest.raises(RepositoryError):
            registry.delete("lab")

    def test_registry_purge_and_history_count(self, db):
        registry = TargetRegistry(db)
        registry.add("lab", "192.168.1.0/24")
        with db.session() as s:
            row_id = TargetRepository(s).get_by_name("lab").id
        for _ in range(2):
            make_scan(db, row_id)

        pending = registry.history_count("lab")
        assert pending["scans"] == 2

        counts = registry.purge("lab")
        assert counts["scans"] == 2
        assert registry.list() == []

    def test_only_the_purged_target_is_affected(self, db):
        registry = TargetRegistry(db)
        registry.add("keep", "192.168.1.0/24")
        registry.add("drop", "10.0.0.0/24")
        with db.session() as s:
            drop_id = TargetRepository(s).get_by_name("drop").id
        make_scan(db, drop_id)

        registry.purge("drop")
        assert [t.name for t in registry.list()] == ["keep"]