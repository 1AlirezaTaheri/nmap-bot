"""Tests for the retention policy.

Selection rule (see ``ScanRepository.deletable_ids``): a scan is deleted
only when it is outside the age window AND not protected. Protection:
the newest ``keep_per_target`` scans, plus the newest *succeeded* scan.

The baseline rule dominates: since the newest succeeded scan is always
protected, a test that wants rows deleted must make those rows either
``failed`` or older than a newer baseline.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from core.retention import RetentionService
from database.database import Database
from database.models import ChangeEvent, Host, Scan, Service
from database.repository import ScanRepository, TargetRepository


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/t.db")
    database.create_all()
    yield database
    database.dispose()


def add_scan(db, target_id, *, status="succeeded", age_days=0, profile="service"):
    """Insert a finished scan with a controlled age."""
    with db.session() as s:
        repo = ScanRepository(s)
        scan = repo.create(target_id, profile)
        scan.status = status
        scan.finished_at = datetime.utcnow() - timedelta(days=age_days)
        scan.started_at = scan.finished_at
        scan.host_count = 0
        scan.service_count = 0
        return scan.id


def doomed_ids(db, target_id, *, keep_days=30, keep_per_target=100):
    with db.session() as s:
        return ScanRepository(s).deletable_ids(
            target_id, keep_days=keep_days, keep_per_target=keep_per_target
        )


class TestDeletableIds:
    def test_keeps_recent_scans(self, db):
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        for _ in range(5):
            add_scan(db, tid, age_days=1)
        assert doomed_ids(db, tid) == []

    def test_deletes_scans_beyond_count(self, db):
        """All old and failed, so only the count cap and baseline protect."""
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        ids = [add_scan(db, tid, status="failed", age_days=60) for _ in range(5)]

        doomed = set(doomed_ids(db, tid, keep_per_target=2))
        assert doomed == set(ids[:3])
        assert ids[-1] not in doomed   # newest 2 protected by count
        assert ids[-2] not in doomed

    def test_recent_scans_survive_the_count_cap(self, db):
        """Inside the age window nothing is deleted, however many there are."""
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        for _ in range(5):
            add_scan(db, tid, status="failed", age_days=1)
        assert doomed_ids(db, tid, keep_per_target=2) == []

    def test_deletes_old_failed_scan_past_baseline(self, db):
        """An old failed scan older than a newer baseline is deletable."""
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        add_scan(db, tid, status="succeeded", age_days=40)   # baseline
        stale = add_scan(db, tid, status="failed", age_days=90)

        doomed = doomed_ids(db, tid, keep_days=30, keep_per_target=1)
        assert stale in doomed

    def test_never_deletes_the_baseline(self, db):
        """THE invariant: an old successful scan is kept as baseline."""
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        baseline = add_scan(db, tid, status="succeeded", age_days=365)
        for i in range(3):
            add_scan(db, tid, status="failed", age_days=400 - i)

        doomed = doomed_ids(db, tid, keep_days=7, keep_per_target=1)
        assert baseline not in doomed

    def test_baseline_is_newest_successful_only(self, db):
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        older = add_scan(db, tid, status="succeeded", age_days=100)
        newer = add_scan(db, tid, status="succeeded", age_days=80)

        doomed = doomed_ids(db, tid, keep_days=7, keep_per_target=1)
        assert newer not in doomed   # newest succeeded = baseline
        assert older in doomed

    def test_target_with_no_scans(self, db):
        with db.session() as s:
            tid = TargetRepository(s).add("empty", "10.0.0.0/24").id
        assert doomed_ids(db, tid) == []


class TestRetentionService:
    def test_deletes_in_fk_order(self, db):
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        # a newer baseline protects only itself
        add_scan(db, tid, status="succeeded", age_days=1)
        doomed_scan = add_scan(db, tid, status="failed", age_days=200)

        with db.session() as s:
            host = Host(scan_id=doomed_scan, address="10.0.0.9", state="up")
            s.add(host)
            s.flush()
            s.add(Service(host_id=host.id, port=22, protocol="tcp", state="open",
                         service_name="ssh"))
            s.add(ChangeEvent(scan_id=doomed_scan, change_type="new_host",
                              host="10.0.0.9"))

        report = RetentionService(db).run(keep_days=30, keep_per_target=1)

        assert report.scans_deleted == 1
        assert report.hosts_deleted == 1
        assert report.services_deleted == 1
        assert report.change_events_deleted == 1
        assert report.total_rows == 4

        with db.session() as s:
            assert s.get(Scan, doomed_scan) is None
            assert s.query(Host).filter(Host.scan_id == doomed_scan).count() == 0

    def test_preserves_baseline_in_a_real_run(self, db):
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        baseline = add_scan(db, tid, status="succeeded", age_days=500)
        junk = [
            add_scan(db, tid, status="failed", age_days=400 - i)
            for i in range(3)
        ]

        RetentionService(db).run(keep_days=7, keep_per_target=1)

        with db.session() as s:
            assert s.get(Scan, baseline) is not None
            # the newest junk scan is protected by the count cap of 1
            assert s.get(Scan, junk[-1]) is not None
            assert s.get(Scan, junk[0]) is None
            assert s.get(Scan, junk[1]) is None

    def test_multiple_targets_are_independent(self, db):
        with db.session() as s:
            a = TargetRepository(s).add("a", "10.0.0.0/24").id
            b = TargetRepository(s).add("b", "10.1.0.0/24").id
        keep_a = add_scan(db, a, age_days=0)
        add_scan(db, b, status="succeeded", age_days=1)      # b baseline
        old_b = add_scan(db, b, status="failed", age_days=99)

        report = RetentionService(db).run(keep_days=30, keep_per_target=1)

        with db.session() as s:
            assert s.get(Scan, keep_a) is not None
            assert s.get(Scan, old_b) is None
        assert report.targets_scanned == 2

    def test_report_text(self, db):
        report = RetentionService(db).run(keep_days=30, keep_per_target=10)
        assert "Cleanup complete" in report.text()
        assert "total rows" in report.text()