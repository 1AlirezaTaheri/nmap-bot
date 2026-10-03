"""Tests for detached-instance safety.

Regression tests for a real bug: ``/scans <target>`` loaded ``Scan`` rows,
closed the session, then rendered them. ``scan_history()`` touched
``s.target.name``, a *lazy* relationship, which raised
``DetachedInstanceError`` once the session closed. The user only saw the
catch-all error message instead of their history.

Two layers are covered:
  1. the repository eager-loads ``target`` so it is safe to detach;
  2. the formatter degrades gracefully even for rows it did not load.
"""

from __future__ import annotations

import pytest

from bot.messages import reports
from database.database import Database
from database.repository import ScanRepository, TargetRepository


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/t.db")
    database.create_all()
    yield database
    database.dispose()


def seed(db: Database, scans: int = 3, target_name: str = "home") -> int:
    """Create a target with a few scans and return its id."""
    with db.session() as s:
        target = TargetRepository(s).add(target_name, "192.168.174.0/24")
        target_id = target.id
    with db.session() as s:
        repo = ScanRepository(s)
        for i in range(scans):
            scan = repo.create(target_id, "service")
            scan.status = "succeeded" if i else "failed"
            scan.host_count = 2
            scan.service_count = 3
            scan.duration_ms = 1000 + i
    return target_id


class TestRecentEagerLoadsTarget:
    def test_target_accessible_after_session_closes(self, db):
        """The regression: this raised DetachedInstanceError before."""
        target_id = seed(db)

        with db.session() as s:
            rows = ScanRepository(s).recent(target_id, limit=10)

        # Session is closed here. Touching .target.name must still work.
        assert rows, "expected seeded scans"
        for row in rows:
            assert row.target is not None
            assert row.target.name == "home"

    def test_recent_still_returns_correct_order_and_count(self, db):
        target_id = seed(db, scans=3)
        with db.session() as s:
            rows = ScanRepository(s).recent(target_id, limit=10)

        assert len(rows) == 3
        assert [r.id for r in rows] == sorted((r.id for r in rows), reverse=True)

    def test_limit_is_honoured(self, db):
        target_id = seed(db, scans=5)
        with db.session() as s:
            rows = ScanRepository(s).recent(target_id, limit=2)
        assert len(rows) == 2


class TestLatestSucceededEagerLoads:
    def test_detached_baseline_has_hosts_and_services(self, db):
        target_id = seed(db, scans=2)  # scan #1 failed, #2 succeeded

        with db.session() as s:
            baseline = ScanRepository(s).latest_succeeded(target_id, "service")

        # Session is closed here; baseline must be usable anyway.
        assert baseline is not None
        assert baseline.status == "succeeded"
        for host in baseline.hosts:
            list(host.services)  # must not raise DetachedInstanceError


class TestScanHistoryIsDefensive:
    def test_renders_detached_rows(self, db):
        target_id = seed(db, scans=3)

        with db.session() as s:
            rows = ScanRepository(s).recent(target_id, limit=10)

        text = reports.scan_history("en", rows)
        assert isinstance(text, str)
        assert "Scan history" in text
        assert "home" in text

    def test_handles_row_with_no_target_loaded(self, db):
        """A bare object with no target attribute must not explode."""
        target_id = seed(db, scans=1)
        with db.session() as s:
            rows = ScanRepository(s).recent(target_id, limit=10)

        class Bare:
            id = 99
            profile = "quick"
            status = "succeeded"
            started_at = None
            host_count = 1
            service_count = 2
            target = None

        text = reports.scan_history("en", [Bare(), *rows])
        assert "#99" in text
        assert "?" in text

    def test_handles_raising_target_property(self, db):
        """getattr cannot save us here: DetachedInstanceError is not
        AttributeError, so the formatter must use try/except."""

        class Hostile:
            id = 7
            profile = "deep"
            status = "failed"
            started_at = None
            host_count = 0
            service_count = 0

            @property
            def target(self):
                raise RuntimeError("detached!")

        text = reports.scan_history("en", [Hostile()])
        assert "#7" in text
        assert "?" in text

    def test_empty_list(self):
        assert reports.scan_history("en", []) == "No scans recorded yet."

    def test_missing_started_at_renders_placeholder(self, db):
        target_id = seed(db, scans=1)
        with db.session() as s:
            rows = ScanRepository(s).recent(target_id, limit=10)
        for row in rows:
            row.started_at = None
        text = reports.scan_history("en", rows)
        assert "?" in text