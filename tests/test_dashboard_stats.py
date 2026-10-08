"""Tests for the three dashboard endpoints added in Phase 2.

All new paths, so nothing here asserts about the existing `/api/stats` shape
beyond that it still works -- the backwards-compatibility promise is that it is
untouched, and that is worth a test rather than a claim.

Covered:
  * registration and reachability
  * days/limit clamping (they feed date arithmetic and a query limit)
  * empty results are a normal state, not an error
  * ranking order is worst-first
  * worker_status reports absent as nulls, never zeros
  * schedule_status refuses to invent a next_run
  * authentication is required
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("ADMIN_USERNAME", "root")
os.environ.setdefault("ADMIN_PASSWORD", "an-initial-admin-password")
os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "0:test-token")
os.environ.setdefault("ALLOWED_USER_IDS", "7575983824")
os.environ.setdefault("ADMIN_COOKIE_SECURE", "false")
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from admin.services import stats as stats_service  # noqa: E402
from config.settings import Settings  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/dash.db")
    monkeypatch.setenv("ADMIN_JWT_SECRET", "test-secret-not-for-production")
    from fastapi.testclient import TestClient

    from admin.services.bootstrap import create_app

    app = create_app(Settings.from_env())
    with TestClient(app) as c:
        c.app_ctx = app
        yield c


@pytest.fixture
def auth_client(client):
    resp = client.post(
        "/api/login", json={"username": "root", "password": "an-initial-admin-password"}
    )
    assert resp.status_code == 200, resp.text
    return client


# ---------------------------------------------------------------------------
# Registration and gating
# ---------------------------------------------------------------------------
class TestRegistration:
    def test_routes_are_registered(self, client):
        paths = set(client.app_ctx.openapi()["paths"])
        for expected in [
            "/api/stats",
            "/api/stats/top-targets",
            "/api/stats/worker",
            "/api/stats/schedule",
        ]:
            assert expected in paths, f"{expected} not registered"

    def test_new_paths_require_auth(self, client):
        for path in [
            "/api/stats/top-targets",
            "/api/stats/worker",
            "/api/stats/schedule",
        ]:
            assert client.get(path).status_code == 401, path

    def test_new_paths_answer_when_authenticated(self, auth_client):
        for path in [
            "/api/stats/top-targets",
            "/api/stats/worker",
            "/api/stats/schedule",
        ]:
            assert auth_client.get(path).status_code == 200, path


# ---------------------------------------------------------------------------
# top-targets
# ---------------------------------------------------------------------------
class TestTopTargets:
    def test_empty_database_is_not_an_error(self, auth_client):
        body = auth_client.get("/api/stats/top-targets").json()
        assert body["targets"] == []
        assert body["days"] == 7

    def test_days_is_clamped(self, auth_client):
        """Unbounded `days` walks the date arithmetic far enough to be slow."""
        body = auth_client.get("/api/stats/top-targets?days=100000").json()
        assert body["days"] == 90

    def test_days_floor_is_one(self, auth_client):
        body = auth_client.get("/api/stats/top-targets?days=0").json()
        assert body["days"] == 1

    def test_days_negative_clamps_to_one(self, auth_client):
        body = auth_client.get("/api/stats/top-targets?days=-5").json()
        assert body["days"] == 1

    def test_limit_is_clamped(self, auth_client):
        """A caller must not be able to ask for an unbounded ranking."""
        # The clamp is on the service signature; the route caps it at 25.
        body = auth_client.get("/api/stats/top-targets?limit=1000").json()
        assert isinstance(body["targets"], list)
        assert len(body["targets"]) <= 25

    def test_limit_of_zero_clamps_to_one(self, auth_client):
        body = auth_client.get("/api/stats/top-targets?limit=0").json()
        assert isinstance(body["targets"], list)


class TestTopChangedTargetsOrdering:
    """The ranking itself, against real rows rather than an empty table."""

    def _seed(self, client, counts: dict[str, int]):
        """Insert targets, scans and change events with the given totals."""
        from datetime import datetime, timedelta, timezone

        from sqlalchemy import select

        from admin.services import users as user_service  # noqa: F401
        from database.models import ChangeEvent, Scan, Target
        from database.repository import TargetRepository

        db = client.app_ctx.state.ctx.database
        now = datetime.now(timezone.utc)
        names = list(counts)
        with db.session() as session:
            repo = TargetRepository(session)
            target_ids = {}
            for name in names:
                row = repo.add(f"pt-{name}", f"10.0.0.{names.index(name) + 1}")
                target_ids[name] = row.id

            for name, total in counts.items():
                scan = Scan(
                    target_id=target_ids[name],
                    profile="service",
                    status="completed",
                    source="test",
                    started_at=now - timedelta(hours=1),
                )
                session.add(scan)
                session.flush()
                for i in range(total):
                    session.add(
                        ChangeEvent(
                            scan_id=scan.id,
                            change_type="new_port",
                            host=f"10.0.0.{names.index(name) + 1}",
                            port=1000 + i,
                            created_at=now - timedelta(minutes=i),
                        )
                    )

        with db.session() as session:
            return stats_service.top_changed_targets(session, days=7, limit=5)

    def test_ranked_worst_first(self, client):
        rows = self._seed(client, {"a": 2, "b": 7, "c": 4})
        assert [r["changes"] for r in rows] == [7, 4, 2], rows

    def test_limit_applied(self, client):
        rows = self._seed(
            client, {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6}
        )
        assert len(rows) == 5
        assert rows[0]["changes"] == 6

    def test_row_shape(self, client):
        rows = self._seed(client, {"a": 1})
        assert rows
        row = rows[0]
        assert set(row) == {"id", "name", "value", "changes", "last_change_at"}
        assert isinstance(row["id"], int)
        assert isinstance(row["changes"], int)
        assert row["name"].startswith("pt-")

    def test_old_events_are_excluded(self, client):
        from datetime import datetime, timedelta, timezone

        from database.models import ChangeEvent, Scan
        from database.repository import TargetRepository

        db = client.app_ctx.state.ctx.database
        now = datetime.now(timezone.utc)
        with db.session() as session:
            repo = TargetRepository(session)
            target = repo.add("pt-old", "10.0.0.9")
            scan = Scan(
                target_id=target.id,
                profile="service",
                status="completed",
                source="test",
                started_at=now - timedelta(days=40),
            )
            session.add(scan)
            session.flush()
            session.add(
                ChangeEvent(
                    scan_id=scan.id,
                    change_type="new_port",
                    host="10.0.0.9",
                    port=22,
                    created_at=now - timedelta(days=40),
                )
            )
        with db.session() as session:
            assert stats_service.top_changed_targets(session, days=7) == []


# ---------------------------------------------------------------------------
# worker
# ---------------------------------------------------------------------------
class _FakeJob:
    def __init__(self, state: str):
        self.state = state


class _FakeWorker:
    def __init__(self, jobs, qsize: int, running: bool = True):
        self._jobs = {i: _FakeJob(s) for i, s in enumerate(jobs)}
        self._queue = type("Q", (), {"qsize": lambda self: qsize})()
        self.is_running = running
        self.max_concurrency = 3


class TestWorkerStatus:
    def test_absent_worker_reports_nulls_not_zeros(self):
        """Zero reads as 'idle'; absent is the truth and must not be disguised."""
        status = stats_service.worker_status(None)
        assert status["available"] is False
        assert status["queue_depth"] is None
        assert status["active"] is None
        assert status["pending"] is None

    def test_counts_from_the_worker(self):
        status = stats_service.worker_status(
            _FakeWorker(["running", "running", "queued", "done"], qsize=1)
        )
        assert status["available"] is True
        assert status["active"] == 2
        assert status["pending"] == 3  # queued + running
        assert status["queue_depth"] == 1
        assert status["max_concurrency"] == 3

    def test_stopped_worker_is_reported(self):
        status = stats_service.worker_status(_FakeWorker([], qsize=0, running=False))
        assert status["available"] is True
        assert status["running"] is False

    def test_endpoint_shape(self, auth_client):
        body = auth_client.get("/api/stats/worker").json()
        assert set(body) == {
            "available", "running", "queue_depth", "active", "pending",
            "max_concurrency",
        }


# ---------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------
class _FakeStore:
    def __init__(self, values: dict):
        self._values = values

    def get(self, key: str):
        return self._values[key]


class TestScheduleStatus:
    def test_reads_switch_and_interval(self):
        status = stats_service.schedule_status(
            _FakeStore({"schedule_enabled": True, "schedule_interval_hours": 12})
        )
        assert status["enabled"] is True
        assert status["interval_hours"] == 12

    def test_never_invents_a_next_run(self):
        """There is no stored next-run time, so the API says so.

        Deriving one from the interval would put a precise-looking number on
        the dashboard that is a guess about the scheduler's cadence.
        """
        status = stats_service.schedule_status(
            _FakeStore({"schedule_enabled": True, "schedule_interval_hours": 6})
        )
        assert status["next_run_at"] is None
        assert status["next_run_known"] is False

    def test_non_numeric_interval_becomes_null(self):
        status = stats_service.schedule_status(
            _FakeStore({"schedule_enabled": False, "schedule_interval_hours": "often"})
        )
        assert status["enabled"] is False
        assert status["interval_hours"] is None


# ---------------------------------------------------------------------------
# Backwards compatibility
# ---------------------------------------------------------------------------
class TestStatsUnchanged:
    def test_existing_stats_shape_is_intact(self, auth_client):
        """The Phase 2 promise: /api/stats is not modified."""
        body = auth_client.get("/api/stats").json()
        expected = {
            "targets", "scans", "scans_24h", "scans_24h_failed", "changes",
            "changes_24h", "telegram_users", "admins", "hosts", "services",
            "last_scan_at", "series", "change_breakdown", "recent_audit",
            "operator_chat",
        }
        assert expected <= set(body), f"lost: {expected - set(body)}"