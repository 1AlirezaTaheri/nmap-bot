"""Tests for the three target-detail endpoints added in Phase 3.

The pre-existing `/targets/{id}/scans` and `/targets/{id}/changes` are reused
untouched; what is new is the header, the timeline and the hosts payload.

The IDOR case is the one worth the most attention here: a valid scan id read
through a target id that does not own it. Without the ownership check the
endpoint would let any caller read any scan's host inventory by guessing ids.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

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

PASSWORD = "an-initial-admin-password"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/td.db")
    monkeypatch.setenv("ADMIN_JWT_SECRET", "test-secret-not-for-production")
    from fastapi.testclient import TestClient

    from admin.services.bootstrap import create_app

    app = create_app(Settings.from_env())
    with TestClient(app) as c:
        c.app_ctx = app
        yield c


@pytest.fixture
def auth_client(client):
    resp = client.post("/api/login", json={"username": "root", "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return client


# ---------------------------------------------------------------------------
# seeding helpers
# ---------------------------------------------------------------------------
def seed_target(client, name: str, value: str, group: str | None = None) -> int:
    from database.repository import TargetRepository

    db = client.app_ctx.state.ctx.database
    with db.session() as session:
        return TargetRepository(session).add(name, value, group).id


def seed_scan(
    client,
    target_id: int,
    profile: str = "service",
    status: str = "completed",
    days_ago: int = 0,
    hosts: list[tuple[str, list[tuple[int, str, str | None]]]] | None = None,
) -> int:
    """Insert a scan, optionally with hosts and services."""
    from database.models import Host, Scan, Service

    db = client.app_ctx.state.ctx.database
    now = datetime.now(timezone.utc)
    with db.session() as session:
        scan = Scan(
            target_id=target_id,
            profile=profile,
            status=status,
            source="test",
            started_at=now - timedelta(days=days_ago),
            finished_at=now - timedelta(days=days_ago),
            duration_ms=1234,
            host_count=len(hosts or []),
            service_count=sum(len(svc) for _, svc in (hosts or [])),
        )
        session.add(scan)
        session.flush()
        scan_id = scan.id

        for address, services in hosts or []:
            host = Host(scan_id=scan_id, address=address, state="up")
            session.add(host)
            session.flush()
            for port, proto, name in services:
                session.add(
                    Service(
                        host_id=host.id,
                        port=port,
                        protocol=proto,
                        state="open",
                        service_name=name,
                        product="test-product",
                        version="1.0",
                    )
                )
    return scan_id


# ---------------------------------------------------------------------------
# registration and gating
# ---------------------------------------------------------------------------
class TestRegistration:
    def test_routes_registered(self, client):
        paths = set(client.app_ctx.openapi()["paths"])
        for expected in [
            "/api/targets/{target_id}",
            "/api/targets/{target_id}/timeline",
            "/api/targets/{target_id}/scans/{scan_id}/hosts",
        ]:
            assert expected in paths, f"{expected} not registered"

    def test_all_require_auth(self, client):
        for path in [
            "/api/targets/1",
            "/api/targets/1/timeline",
            "/api/targets/1/scans/1/hosts",
        ]:
            assert client.get(path).status_code == 401, path

    def test_answer_when_authenticated(self, auth_client):
        for path in [
            "/api/targets/1",
            "/api/targets/1/timeline",
            "/api/targets/1/scans/1/hosts",
        ]:
            assert auth_client.get(path).status_code in (200, 404), path


# ---------------------------------------------------------------------------
# target_detail
# ---------------------------------------------------------------------------
class TestTargetDetail:
    def test_empty_database_404s(self, auth_client):
        assert auth_client.get("/api/targets/999999").status_code == 404

    def test_shape(self, auth_client):
        tid = seed_target(auth_client, "td-shape", "10.9.0.0/24", "lab")
        body = auth_client.get(f"/api/targets/{tid}").json()
        assert set(body) == {
            "id", "name", "value", "group", "enabled", "created_at",
            "scan_count", "schedule",
        }
        assert body["name"] == "td-shape"
        assert body["value"] == "10.9.0.0/24"
        assert body["group"] == "lab"
        assert body["enabled"] is True
        assert body["schedule"] is None
        assert body["scan_count"] == 0

    def test_group_maps_group_name(self, auth_client):
        """The column is `group_name`; the API field is `group`, matching
        /api/targets. Getting this wrong is a 500 on every request."""
        tid = seed_target(auth_client, "td-group", "10.9.1.0/24", "prod")
        body = auth_client.get(f"/api/targets/{tid}").json()
        assert body["group"] == "prod"

    def test_group_none_when_unset(self, auth_client):
        tid = seed_target(auth_client, "td-nogroup", "10.9.2.0/24")
        assert auth_client.get(f"/api/targets/{tid}").json()["group"] is None

    def test_scan_count_reflects_scans(self, auth_client):
        tid = seed_target(auth_client, "td-count", "10.9.3.0/24")
        seed_scan(auth_client, tid)
        seed_scan(auth_client, tid)
        assert auth_client.get(f"/api/targets/{tid}").json()["scan_count"] == 2

    def test_schedule_present_when_set(self, auth_client):
        """Seed a Schedule row directly.

        ScheduleRepository.set_enabled() takes only (target_id, enabled) --
        it flips an existing row and returns None when there is none. My first
        attempt passed four arguments, which the test would have reported as a
        TypeError rather than the shape mismatch I was actually looking for.
        """
        from datetime import datetime, timedelta, timezone

        from database.models import Schedule

        tid = seed_target(auth_client, "td-sched", "10.9.4.0/24")
        db = auth_client.app_ctx.state.ctx.database
        with db.session() as session:
            session.add(
                Schedule(
                    target_id=tid,
                    profile="service",
                    interval_hours=6,
                    enabled=True,
                    next_run_at=datetime.now(timezone.utc) + timedelta(hours=6),
                )
            )

        body = auth_client.get(f"/api/targets/{tid}").json()
        assert body["schedule"] is not None
        assert body["schedule"]["profile"] == "service"
        assert body["schedule"]["interval_hours"] == 6
        # A schedule row persists next_run_at, unlike the global scheduler.
        assert "next_run_at" in body["schedule"]


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------
class TestTimeline:
    def test_shape(self, auth_client):
        tid = seed_target(auth_client, "tl-shape", "10.9.5.0/24")
        body = auth_client.get(f"/api/targets/{tid}/timeline").json()
        assert body["target_id"] == tid
        assert body["days"] == 30
        assert len(body["series"]) == 30
        assert all(
            {"date", "scans", "failed", "changes"} <= set(p)
            for p in body["series"]
        )

    def test_gaps_are_zero_not_missing(self, auth_client):
        """A day with no activity must appear as a zero.

        Omitting it would make the chart skip a day, which reads as missing
        data rather than as nothing happening.
        """
        tid = seed_target(auth_client, "tl-gap", "10.9.6.0/24")
        seed_scan(auth_client, tid, days_ago=1)
        series = auth_client.get(f"/api/targets/{tid}/timeline?days=7").json()["series"]
        assert len(series) == 7
        assert sum(p["scans"] for p in series) == 1
        assert any(p["scans"] == 0 for p in series)

    def test_counts_todays_scan(self, auth_client):
        tid = seed_target(auth_client, "tl-today", "10.9.7.0/24")
        seed_scan(auth_client, tid, days_ago=0)
        seed_scan(auth_client, tid, days_ago=0)
        series = auth_client.get(f"/api/targets/{tid}/timeline").json()["series"]
        assert series[-1]["scans"] == 2

    def test_failed_counted_separately(self, auth_client):
        tid = seed_target(auth_client, "tl-fail", "10.9.8.0/24")
        seed_scan(auth_client, tid, status="completed")
        seed_scan(auth_client, tid, status="failed")
        series = auth_client.get(f"/api/targets/{tid}/timeline").json()["series"]
        assert series[-1]["scans"] == 2
        assert series[-1]["failed"] == 1

    def test_only_this_targets_scans(self, auth_client):
        a = seed_target(auth_client, "tl-a", "10.9.9.0/24")
        b = seed_target(auth_client, "tl-b", "10.9.10.0/24")
        seed_scan(auth_client, a)
        seed_scan(auth_client, b)
        seed_scan(auth_client, b)
        series = auth_client.get(f"/api/targets/{a}/timeline").json()["series"]
        assert sum(p["scans"] for p in series) == 1

    def test_old_scans_excluded(self, auth_client):
        tid = seed_target(auth_client, "tl-old", "10.9.11.0/24")
        seed_scan(auth_client, tid, days_ago=40)
        series = auth_client.get(f"/api/targets/{tid}/timeline?days=7").json()["series"]
        assert sum(p["scans"] for p in series) == 0

    def test_days_clamped_and_floored(self, auth_client):
        tid = seed_target(auth_client, "tl-clamp", "10.9.12.0/24")
        assert auth_client.get(
            f"/api/targets/{tid}/timeline?days=100000"
        ).json()["days"] == 365
        assert auth_client.get(
            f"/api/targets/{tid}/timeline?days=0"
        ).json()["days"] == 1
        assert auth_client.get(
            f"/api/targets/{tid}/timeline?days=-3"
        ).json()["days"] == 1

    def test_unknown_target_404s(self, auth_client):
        assert auth_client.get("/api/targets/999999/timeline").status_code == 404

    def test_no_future_buckets(self, auth_client):
        tid = seed_target(auth_client, "tl-future", "10.9.13.0/24")
        series = auth_client.get(f"/api/targets/{tid}/timeline").json()["series"]
        today = datetime.now(timezone.utc).date().isoformat()
        assert all(p["date"] <= today for p in series)

    def test_dates_ascending(self, auth_client):
        tid = seed_target(auth_client, "tl-order", "10.9.14.0/24")
        series = auth_client.get(f"/api/targets/{tid}/timeline").json()["series"]
        assert [p["date"] for p in series] == sorted(p["date"] for p in series)


# ---------------------------------------------------------------------------
# scan_hosts
# ---------------------------------------------------------------------------
class TestScanHosts:
    def test_unknown_scan_returns_none_from_the_service(self, auth_client):
        db = auth_client.app_ctx.state.ctx.database
        with db.session() as session:
            assert stats_service.scan_hosts(session, 999999) is None

    def test_empty_scan_returns_empty_lists(self, auth_client):
        tid = seed_target(auth_client, "sh-empty", "10.9.15.0/24")
        sid = seed_scan(auth_client, tid)
        body = auth_client.get(f"/api/targets/{tid}/scans/{sid}/hosts").json()
        assert body["hosts"] == []
        assert body["port_distribution"] == []
        assert body["scan"]["id"] == sid

    def test_hosts_and_services(self, auth_client):
        tid = seed_target(auth_client, "sh-rows", "10.9.16.0/24")
        sid = seed_scan(auth_client, tid, hosts=[
            ("10.9.16.5", [(22, "tcp", "ssh"), (80, "tcp", "http")]),
            ("10.9.16.6", [(22, "tcp", "ssh")]),
        ])
        body = auth_client.get(f"/api/targets/{tid}/scans/{sid}/hosts").json()
        assert len(body["hosts"]) == 2
        assert body["hosts"][0]["address"] == "10.9.16.5"
        assert len(body["hosts"][0]["services"]) == 2

    def test_services_sorted_by_port(self, auth_client):
        tid = seed_target(auth_client, "sh-sort", "10.9.17.0/24")
        sid = seed_scan(auth_client, tid, hosts=[
            ("10.9.17.5", [(443, "tcp", "https"), (22, "tcp", "ssh"), (80, "tcp", "http")]),
        ])
        body = auth_client.get(f"/api/targets/{tid}/scans/{sid}/hosts").json()
        ports = [s["port"] for s in body["hosts"][0]["services"]]
        assert ports == sorted(ports)

    def test_port_distribution_counts_across_hosts(self, auth_client):
        tid = seed_target(auth_client, "sh-dist", "10.9.18.0/24")
        sid = seed_scan(auth_client, tid, hosts=[
            ("10.9.18.5", [(22, "tcp", "ssh"), (80, "tcp", "http")]),
            ("10.9.18.6", [(22, "tcp", "ssh")]),
        ])
        body = auth_client.get(f"/api/targets/{tid}/scans/{sid}/hosts").json()
        dist = {d["port"]: d["count"] for d in body["port_distribution"]}
        assert dist == {22: 2, 80: 1}

    def test_port_distribution_descending(self, auth_client):
        tid = seed_target(auth_client, "sh-desc", "10.9.19.0/24")
        sid = seed_scan(auth_client, tid, hosts=[
            ("10.9.19.5", [(80, "tcp", "http")]),
            ("10.9.19.6", [(80, "tcp", "http"), (443, "tcp", "https")]),
        ])
        body = auth_client.get(f"/api/targets/{tid}/scans/{sid}/hosts").json()
        counts = [d["count"] for d in body["port_distribution"]]
        assert counts == sorted(counts, reverse=True)

    def test_unknown_scan_404s(self, auth_client):
        tid = seed_target(auth_client, "sh-404", "10.9.20.0/24")
        assert auth_client.get(
            f"/api/targets/{tid}/scans/999999/hosts"
        ).status_code == 404

    def test_scan_from_another_target_is_refused(self, auth_client):
        """The IDOR case.

        A valid scan id read through a target id that does not own it must not
        return the host inventory. Without the ownership check this endpoint
        would leak any scan to any caller who can guess ids.
        """
        owner = seed_target(auth_client, "sh-owner", "10.9.21.0/24")
        other = seed_target(auth_client, "sh-other", "10.9.22.0/24")
        sid = seed_scan(
            auth_client, owner,
            hosts=[("10.9.21.5", [(22, "tcp", "ssh")])],
        )
        assert auth_client.get(
            f"/api/targets/{owner}/scans/{sid}/hosts"
        ).status_code == 200
        assert auth_client.get(
            f"/api/targets/{other}/scans/{sid}/hosts"
        ).status_code == 404


# ---------------------------------------------------------------------------
# pre-existing routes untouched
# ---------------------------------------------------------------------------
class TestExistingRoutesUnchanged:
    def test_scans_still_works(self, auth_client):
        tid = seed_target(auth_client, "ex-scans", "10.9.23.0/24")
        seed_scan(auth_client, tid)
        resp = auth_client.get(f"/api/targets/{tid}/scans")
        assert resp.status_code == 200
        assert "scans" in resp.json()

    def test_changes_still_works(self, auth_client):
        tid = seed_target(auth_client, "ex-changes", "10.9.24.0/24")
        resp = auth_client.get(f"/api/targets/{tid}/changes")
        assert resp.status_code == 200
        assert "changes" in resp.json()

    def test_targets_list_shape_unchanged(self, auth_client):
        body = auth_client.get("/api/targets").json()
        assert "targets" in body
        assert isinstance(body["targets"], list)