"""Tests for panel-originated scans.

The important ones here are negative. A scan endpoint that reaches the network
is a capability, and the failure mode to guard against is a second front door
that quietly skips a gate the Telegram path enforces. So:

  * every gate refuses on its own, and each refusal is asserted individually
  * the rate limiter is shared with Telegram rather than a second budget
  * requested_by stays NULL, so no Telegram user's scan_count is inflated
  * provenance lands in the audit log under ACTOR_ADMIN instead
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

from admin.services import auth as auth_service  # noqa: E402
from admin.services import users as user_service  # noqa: E402
from config.settings import Settings  # noqa: E402

PASSWORD = "an-initial-admin-password"


class FakeWorker:
    """Records submissions instead of running nmap.

    Also models the worker having no async lock, because the handler must not
    care: it only awaits next_job_id() and submit().
    """

    def __init__(self):
        self.jobs = []
        self._next = 1

    async def next_job_id(self) -> int:
        value = self._next
        self._next += 1
        return value

    async def submit(self, job) -> None:
        self.jobs.append(job)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/scan.db")
    monkeypatch.setenv("ADMIN_JWT_SECRET", "test-secret-not-for-production")
    from fastapi.testclient import TestClient

    from admin.services.bootstrap import create_app

    app = create_app(Settings.from_env())
    with TestClient(app) as c:
        c.app_ctx = app
        c.worker = FakeWorker()
        app.state.ctx.scan_worker = c.worker
        yield c


@pytest.fixture
def auth_client(client):
    resp = client.post("/api/login", json={"username": "root", "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return client


def seed_target(client, name="scan-target", value="192.0.2.0/24", enabled=True):
    """A target the authorizer will permit (documentation range, in scope)."""
    from database.models import Target

    db = client.app_ctx.state.ctx.database
    with db.session() as session:
        row = Target(name=name, value=value, enabled=1 if enabled else 0)
        session.add(row)
        session.flush()
        return row.id


# ---------------------------------------------------------------------------
# registration and gating
# ---------------------------------------------------------------------------
class TestRegistration:
    def test_routes_registered(self, client):
        paths = set(client.app_ctx.openapi()["paths"])
        assert "/api/targets/{target_id}/scan" in paths
        assert "/api/targets/{target_id}/scan/active" in paths

    def test_requires_auth(self, client):
        seed_target(client)
        assert client.post("/api/targets/1/scan", json={}).status_code == 401

    def test_viewer_cannot_scan(self, client):
        """Scanning reaches the network, so it is not a viewer action."""
        with client.app_ctx.state.ctx.database.session() as session:
            user_service.create_admin(
                session, "scan-viewer",
                auth_service.hash_password("viewer-password-123"),
                role="viewer",
            )
        client.cookies.clear()
        resp = client.post(
            "/api/login",
            json={"username": "scan-viewer", "password": "viewer-password-123"},
        )
        assert resp.status_code == 200, resp.text
        tid = seed_target(client)
        assert client.post(f"/api/targets/{tid}/scan", json={}).status_code == 403

    def test_admin_can_reach_the_handler(self, client):
        """A viewer is refused; the route is not simply broken for everyone."""
        with client.app_ctx.state.ctx.database.session() as session:
            user_service.create_admin(
                session, "scan-admin",
                auth_service.hash_password("admin-password-12345"),
                role="admin",
            )
        client.cookies.clear()
        assert client.post(
            "/api/login",
            json={"username": "scan-admin", "password": "admin-password-12345"},
        ).status_code == 200
        tid = seed_target(client)
        resp = client.post(f"/api/targets/{tid}/scan", json={})
        assert resp.status_code == 202, resp.text


# ---------------------------------------------------------------------------
# the happy path, and what it must not do
# ---------------------------------------------------------------------------
class TestQueueing:
    def test_returns_202_and_a_job_id(self, auth_client):
        tid = seed_target(auth_client)
        resp = auth_client.post(f"/api/targets/{tid}/scan", json={})
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["state"] == "queued"
        assert isinstance(body["job_id"], int)
        assert body["target"] == "scan-target"

    def test_no_body_still_works(self, auth_client):
        tid = seed_target(auth_client)
        assert auth_client.post(f"/api/targets/{tid}/scan").status_code == 202

    def test_job_carries_the_right_shape(self, auth_client):
        tid = seed_target(auth_client, value="192.0.2.0/24")
        auth_client.post(f"/api/targets/{tid}/scan", json={"profile": "quick"})
        job = auth_client.worker.jobs[0]
        assert job.target_name == "scan-target"
        assert job.target_value == "192.0.2.0/24"
        assert job.source == "panel"
        assert job.actor_username == "root"

    def test_requested_by_is_null(self, auth_client):
        """The collision guard.

        Scan.requested_by is the *Telegram* id and the Telegram-user list joins
        it against telegram_user_id for scan counts. An admin id here would
        inflate an unrelated user's tally.
        """
        tid = seed_target(auth_client)
        auth_client.post(f"/api/targets/{tid}/scan", json={})
        assert auth_client.worker.jobs[0].requested_by is None

    def test_chat_id_is_zero(self, auth_client):
        """There is no originating conversation; the bot routes on that."""
        tid = seed_target(auth_client)
        auth_client.post(f"/api/targets/{tid}/scan", json={})
        assert auth_client.worker.jobs[0].chat_id == 0

    def test_panel_scans_do_not_inflate_a_telegram_scan_count(
        self, auth_client
    ):
        """The concrete harm requested_by=None prevents."""
        db = auth_client.app_ctx.state.ctx.database
        with db.session() as session:
            # A Telegram user whose id happens to equal an admin id.
            user_service.upsert_telegram_user(session, 1, username="collide")
        tid = seed_target(auth_client)
        auth_client.post(f"/api/targets/{tid}/scan", json={})

        with db.session() as session:
            rows = user_service.list_telegram_users(session)
        collide = next(r for r in rows if r["telegram_user_id"] == 1)
        assert collide["scan_count"] == 0

    def test_provenance_is_in_the_audit_log(self, auth_client):
        tid = seed_target(auth_client)
        auth_client.post(f"/api/targets/{tid}/scan", json={})

        from sqlalchemy import select

        from database.models import AuditLog

        with auth_client.app_ctx.state.ctx.database.session() as session:
            rows = list(session.scalars(
                select(AuditLog).where(AuditLog.action == "scan.requested")
            ))
        assert rows, "no scan.requested audit row"
        row = rows[-1]
        assert row.actor_type == "admin"
        assert row.actor_username == "root"
        assert row.target_id == "scan-target"

    def test_unknown_profile_is_400(self, auth_client):
        tid = seed_target(auth_client)
        resp = auth_client.post(
            f"/api/targets/{tid}/scan", json={"profile": "no-such-profile"}
        )
        assert resp.status_code == 400
        assert auth_client.worker.jobs == []


# ---------------------------------------------------------------------------
# the gates, one at a time
# ---------------------------------------------------------------------------
class TestGates:
    def test_unknown_target_is_404(self, auth_client):
        resp = auth_client.post("/api/targets/999999/scan", json={})
        assert resp.status_code == 404
        assert auth_client.worker.jobs == []

    def test_disabled_target_is_refused(self, auth_client):
        tid = seed_target(auth_client, enabled=False)
        resp = auth_client.post(f"/api/targets/{tid}/scan", json={})
        assert resp.status_code == 400
        assert auth_client.worker.jobs == []

    def test_in_scope_target_is_accepted(self, auth_client):
        """No ALLOWED_CIDRS configured means the authorizer permits everything.

        Documented behaviour: `assert_target_permitted` returns the validated
        target unchanged when no scope is set. This test exists so the refusal
        test below is not mistaken for a general "everything is refused".
        """
        tid = seed_target(auth_client, value="10.255.255.0/24")
        assert auth_client.post(f"/api/targets/{tid}/scan", json={}).status_code == 202

    def test_out_of_scope_target_is_403(self, tmp_path, monkeypatch):
        """assert_target_permitted runs before anything is queued.

        ALLOWED_CIDRS has to be set for this gate to engage at all, so a fresh
        app is built with the scope set. It gets its own tmp_path rather than
        reusing another fixture's database: an earlier version derived a
        *relative* DATABASE_URL from the existing one, so every test in this
        module silently shared a single file in the working directory and the
        target names collided on their unique constraint.
        """
        monkeypatch.setenv("ALLOWED_CIDRS", "192.168.0.0/16")
        monkeypatch.setenv(
            "DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/scoped.db"
        )

        from fastapi.testclient import TestClient as TC

        from admin.services.bootstrap import create_app

        from database.models import Target as TargetModel

        scoped = create_app(Settings.from_env())
        worker = FakeWorker()
        scoped.state.ctx.scan_worker = worker

        with TC(scoped) as c:
            assert c.post(
                "/api/login",
                json={"username": "root", "password": PASSWORD},
            ).status_code == 200

            with scoped.state.ctx.database.session() as session:
                out_row = TargetModel(
                    name="scoped-out", value="10.255.255.0/24", enabled=1
                )
                in_row = TargetModel(
                    name="scoped-in", value="192.168.9.0/24", enabled=1
                )
                session.add_all([out_row, in_row])
                session.flush()
                out_id, in_id = out_row.id, in_row.id

            resp = c.post(f"/api/targets/{out_id}/scan", json={})
            assert resp.status_code == 403, resp.text
            assert worker.jobs == [], "an out-of-scope target was queued"

            # And a target inside the configured scope still works, so the
            # refusal above is the scope and not a blanket failure.
            assert c.post(
                f"/api/targets/{in_id}/scan", json={}
            ).status_code == 202

    def test_no_worker_is_503(self, auth_client):
        auth_client.app_ctx.state.ctx.scan_worker = None
        tid = seed_target(auth_client)
        resp = auth_client.post(f"/api/targets/{tid}/scan", json={})
        assert resp.status_code == 503

    def test_rate_limiter_refuses_a_repeat(self, auth_client):
        """The limiter is shared and keyed on the target name, so the panel
        cannot start a second scan the limiter would have refused."""
        tid = seed_target(auth_client)
        codes = [
            auth_client.post(f"/api/targets/{tid}/scan", json={}).status_code
            for _ in range(4)
        ]
        assert 429 in codes, codes
        assert len(auth_client.worker.jobs) < 4

    def test_rate_limiter_is_per_target(self, auth_client):
        """One target's exhausted budget must not block another."""
        a = seed_target(auth_client, name="limit-a", value="192.0.2.0/24")
        b = seed_target(auth_client, name="limit-b", value="198.51.100.0/24")
        for _ in range(4):
            auth_client.post(f"/api/targets/{a}/scan", json={})
        assert auth_client.post(f"/api/targets/{b}/scan", json={}).status_code == 202


# ---------------------------------------------------------------------------
# active-scan polling
# ---------------------------------------------------------------------------
class TestActiveScan:
    def test_null_when_nothing_running(self, auth_client):
        tid = seed_target(auth_client)
        assert auth_client.get(f"/api/targets/{tid}/scan/active").json() == {
            "scan": None
        }

    def test_reports_a_running_scan(self, auth_client):
        from database.models import Scan

        tid = seed_target(auth_client)
        db = auth_client.app_ctx.state.ctx.database
        with db.session() as session:
            session.add(
                Scan(target_id=tid, profile="service", status="running",
                     source="panel")
            )
        body = auth_client.get(f"/api/targets/{tid}/scan/active").json()
        assert body["scan"]["status"] == "running"
        assert body["scan"]["source"] == "panel"

    def test_ignores_finished_scans(self, auth_client):
        from database.models import Scan

        tid = seed_target(auth_client)
        db = auth_client.app_ctx.state.ctx.database
        with db.session() as session:
            session.add(
                Scan(target_id=tid, profile="service", status="completed",
                     source="panel")
            )
        assert auth_client.get(f"/api/targets/{tid}/scan/active").json() == {
            "scan": None
        }

    def test_scoped_to_the_target(self, auth_client):
        from database.models import Scan

        a = seed_target(auth_client, name="act-a", value="192.0.2.0/24")
        b = seed_target(auth_client, name="act-b", value="198.51.100.0/24")
        db = auth_client.app_ctx.state.ctx.database
        with db.session() as session:
            session.add(
                Scan(target_id=a, profile="service", status="running",
                     source="panel")
            )
        assert auth_client.get(f"/api/targets/{b}/scan/active").json() == {
            "scan": None
        }


# ---------------------------------------------------------------------------
# delivery routing
# ---------------------------------------------------------------------------
class TestDeliveryRouting:
    def test_panel_is_routed_like_scheduled(self):
        """bot/app.py must route "panel" down the no-conversation branch.

        Sending to chat_id 0 raises inside Telegram's client, and that send
        happens before the scan.completed audit row -- so without this the scan
        would complete with no audit trail and an exception in the bot log on
        every single one.
        """
        import inspect

        import bot.app as app_mod

        src = inspect.getsource(app_mod)
        assert 'if job.source in ("scheduled", "panel"):' in src, (
            "panel jobs would be sent to chat_id 0 and never audited"
        )

    def test_audit_details_record_the_real_source(self):
        """The branch matches on "panel" but the row must say "panel"."""
        import inspect

        import bot.app as app_mod

        src = inspect.getsource(app_mod)
        assert '"source": job.source,' in src, (
            "the audit row would claim a panel scan was scheduled"
        )

    def test_panel_source_fits_the_column(self):
        """Scan.source is String(16); "panel" fits with room to spare."""
        from database.models import Scan

        assert Scan.__table__.c.source.type.length >= len("panel")