"""Tests for Telegram/admin user management and dashboard statistics."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from admin.services import stats as stats_service
from admin.services import users as user_service
from admin.services.users import UserError
from admin.services.auth import hash_password
from database.database import Database
from database.models import ChangeEvent, Scan, Target


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/t.db")
    database.create_all()
    yield database
    database.dispose()


PASSWORD = "a-long-enough-password"


class TestAdminUsers:
    def test_create_and_read_back(self, db):
        with db.session() as s:
            row = user_service.create_admin(
                s, "root", hash_password(PASSWORD), role="superadmin"
            )
            assert row.id is not None
        with db.session() as s:
            found = user_service.get_admin_by_username(s, "root")
            assert found.role == "superadmin"

    def test_duplicate_username_rejected(self, db):
        with db.session() as s:
            user_service.create_admin(s, "root", hash_password(PASSWORD))
        with pytest.raises(UserError):
            with db.session() as s:
                user_service.create_admin(s, "root", hash_password(PASSWORD))

    def test_empty_username_rejected(self, db):
        with pytest.raises(UserError):
            with db.session() as s:
                user_service.create_admin(s, "  ", hash_password(PASSWORD))

    def test_bad_role_rejected(self, db):
        with pytest.raises(UserError):
            with db.session() as s:
                user_service.create_admin(
                    s, "root", hash_password(PASSWORD), role="wizard"
                )

    def test_count_and_touch_login(self, db):
        with db.session() as s:
            user_service.create_admin(s, "root", hash_password(PASSWORD))
        with db.session() as s:
            assert user_service.admin_count(s) == 1
            user_service.touch_login(s, 1)
        with db.session() as s:
            assert user_service.get_admin(s, 1).last_login_at is not None

    def test_count_admins_with_role(self, db):
        with db.session() as s:
            user_service.create_admin(s, "a", hash_password(PASSWORD), role="admin")
            user_service.create_admin(
                s, "b", hash_password(PASSWORD), role="superadmin"
            )
        with db.session() as s:
            assert user_service.count_admins_with_role(s, "superadmin") == 1


class TestTelegramUsers:
    def test_upsert_creates(self, db):
        with db.session() as s:
            row = user_service.upsert_telegram_user(
                s, 12345, username="alice", role="operator", language="en"
            )
            assert row.role == "operator"
            assert row.language == "en"
            assert row.enabled is True

    def test_upsert_is_idempotent(self, db):
        with db.session() as s:
            user_service.upsert_telegram_user(s, 12345, username="alice")
        with db.session() as s:
            user_service.upsert_telegram_user(s, 12345, username="alice2")
        with db.session() as s:
            assert len(user_service.list_telegram_users(s)) == 1

    def test_refresh_updates_username_only(self, db):
        with db.session() as s:
            user_service.upsert_telegram_user(
                s, 1, username="alice", role="admin", language="en"
            )
        with db.session() as s:
            user_service.upsert_telegram_user(s, 1, username="alice_new")
        with db.session() as s:
            row = user_service.get_telegram_user(s, 1)
            # the panel-set role and language must survive a bot heartbeat
            assert row.role == "admin"
            assert row.language == "en"
            assert row.username == "alice_new"

    def test_update_role_and_language(self, db):
        with db.session() as s:
            user_service.upsert_telegram_user(s, 1)
        with db.session() as s:
            row = user_service.update_telegram_user(
                s, 1, role="operator", language="fa"
            )
            assert row.role == "operator"
            assert row.language == "fa"

    def test_update_rejects_bad_role(self, db):
        with db.session() as s:
            user_service.upsert_telegram_user(s, 1)
        with pytest.raises(UserError):
            with db.session() as s:
                user_service.update_telegram_user(s, 1, role="wizard")

    def test_update_rejects_bad_language(self, db):
        with db.session() as s:
            user_service.upsert_telegram_user(s, 1)
        with pytest.raises(UserError):
            with db.session() as s:
                user_service.update_telegram_user(s, 1, language="de")

    def test_update_missing_user_raises(self, db):
        with pytest.raises(UserError):
            with db.session() as s:
                user_service.update_telegram_user(s, 999, role="admin")

    def test_disable(self, db):
        with db.session() as s:
            user_service.upsert_telegram_user(s, 1)
        with db.session() as s:
            row = user_service.update_telegram_user(s, 1, enabled=False)
            assert row.enabled is False

    def test_delete(self, db):
        with db.session() as s:
            user_service.upsert_telegram_user(s, 1)
        with db.session() as s:
            assert user_service.delete_telegram_user(s, 1) is True
        with db.session() as s:
            assert user_service.delete_telegram_user(s, 1) is False

    def test_scan_counts_are_joined_in(self, db):
        with db.session() as s:
            target = Target(name="home", value="10.0.0.0/24")
            s.add(target)
            s.flush()
            tid = target.id
        with db.session() as s:
            user_service.upsert_telegram_user(s, 7)
            for _ in range(3):
                scan = Scan(target_id=tid, profile="quick", status="succeeded",
                            requested_by=7)
                s.add(scan)
            s.add(Scan(target_id=tid, profile="quick", status="succeeded",
                       requested_by=None))
        with db.session() as s:
            rows = user_service.list_telegram_users(s)
        assert rows[0]["scan_count"] == 3

    def test_sync_from_allowed(self, db):
        assert user_service.sync_from_allowed(db, (1, 2, 3)) == 3
        # Second run finds everyone already present.
        assert user_service.sync_from_allowed(db, (1, 2, 3)) == 0
        with db.session() as s:
            assert len(user_service.list_telegram_users(s)) == 3

    def test_sync_from_allowed_empty(self, db):
        assert user_service.sync_from_allowed(db, ()) == 0


def _seed_scans(db, n, *, target_name="home"):
    with db.session() as s:
        target = Target(name=target_name, value="10.0.0.0/24")
        s.add(target)
        s.flush()
        tid = target.id
    ids = []
    for i in range(n):
        with db.session() as s:
            scan = Scan(target_id=tid, profile="quick", status="succeeded")
            scan.started_at = datetime.utcnow() - timedelta(days=i)
            scan.finished_at = scan.started_at
            s.add(scan)
            s.flush()
            ids.append(scan.id)
    return tid, ids


class TestDashboard:
    def test_counts(self, db):
        _seed_scans(db, 3)
        with db.session() as s:
            stats = stats_service.dashboard(s)
        assert stats.targets == 1
        assert stats.scans == 3

    def test_failed_scans_counted(self, db):
        tid, _ = _seed_scans(db, 2)
        with db.session() as s:
            s.add(Scan(target_id=tid, profile="quick", status="failed"))
        with db.session() as s:
            stats = stats_service.dashboard(s)
        assert stats.scans == 3

    def test_series_has_one_bucket_per_day(self, db):
        _seed_scans(db, 3)
        with db.session() as s:
            stats = stats_service.dashboard(s, days=7)
        assert len(stats.series) == 7
        assert sum(p["scans"] for p in stats.series) == 3

    def test_series_shape(self, db):
        _seed_scans(db, 1)
        with db.session() as s:
            series = stats_service.daily_series(s, days=3)
        for point in series:
            assert set(point) == {"date", "scans", "failed", "changes"}

    def test_change_breakdown(self, db):
        tid, ids = _seed_scans(db, 1)
        with db.session() as s:
            s.add(ChangeEvent(scan_id=ids[0], change_type="new_host", host="10.0.0.1"))
            s.add(ChangeEvent(scan_id=ids[0], change_type="new_host", host="10.0.0.2"))
            s.add(ChangeEvent(scan_id=ids[0], change_type="closed_port",
                              host="10.0.0.3", port=23))
        with db.session() as s:
            counts = stats_service.change_breakdown(s, days=7)
        assert counts["new_host"] == 2
        assert counts["closed_port"] == 1

    def test_last_scan_recorded(self, db):
        _seed_scans(db, 1)
        with db.session() as s:
            stats = stats_service.dashboard(s)
        assert stats.last_scan_at is not None


class TestTargetOverview:
    def test_lists_targets_with_counts(self, db):
        _tid, _ids = _seed_scans(db, 2)
        with db.session() as s:
            rows = stats_service.targets_with_counts(s)
        assert len(rows) == 1
        assert rows[0]["name"] == "home"
        assert rows[0]["scan_count"] == 2
        assert rows[0]["failed_count"] == 0
        assert rows[0]["schedule"] is None

    def test_target_scans_history(self, db):
        tid, _ids = _seed_scans(db, 3)
        with db.session() as s:
            scans = stats_service.target_scans(s, tid, limit=2)
        assert len(scans) == 2
        assert scans[0]["status"] == "succeeded"

    def test_target_changes(self, db):
        tid, ids = _seed_scans(db, 1)
        with db.session() as s:
            s.add(ChangeEvent(scan_id=ids[0], change_type="new_host", host="10.0.0.1"))
        with db.session() as s:
            changes = stats_service.target_changes(s, tid)
        assert len(changes) == 1
        assert changes[0]["host"] == "10.0.0.1"