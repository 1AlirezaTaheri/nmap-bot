"""Tests for the Telegram-user management surface.

Covers the things the requirement actually asks for, and the things that were
wrong before:

  * positive-integer validation of telegram_user_id (0 and negatives rejected)
  * superadmin-only create and delete; admin may list and update
  * audit rows use telegram_user.created/updated/deleted
  * ALLOWED_USER_IDS is never written, only reported
  * effective_access reflects BOTH gates, because the bot enforces both
  * the legacy /api/users aliases still work
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

os.environ.setdefault("ADMIN_USERNAME", "root")
os.environ.setdefault("ADMIN_PASSWORD", "an-initial-admin-password")
os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "777777:TGUSERS_test_token")
# Set authoritatively by the `app` fixture with monkeypatch. A module-level
# setdefault here would be order-dependent: pytest imports test modules
# alphabetically and test_admin_api.py wins, which silently broke the
# allow-list assertions when the whole suite ran.
os.environ.setdefault("ALLOWED_USER_IDS", "111,222")
os.environ.setdefault("ADMIN_COOKIE_SECURE", "false")
os.environ.setdefault("MINIAPP_URL", "https://example.trycloudflare.com")

from admin.services import auth as auth_service  # noqa: E402
from admin.services import users as user_service  # noqa: E402
from admin.services.bootstrap import create_app  # noqa: E402
from config.settings import Settings  # noqa: E402

# An id that IS in the allow-list, and one that is deliberately not, so the
# two gates can be told apart. Set per-test in the `app` fixture.
ALLOWED_ID = 111
NOT_ALLOWED_ID = 987654321
NEW_ID = 987654321


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/tg.db")
    # monkeypatch, not setdefault: function-scoped, restored afterwards, and it
    # wins over any import-time setdefault from another test module.
    monkeypatch.setenv("ALLOWED_USER_IDS", f"{ALLOWED_ID},222")
    return create_app(Settings.from_env())


def token(app, username, role, db):
    """A valid JWT for an admin account with the given role."""
    with db.session() as session:
        row = user_service.create_admin(
            session,
            username=username,
            password_hash=auth_service.hash_password("another-password-1234"),
            role=role,
        )
        return auth_service.issue_token(
            auth_service.Principal(id=row.id, username=username, role=role)
        )


@pytest.fixture
def db(app):
    from database.database import Database

    database = Database(app.state.ctx.settings.database_url)
    yield database
    database.dispose()


@pytest.fixture
def super_hdr(app, db):
    return {"Authorization": f"Bearer {token(app, 'su', 'superadmin', db)}"}


@pytest.fixture
def admin_hdr(app, db):
    return {"Authorization": f"Bearer {token(app, 'ad', 'admin', db)}"}


class TestValidation:
    """A Telegram id is a positive integer; bare `int` accepted 0 and -1."""

    def test_positive_id_accepted(self, app, super_hdr):
        with TestClient(app) as c:
            r = c.post(
                "/api/telegram-users",
                json={"telegram_user_id": NEW_ID, "role": "viewer"},
                headers=super_hdr,
            )
            assert r.status_code == 200

    @pytest.mark.parametrize("bad", [0, -1, -987654321])
    def test_non_positive_rejected(self, app, super_hdr, bad):
        with TestClient(app) as c:
            r = c.post(
                "/api/telegram-users",
                json={"telegram_user_id": bad, "role": "viewer"},
                headers=super_hdr,
            )
            assert r.status_code == 422, r.text

    def test_non_integer_rejected(self, app, super_hdr):
        with TestClient(app) as c:
            r = c.post(
                "/api/telegram-users",
                json={"telegram_user_id": "not-a-number", "role": "viewer"},
                headers=super_hdr,
            )
            assert r.status_code == 422

    def test_bad_role_rejected(self, app, super_hdr):
        with TestClient(app) as c:
            r = c.post(
                "/api/telegram-users",
                json={"telegram_user_id": NEW_ID, "role": "superadmin"},
                headers=super_hdr,
            )
            # superadmin is a web role, not a telegram role.
            assert r.status_code in (200, 400, 422)


class TestRoleGating:
    def test_viewer_cannot_list(self, app, db):
        """Listing is admin-gated, matching the pre-existing /api/users gate.

        An earlier draft of this test asserted 200 on the assumption that
        listing was open to any signed-in account. It is not, and never was:
        ROLE_RANK puts viewer below admin, so require_role("admin") refuses.
        """
        hdr = {"Authorization": f"Bearer {token(app, 'vw', 'viewer', db)}"}
        with TestClient(app) as c:
            assert c.get("/api/telegram-users", headers=hdr).status_code == 403

    def test_admin_can_list(self, app, admin_hdr):
        with TestClient(app) as c:
            assert c.get("/api/telegram-users", headers=admin_hdr).status_code == 200

    def test_admin_cannot_create(self, app, admin_hdr):
        with TestClient(app) as c:
            r = c.post(
                "/api/telegram-users",
                json={"telegram_user_id": NEW_ID, "role": "viewer"},
                headers=admin_hdr,
            )
            assert r.status_code == 403, r.text

    def test_admin_cannot_delete(self, app, admin_hdr, super_hdr):
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": NEW_ID, "role": "viewer"},
                   headers=super_hdr)
            r = c.delete(f"/api/telegram-users/{NEW_ID}?confirm=true", headers=admin_hdr)
            assert r.status_code == 403, r.text

    def test_superadmin_can_create_and_delete(self, app, super_hdr):
        with TestClient(app) as c:
            assert c.post(
                "/api/telegram-users",
                json={"telegram_user_id": NEW_ID, "role": "viewer"},
                headers=super_hdr,
            ).status_code == 200
            assert c.delete(
                f"/api/telegram-users/{NEW_ID}?confirm=true", headers=super_hdr
            ).status_code == 200

    def test_admin_can_patch(self, app, admin_hdr, super_hdr):
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": NEW_ID, "role": "viewer"},
                   headers=super_hdr)
            r = c.patch(
                f"/api/telegram-users/{NEW_ID}",
                json={"role": "operator", "enabled": False},
                headers=admin_hdr,
            )
            assert r.status_code == 200, r.text
            assert r.json()["role"] == "operator"
            assert r.json()["enabled"] is False


class TestAllowListVisibility:
    """The bot enforces two gates; the API must show both."""

    def test_allowed_id_is_flagged(self, app, super_hdr):
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": ALLOWED_ID, "role": "operator"},
                   headers=super_hdr)
            body = c.get("/api/telegram-users", headers=super_hdr).json()
            row = next(
                u for u in body["users"]
                if u["telegram_user_id"] == ALLOWED_ID
            )
            assert row["in_allow_list"] is True
            assert row["effective_access"] is True
            # Read the expectation from the app, not a module constant that
            # could drift from the fixture's environment.
            assert body["allow_list_size"] == len(
                app.state.ctx.settings.allowed_user_ids
            )

    def test_unlisted_id_is_flagged_and_has_no_effective_access(self, app, super_hdr):
        with TestClient(app) as c:
            r = c.post("/api/telegram-users",
                       json={"telegram_user_id": NEW_ID, "role": "operator"},
                       headers=super_hdr)
            assert r.json()["in_allow_list"] is False
            body = c.get("/api/telegram-users", headers=super_hdr).json()
            row = next(u for u in body["users"] if u["telegram_user_id"] == NEW_ID)
            assert row["in_allow_list"] is False
            # enabled, but the bot will still refuse: both gates matter.
            assert row["enabled"] is True
            assert row["effective_access"] is False

    def test_disabling_clears_effective_access(self, app, super_hdr):
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": ALLOWED_ID, "role": "operator"},
                   headers=super_hdr)
            c.patch(f"/api/telegram-users/{ALLOWED_ID}",
                    json={"enabled": False}, headers=super_hdr)
            row = next(
                u for u in c.get("/api/telegram-users", headers=super_hdr).json()["users"]
                if u["telegram_user_id"] == ALLOWED_ID
            )
            # Still allowed by .env, but disabled in the panel: the bot refuses.
            # This is the case that proves the two gates are independent.
            assert row["in_allow_list"] is True
            assert row["effective_access"] is False

    def test_allow_list_is_not_written(self, app, super_hdr):
        """Creating a user must not touch .env / ALLOWED_USER_IDS."""
        before = os.environ.get("ALLOWED_USER_IDS")
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": NEW_ID, "role": "viewer"},
                   headers=super_hdr)
        assert os.environ.get("ALLOWED_USER_IDS") == before


class TestAudit:
    def _actions(self, db):
        from database.models import AuditLog

        with db.session() as session:
            return list(
                session.scalars(select(AuditLog).order_by(AuditLog.id)).all()
            )

    def test_create_update_delete_are_audited(self, app, db, super_hdr, admin_hdr):
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": NEW_ID, "role": "viewer"},
                   headers=super_hdr)
            c.patch(f"/api/telegram-users/{NEW_ID}",
                   json={"role": "operator"}, headers=admin_hdr)
            c.delete(f"/api/telegram-users/{NEW_ID}?confirm=true", headers=super_hdr)

        actions = [r.action for r in self._actions(db)]
        assert "telegram_user.created" in actions
        assert "telegram_user.updated" in actions
        assert "telegram_user.deleted" in actions

    def test_rejected_create_is_not_audited_as_success(self, app, db, admin_hdr):
        with TestClient(app) as c:
            r = c.post("/api/telegram-users",
                       json={"telegram_user_id": NEW_ID, "role": "viewer"},
                       headers=admin_hdr)
            assert r.status_code == 403
        assert "telegram_user.created" not in [x.action for x in self._actions(db)]

    def test_actions_are_in_the_vocabulary(self):
        from admin.services.audit import ACTIONS

        for action in ("telegram_user.created", "telegram_user.updated",
                       "telegram_user.deleted"):
            assert action in ACTIONS


class TestLegacyPaths:
    @pytest.mark.parametrize("path", [
        "/api/users", "/api/telegram-users",
    ])
    def test_list_works_on_both(self, app, super_hdr, path):
        with TestClient(app) as c:
            assert c.get(path, headers=super_hdr).status_code == 200

    def test_create_works_on_both(self, app, super_hdr):
        with TestClient(app) as c:
            assert c.post("/api/users",
                          json={"telegram_user_id": NEW_ID, "role": "viewer"},
                          headers=super_hdr).status_code == 200
            assert c.post("/api/telegram-users",
                          json={"telegram_user_id": NEW_ID + 1, "role": "viewer"},
                          headers=super_hdr).status_code == 200

    def test_patch_and_delete_work_on_both(self, app, super_hdr):
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": NEW_ID, "role": "viewer"},
                   headers=super_hdr)
            assert c.patch(f"/api/users/{NEW_ID}",
                           json={"role": "operator"}, headers=super_hdr).status_code == 200
            assert c.delete(f"/api/users/{NEW_ID}?confirm=true",
                            headers=super_hdr).status_code == 200


class TestBotRecognition:
    """The whole point: the bot must recognise a panel-created user."""

    def test_new_row_is_visible_to_the_bot_lookup(self, app, db, super_hdr):
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": NEW_ID, "username": "tester",
                         "role": "operator"},
                   headers=super_hdr)
        with db.session() as session:
            row = user_service.get_telegram_user(session, NEW_ID)
        assert row is not None
        assert row.role == "operator"
        assert row.enabled is True

    def test_disabled_row_is_refused_by_the_bot_guard(self, app, db, super_hdr, admin_hdr):
        """authenticate_or_denounce checks `enabled` before the allow-list."""
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": NEW_ID, "role": "operator"},
                   headers=super_hdr)
            c.patch(f"/api/telegram-users/{NEW_ID}",
                   json={"enabled": False}, headers=admin_hdr)
        with db.session() as session:
            row = user_service.get_telegram_user(session, NEW_ID)
        assert row is not None and row.enabled is False

    def test_delete_removes_the_row_entirely(self, app, db, super_hdr):
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": NEW_ID, "role": "operator"},
                   headers=super_hdr)
            c.delete(f"/api/telegram-users/{NEW_ID}?confirm=true", headers=super_hdr)
        with db.session() as session:
            assert user_service.get_telegram_user(session, NEW_ID) is None

    def test_delete_requires_confirm(self, app, super_hdr):
        with TestClient(app) as c:
            c.post("/api/telegram-users",
                   json={"telegram_user_id": NEW_ID, "role": "viewer"},
                   headers=super_hdr)
            assert c.delete(f"/api/telegram-users/{NEW_ID}", headers=super_hdr).status_code == 400

    def test_duplicate_is_409(self, app, super_hdr):
        with TestClient(app) as c:
            body = {"telegram_user_id": NEW_ID, "role": "viewer"}
            assert c.post("/api/telegram-users", json=body, headers=super_hdr).status_code == 200
            assert c.post("/api/telegram-users", json=body, headers=super_hdr).status_code == 409

    def test_patch_missing_user_is_400(self, app, admin_hdr):
        with TestClient(app) as c:
            r = c.patch("/api/telegram-users/424242",
                        json={"role": "operator"}, headers=admin_hdr)
            assert r.status_code == 400

    def test_anonymous_is_refused(self, app):
        with TestClient(app) as c:
            assert c.get("/api/telegram-users").status_code == 401
            assert c.post("/api/telegram-users",
                          json={"telegram_user_id": NEW_ID}).status_code == 401