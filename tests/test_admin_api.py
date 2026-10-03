"""End-to-end tests for the FastAPI admin API using TestClient."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("ADMIN_USERNAME", "root")
os.environ.setdefault("ADMIN_PASSWORD", "an-initial-admin-password")
os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "0:test-token")
os.environ.setdefault("ALLOWED_USER_IDS", "7575983824")
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("ADMIN_COOKIE_SECURE", "false")

from admin.services.auth import COOKIE_NAME, hash_password  # noqa: E402
from admin.services.users import create_admin  # noqa: E402
from config.settings import Settings  # noqa: E402

PASSWORD = "an-initial-admin-password"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/admin.db"
    )
    from fastapi.testclient import TestClient

    from admin.services.bootstrap import create_app

    settings = Settings.from_env()
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Client with a signed-in superadmin cookie."""
    resp = client.post(
        "/api/login", json={"username": "root", "password": PASSWORD}
    )
    assert resp.status_code == 200, resp.text
    return client


class TestBootstrap:
    def test_creates_initial_superadmin(self, client):
        with client:
            login = client.post(
                "/api/login", json={"username": "root", "password": PASSWORD}
            )
            assert login.status_code == 200
            resp = client.get("/api/me")
            assert resp.status_code == 200
            assert resp.json()["role"] == "superadmin"

    def test_health_reports_database(self, client):
        with client:
            body = client.get("/api/health").json()
            assert body["database"] == "ok"

    def test_seeds_settings(self, client):
        with client:
            client.post("/api/login", json={"username": "root", "password": PASSWORD})
            resp = client.get("/api/settings")
            assert resp.status_code == 200
            assert "bot_language" in resp.json()["settings"]

    def test_health_needs_no_auth(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestAuth:
    def test_login_succeeds_and_sets_httponly_cookie(self, client):
        with client:
            resp = client.post(
                "/api/login", json={"username": "root", "password": PASSWORD}
            )
            assert resp.status_code == 200
            assert COOKIE_NAME in resp.cookies

    def test_me_requires_auth(self, client):
        with client:
            assert client.get("/api/me").status_code == 401

    def test_me_returns_identity(self, auth_client):
        resp = auth_client.get("/api/me")
        assert resp.json()["username"] == "root"
        assert resp.json()["role"] == "superadmin"

    def test_wrong_password_rejected(self, client):
        with client:
            resp = client.post(
                "/api/login", json={"username": "root", "password": "wrong"}
            )
            assert resp.status_code == 401

    def test_unknown_user_rejected_identically(self, client):
        """Same response for bad password and unknown user — no enumeration."""
        with client:
            a = client.post(
                "/api/login", json={"username": "root", "password": "wrong"}
            )
            b = client.post(
                "/api/login", json={"username": "ghost", "password": "wrong"}
            )
            assert a.status_code == b.status_code
            assert a.json() == b.json()

    def test_logout_clears_cookie(self, auth_client):
        auth_client.post("/api/logout")
        assert auth_client.get("/api/me").status_code == 401

    def test_bearer_token_accepted(self, client):
        with client:
            token = client.post(
                "/api/login", json={"username": "root", "password": PASSWORD}
            ).json()
            # obtain a raw token by logging in again and reading the cookie
            login = client.post(
                "/api/login", json={"username": "root", "password": PASSWORD}
            )
            raw = login.cookies.get(COOKIE_NAME) or token.get("token")
            if raw:
                resp = client.get(
                    "/api/me", headers={"Authorization": f"Bearer {raw}"}
                )
                assert resp.status_code == 200

    def test_login_throttled_after_five_attempts(self, client):
        with client:
            for _ in range(5):
                client.post(
                    "/api/login", json={"username": "root", "password": "wrong"}
                )
            resp = client.post(
                "/api/login", json={"username": "root", "password": "wrong"}
            )
            assert resp.status_code == 429

    def test_failed_login_is_audited(self, client):
        with client:
            client.post("/api/login", json={"username": "root", "password": "wrong"})
            client.post("/api/login", json={"username": "root", "password": PASSWORD})
            resp = client.get("/api/audit", params={"action": "auth.login_failed"})
            assert resp.json()["total"] >= 1

    def test_successful_login_is_audited(self, client):
        with client:
            client.post("/api/login", json={"username": "root", "password": PASSWORD})
            resp = client.get("/api/audit", params={"action": "auth.login"})
            assert resp.json()["total"] >= 1


class TestPages:
    def test_root_redirects_to_login(self, client):
        with client:
            assert client.get("/", follow_redirects=False).status_code in (302, 307)

    def test_login_page_renders(self, client):
        with client:
            resp = client.get("/admin/login")
            assert resp.status_code == 200
            assert "NetSentinel" in resp.text

    def test_anonymous_redirected_from_dashboard(self, client):
        with client:
            resp = client.get("/admin", follow_redirects=False)
            assert resp.status_code in (302, 307)

    def test_dashboard_renders_when_authed(self, auth_client):
        resp = auth_client.get("/admin")
        assert resp.status_code == 200
        assert "Dashboard" in resp.text

    def test_all_pages_render(self, auth_client):
        for path in ("/admin", "/admin/users", "/admin/targets",
                     "/admin/audit", "/admin/settings"):
            resp = auth_client.get(path)
            assert resp.status_code == 200, path

    def test_pages_escape_html(self, auth_client):
        """Auto-escaping must neutralise a hostile username in a table."""
        auth_client.post(
            "/api/users",
            json={"telegram_user_id": 4242, "username": "<script>x</script>"},
        )
        resp = auth_client.get("/admin/users")
        assert resp.status_code == 200
        assert "<script>x</script>" not in resp.text
        assert "&lt;script&gt;" in resp.text


class TestUsersApi:
    def test_list_empty(self, auth_client):
        resp = auth_client.get("/api/users")
        assert resp.status_code == 200
        assert isinstance(resp.json()["users"], list)

    def test_create_user(self, auth_client):
        resp = auth_client.post(
            "/api/users", json={"telegram_user_id": 111, "role": "operator"}
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "operator"

    def test_duplicate_user_conflicts(self, auth_client):
        auth_client.post("/api/users", json={"telegram_user_id": 111})
        resp = auth_client.post("/api/users", json={"telegram_user_id": 111})
        assert resp.status_code == 409

    def test_patch_user(self, auth_client):
        auth_client.post("/api/users", json={"telegram_user_id": 111})
        resp = auth_client.patch(
            "/api/users/111", json={"language": "en", "enabled": False}
        )
        assert resp.status_code == 200
        assert resp.json()["language"] == "en"
        assert resp.json()["enabled"] is False

    def test_patch_rejects_bad_role(self, auth_client):
        auth_client.post("/api/users", json={"telegram_user_id": 111})
        resp = auth_client.patch("/api/users/111", json={"role": "wizard"})
        assert resp.status_code == 400

    def test_delete_requires_confirm(self, auth_client):
        auth_client.post("/api/users", json={"telegram_user_id": 111})
        resp = auth_client.delete("/api/users/111")
        assert resp.status_code == 400

    def test_delete_with_confirm(self, auth_client):
        auth_client.post("/api/users", json={"telegram_user_id": 111})
        resp = auth_client.delete("/api/users/111", params={"confirm": "true"})
        assert resp.status_code == 200

    def test_delete_missing_user_404(self, auth_client):
        resp = auth_client.delete("/api/users/999", params={"confirm": "true"})
        assert resp.status_code == 404

    def test_user_action_is_audited(self, auth_client):
        auth_client.post("/api/users", json={"telegram_user_id": 222})
        resp = auth_client.get("/api/audit", params={"action": "user.add"})
        assert resp.json()["total"] >= 1


class TestSettingsApi:
    def test_get_settings(self, auth_client):
        resp = auth_client.get("/api/settings")
        assert resp.status_code == 200
        body = resp.json()["settings"]
        assert body["bot_language"]["default"] == "fa"
        assert "description" in body["retention_days"]

    def test_patch_setting(self, auth_client):
        resp = auth_client.patch(
            "/api/settings", json={"values": {"retention_days": "7"}}
        )
        assert resp.status_code == 200
        assert resp.json()["settings"]["retention_days"] == 7

    def test_change_is_persisted(self, auth_client):
        auth_client.patch("/api/settings", json={"values": {"bot_language": "en"}})
        resp = auth_client.get("/api/settings")
        assert resp.json()["settings"]["bot_language"]["value"] == "en"

    def test_invalid_value_rejected(self, auth_client):
        resp = auth_client.patch(
            "/api/settings", json={"values": {"bot_language": "de"}}
        )
        assert resp.status_code == 400

    def test_unknown_key_rejected(self, auth_client):
        resp = auth_client.patch(
            "/api/settings", json={"values": {"nope": "1"}}
        )
        assert resp.status_code == 400

    def test_batch_is_atomic(self, auth_client):
        resp = auth_client.patch(
            "/api/settings",
            json={"values": {"retention_days": "5", "bot_language": "de"}},
        )
        assert resp.status_code == 400
        # the good value must not have been applied
        again = auth_client.get("/api/settings")
        assert again.json()["settings"]["retention_days"]["value"] == 30

    def test_change_is_audited(self, auth_client):
        auth_client.patch("/api/settings", json={"values": {"retention_days": "9"}})
        resp = auth_client.get("/api/audit", params={"action": "settings.update"})
        assert resp.json()["total"] >= 1


class TestTargetsApi:
    def test_list_empty(self, auth_client):
        resp = auth_client.get("/api/targets")
        assert resp.status_code == 200
        assert resp.json()["targets"] == []

    def test_create_target(self, auth_client):
        resp = auth_client.post(
            "/api/targets", json={"name": "home", "value": "10.0.0.0/24"}
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "home"

    def test_duplicate_target_conflicts(self, auth_client):
        auth_client.post("/api/targets", json={"name": "home", "value": "10.0.0.0/24"})
        resp = auth_client.post(
            "/api/targets", json={"name": "home", "value": "10.0.0.1"}
        )
        assert resp.status_code == 409

    def test_invalid_target_rejected(self, auth_client):
        resp = auth_client.post(
            "/api/targets", json={"name": "bad", "value": "-sV 8.8.8.8"}
        )
        assert resp.status_code == 400

    def test_oversized_name_rejected(self, auth_client):
        resp = auth_client.post(
            "/api/targets", json={"name": "x" * 200, "value": "10.0.0.0/24"}
        )
        assert resp.status_code in (400, 422)

    def test_purge_requires_confirm(self, auth_client):
        created = auth_client.post(
            "/api/targets", json={"name": "home", "value": "10.0.0.0/24"}
        ).json()
        tid = auth_client.get("/api/targets").json()["targets"][0]["id"]
        resp = auth_client.delete(f"/api/targets/{tid}")
        assert resp.status_code == 400
        assert "confirm" in resp.json()["detail"]

    def test_purge_with_confirm(self, auth_client):
        auth_client.post("/api/targets", json={"name": "home", "value": "10.0.0.0/24"})
        tid = auth_client.get("/api/targets").json()["targets"][0]["id"]
        resp = auth_client.delete(
            f"/api/targets/{tid}", params={"confirm": "true"}
        )
        assert resp.status_code == 200
        assert auth_client.get("/api/targets").json()["targets"] == []

    def test_purge_missing_target_404(self, auth_client):
        resp = auth_client.delete(
            "/api/targets/999", params={"confirm": "true"}
        )
        assert resp.status_code == 404

    def test_target_scans_endpoint(self, auth_client):
        auth_client.post("/api/targets", json={"name": "home", "value": "10.0.0.0/24"})
        tid = auth_client.get("/api/targets").json()["targets"][0]["id"]
        assert auth_client.get(f"/api/targets/{tid}/scans").status_code == 200
        assert auth_client.get(f"/api/targets/{tid}/changes").status_code == 200


class TestAuditApi:
    def test_requires_auth(self, client):
        with client:
            assert client.get("/api/audit").status_code == 401

    def test_filter_by_action(self, auth_client):
        auth_client.post("/api/users", json={"telegram_user_id": 333})
        resp = auth_client.get("/api/audit", params={"action": "user.add"})
        assert resp.json()["total"] >= 1

    def test_filter_by_success(self, auth_client):
        resp = auth_client.get("/api/audit", params={"success": "true"})
        assert resp.status_code == 200
        assert all(e["success"] for e in resp.json()["entries"])

    def test_csv_export(self, auth_client):
        auth_client.post("/api/users", json={"telegram_user_id": 444})
        resp = auth_client.get("/api/audit/export.csv")
        assert resp.status_code == 200
        assert "actor_type" in resp.text

    def test_bad_timestamp_rejected(self, auth_client):
        resp = auth_client.get("/api/audit", params={"since": "not-a-date"})
        assert resp.status_code == 400


class TestStatsApi:
    def test_stats_shape(self, auth_client):
        resp = auth_client.get("/api/stats")
        assert resp.status_code == 200
        body = resp.json()
        for key in ("targets", "scans", "changes", "series"):
            assert key in body
        assert len(body["series"]) == 7


class TestRoleGating:
    def test_viewer_cannot_write(self, tmp_path, monkeypatch):
        """A viewer must be refused every mutating endpoint."""
        monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/r.db")
        from fastapi.testclient import TestClient

        from admin.services.bootstrap import create_app

        app = create_app(Settings.from_env())
        with TestClient(app) as c:
            c.post("/api/login", json={"username": "root", "password": PASSWORD})
            with app.state.ctx.database.session() as s:
                create_admin(s, "watcher", hash_password(PASSWORD), role="viewer")

            # log in as the viewer
            c.cookies.clear()
            c.post("/api/login", json={"username": "watcher", "password": PASSWORD})

            assert c.get("/api/stats").status_code == 200          # read OK
            assert c.post(
                "/api/users", json={"telegram_user_id": 999}
            ).status_code == 403                                     # write refused
            assert c.patch(
                "/api/settings", json={"values": {"retention_days": "7"}}
            ).status_code == 403

    def test_viewer_cannot_purge(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/p.db")
        from fastapi.testclient import TestClient

        from admin.services.bootstrap import create_app

        app = create_app(Settings.from_env())
        with TestClient(app) as c:
            c.post("/api/login", json={"username": "root", "password": PASSWORD})
            c.post("/api/targets", json={"name": "home", "value": "10.0.0.0/24"})
            tid = c.get("/api/targets").json()["targets"][0]["id"]

            with app.state.ctx.database.session() as s:
                create_admin(s, "watcher", hash_password(PASSWORD), role="viewer")
            c.cookies.clear()
            c.post("/api/login", json={"username": "watcher", "password": PASSWORD})

            resp = c.delete(f"/api/targets/{tid}", params={"confirm": "true"})
            assert resp.status_code == 403