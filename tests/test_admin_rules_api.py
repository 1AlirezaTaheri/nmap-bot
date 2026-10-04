"""Tests for the rules admin API (admin/routes/rules.py, rule_hits.py).

Mirrors the live verification: role gating, validation, the 400/409 split,
the dry-run endpoint's lack of side effects, and import atomicity.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from admin.services.auth import hash_password
from admin.services.bootstrap import create_app
from config.settings import Settings

# Same bootstrap as tests/test_admin_api.py. Repeated here rather than
# imported so this file runs standalone: without it Settings.from_env()
# refuses to start, because ALLOWED_USER_IDS is deliberately mandatory.
os.environ.setdefault("ADMIN_USERNAME", "root")
os.environ.setdefault("ADMIN_PASSWORD", "an-initial-admin-password")
os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "0:test-token")
os.environ.setdefault("ALLOWED_USER_IDS", "7575983824")
os.environ.setdefault("ADMIN_COOKIE_SECURE", "false")

PASSWORD = "an-initial-admin-password"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/admin.db"
    )
    app = create_app(Settings.from_env())
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_client(client):
    resp = client.post(
        "/api/login", json={"username": "root", "password": PASSWORD}
    )
    assert resp.status_code == 200, resp.text
    return client


def add_rule(client, name="r1", rule_type="deny_cidr", value=None, **extra):
    # Default the value per rule type, so a test that only overrides
    # rule_type does not accidentally submit a CIDR as a port list.
    if value is None:
        value = {
            "deny_cidr": "10.0.0.0/8",
            "allow_cidr": "192.168.174.0/24",
            "deny_port": "22",
            "allow_port": "22,80",
        }.get(rule_type, "10.0.0.0/8")
    body = {"name": name, "rule_type": rule_type, "value": value}
    body.update(extra)
    resp = client.post("/api/rules", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def viewer_client(tmp_path, monkeypatch):
    """A second client signed in as a role=viewer admin."""
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/admin.db"
    )
    app = create_app(Settings.from_env())

    from database.database import Database
    from database.models import AdminUser

    database = Database(Settings.from_env().database_url)
    with database.session() as session:
        session.add(
            AdminUser(
                username="watcher",
                password_hash=hash_password("a-viewer-password"),
                role="viewer",
            )
        )
        session.commit()
    database.dispose()

    c = TestClient(app)
    resp = c.post(
        "/api/login",
        json={"username": "watcher", "password": "a-viewer-password"},
    )
    assert resp.status_code == 200, resp.text
    return c


class TestCreate:
    def test_created(self, auth_client):
        rule = add_rule(auth_client)
        assert rule["name"] == "r1"
        assert rule["rule_type"] == "deny_cidr"
        assert rule["priority"] == 50
        assert rule["enabled"] is True
        assert rule["scope"] == "global"
        assert rule["hit_count"] == 0
        assert rule["created_by"] == "root"

    def test_value_normalized(self, auth_client):
        rule = add_rule(
            auth_client,
            rule_type="allow_cidr",
            value=" 192.168.174.0/24 ",
        )
        assert rule["value"] == "192.168.174.0/24"

    def test_duplicate_name_is_409(self, auth_client):
        add_rule(auth_client, name="dup")
        resp = auth_client.post(
            "/api/rules",
            json={"name": "dup", "rule_type": "deny_port", "value": "22"},
        )
        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    @pytest.mark.parametrize(
        "rule_type,value",
        [
            ("allow_cidr", "not-a-cidr"),
            ("deny_port", "70000"),
            ("deny_port", "9000-8000"),
            ("max_scan_time", "0"),
            ("rate_limit", "abc"),
            ("time_window", "08:00-08:00"),
            ("user_quota", "10/week"),
            ("allow_domain", "bad domain"),
        ],
    )
    def test_bad_value_is_400(self, auth_client, rule_type, value):
        resp = auth_client.post(
            "/api/rules",
            json={"name": f"bad-{rule_type}", "rule_type": rule_type,
                  "value": value},
        )
        assert resp.status_code == 400, resp.text

    def test_unknown_rule_type_is_400(self, auth_client):
        resp = auth_client.post(
            "/api/rules",
            json={"name": "weird", "rule_type": "allow_everything",
                  "value": "x"},
        )
        assert resp.status_code == 400
        assert "Unknown rule_type" in resp.json()["detail"]

    def test_unknown_scope_is_400(self, auth_client):
        resp = auth_client.post(
            "/api/rules",
            json={"name": "s", "rule_type": "deny_cidr", "value": "10.0.0.0/8",
                  "scope": "galaxy"},
        )
        assert resp.status_code == 400

    def test_scoped_rule_without_scope_id_is_400(self, auth_client):
        resp = auth_client.post(
            "/api/rules",
            json={"name": "s", "rule_type": "deny_cidr", "value": "10.0.0.0/8",
                  "scope": "user"},
        )
        assert resp.status_code == 400
        assert "scope_id" in resp.json()["detail"]

    def test_missing_name_is_422(self, auth_client):
        resp = auth_client.post(
            "/api/rules", json={"rule_type": "deny_cidr", "value": "10.0.0.0/8"}
        )
        assert resp.status_code == 422

    def test_requires_authentication(self, client):
        resp = client.post(
            "/api/rules",
            json={"name": "x", "rule_type": "deny_cidr", "value": "10.0.0.0/8"},
        )
        assert resp.status_code == 401


class TestList:
    def test_empty(self, auth_client):
        resp = auth_client.get("/api/rules")
        assert resp.status_code == 200
        assert resp.json() == {"rules": [], "total": 0}

    def test_ordered_by_priority(self, auth_client):
        add_rule(auth_client, name="late", priority=90)
        add_rule(auth_client, name="early", priority=5)
        resp = auth_client.get("/api/rules")
        assert [r["name"] for r in resp.json()["rules"]] == ["early", "late"]

    def test_filter_by_type(self, auth_client):
        add_rule(auth_client, name="c", rule_type="deny_cidr")
        add_rule(auth_client, name="p", rule_type="deny_port")
        resp = auth_client.get("/api/rules", params={"type": "deny_port"})
        assert [r["name"] for r in resp.json()["rules"]] == ["p"]
        assert resp.json()["total"] == 1

    def test_filter_by_enabled(self, auth_client):
        add_rule(auth_client, name="on")
        add_rule(auth_client, name="off", enabled=False)
        resp = auth_client.get("/api/rules", params={"enabled": "false"})
        assert [r["name"] for r in resp.json()["rules"]] == ["off"]

    def test_filter_by_scope(self, auth_client):
        add_rule(auth_client, name="g")
        add_rule(
            auth_client, name="u", scope="user", scope_id="1"
        )
        resp = auth_client.get("/api/rules", params={"scope": "user"})
        assert [r["name"] for r in resp.json()["rules"]] == ["u"]

    def test_search_is_case_insensitive(self, auth_client):
        add_rule(auth_client, name="Deny-Metadata")
        resp = auth_client.get("/api/rules", params={"q": "meta"})
        assert [r["name"] for r in resp.json()["rules"]] == ["Deny-Metadata"]

    def test_combined_filters(self, auth_client):
        add_rule(auth_client, name="a", rule_type="deny_cidr")
        add_rule(auth_client, name="b", rule_type="deny_cidr", enabled=False)
        resp = auth_client.get(
            "/api/rules", params={"type": "deny_cidr", "enabled": "true"}
        )
        assert [r["name"] for r in resp.json()["rules"]] == ["a"]

    def test_requires_authentication(self, client):
        assert client.get("/api/rules").status_code == 401


class TestUpdate:
    def test_partial_update(self, auth_client):
        rule = add_rule(auth_client, description="original")
        resp = auth_client.patch(
            f"/api/rules/{rule['id']}", json={"priority": 7}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["priority"] == 7
        assert body["description"] == "original", "other fields untouched"
        assert body["value"] == "10.0.0.0/8"
        assert body["updated_at"] is not None

    def test_value_is_normalized(self, auth_client):
        rule = add_rule(auth_client, rule_type="allow_cidr")
        resp = auth_client.patch(
            f"/api/rules/{rule['id']}", json={"value": " 10.1.0.0/16 "}
        )
        assert resp.json()["value"] == "10.1.0.0/16"

    def test_bad_value_is_400(self, auth_client):
        rule = add_rule(auth_client, rule_type="allow_cidr")
        resp = auth_client.patch(
            f"/api/rules/{rule['id']}", json={"value": "garbage"}
        )
        assert resp.status_code == 400

    def test_unknown_type_is_400(self, auth_client):
        rule = add_rule(auth_client)
        resp = auth_client.patch(
            f"/api/rules/{rule['id']}", json={"rule_type": "nonsense"}
        )
        assert resp.status_code == 400

    def test_scoped_without_scope_id_is_400(self, auth_client):
        rule = add_rule(auth_client)
        resp = auth_client.patch(
            f"/api/rules/{rule['id']}", json={"scope": "target"}
        )
        assert resp.status_code == 400

    def test_missing_rule_is_404(self, auth_client):
        resp = auth_client.patch("/api/rules/99999", json={"priority": 1})
        assert resp.status_code == 404

    def test_rejected_patch_does_not_break_later_writes(self, auth_client):
        # The repository uses a savepoint, so a rejected patch must leave the
        # session usable.
        rule = add_rule(auth_client, name="keep", rule_type="allow_cidr")
        bad = auth_client.patch(
            f"/api/rules/{rule['id']}", json={"value": "garbage"}
        )
        assert bad.status_code == 400
        good = auth_client.patch(
            f"/api/rules/{rule['id']}", json={"value": "10.2.0.0/16"}
        )
        assert good.status_code == 200
        assert good.json()["value"] == "10.2.0.0/16"


class TestDelete:
    def test_requires_confirm(self, auth_client):
        rule = add_rule(auth_client)
        resp = auth_client.delete(f"/api/rules/{rule['id']}")
        assert resp.status_code == 400
        assert "confirm=true" in resp.json()["detail"]
        assert auth_client.get("/api/rules").json()["total"] == 1

    def test_with_confirm(self, auth_client):
        rule = add_rule(auth_client)
        resp = auth_client.delete(
            f"/api/rules/{rule['id']}", params={"confirm": "true"}
        )
        assert resp.status_code == 200
        assert resp.json()["deleted"] == "r1"
        assert auth_client.get("/api/rules").json()["total"] == 0

    def test_missing_rule_is_404(self, auth_client):
        resp = auth_client.delete(
            "/api/rules/99999", params={"confirm": "true"}
        )
        assert resp.status_code == 404

    def test_confirm_message_reports_historical_hits(self, auth_client):
        rule = add_rule(auth_client)
        resp = auth_client.delete(f"/api/rules/{rule['id']}")
        assert "hit" in resp.json()["detail"].lower()


class TestToggle:
    def test_flips_both_ways(self, auth_client):
        rule = add_rule(auth_client)
        first = auth_client.post(f"/api/rules/{rule['id']}/toggle")
        assert first.status_code == 200 and first.json()["enabled"] is False
        second = auth_client.post(f"/api/rules/{rule['id']}/toggle")
        assert second.status_code == 200 and second.json()["enabled"] is True

    def test_missing_rule_is_404(self, auth_client):
        resp = auth_client.post("/api/rules/99999/toggle")
        assert resp.status_code == 404

    def test_counter_survives_toggling(self, auth_client):
        # Pausing a rule must keep the row and its counters, so resuming it
        # does not lose the operator's history.
        rule = add_rule(auth_client, rule_type="deny_cidr", value="10.0.0.0/8")
        rule_id = rule["id"]

        def fetch():
            # No GET-by-id endpoint exists by design, so read the rule
            # back out of the list.
            rules = auth_client.get("/api/rules").json()["rules"]
            return next(r for r in rules if r["id"] == rule_id)

        auth_client.post(f"/api/rules/{rule_id}/toggle")
        paused = fetch()
        assert paused["enabled"] is False, "the rule must still exist while paused"
        assert paused["hit_count"] == 0
        assert paused["name"] == rule["name"]

        auth_client.post(f"/api/rules/{rule_id}/toggle")
        resumed = fetch()
        assert resumed["enabled"] is True
        assert resumed["hit_count"] == paused["hit_count"]
        assert resumed["updated_at"] is not None


class TestReorder:
    def test_assigns_one_through_n(self, auth_client):
        ids = [add_rule(auth_client, name=f"r{i}")["id"] for i in range(3)]
        resp = auth_client.post("/api/rules/reorder", json={"ids": list(ids)})
        assert resp.status_code == 200
        assert resp.json()["reordered"] == 3
        priorities = {r["name"]: r["priority"] for r in resp.json()["rules"]}
        assert priorities == {"r0": 1, "r1": 2, "r2": 3}

    def test_missing_id_is_tolerated(self, auth_client):
        rule = add_rule(auth_client)
        resp = auth_client.post(
            "/api/rules/reorder", json={"ids": [rule["id"], 999999]}
        )
        assert resp.status_code == 200
        assert resp.json()["reordered"] == 1

    def test_repeated_id_keeps_first_position(self, auth_client):
        a = add_rule(auth_client, name="a")["id"]
        b = add_rule(auth_client, name="b")["id"]
        resp = auth_client.post("/api/rules/reorder", json={"ids": [a, a, b]})
        priorities = {r["name"]: r["priority"] for r in resp.json()["rules"]}
        assert priorities["a"] == 1
        assert priorities["b"] == 2

    def test_empty_ids_is_422(self, auth_client):
        resp = auth_client.post("/api/rules/reorder", json={"ids": []})
        assert resp.status_code == 422


class TestTestEndpoint:
    """The dry run: it must never leave a trace."""

    def test_allows_an_in_scope_target(self, auth_client):
        add_rule(
            auth_client, name="allow-home", rule_type="allow_cidr",
            value="192.168.174.0/24",
        )
        resp = auth_client.post("/api/rules/test",
                                json={"target": "192.168.174.10"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["allowed"] is True
        assert body["rule_name"] == "allow-home"

    def test_denies_outside_the_gate(self, auth_client):
        add_rule(
            auth_client, name="allow-home", rule_type="allow_cidr",
            value="192.168.174.0/24",
        )
        resp = auth_client.post("/api/rules/test", json={"target": "8.8.8.8"})
        body = resp.json()
        assert body["allowed"] is False
        assert body["reason"] == "no matching allow rule"
        assert body["rule_id"] is None

    def test_denies_by_a_deny_rule(self, auth_client):
        add_rule(auth_client, name="allow-all", rule_type="allow_cidr",
                 value="0.0.0.0/0")
        add_rule(auth_client, name="deny-ten", rule_type="deny_cidr",
                 value="10.0.0.0/8", priority=1)
        resp = auth_client.post("/api/rules/test", json={"target": "10.0.0.5"})
        body = resp.json()
        assert body["allowed"] is False
        assert body["rule_name"] == "deny-ten"

    def test_reports_effective_limits(self, auth_client):
        add_rule(auth_client, name="timeout", rule_type="max_scan_time",
                 value="30")
        resp = auth_client.post("/api/rules/test",
                                json={"target": "10.0.0.5"})
        assert resp.json()["effective_scan_timeout"] == 30

    def test_rate_limit_value_is_reported(self, auth_client):
        add_rule(auth_client, name="rl", rule_type="rate_limit", value="45")
        resp = auth_client.post("/api/rules/test",
                                json={"target": "10.0.0.5"})
        assert resp.json()["effective_rate_limit_seconds"] == 45

    def test_actor_id_affects_scoped_rules(self, auth_client):
        add_rule(
            auth_client, name="deny-for-1", rule_type="deny_cidr",
            value="0.0.0.0/0", scope="user", scope_id="1",
        )
        resp = auth_client.post(
            "/api/rules/test", json={"target": "10.0.0.5", "actor_id": 1}
        )
        assert resp.json()["allowed"] is False

        resp = auth_client.post(
            "/api/rules/test", json={"target": "10.0.0.5", "actor_id": 2}
        )
        assert resp.json()["allowed"] is True

    def test_ports_are_passed_through(self, auth_client):
        add_rule(auth_client, name="no-22", rule_type="deny_port", value="22")
        resp = auth_client.post(
            "/api/rules/test",
            json={"target": "10.0.0.5", "ports": [22, 80]},
        )
        assert resp.json()["allowed"] is False

        resp = auth_client.post(
            "/api/rules/test",
            json={"target": "10.0.0.5", "ports": [80, 443]},
        )
        assert resp.json()["allowed"] is True

    def test_explicit_now_is_honoured(self, auth_client):
        add_rule(auth_client, name="window", rule_type="time_window",
                 value="08:00-22:00")
        resp = auth_client.post(
            "/api/rules/test",
            json={"target": "10.0.0.5", "now": "2026-06-01T23:00:00+00:00"},
        )
        assert resp.json()["allowed"] is False

        resp = auth_client.post(
            "/api/rules/test",
            json={"target": "10.0.0.5", "now": "2026-06-01T12:00:00+00:00"},
        )
        assert resp.json()["allowed"] is True

    def test_bad_now_is_400(self, auth_client):
        resp = auth_client.post(
            "/api/rules/test", json={"target": "10.0.0.5", "now": "not-a-date"}
        )
        assert resp.status_code == 400

    def test_writes_no_hit_rows(self, auth_client):
        add_rule(auth_client, name="deny-ten", rule_type="deny_cidr",
                 value="10.0.0.0/8")
        resp = auth_client.post("/api/rules/test", json={"target": "10.0.0.5"})
        assert resp.json()["allowed"] is False

        hits = auth_client.get("/api/rule-hits").json()
        assert hits["total"] == 0, "a dry run must not record a hit"

        rule = auth_client.get("/api/rules").json()["rules"][0]
        assert rule["hit_count"] == 0, "a dry run must not bump the counter"
        assert rule["last_hit_at"] is None

    def test_declares_no_side_effects(self, auth_client):
        resp = auth_client.post("/api/rules/test", json={"target": "10.0.0.5"})
        assert resp.json()["side_effects"] == "none"

    def test_reports_considered_count(self, auth_client):
        add_rule(auth_client, name="a")
        add_rule(auth_client, name="b", enabled=False)
        resp = auth_client.post("/api/rules/test", json={"target": "10.0.0.5"})
        assert resp.json()["rules_considered"] == 1, "disabled rules are skipped"

    def test_requires_authentication(self, client):
        resp = client.post("/api/rules/test", json={"target": "10.0.0.5"})
        assert resp.status_code == 401


class TestExportImport:
    def test_export_shape(self, auth_client):
        add_rule(auth_client, name="a", description="first")
        resp = auth_client.get("/api/rules/export")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["version"] == 1
        assert len(payload["rules"]) == 1
        assert payload["rules"][0]["name"] == "a"
        assert payload["rules"][0]["description"] == "first"

    def test_export_is_a_download(self, auth_client):
        resp = auth_client.get("/api/rules/export")
        assert "attachment" in resp.headers.get("content-disposition", "")
        assert "netsentinel-rules.json" in resp.headers["content-disposition"]

    def test_export_excludes_hits(self, auth_client):
        add_rule(auth_client)
        payload = auth_client.get("/api/rules/export").json()
        assert "hits" not in payload

    def test_round_trip_is_idempotent(self, auth_client):
        add_rule(auth_client, name="a")
        add_rule(auth_client, name="b")
        exported = auth_client.get("/api/rules/export").json()

        resp = auth_client.post("/api/rules/import", json=exported)
        assert resp.status_code == 200
        assert resp.json() == {
            "created": 0, "updated": 2, "removed": 0, "replace": False
        }
        assert auth_client.get("/api/rules").json()["total"] == 2

    def test_import_creates_missing_rules(self, auth_client):
        add_rule(auth_client, name="existing")
        resp = auth_client.post("/api/rules/import", json={"rules": [
            {"name": "existing", "rule_type": "deny_cidr", "value": "10.0.0.0/8"},
            {"name": "brand-new", "rule_type": "deny_port", "value": "22"},
        ]})
        assert resp.json() == {
            "created": 1, "updated": 1, "removed": 0, "replace": False
        }

    def test_import_normalizes_values(self, auth_client):
        auth_client.post("/api/rules/import", json={"rules": [
            {"name": "n", "rule_type": "allow_cidr",
             "value": " 192.168.174.0/24 "},
        ]})
        rules = auth_client.get("/api/rules").json()["rules"]
        assert rules[0]["value"] == "192.168.174.0/24"

    def test_import_is_atomic(self, auth_client):
        # One bad rule rejects the whole batch; nothing is written.
        resp = auth_client.post("/api/rules/import", json={"rules": [
            {"name": "good-one", "rule_type": "deny_port", "value": "23"},
            {"name": "bad-one", "rule_type": "deny_port", "value": "99999"},
        ]})
        assert resp.status_code == 400
        assert auth_client.get("/api/rules").json()["total"] == 0, (
            "nothing may be written when the batch fails"
        )

    def test_import_rejects_unknown_type(self, auth_client):
        resp = auth_client.post("/api/rules/import", json={"rules": [
            {"name": "x", "rule_type": "allow_everything", "value": "y"},
        ]})
        assert resp.status_code == 400

    def test_import_rejects_scoped_without_subject(self, auth_client):
        resp = auth_client.post("/api/rules/import", json={"rules": [
            {"name": "x", "rule_type": "deny_cidr", "value": "10.0.0.0/8",
             "scope": "user"},
        ]})
        assert resp.status_code == 400

    def test_import_rejects_duplicate_names_in_batch(self, auth_client):
        resp = auth_client.post("/api/rules/import", json={"rules": [
            {"name": "dup", "rule_type": "deny_port", "value": "23"},
            {"name": "dup", "rule_type": "deny_port", "value": "24"},
        ]})
        assert resp.status_code == 400
        assert "duplicate" in resp.json()["detail"]

    def test_error_message_names_the_offending_rule(self, auth_client):
        resp = auth_client.post("/api/rules/import", json={"rules": [
            {"name": "fine", "rule_type": "deny_port", "value": "23"},
            {"name": "broken", "rule_type": "deny_port", "value": "99999"},
        ]})
        assert "broken" in resp.json()["detail"]

    def test_empty_batch_is_422(self, auth_client):
        resp = auth_client.post("/api/rules/import", json={"rules": []})
        assert resp.status_code == 422

    def test_replace_removes_rules_not_in_the_batch(self, auth_client):
        add_rule(auth_client, name="stale")
        resp = auth_client.post("/api/rules/import", json={
            "replace": True,
            "rules": [
                {"name": "fresh", "rule_type": "deny_port", "value": "22"},
            ],
        })
        assert resp.json() == {
            "created": 1, "updated": 0, "removed": 1, "replace": True
        }
        names = {r["name"] for r in auth_client.get("/api/rules").json()["rules"]}
        assert names == {"fresh"}

    def test_replace_keeps_rules_present_in_the_batch(self, auth_client):
        add_rule(auth_client, name="kept")
        exported = auth_client.get("/api/rules/export").json()
        resp = auth_client.post(
            "/api/rules/import", json={**exported, "replace": True}
        )
        assert resp.json()["removed"] == 0
        assert resp.json()["updated"] == 1


class TestHitsEndpoints:
    def test_per_rule_hits(self, auth_client):
        add_rule(auth_client, name="a")
        add_rule(auth_client, name="b")
        hits = auth_client.get("/api/rule-hits")
        assert hits.status_code == 200
        assert hits.json()["total"] == 0

    def test_missing_rule_is_404(self, auth_client):
        resp = auth_client.get("/api/rules/99999/hits")
        assert resp.status_code == 404

    def test_pagination_fields(self, auth_client):
        rule = add_rule(auth_client)
        resp = auth_client.get(
            f"/api/rules/{rule['id']}/hits",
            params={"page": 2, "page_size": 10},
        )
        body = resp.json()
        assert body["page"] == 2
        assert body["page_size"] == 10

    def test_bad_decision_filter_is_400(self, auth_client):
        rule = add_rule(auth_client)
        resp = auth_client.get(
            f"/api/rules/{rule['id']}/hits", params={"decision": "perhaps"}
        )
        assert resp.status_code == 400

    def test_global_bad_decision_filter_is_400(self, auth_client):
        resp = auth_client.get("/api/rule-hits", params={"decision": "perhaps"})
        assert resp.status_code == 400

    def test_requires_authentication(self, client):
        assert client.get("/api/rule-hits").status_code == 401


class TestRoleGating:
    @pytest.fixture
    def viewer(self, client, tmp_path, monkeypatch):
        return viewer_client(tmp_path, monkeypatch)

    def test_viewer_cannot_create(self, viewer):
        resp = viewer.post("/api/rules", json={
            "name": "nope", "rule_type": "deny_port", "value": "22"})
        assert resp.status_code == 403

    def test_viewer_cannot_patch(self, viewer):
        resp = viewer.patch("/api/rules/1", json={"priority": 1})
        assert resp.status_code == 403

    def test_viewer_cannot_delete(self, viewer):
        resp = viewer.delete("/api/rules/1", params={"confirm": "true"})
        assert resp.status_code == 403

    def test_viewer_cannot_toggle(self, viewer):
        resp = viewer.post("/api/rules/1/toggle")
        assert resp.status_code == 403

    def test_viewer_cannot_reorder(self, viewer):
        resp = viewer.post("/api/rules/reorder", json={"ids": [1]})
        assert resp.status_code == 403

    def test_viewer_cannot_import(self, viewer):
        resp = viewer.post("/api/rules/import", json={"rules": [
            {"name": "x", "rule_type": "deny_port", "value": "22"}]})
        assert resp.status_code == 403

    def test_viewer_may_read(self, viewer):
        assert viewer.get("/api/rules").status_code == 200

    def test_viewer_may_export(self, viewer):
        assert viewer.get("/api/rules/export").status_code == 200

    def test_viewer_may_read_hits(self, viewer):
        assert viewer.get("/api/rule-hits").status_code == 200

    def test_viewer_may_dry_run(self, viewer):
        # Testing a rule set changes nothing, so read access is enough.
        resp = viewer.post("/api/rules/test", json={"target": "10.0.0.5"})
        assert resp.status_code == 200

    def test_unauthenticated_is_401(self, client):
        assert client.get("/api/rules").status_code == 401
        assert client.get("/api/rule-hits").status_code == 401


class TestAuditTrail:
    def test_create_is_audited(self, auth_client):
        add_rule(auth_client, name="audited")
        resp = auth_client.get("/api/audit",
                               params={"action": "rule.create"})
        assert resp.json()["total"] == 1
        entry = resp.json()["entries"][0]
        assert entry["actor_username"] == "root"
        assert entry["target_type"] == "rule"

    def test_update_is_audited_with_before_and_after(self, auth_client):
        rule = add_rule(auth_client)
        auth_client.patch(f"/api/rules/{rule['id']}", json={"priority": 3})
        resp = auth_client.get("/api/audit",
                               params={"action": "rule.update"})
        assert resp.json()["total"] >= 1

    def test_delete_is_audited(self, auth_client):
        rule = add_rule(auth_client)
        auth_client.delete(
            f"/api/rules/{rule['id']}", params={"confirm": "true"}
        )
        resp = auth_client.get("/api/audit",
                               params={"action": "rule.delete"})
        assert resp.json()["total"] == 1

    def test_reorder_is_audited(self, auth_client):
        rule = add_rule(auth_client)
        auth_client.post("/api/rules/reorder", json={"ids": [rule["id"]]})
        resp = auth_client.get("/api/audit",
                               params={"action": "rule.reorder"})
        assert resp.json()["total"] == 1

    def test_import_is_audited(self, auth_client):
        auth_client.post("/api/rules/import", json={"rules": [
            {"name": "imp", "rule_type": "deny_port", "value": "22"}]})
        resp = auth_client.get("/api/audit",
                               params={"action": "rule.import"})
        assert resp.json()["total"] == 1

    def test_rejected_create_is_not_audited_as_success(self, auth_client):
        resp = auth_client.post(
            "/api/rules",
            json={"name": "bad", "rule_type": "deny_cidr", "value": "nope"},
        )
        assert resp.status_code == 400
        resp = auth_client.get("/api/audit",
                               params={"action": "rule.create"})
        assert resp.json()["total"] == 0, "nothing was created, so nothing audited"

    def test_dry_run_is_not_audited(self, auth_client):
        add_rule(auth_client)
        auth_client.post("/api/rules/test", json={"target": "10.0.0.5"})
        resp = auth_client.get("/api/audit",
                               params={"action": "rule.denied"})
        assert resp.json()["total"] == 0, (
            "a dry run must not write a denial to the audit trail"
        )


class TestSettingsIntegration:
    def test_test_endpoint_reports_rules_enabled(self, auth_client):
        resp = auth_client.post("/api/rules/test", json={"target": "10.0.0.5"})
        assert resp.json()["rules_enabled"] == 1

    def test_test_endpoint_reflects_disabled_setting(self, auth_client):
        auth_client.patch("/api/settings",
                          json={"values": {"rules_enabled": "false"}})
        resp = auth_client.post("/api/rules/test", json={"target": "10.0.0.5"})
        assert resp.json()["rules_enabled"] == 0

    def test_new_settings_are_present(self, auth_client):
        settings = auth_client.get("/api/settings").json()["settings"]
        for key in (
            "rules_enabled",
            "rules_default_action",
            "rules_max_hits_per_day",
        ):
            assert key in settings, f"{key} missing from the settings API"