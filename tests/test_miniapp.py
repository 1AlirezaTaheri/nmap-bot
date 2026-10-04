"""Tests for the Telegram Mini App: initData verification and the /miniapp API.

The signature scheme is the security boundary, so it gets the most attention:
a forged blob, a tampered blob, a stale one and one signed with the wrong bot
token must all be refused, and every refusal must be audited.
"""

from __future__ import annotations

import os
import pathlib
import time

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("ADMIN_USERNAME", "root")
os.environ.setdefault("ADMIN_PASSWORD", "an-initial-admin-password")
os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "777777:MINIAPP_test_token")
os.environ.setdefault("ALLOWED_USER_IDS", "7575983824")
os.environ.setdefault("ADMIN_COOKIE_SECURE", "false")
os.environ.setdefault("MINIAPP_URL", "https://example.trycloudflare.com")

from admin.services.bootstrap import create_app  # noqa: E402
from config.settings import Settings  # noqa: E402
from core.miniapp_auth import (  # noqa: E402
    MiniAppAuthError,
    build_check_string,
    compute_signature,
    derive_secret_key,
    is_miniapp_enabled,
    mini_app_url,
    sign_init_data,
    validate_init_data,
)

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
USER_ID = 7575983824
HEADER = "X-Telegram-Init-Data"


def user_json(user_id: int = USER_ID, first: str = "Alireza") -> str:
    return (
        '{"id":%d,"first_name":"%s","last_name":"T","username":"alireza",'
        '"language_code":"en","is_premium":false}' % (user_id, first)
    )


def blob(
    user_id: int = USER_ID,
    auth_date: int | None = None,
    token: str = TOKEN,
    **extra: str,
) -> str:
    fields = [("query_id", "AAHdF6IQ"), ("user", user_json(user_id))]
    fields.append(
        ("auth_date", str(auth_date if auth_date is not None else int(time.time())))
    )
    fields.extend(extra.items())
    return sign_init_data(token, fields)


# ---------------------------------------------------------------------------
# Signature scheme
# ---------------------------------------------------------------------------


class TestKeyDerivation:
    def test_secret_is_hmac_key_webappdata(self):
        import hashlib
        import hmac

        expected = hmac.new(
            b"WebAppData", TOKEN.encode(), hashlib.sha256
        ).digest()
        assert derive_secret_key(TOKEN) == expected

    def test_not_the_reversed_arguments(self):
        import hashlib
        import hmac

        # HMAC(key=token, msg=WebAppData) is a common mistake and produces a
        # signature Telegram rejects, which would look like a random bug.
        wrong = hmac.new(TOKEN.encode(), b"WebAppData", hashlib.sha256).digest()
        assert derive_secret_key(TOKEN) != wrong

    def test_secret_is_32_bytes(self):
        assert len(derive_secret_key(TOKEN)) == 32


class TestCheckString:
    def test_sorted_and_newline_joined(self):
        fields = [("b", "2"), ("a", "1"), ("hash", "deadbeef")]
        assert build_check_string(fields) == "a=1\nb=2"

    def test_excludes_hash(self):
        assert "hash" not in build_check_string([("hash", "x"), ("a", "1")])

    def test_deterministic(self):
        fields = [("z", "1"), ("a", "2")]
        assert build_check_string(fields) == build_check_string(list(reversed(fields)))


class TestValidateInitData:
    def test_accepts_a_well_formed_blob(self):
        result = validate_init_data(blob(), TOKEN)
        assert result["user"]["id"] == USER_ID
        assert result["user"]["first_name"] == "Alireza"

    @pytest.mark.parametrize("value", ["", "   "])
    def test_rejects_empty(self, value):
        with pytest.raises(MiniAppAuthError) as exc:
            validate_init_data(value, TOKEN)
        assert exc.value.code == "missing"

    def test_rejects_a_missing_hash(self):
        with pytest.raises(MiniAppAuthError) as exc:
            validate_init_data("user=%7B%22id%22%3A1%7D&auth_date=1", TOKEN)
        assert exc.value.code == "no_hash"

    def test_rejects_a_forged_hash(self):
        forged = blob().rsplit("=", 1)[0] + "=" + ("0" * 64)
        with pytest.raises(MiniAppAuthError) as exc:
            validate_init_data(forged, TOKEN)
        assert exc.value.code == "bad_signature"

    def test_rejects_a_tampered_field(self):
        # The whole point of signing: changing the user id invalidates it.
        tampered = blob().replace(str(USER_ID), "1111111111")
        with pytest.raises(MiniAppAuthError) as exc:
            validate_init_data(tampered, TOKEN)
        assert exc.value.code == "bad_signature"

    def test_rejects_another_bot_token(self):
        with pytest.raises(MiniAppAuthError) as exc:
            validate_init_data(blob(), "999999:other")
        assert exc.value.code == "bad_signature"

    def test_rejects_stale(self):
        stale = blob(auth_date=int(time.time()) - 90000)
        with pytest.raises(MiniAppAuthError) as exc:
            validate_init_data(stale, TOKEN, max_age_seconds=86400)
        assert exc.value.code == "expired"

    def test_accepts_just_inside_the_limit(self):
        fresh = blob(auth_date=int(time.time()) - 86300)
        assert validate_init_data(fresh, TOKEN, max_age_seconds=86400)

    def test_rejects_a_future_auth_date(self):
        # A skewed clock must not buy extra life.
        future = blob(auth_date=int(time.time()) + 3600)
        with pytest.raises(MiniAppAuthError) as exc:
            validate_init_data(future, TOKEN)
        assert exc.value.code == "bad_auth_date"

    def test_signature_check_precedes_the_freshness_check(self):
        # Otherwise an attacker learns about staleness from blobs they forged.
        forged_and_old = blob(auth_date=1).rsplit("=", 1)[0] + "=" + ("f" * 64)
        with pytest.raises(MiniAppAuthError) as exc:
            validate_init_data(forged_and_old, TOKEN)
        assert exc.value.code == "bad_signature"

    def test_start_param_is_extracted(self):
        assert validate_init_data(
            blob(start_param="scan home"), TOKEN
        )["start_param"] == "scan home"

    def test_signature_is_reproducible(self):
        check_string = build_check_string(
            [("auth_date", "1"), ("user", user_json())]
        )
        assert compute_signature(TOKEN, check_string) == compute_signature(
            TOKEN, check_string
        )


class TestUrlHelpers:
    def test_app_path(self):
        assert mini_app_url("https://x.trycloudflare.com") == (
            "https://x.trycloudflare.com/app"
        )

    def test_start_param_is_encoded(self):
        assert "startapp=scan%20home" in mini_app_url(
            "https://x.trycloudflare.com", "scan home"
        )

    def test_empty_base(self):
        assert mini_app_url("") == ""

    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://x.trycloudflare.com", True),
            ("http://127.0.0.1:8080", False),
            ("", False),
            (None, False),
        ],
    )
    def test_https_required(self, url, expected):
        assert is_miniapp_enabled(url) is expected


# ---------------------------------------------------------------------------
# The HTTP surface
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/miniapp.db"
    )
    app = create_app(Settings.from_env())
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth(client):
    def _headers(**kwargs):
        return {HEADER: blob(**kwargs)}

    return _headers


READ_PATHS = (
    "/miniapp/me",
    "/miniapp/stats",
    "/miniapp/targets",
    "/miniapp/changes",
    "/miniapp/rules",
    "/miniapp/scans/active",
    "/miniapp/profiles",
)


class TestAuthentication:
    @pytest.mark.parametrize("path", READ_PATHS)
    def test_absent_header_is_401(self, client, path):
        assert client.get(path).status_code == 401

    def test_forged_is_401(self, client):
        forged = blob().rsplit("=", 1)[0] + "=" + ("a" * 64)
        resp = client.get("/miniapp/me", headers={HEADER: forged})
        assert resp.status_code == 401

    def test_tampered_is_401(self, client):
        tampered = blob().replace(str(USER_ID), "1")
        assert client.get("/miniapp/me", headers={HEADER: tampered}).status_code == 401

    def test_wrong_token_is_401(self, client):
        other = blob(token="111111:nope")
        assert client.get("/miniapp/me", headers={HEADER: other}).status_code == 401

    def test_user_outside_the_allowlist_is_403(self, client):
        # A validly signed blob from someone not in ALLOWED_USER_IDS: the
        # signature proves who they are, the allow-list decides if they may.
        resp = client.get("/miniapp/me", headers={HEADER: blob(user_id=999999999)})
        assert resp.status_code == 403

    def test_me_creates_the_row_on_first_visit(self, client):
        resp = client.get("/miniapp/me", headers={HEADER: blob()})
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == USER_ID
        assert body["display_name"] == "Alireza T"
        assert "role" in body and "language" in body

    def test_language_is_seeded_from_the_telegram_locale(self, client):
        body = client.get("/miniapp/me", headers={HEADER: blob()}).json()
        # user_json carries language_code "en"
        assert body["language"] == "en"

    def test_failures_are_audited(self, client):
        client.get("/miniapp/me")
        client.get("/miniapp/me", headers={HEADER: blob(user_id=999999999)})

        from sqlalchemy import select

        from database.database import Database
        from database.models import AuditLog

        database = Database(Settings.from_env().database_url)
        with database.session() as session:
            rows = session.scalars(
                select(AuditLog).where(
                    AuditLog.action == "miniapp.auth_failed"
                )
            ).all()
            codes = {r.details for r in rows if r.details}
        database.dispose()

        assert len(rows) >= 2
        assert any("missing" in c for c in codes)
        assert any("not_allowed" in c for c in codes)


class TestAuthorization:
    @pytest.fixture
    def operator(self, client):
        from admin.services.users import update_telegram_user
        from database.database import Database

        client.get("/miniapp/me", headers={HEADER: blob()})
        database = Database(Settings.from_env().database_url)
        with database.session() as session:
            update_telegram_user(session, USER_ID, role="operator")
        database.dispose()
        return client

    def test_a_viewer_cannot_add_a_target(self, client):
        client.get("/miniapp/me", headers={HEADER: blob()})
        resp = client.post(
            "/miniapp/targets",
            json={"name": "home", "value": "192.168.1.0/24"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 403

    def test_an_operator_can_add_a_target(self, operator):
        resp = operator.post(
            "/miniapp/targets",
            json={"name": "home", "value": "192.168.1.0/24"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 201

    def test_duplicate_target_is_409(self, operator):
        body = {"name": "dup", "value": "192.168.1.0/24"}
        assert operator.post(
            "/miniapp/targets", json=body, headers={HEADER: blob()}
        ).status_code == 201
        assert operator.post(
            "/miniapp/targets", json=body, headers={HEADER: blob()}
        ).status_code == 409

    def test_invalid_target_is_400(self, operator):
        resp = operator.post(
            "/miniapp/targets",
            json={"name": "bad", "value": "not a target"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 400

    def test_a_disabled_account_is_refused_on_reads(self, operator):
        from admin.services.users import update_telegram_user
        from database.database import Database

        database = Database(Settings.from_env().database_url)
        with database.session() as session:
            update_telegram_user(session, USER_ID, enabled=False)

        for path in READ_PATHS:
            resp = operator.get(path, headers={HEADER: blob()})
            assert resp.status_code == 403, f"{path} returned {resp.status_code}"

        resp = operator.post(
            "/miniapp/targets",
            json={"name": "x", "value": "10.0.0.0/24"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 403
        database.dispose()


class TestSettings:
    def test_update_language(self, client):
        client.get("/miniapp/me", headers={HEADER: blob()})
        resp = client.patch(
            "/miniapp/settings",
            json={"language": "fa"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 200

    def test_regional_locale_is_accepted(self, client):
        # Telegram sends "en-US"; it must store "en", not silently fall back.
        client.get("/miniapp/me", headers={HEADER: blob()})
        resp = client.patch(
            "/miniapp/settings",
            json={"language": "en-US"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 200
        body = client.get("/miniapp/me", headers={HEADER: blob()}).json()
        assert body["language"] == "en"

    def test_a_saved_language_survives_the_next_request(self, client):
        """The regression: the Telegram locale must not overwrite a choice.

        user_json() carries language_code "en", so seeding on every auth
        would reset the stored value to "en" after the PATCH set it to "fa".
        """
        client.get("/miniapp/me", headers={HEADER: blob()})

        saved = client.patch(
            "/miniapp/settings",
            json={"language": "fa"},
            headers={HEADER: blob()},
        )
        assert saved.status_code == 200
        assert (
            client.get("/miniapp/me", headers={HEADER: blob()}).json()["language"]
            == "fa"
        )

        # And again, to be sure it is not a one-shot.
        client.get("/miniapp/stats", headers={HEADER: blob()})
        client.get("/miniapp/me", headers={HEADER: blob()})
        assert (
            client.get("/miniapp/me", headers={HEADER: blob()}).json()["language"]
            == "fa"
        )

    def test_unknown_language_is_400(self, client):
        client.get("/miniapp/me", headers={HEADER: blob()})
        resp = client.patch(
            "/miniapp/settings",
            json={"language": "zz"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 400

    def test_toggle_notifications(self, client):
        client.get("/miniapp/me", headers={HEADER: blob()})
        resp = client.patch(
            "/miniapp/settings",
            json={"notifications_enabled": False},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 200
        body = client.get("/miniapp/me", headers={HEADER: blob()}).json()
        assert body["notifications_enabled"] is False

    def test_empty_update_is_400(self, client):
        client.get("/miniapp/me", headers={HEADER: blob()})
        resp = client.patch("/miniapp/settings", json={}, headers={HEADER: blob()})
        assert resp.status_code == 400


class TestReads:
    @pytest.fixture(autouse=True)
    def _seed(self, client):
        client.get("/miniapp/me", headers={HEADER: blob()})

    def test_stats_shape(self, client):
        body = client.get("/miniapp/stats", headers={HEADER: blob()}).json()
        for field in (
            "targets",
            "scans_24h",
            "changes_24h",
            "series",
            "change_breakdown",
        ):
            assert field in body

    def test_targets_shape(self, client):
        body = client.get("/miniapp/targets", headers={HEADER: blob()}).json()
        assert "targets" in body and "total" in body

    def test_rules_advertise_the_vocabulary(self, client):
        body = client.get("/miniapp/rules", headers={HEADER: blob()}).json()
        assert "rule_types" in body
        assert "deny_cidr" in body["rule_types"]

    def test_changes_paginates(self, client):
        body = client.get(
            "/miniapp/changes?page=1&page_size=5", headers={HEADER: blob()}
        ).json()
        assert set(body) >= {"changes", "total", "page", "page_size"}
        assert body["page"] == 1

    def test_changes_can_filter(self, client):
        body = client.get(
            "/miniapp/changes?change_type=new_host", headers={HEADER: blob()}
        ).json()
        assert body["total"] == 0

    def test_active_scan_is_null_when_idle(self, client):
        body = client.get("/miniapp/scans/active", headers={HEADER: blob()}).json()
        assert body["scan"] is None

    def test_missing_scan_is_404(self, client):
        resp = client.get("/miniapp/scans/424242", headers={HEADER: blob()})
        assert resp.status_code == 404

    def test_profiles(self, client):
        body = client.get("/miniapp/profiles", headers={HEADER: blob()}).json()
        assert set(body["profiles"]) == {"quick", "service", "deep"}


class TestRulesDryRun:
    @pytest.fixture(autouse=True)
    def _seed(self, client):
        client.get("/miniapp/me", headers={HEADER: blob()})

    def test_returns_a_decision(self, client):
        resp = client.post(
            "/miniapp/rules/test",
            json={"target": "10.0.0.5"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["allowed"] is True
        assert body["side_effects"] == "none"

    def test_writes_nothing(self, client):
        before = client.get("/miniapp/rules", headers={HEADER: blob()}).json()
        client.post(
            "/miniapp/rules/test",
            json={"target": "10.0.0.5"},
            headers={HEADER: blob()},
        )
        after = client.get("/miniapp/rules", headers={HEADER: blob()}).json()
        assert after["total"] == before["total"]

    def test_rejects_a_bad_timestamp(self, client):
        resp = client.post(
            "/miniapp/rules/test",
            json={"target": "10.0.0.5", "now": "not-a-date"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 400


class TestScanRequest:
    @pytest.fixture
    def operator(self, client):
        from admin.services.users import update_telegram_user
        from database.database import Database

        client.get("/miniapp/me", headers={HEADER: blob()})
        with client.app.state.ctx.database.session() as session:
            from core.target_manager import TargetRegistry

            TargetRegistry(client.app.state.ctx.database).add(
                "home", "192.168.1.0/24"
            )
        database = Database(Settings.from_env().database_url)
        with database.session() as session:
            update_telegram_user(session, USER_ID, role="operator")
        database.dispose()
        return client

    def test_unregistered_name_resolves_as_an_ad_hoc_target(self, operator):
        """Mirrors /scan: a raw address works without registration.

        The bot's /scan accepts either a registered name or an ad-hoc target
        string, and the Mini App deliberately reuses that resolution so there
        is one policy rather than two. A bare hostname is therefore queued,
        exactly as `/scan somename` would be.
        """
        resp = operator.post(
            "/miniapp/scan",
            json={"target": "lab-host.example.test"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 202
        assert resp.json()["target"] == "lab-host.example.test"

    def test_a_registered_name_wins_over_the_raw_string(self, operator):
        # resolve() checks the registry first, so "home" is the registered
        # target rather than a hostname literally called "home".
        resp = operator.post(
            "/miniapp/scan",
            json={"target": "home"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 202
        assert resp.json()["target"] == "home"

    def test_a_string_that_is_neither_is_404(self, operator):
        # Neither a registered name nor a parseable target: this is the case
        # that must not silently become a scan of something unintended.
        resp = operator.post(
            "/miniapp/scan",
            json={"target": "not a target at all!!"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 404

    def test_bad_profile_is_400(self, operator):
        resp = operator.post(
            "/miniapp/scan",
            json={"target": "home", "profile": "nuclear"},
            headers={HEADER: blob()},
        )
        assert resp.status_code == 400

    def test_a_viewer_cannot_queue_a_scan(self, client):
        client.get("/miniapp/me", headers={HEADER: blob()})
        resp = client.post(
            "/miniapp/scan", json={"target": "home"}, headers={HEADER: blob()}
        )
        assert resp.status_code == 403


class TestServing:
    def test_mini_app_shell_or_a_build_hint(self, client):
        # Resolve from this file, not from a hardcoded host path: the suite
        # runs with the repo mounted at /src inside the container, so the
        # host path does not exist there and the test would always take the
        # "not built" branch and assert the wrong status.
        repo = pathlib.Path(__file__).resolve().parent.parent
        built = (repo / "mini-app" / "dist" / "index.html").exists()
        resp = client.get("/app")
        if built:
            assert resp.status_code == 200
            assert 'id="root"' in resp.text
        else:
            assert resp.status_code == 503
            assert "npm run build" in resp.json()["detail"]

    def test_client_routes_fall_through(self, client):
        for path in ("/app", "/app/", "/app/targets", "/app/anything"):
            assert client.get(path).status_code in (200, 503)


class TestBotAffordances:
    def test_menu_button_is_built_when_configured(self):
        from bot import miniapp as ui

        class S:
            miniapp_url = "https://x.trycloudflare.com"

        button = ui.menu_button(S())
        assert button is not None
        assert button.web_app.url == "https://x.trycloudflare.com/app"

    def test_menu_button_is_none_when_unset(self):
        from bot import miniapp as ui

        class S:
            miniapp_url = ""

        assert ui.menu_button(S()) is None

    def test_menu_button_is_none_for_plain_http(self):
        from bot import miniapp as ui

        class S:
            miniapp_url = "http://127.0.0.1:8080"

        assert ui.menu_button(S()) is None, (
            "Telegram cannot load a plain-HTTP Mini App"
        )

    def test_keyboard_is_none_when_unset(self):
        from bot import miniapp as ui

        class S:
            miniapp_url = ""

        assert ui.inline_keyboard(S()) is None

    def test_keyboard_has_one_web_app_button(self):
        from bot import miniapp as ui

        class S:
            miniapp_url = "https://x.trycloudflare.com"

        keyboard = ui.inline_keyboard(S())
        row = keyboard.inline_keyboard[0]
        assert len(row) == 1
        assert row[0].web_app.url.endswith("/app")

    def test_url_carries_a_start_param(self):
        from bot import miniapp as ui

        class S:
            miniapp_url = "https://x.trycloudflare.com"

        assert "startapp=home" in ui.app_url(S, "home")