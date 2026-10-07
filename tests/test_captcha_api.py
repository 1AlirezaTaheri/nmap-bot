"""HTTP-level tests for the CAPTCHA on /api/login and /api/captcha.

Goes through the real application, so it covers what the unit tests cannot:
that the setting is consulted, that the status codes are what the frontend
branches on, and -- the important one -- that with the setting off the login
payload and behaviour are unchanged.

The fixtures are local rather than shared with conftest.py, which only
provides the anyio backend. This mirrors the pattern already used in
test_admin_api.py.
"""

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

from admin.services import auth as auth_service  # noqa: E402
from admin.services import captcha as captcha_service  # noqa: E402
from config.settings import Settings  # noqa: E402

USERNAME = "root"
PASSWORD = "an-initial-admin-password"


def build_client(tmp_path, monkeypatch, *, captcha_enabled: str):
    """A TestClient over a fresh app whose CAPTCHA is `captcha_enabled`.

    Settings is a frozen dataclass, so the flag cannot be patched onto an
    existing instance: it has to be set in the environment *before*
    create_app reads it. Hence a factory parameter rather than a fixture that
    toggles the attribute afterwards.
    """
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/captcha.db"
    )
    monkeypatch.setenv("ADMIN_JWT_SECRET", "test-secret-not-for-production")
    monkeypatch.setenv("CAPTCHA_ENABLED", captcha_enabled)

    from fastapi.testclient import TestClient

    from admin.services.bootstrap import create_app

    app = create_app(Settings.from_env())
    assert app.state.ctx.settings.captcha_enabled is (captcha_enabled == "true")
    client = TestClient(app)
    client.__enter__()
    client.app_ctx = app
    return client


@pytest.fixture
def client(tmp_path, monkeypatch):
    """CAPTCHA off -- the default a fresh deployment starts in."""
    c = build_client(tmp_path, monkeypatch, captcha_enabled="false")
    yield c
    c.__exit__(None, None, None)


@pytest.fixture
def enabled(tmp_path, monkeypatch):
    c = build_client(tmp_path, monkeypatch, captcha_enabled="true")
    yield c
    c.__exit__(None, None, None)


@pytest.fixture
def disabled(client):
    """Same app as `client`; named so the intent reads clearly at the call site."""
    return client


def solve(question: str) -> int:
    """Answer a challenge the way a person would: by reading it.

    Regex rather than ``split()``: "12 - 4 = ?" splits into three
    whitespace-separated fields, so the naive version raised on subtraction.
    """
    import re

    match = re.fullmatch(r"\s*(\d+)\s*([+-])\s*(\d+)\s*=\s*\?\s*", question)
    assert match is not None, f"unparseable question: {question!r}"
    a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
    return a - b if op == "-" else a + b


def peer_ip(client) -> str:
    """The address the app sees for a TestClient request.

    Computed by running the app's own dependency against a synthetic request,
    rather than hardcoded. Starlette's TestClient presents a transport whose
    peer host is "testclient", not "127.0.0.1", so assuming an address made
    every direct check fail with ip_mismatch while the endpoint under test was
    behaving correctly.

    A synthetic request is used rather than wrapping api.client_ip around a
    real call, because that would spend the login rate limiter's budget on
    every lookup -- and the tests that need this helper are the ones
    measuring that budget.
    """
    from admin.deps import client_ip

    class _Ctx:
        settings = client.app_ctx.state.ctx.settings

    class _Request:
        app = type("_A", (), {"state": type("_S", (), {"ctx": _Ctx()})()})()
        headers: dict[str, str] = {}
        client = type("_C", (), {"host": "testclient"})()

    return client_ip(_Request())


def get_captcha(client):
    """Fetch a challenge over HTTP. Returns (token, answer)."""
    resp = client.get("/api/captcha")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return body["token"], solve(body["question"])


def issue_directly(client):
    """Mint a challenge in-process, bypassing the HTTP rate limiter.

    GET /api/captcha deliberately shares the login limiter, so a test that
    needs several challenges to submit cannot obtain them over HTTP without
    spending the very budget it is trying to measure.
    """
    ctx = client.app_ctx.state.ctx
    ch = captcha_service.issue_challenge(peer_ip(client), ctx.captcha_store)
    assert ch.token, "issue_directly ran into the per-client challenge cap"
    return ch.token, ch.answer


def audit_rows(client, action):
    """Read audit rows straight from the app's database."""
    from sqlalchemy import select

    from database.models import AuditLog

    with client.app_ctx.state.ctx.database.session() as session:
        return list(session.scalars(
            select(AuditLog).where(AuditLog.action == action)))


def clear_limiter(client):
    client.app_ctx.state.ctx.login_limiter.prune()


# ---------------------------------------------------------------------------
# GET /api/captcha
# ---------------------------------------------------------------------------
class TestCaptchaEndpoint:
    def test_returns_question_and_token(self, client):
        resp = client.get("/api/captcha")
        assert resp.status_code == 200
        body = resp.json()
        assert body["question"]
        assert body["token"].startswith(captcha_service.TOKEN_PREFIX)
        assert body["expires_in"] == captcha_service.TOKEN_TTL_SECONDS

    def test_needs_no_session(self, client):
        """The login page is not authenticated yet."""
        assert client.get("/api/captcha").status_code == 200

    def test_question_is_answerable(self, client):
        for _ in range(5):
            assert solve(client.get("/api/captcha").json()["question"]) >= 0

    def test_response_never_contains_the_answer(self, client):
        """Asserted at the HTTP surface, where it actually matters.

        Compared claim-by-claim, not as a substring: the digest is 64 hex
        characters, so a one- or two-digit answer occurs inside it by chance
        every few requests, which makes a substring assertion fail for
        reasons unrelated to the code.
        """
        # Each challenge is spent before the next is fetched: the endpoint shares
        # the login rate limiter and the store caps outstanding challenges per
        # client, so a tight loop would run out of both and start asserting on
        # error responses instead of on payloads.
        for _ in range(10):
            resp = client.get("/api/captcha")
            # The endpoint shares the login rate limiter, so a tight loop will
            # legitimately start returning 429 partway through. Stop there:
            # a refusal carries no payload and there is nothing to assert.
            if resp.status_code == 429:
                break
            assert resp.status_code == 200, resp.text
            body = resp.json()
            answer = solve(body["question"])
            assert answer not in body.values()
            assert "answer" not in body
            assert body["token"] != str(answer)

            ctx = client.app_ctx.state.ctx
            ok, reason = captcha_service.verify_challenge(
                body["token"], answer, peer_ip(client), ctx.captcha_store)
            assert ok, f"freshly issued challenge did not verify: {reason}"

    def test_rate_limited_like_login(self, client):
        """Otherwise it is a free way to pull challenges in bulk."""
        codes = [client.get("/api/captcha").status_code for _ in range(7)]
        assert 429 in codes, codes


# ---------------------------------------------------------------------------
# CAPTCHA on
# ---------------------------------------------------------------------------
class TestLoginWithCaptcha:
    def test_correct_answer_logs_in(self, enabled):
        token, answer = get_captcha(enabled)
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": token, "captcha_answer": str(answer),
        })
        assert resp.status_code == 200, resp.text

    def test_wrong_answer_is_400(self, enabled):
        token, answer = get_captcha(enabled)
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": token, "captcha_answer": str(answer + 1),
        })
        assert resp.status_code == 400
        assert "captcha" in resp.json()["detail"].lower()

    def test_missing_captcha_is_400(self, enabled):
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
        })
        assert resp.status_code == 400

    def test_correct_password_without_a_challenge_is_400(self, enabled):
        """Even with the right password: the check runs first."""
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
        })
        assert resp.status_code == 400

    def test_answer_may_be_a_string(self, enabled):
        """The browser sends a string, so this is the real path."""
        token, answer = get_captcha(enabled)
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": token, "captcha_answer": f" {answer} ",
        })
        assert resp.status_code == 200, resp.text

    def test_wrong_answer_rejected_before_bcrypt(self, enabled, monkeypatch):
        """Order matters for cost: bcrypt at cost 12 must not run."""
        calls = []
        original = auth_service.verify_password

        def spy(plain, hashed):
            calls.append(plain)
            return original(plain, hashed)

        monkeypatch.setattr(auth_service, "verify_password", spy)
        token, answer = get_captcha(enabled)
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": token, "captcha_answer": str(answer + 1),
        })
        assert resp.status_code == 400
        assert calls == [], "password verification ran despite a failed challenge"

    def test_replayed_token_is_400(self, enabled):
        token, answer = get_captcha(enabled)
        first = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": token, "captcha_answer": str(answer),
        })
        assert first.status_code == 200

        # Replay the same challenge. Clear the session cookie first so this is
        # about the challenge, not about already being signed in.
        enabled.cookies.clear()
        second = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": token, "captcha_answer": str(answer),
        })
        assert second.status_code == 400

    def test_forged_token_is_400(self, enabled):
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": captcha_service.TOKEN_PREFIX + "x" * 200,
            "captcha_answer": "5",
        })
        assert resp.status_code == 400

    def test_session_token_is_not_accepted_as_a_challenge(self, enabled):
        """Same signing key, different token type: must not cross over."""
        session = auth_service.issue_token(
            auth_service.Principal(id=1, username=USERNAME, role="superadmin"))
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": captcha_service.TOKEN_PREFIX + session,
            "captcha_answer": "5",
        })
        assert resp.status_code == 400

    def test_challenge_is_audited(self, enabled):
        token, answer = get_captcha(enabled)
        enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": token, "captcha_answer": str(answer + 1),
        })
        rows = audit_rows(enabled, "auth.login_failed")
        assert rows, "a failed challenge left no audit row"
        assert any("captcha" in str(r.details) for r in rows), \
            f"no captcha reason recorded: {[r.details for r in rows]}"

    def test_audit_does_not_record_the_answer(self, enabled):
        token, answer = get_captcha(enabled)
        enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": token, "captcha_answer": str(answer + 1),
        })
        for row in audit_rows(enabled, "auth.login_failed"):
            assert str(answer) not in str(row.details)
            assert str(answer + 1) not in str(row.details)

    def test_rate_limiter_still_applies(self, enabled):
        """A wrong challenge must not be a way around the limiter.

        Only login attempts are counted here. GET /api/captcha shares the same
        limiter, so fetching a challenge per attempt spends the budget on its
        own; the fetch is therefore taken from the budget's slack by issuing
        the challenges first and only then posting.
        """
        # Mint challenges one at a time: the store allows only 5 outstanding per
        # client, so holding all 7 at once returns unusable tokens for the last
        # two and the test would measure the wrong thing.
        codes = []
        for _ in range(7):
            token, answer = issue_directly(enabled)
            codes.append(enabled.post("/api/login", json={
                "username": USERNAME, "password": "wrong-password-here",
                "captcha_token": token, "captcha_answer": str(answer),
            }).status_code)
        assert 429 in codes, codes

    def test_throttled_before_the_challenge_is_read(self, enabled):
        """Order matters here too: 429 must win over 400."""
        for _ in range(6):
            enabled.post("/api/login", json={
                "username": USERNAME, "password": "wrong-password-here",
            })
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
        })
        assert resp.status_code == 429

    def test_challenge_from_another_address_is_refused(self, enabled, monkeypatch):
        """The token records the requesting address and must match at check."""
        token, answer = get_captcha(enabled)
        # Patched on admin.routes.api, not admin.deps: api.py imported the name
        # directly (`from admin.deps import client_ip`), so rebinding it in
        # deps has no effect on the handler under test.
        import admin.routes.api as api_mod

        monkeypatch.setattr(api_mod, "client_ip", lambda request: "203.0.113.9")
        resp = enabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": token, "captcha_answer": str(answer),
        })
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# CAPTCHA off: behaviour must be exactly as before
# ---------------------------------------------------------------------------
class TestLoginWithoutCaptcha:
    def test_login_succeeds_without_any_challenge(self, disabled):
        resp = disabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
        })
        assert resp.status_code == 200, resp.text

    def test_wrong_password_still_401_not_400(self, disabled):
        """The status distinguishes 'no challenge' from 'wrong challenge'."""
        resp = disabled.post("/api/login", json={
            "username": USERNAME, "password": "wrong-password-here",
        })
        assert resp.status_code == 401

    def test_a_bogus_challenge_is_ignored_when_off(self, disabled):
        """Extra fields are not read, so an old client still works."""
        resp = disabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
            "captcha_token": captcha_service.TOKEN_PREFIX + "garbage",
            "captcha_answer": "wrong",
        })
        assert resp.status_code == 200, resp.text

    def test_payload_shape_is_unchanged(self, disabled):
        """username/password only: exactly what the old frontend sent."""
        resp = disabled.post("/api/login", json={
            "username": USERNAME, "password": PASSWORD,
        })
        assert resp.status_code == 200
        assert "username" in resp.json()

    def test_rate_limiter_still_applies(self, disabled):
        codes = [disabled.post("/api/login", json={
            "username": USERNAME, "password": "wrong-password-here",
        }).status_code for _ in range(7)]
        assert 429 in codes, codes

    def test_no_captcha_audit_rows_when_off(self, disabled):
        disabled.post("/api/login", json={
            "username": USERNAME, "password": "wrong-password-here",
        })
        rows = audit_rows(disabled, "auth.login_failed")
        assert rows
        assert not any("captcha" in str(r.details) for r in rows)

    def test_default_setting_is_off(self, client):
        """A fresh deployment must not start enforcing a CAPTCHA."""
        assert client.app_ctx.state.ctx.settings.captcha_enabled is False


# ---------------------------------------------------------------------------
# The Mini App must be untouched
# ---------------------------------------------------------------------------
class TestMiniAppUnaffected:
    def test_miniapp_routes_still_present(self, client):
        # Not app.routes or app.router.routes: this FastAPI version records an
        # include_router() call as a single `_IncludedRouter` object with no
        # `.path`, so enumerating either list finds four docs routes and two
        # static mounts and nothing else. The OpenAPI schema is built from the
        # resolved routes, so it is the only list that is actually complete.
        paths = set(client.app_ctx.openapi()["paths"])
        assert "/miniapp/me" in paths, sorted(paths)
        assert "/api/captcha" in paths
        assert "/api/login" in paths

    def test_miniapp_me_still_refuses_without_init_data(self, client):
        assert client.get("/miniapp/me").status_code == 401

    def test_miniapp_me_still_refuses_a_forged_hash(self, client):
        resp = client.get(
            "/miniapp/me",
            headers={"X-Telegram-Init-Data": "user=%7B%7D&hash=" + "0" * 64},
        )
        assert resp.status_code == 401

    def test_captcha_endpoint_does_not_shadow_a_miniapp_route(self, client):
        """One route per path, and nothing under /miniapp changed."""
        paths = client.app_ctx.openapi()["paths"]
        assert "/api/captcha" in paths
        assert not any("captcha" in p for p in paths if p.startswith("/miniapp"))
        # The endpoint must not require a session either: it is on the login
        # page. Security is not declared in the schema, so this is asserted
        # behaviourally by TestCaptchaEndpoint.test_needs_no_session; here we
        # only confirm it was registered on the /api router, not behind a
        # dependency the login page cannot satisfy.
        assert set(paths["/api/captcha"]) == {"get"}, \
            "expected a GET-only route"