"""Tests for admin auth: bcrypt hashing, JWT, login throttling."""

from __future__ import annotations

import time

import pytest

from admin.services import auth as auth_service
from admin.services.auth import (
    ALGORITHM,
    MIN_PASSWORD_LENGTH,
    AuthError,
    LoginRateLimiter,
    Principal,
    decode_token,
    hash_password,
    issue_token,
    needs_rehash,
    secret_key,
    verify_password,
)

GOOD_PASSWORD = "correct-horse-battery-staple"


class TestPasswordHashing:
    def test_hash_and_verify(self):
        hashed = hash_password(GOOD_PASSWORD)
        assert verify_password(GOOD_PASSWORD, hashed) is True
        assert verify_password("wrong-password", hashed) is False

    def test_hash_is_not_plaintext(self):
        hashed = hash_password(GOOD_PASSWORD)
        assert GOOD_PASSWORD not in hashed
        assert hashed.startswith("$2")

    def test_hash_is_salted(self):
        a = hash_password(GOOD_PASSWORD)
        b = hash_password(GOOD_PASSWORD)
        assert a != b  # distinct salts

    def test_short_password_rejected(self):
        with pytest.raises(AuthError):
            hash_password("short")

    def test_empty_password_rejected(self):
        with pytest.raises(AuthError):
            hash_password("")

    def test_minimum_length_is_enforced(self):
        with pytest.raises(AuthError):
            hash_password("x" * (MIN_PASSWORD_LENGTH - 1))

    def test_verify_with_empty_hash_is_false(self):
        assert verify_password(GOOD_PASSWORD, "") is False

    def test_verify_with_empty_password_is_false(self):
        assert verify_password("", hash_password(GOOD_PASSWORD)) is False

    def test_verify_tolerates_garbage_hash(self):
        assert verify_password(GOOD_PASSWORD, "not-a-bcrypt-hash") is False

    def test_needs_rehash_detects_legacy(self):
        # A bcrypt hash from an older cost should be flagged.
        assert needs_rehash("$2b$04$abcdefghijklmnopqrstuuKZfMGoVzqOq3rW7NEHDIeEcVxJkZ0Yq1S") is True


class TestTokenRoundTrip:
    def test_issue_then_decode(self):
        principal = Principal(id=7, username="root", role="superadmin")
        token = issue_token(principal)
        decoded = decode_token(token)
        assert decoded.id == 7
        assert decoded.username == "root"
        assert decoded.role == "superadmin"

    def test_token_is_a_string(self):
        token = issue_token(Principal(1, "a", "viewer"))
        assert isinstance(token, str)

    def test_rejects_garbage_token(self):
        with pytest.raises(AuthError):
            decode_token("not-a-jwt")

    def test_rejects_empty_token(self):
        with pytest.raises(AuthError):
            decode_token("")

    def test_rejects_tampered_token(self):
        token = issue_token(Principal(1, "a", "viewer"))
        with pytest.raises(AuthError):
            decode_token(token[:-4] + "AAAA")

    def test_rejects_expired_token(self):
        token = issue_token(Principal(1, "a", "viewer"), ttl_seconds=-10)
        with pytest.raises(AuthError) as exc:
            decode_token(token)
        assert "expired" in str(exc.value).lower()

    def test_rejects_token_signed_with_another_secret(self):
        import jwt as pyjwt

        forged = pyjwt.encode(
            {"sub": "1", "username": "root", "role": "superadmin",
             "exp": int(time.time()) + 999},
            "a-different-secret",
            algorithm=ALGORITHM,
        )
        with pytest.raises(AuthError):
            decode_token(forged)

    def test_rejects_token_with_bad_role(self):
        import jwt as pyjwt

        bad = pyjwt.encode(
            {"sub": "1", "username": "x", "role": "wizard",
             "exp": int(time.time()) + 999},
            secret_key(), algorithm=ALGORITHM,
        )
        with pytest.raises(AuthError):
            decode_token(bad)

    def test_rejects_token_missing_subject(self):
        import jwt as pyjwt

        bad = pyjwt.encode(
            {"username": "x", "role": "admin", "exp": int(time.time()) + 999},
            secret_key(), algorithm=ALGORITHM,
        )
        with pytest.raises(AuthError):
            decode_token(bad)


class TestRoleRanking:
    @pytest.mark.parametrize(
        "role,required,allowed",
        [
            ("superadmin", "viewer", True),
            ("superadmin", "admin", True),
            ("superadmin", "superadmin", True),
            ("admin", "viewer", True),
            ("admin", "admin", True),
            ("admin", "superadmin", False),
            ("viewer", "viewer", True),
            ("viewer", "admin", False),
            ("viewer", "superadmin", False),
            ("wizard", "viewer", False),
        ],
    )
    def test_role_matrix(self, role, required, allowed):
        assert Principal(1, "u", role).has_role(required) is allowed


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class TestLoginRateLimiter:
    def test_allows_up_to_the_limit(self):
        clock = FakeClock()
        rl = LoginRateLimiter(5, 60, clock=clock)
        for _ in range(5):
            allowed, _remaining = rl.check("1.2.3.4")
            assert allowed is True

    def test_blocks_on_the_sixth_attempt(self):
        clock = FakeClock()
        rl = LoginRateLimiter(5, 60, clock=clock)
        for _ in range(5):
            rl.check("1.2.3.4")
        allowed, remaining = rl.check("1.2.3.4")
        assert allowed is False
        assert remaining == 0

    def test_limit_is_per_ip(self):
        clock = FakeClock()
        rl = LoginRateLimiter(2, 60, clock=clock)
        rl.check("1.1.1.1")
        rl.check("1.1.1.1")
        assert rl.check("1.1.1.1")[0] is False
        assert rl.check("2.2.2.2")[0] is True

    def test_window_expires(self):
        clock = FakeClock()
        rl = LoginRateLimiter(5, 60, clock=clock)
        for _ in range(5):
            rl.check("1.2.3.4")
        clock.advance(61)
        assert rl.check("1.2.3.4")[0] is True

    def test_reset_clears_the_counter(self):
        clock = FakeClock()
        rl = LoginRateLimiter(1, 60, clock=clock)
        rl.check("1.2.3.4")
        assert rl.check("1.2.3.4")[0] is False
        rl.reset("1.2.3.4")
        assert rl.check("1.2.3.4")[0] is True

    def test_remaining_counts_down(self):
        clock = FakeClock()
        rl = LoginRateLimiter(3, 60, clock=clock)
        assert rl.check("ip")[1] == 2
        assert rl.check("ip")[1] == 1
        assert rl.check("ip")[1] == 0

    def test_prune_drops_stale_ips(self):
        clock = FakeClock()
        rl = LoginRateLimiter(5, 60, clock=clock)
        rl.check("a")
        rl.check("b")
        clock.advance(120)
        rl.prune()
        assert rl._hits == {}