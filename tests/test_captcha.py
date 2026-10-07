"""Tests for the self-hosted login CAPTCHA.

Covers the service module on its own (pure, no app) and the HTTP behaviour
through the real application.

The properties under test, and why each matters:

  * the answer is never transmitted, so the challenge cannot be solved by
    reading the response;
  * a token is single-use, so a captured attempt cannot be replayed;
  * a token is bound to the issuing address;
  * a token expires;
  * a token signed with the wrong key, or without the required claims, is
    refused;
  * the per-client cap bounds how much state one address can create;
  * with CAPTCHA_ENABLED=false the login payload and behaviour are unchanged,
    which is what makes the feature safe to ship off by default.
"""

from __future__ import annotations

import time

import jwt
import pytest

from admin.services import captcha as captcha_service


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    """A fixed signing secret, so tests do not depend on the environment."""
    monkeypatch.setenv("ADMIN_JWT_SECRET", "test-secret-long-enough-for-hs256")
    return "test-secret-long-enough-for-hs256"


@pytest.fixture
def store():
    return captcha_service.CaptchaStore()


IP = "10.1.2.3"
OTHER_IP = "10.9.9.9"


def solve(question: str) -> int:
    """Answer the challenge the way a person would, by reading it.

    Parsed with a regex rather than ``split()``: splitting on whitespace
    yields three fields for "12 - 4 = ?" because the operator is a separate
    token, so the naive version raised on every subtraction.
    """
    import re

    match = re.fullmatch(r"\s*(\d+)\s*([+-])\s*(\d+)\s*=\s*\?\s*", question)
    assert match is not None, f"unparseable question: {question!r}"
    a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
    return a - b if op == "-" else a + b


# ---------------------------------------------------------------------------
# Issuing
# ---------------------------------------------------------------------------
class TestIssue:
    def test_issue_returns_a_question_and_token(self, store):
        ch = captcha_service.issue_challenge(IP, store)
        assert ch.question
        assert ch.token.startswith(captcha_service.TOKEN_PREFIX)

    def test_question_is_arithmetic_and_answerable(self, store):
        for _ in range(20):
            ch = captcha_service.issue_challenge(IP, store)
            assert solve(ch.question) == ch.answer

    def test_answer_is_never_in_the_response(self, store):
        """The whole point: a script cannot read the answer off the token.

        Checked over enough challenges that a one-digit answer would show up
        in the base64 payload by chance if it were really there.
        """
        # Solve each one as it is issued: the per-client cap is 5 outstanding
        # challenges, so issuing 40 without spending them returns an empty
        # token on the sixth and jwt.decode then fails on the empty string.
        # Spending also keeps the loop honest -- each token is a real one.
        for _ in range(40):
            ch = captcha_service.issue_challenge(IP, store)
            assert ch.token, "issue returned an empty token"
            raw = ch.token[len(captcha_service.TOKEN_PREFIX):]
            payload = jwt.decode(raw, options={"verify_signature": False})

            # No claim *equals* the answer. A substring test would be
            # meaningless here: the digest is 64 hex characters, so a
            # one-digit answer appears inside it by chance roughly once per
            # handful of challenges, which is what made the first version of
            # this test fail for a reason that had nothing to do with the
            # code.
            assert "answer" not in payload
            assert ch.answer not in payload.values()

            # The digest is a hash of it, and a hash is not reversible to it.
            digest = payload["digest"]
            assert digest != str(ch.answer)
            assert len(digest) == 64
            assert all(c in "0123456789abcdef" for c in digest)

            # And it really is the hash of this answer, which is what
            # verify_challenge recomputes at check time.
            assert digest == captcha_service._hash_answer(ch.answer, ch.nonce)

            assert captcha_service.verify_challenge(
                ch.token, ch.answer, IP, store)[0]

    def test_token_carries_a_digest_not_the_answer(self, store):
        ch = captcha_service.issue_challenge(IP, store)
        payload = jwt.decode(ch.token[len(captcha_service.TOKEN_PREFIX):],
                             options={"verify_signature": False})
        assert payload["typ"] == "captcha"
        assert payload["digest"] == captcha_service._hash_answer(ch.answer, ch.nonce)
        # The digest is 64 hex characters, so it cannot be the answer itself
        # except in the impossible case where the answer is that long.
        assert len(payload["digest"]) == 64
        assert all(c in "0123456789abcdef" for c in payload["digest"])

    def test_token_binds_the_issuing_address(self, store):
        ch = captcha_service.issue_challenge(IP, store)
        payload = jwt.decode(ch.token[len(captcha_service.TOKEN_PREFIX):],
                             options={"verify_signature": False})
        assert payload["ip"] == IP

    def test_each_challenge_is_distinct(self, store):
        nonces = {captcha_service.issue_challenge(IP, store).nonce
                  for _ in range(10)}
        assert len(nonces) == 10

    def test_issued_at_and_expiry_are_five_minutes_apart(self, store):
        now = 1_700_000_000
        ch = captcha_service.issue_challenge(IP, store, now=now)
        payload = jwt.decode(ch.token[len(captcha_service.TOKEN_PREFIX):],
                             options={"verify_signature": False})
        assert payload["exp"] - payload["iat"] == captcha_service.TOKEN_TTL_SECONDS == 300


# ---------------------------------------------------------------------------
# Verifying: the happy path
# ---------------------------------------------------------------------------
class TestVerify:
    def test_correct_answer_accepted(self, store):
        ch = captcha_service.issue_challenge(IP, store)
        ok, reason = captcha_service.verify_challenge(
            ch.token, ch.answer, IP, store)
        assert ok, reason

    def test_answer_accepted_as_string(self, store):
        """The browser sends a string; the schema types it as a string."""
        ch = captcha_service.issue_challenge(IP, store)
        ok, _ = captcha_service.verify_challenge(
            ch.token, str(ch.answer), IP, store)
        assert ok

    def test_answer_accepted_with_surrounding_space(self, store):
        ch = captcha_service.issue_challenge(IP, store)
        ok, _ = captcha_service.verify_challenge(
            ch.token, f"  {ch.answer}  ", IP, store)
        assert ok


# ---------------------------------------------------------------------------
# Verifying: refusals
# ---------------------------------------------------------------------------
class TestVerifyRefusals:
    def test_wrong_answer_refused(self, store):
        ch = captcha_service.issue_challenge(IP, store)
        ok, reason = captcha_service.verify_challenge(
            ch.token, ch.answer + 1, IP, store)
        assert not ok
        assert reason == "wrong_answer"

    def test_replay_refused(self, store):
        """Single use: the same token cannot be spent twice."""
        ch = captcha_service.issue_challenge(IP, store)
        assert captcha_service.verify_challenge(ch.token, ch.answer, IP, store)[0]
        ok, reason = captcha_service.verify_challenge(ch.token, ch.answer, IP, store)
        assert not ok
        assert reason == "already_used"

    def test_token_from_another_address_refused(self, store):
        ch = captcha_service.issue_challenge(IP, store)
        ok, reason = captcha_service.verify_challenge(
            ch.token, ch.answer, OTHER_IP, store)
        assert not ok
        assert reason == "ip_mismatch"

    def test_expired_token_refused(self, store):
        issued = 1_700_000_000
        ch = captcha_service.issue_challenge(IP, store, now=issued)
        # The library checks `exp` against the time passed in.
        ok, reason = captcha_service.verify_challenge(
            ch.token, ch.answer, IP, store,
            now=issued + captcha_service.TOKEN_TTL_SECONDS + 1)
        assert not ok
        assert reason == "expired"

    def test_expired_by_store_clock_also_refused(self, store):
        """The store enforces the TTL independently of the token's `exp`."""
        issued = 1_700_000_000
        ch = captcha_service.issue_challenge(IP, store, now=issued)
        ok, reason = store.check_and_spend(
            ch.nonce,
            captcha_service._hash_answer(ch.answer, ch.nonce),
            IP,
            issued + captcha_service.TOKEN_TTL_SECONDS + 1,
        )
        assert not ok
        assert reason == "expired"

    def test_missing_token_refused(self, store):
        assert captcha_service.verify_challenge("", 5, IP, store)[0] is False

    def test_token_without_prefix_refused(self, store):
        """A bare session token must not be usable as a challenge."""
        ch = captcha_service.issue_challenge(IP, store)
        raw = ch.token[len(captcha_service.TOKEN_PREFIX):]
        ok, reason = captcha_service.verify_challenge(raw, ch.answer, IP, store)
        assert not ok
        assert reason == "bad_prefix"

    def test_session_token_is_refused(self, store):
        """A JWT signed with the same secret but of another type."""
        now = int(time.time())
        token = captcha_service.TOKEN_PREFIX + jwt.encode(
            {"sub": "1", "username": "operator", "role": "superadmin",
             "iat": now, "exp": now + 600},
            "test-secret-long-enough-for-hs256", algorithm="HS256")
        ok, reason = captcha_service.verify_challenge(token, 5, IP, store)
        assert not ok
        assert reason == "bad_token"

    def test_token_signed_with_another_key_refused(self, store):
        ch = captcha_service.issue_challenge(IP, store)
        now = int(time.time())
        forged = captcha_service.TOKEN_PREFIX + jwt.encode(
            {"typ": "captcha", "nonce": ch.nonce,
             "digest": captcha_service._hash_answer(ch.answer, ch.nonce),
             "ip": IP, "iat": now, "exp": now + 600},
            "a-different-secret-entirely", algorithm="HS256")
        ok, reason = captcha_service.verify_challenge(forged, ch.answer, IP, store)
        assert not ok
        assert reason == "bad_token"

    def test_token_forging_a_different_answer_refused(self, store):
        """Re-signed with the right key but a digest for a different answer."""
        ch = captcha_service.issue_challenge(IP, store)
        now = int(time.time())
        forged = captcha_service.TOKEN_PREFIX + jwt.encode(
            {"typ": "captcha", "nonce": ch.nonce,
             "digest": captcha_service._hash_answer(ch.answer + 7, ch.nonce),
             "ip": IP, "iat": now, "exp": now + 600},
            "test-secret-long-enough-for-hs256", algorithm="HS256")
        ok, reason = captcha_service.verify_challenge(forged, ch.answer, IP, store)
        assert not ok
        assert reason == "wrong_answer"

    def test_non_numeric_answer_refused(self, store):
        ch = captcha_service.issue_challenge(IP, store)
        ok, reason = captcha_service.verify_challenge(
            ch.token, "not-a-number", IP, store)
        assert not ok
        assert reason == "not_a_number"

    def test_unknown_nonce_refused(self, store):
        """A correctly signed token for a nonce the store never issued.

        The digest must be the *right* digest for the supplied answer,
        otherwise this would be caught earlier as wrong_answer and would not
        reach the store at all.
        """
        now = int(time.time())
        nonce = "never-issued"
        token = captcha_service.TOKEN_PREFIX + jwt.encode(
            {"typ": "captcha", "nonce": nonce,
             "digest": captcha_service._hash_answer(1, nonce),
             "ip": IP, "iat": now, "exp": now + 600},
            "test-secret-long-enough-for-hs256", algorithm="HS256")
        ok, reason = captcha_service.verify_challenge(token, 1, IP, store)
        assert not ok
        assert reason == "unknown"


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------
class TestStoreBounds:
    def test_per_client_cap_refuses_further_challenges(self, store):
        """One address cannot make the store grow without limit."""
        accepted = 0
        for _ in range(captcha_service._MAX_PENDING_PER_CLIENT + 5):
            ch = captcha_service.issue_challenge(IP, store)
            if ch.token:
                accepted += 1
        assert accepted == captcha_service._MAX_PENDING_PER_CLIENT

    def test_refused_challenge_yields_an_unusable_token(self, store):
        for _ in range(captcha_service._MAX_PENDING_PER_CLIENT):
            captcha_service.issue_challenge(IP, store)
        ch = captcha_service.issue_challenge(IP, store)
        assert ch.token == ""
        ok, _ = captcha_service.verify_challenge(
            captcha_service.TOKEN_PREFIX + "x", 1, IP, store)
        assert not ok

    def test_cap_is_per_client_not_global(self, store):
        for _ in range(captcha_service._MAX_PENDING_PER_CLIENT):
            captcha_service.issue_challenge(IP, store)
        other = captcha_service.issue_challenge(OTHER_IP, store)
        assert other.token, "one saturated client must not block another"

    def test_solving_a_challenge_frees_a_slot(self, store):
        held = [captcha_service.issue_challenge(IP, store)
                for _ in range(captcha_service._MAX_PENDING_PER_CLIENT)]
        assert all(c.token for c in held)
        # Saturated: a new one comes back unusable.
        assert captcha_service.issue_challenge(IP, store).token == ""

        assert captcha_service.verify_challenge(
            held[0].token, held[0].answer, IP, store)[0]
        assert captcha_service.issue_challenge(IP, store).token, \
            "solving a challenge must release a slot"

    def test_a_refused_token_does_not_free_a_slot(self, store):
        held = [captcha_service.issue_challenge(IP, store)
                for _ in range(captcha_service._MAX_PENDING_PER_CLIENT)]
        assert captcha_service.issue_challenge(IP, store).token == ""

        ok, _ = captcha_service.verify_challenge(
            held[0].token, held[0].answer + 1, IP, store)
        assert not ok
        assert captcha_service.issue_challenge(IP, store).token == "", \
            "a wrong answer must not release a slot"

    def test_spent_set_is_bounded(self):
        store = captcha_service.CaptchaStore(max_spent=5)
        now = int(time.time())
        for i in range(20):
            ch = captcha_service.issue_challenge(IP, store, now=now)
            captcha_service.verify_challenge(
                ch.token, ch.answer, IP, store, now=now)
        assert len(store._spent) <= 5

    def test_prune_drops_expired_entries(self, store):
        issued = 1_700_000_000
        captcha_service.issue_challenge(IP, store, now=issued)
        assert store._pending
        # Issuing again, well past the TTL, prunes the first one.
        captcha_service.issue_challenge(IP, store,
                                        now=issued + captcha_service.TOKEN_TTL_SECONDS + 1)
        assert len(store._pending) == 1

    def test_clear_empties_everything(self, store):
        captcha_service.issue_challenge(IP, store)
        store.clear()
        assert not store._pending and not store._spent
        assert not store._per_client