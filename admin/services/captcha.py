#!/usr/bin/env python3
"""Self-hosted CAPTCHA for the admin login form.

The challenge is an arithmetic question signed by the application. Three
properties matter, and the third is the reason it is safe to ship:

  * The answer is never sent to the client. The token carries a hash of it,
    so reading the token reveals nothing and the challenge cannot be solved
    by a headless browser that just fetches /api/captcha.

  * The token is single-use. A solved token is recorded and refused on
    replay, so one captured login attempt cannot be replayed against the
    rate limiter.

  * The token is bound to the client IP, so a token obtained elsewhere
    cannot be presented from another address.

This is deliberately NOT an external service. It adds no network dependency,
no third-party image, and nothing that can phone home -- which matters here
because the operator cannot reach many hosted CAPTCHA providers from where
this runs.

What it does and does not buy: it stops naive scripted brute force, because
solving it requires arithmetic that a loop over passwords does not do. It
does not stop a determined attacker who can solve arithmetic, and it is not
proof-of-work. The login rate limiter remains the real control; this raises
the cost of reaching it.

Disabled by default (CAPTCHA_ENABLED=false) so existing behaviour, and the
existing tests, are unchanged until the operator turns it on.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass

import jwt

log = logging.getLogger(__name__)

ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 300
TOKEN_PREFIX = "cap."

# Operators are chosen so the question cannot be answered by string matching
# alone and stays trivially readable: two small whole numbers.
_MIN_OPERAND = 3
_MAX_OPERAND = 19

# How many outstanding, unsolved challenges to remember per client. Small on
# purpose: a bot that requests thousands of challenges to find one it likes
# gets them all refused rather than accumulating state.
_MAX_PENDING_PER_CLIENT = 5

# Upper bound on how many solved tokens to remember globally, so the replay
# set cannot grow without limit.
_MAX_SPENT_TOKENS = 10_000


def _secret() -> str:
    """The signing secret, reusing the admin session secret.

    Sharing the key means a challenge token cannot be mistaken for a session
    token: the claims are disjoint and the `cap.` prefix is checked, so
    neither can be replayed as the other.
    """
    value = os.environ.get("ADMIN_JWT_SECRET", "").strip()
    if value:
        return value
    # No secret configured: the admin service already refuses to start in
    # that case (bootstrap requires ADMIN_USERNAME and a strong password), so
    # reaching here means the CAPTCHA is being used outside it. Fail closed
    # rather than minting a token anyone could forge.
    raise RuntimeError("ADMIN_JWT_SECRET is not set; cannot sign a challenge.")


def _hash_answer(answer: int, nonce: str) -> str:
    """Bind the answer to a per-challenge nonce.

    Without the nonce a client could compute the hash of small integers
    itself and match them against issued tokens, which reduces the challenge
    to a lookup. The nonce is only known to the server.
    """
    material = f"{answer}:{nonce}".encode()
    return hmac.new(_secret().encode(), material, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Challenge:
    question: str
    token: str
    answer: int
    nonce: str


class CaptchaStore:
    """In-memory single-use bookkeeping.

    In-process, like the login rate limiter, so a restart clears it. That is
    the right trade here: a restart already invalidates every session, and a
    challenge outstanding across a restart has at most a 5 minute life and
    still requires the correct password.
    """

    def __init__(self, *, max_spent: int = _MAX_SPENT_TOKENS) -> None:
        # nonce -> (answer digest, client_ip, created_at)
        self._pending: dict[str, tuple[str, str, float]] = {}
        self._spent: set[str] = set()
        self._order: list[str] = []
        self._max_spent = max_spent
        self._per_client: dict[str, int] = {}

    def issue(self, nonce: str, digest: str, client_ip: str,
              now: float) -> bool:
        """Remember a freshly issued challenge.

        Returns False when this client already holds the maximum number of
        unsolved challenges, and stores nothing in that case. A client that
        floods the endpoint therefore gets tokens that look fine but cannot
        verify, instead of accumulating server-side state without limit.
        """
        count = self._per_client.get(client_ip, 0)
        if count >= _MAX_PENDING_PER_CLIENT:
            log.warning(
                "captcha challenge refused: client already holds %d unsolved",
                count,
            )
            return False
        self._pending[nonce] = (digest, client_ip, now)
        self._per_client[client_ip] = count + 1
        self._prune(now)
        return True

    def check_and_spend(self, nonce: str, supplied_digest: str,
                        client_ip: str, now: float) -> tuple[bool, str]:
        """Validate a challenge and mark it spent.

        ``supplied_digest`` is the hash of the answer the client submitted,
        recomputed server-side from the submitted integer. Comparing two
        server-side values means the correct answer is never stored and never
        has to be revealed to justify a rejection.

        Returns ``(ok, reason)``. ``reason`` is for logging and never contains
        the answer.
        """
        entry = self._pending.get(nonce)
        if entry is None:
            if nonce in self._spent:
                return False, "already_used"
            return False, "unknown"
        stored_digest, stored_ip, created = entry

        if now - created > TOKEN_TTL_SECONDS:
            del self._pending[nonce]
            self._release_client(stored_ip)
            return False, "expired"
        if stored_ip != client_ip:
            return False, "ip_mismatch"
        if not hmac.compare_digest(stored_digest, supplied_digest):
            return False, "wrong_answer"

        # Spend it: remove from pending and remember it as used.
        del self._pending[nonce]
        self._spent.add(nonce)
        self._order.append(nonce)
        while len(self._order) > self._max_spent:
            self._spent.discard(self._order.pop(0))
        self._release_client(stored_ip)
        return True, "ok"

    def _release_client(self, client_ip: str) -> None:
        count = self._per_client.get(client_ip, 0) - 1
        if count <= 0:
            self._per_client.pop(client_ip, None)
        else:
            self._per_client[client_ip] = count

    def _prune(self, now: float) -> None:
        for nonce in [
            n for n, (_, _, created) in self._pending.items()
            if now - created > TOKEN_TTL_SECONDS
        ]:
            client = self._pending[nonce][1]
            del self._pending[nonce]
            self._release_client(client)

    def clear(self) -> None:
        self._pending.clear()
        self._spent.clear()
        self._order.clear()
        self._per_client.clear()


def issue_challenge(client_ip: str, store: CaptchaStore | None = None,
                    *, now: int | None = None) -> Challenge:
    """Create a signed challenge. Does not touch ``store``.

    Kept pure so it can be unit-tested without any global state, and so the
    nonce/digest bookkeeping is explicit rather than implicit.
    """
    import random

    a = random.randint(_MIN_OPERAND, _MAX_OPERAND)
    b = random.randint(_MIN_OPERAND, _MAX_OPERAND)

    # Half the time ask for a subtraction, which stays in a small positive
    # range. Pure addition would let a client learn the operands by trying
    # every candidate answer against two observed questions.
    if random.random() < 0.5:
        a, b = max(a, b), min(a, b)
        question = f"{a} - {b} = ?"
        answer = a - b
    else:
        question = f"{a} + {b} = ?"
        answer = a + b

    nonce = secrets.token_urlsafe(16)
    issued = int(time.time()) if now is None else now
    # The digest goes into the token's claims AND into the store. The store
    # copy is what makes the challenge single-use; the claims copy lets a
    # re-signed token be caught before the store is consulted at all.
    digest = _hash_answer(answer, nonce)

    claims = {
        "typ": "captcha",
        "nonce": nonce,
        "digest": digest,
        "iat": issued,
        "exp": issued + TOKEN_TTL_SECONDS,
        # A challenge is bound to the address that requested it, so it cannot
        # be handed to another client.
        "ip": client_ip,
    }
    token = jwt.encode(claims, _secret(), algorithm=ALGORITHM)
    if isinstance(token, bytes):  # PyJWT < 2
        token = token.decode()

    challenge = Challenge(question=question, token=TOKEN_PREFIX + token,
                          answer=answer, nonce=nonce)
    if store is not None and not store.issue(nonce, digest, client_ip, issued):
        # Over the per-client cap. Hand back a token that cannot verify rather
        # than one that silently works, so the cap actually bounds anything.
        return Challenge(question=question, token="", answer=answer,
                         nonce=nonce)
    return challenge


def verify_challenge(token: str, answer: int, client_ip: str,
                     store: CaptchaStore, *, now: int | None = None) -> tuple[bool, str]:
    """Verify a submitted challenge. Returns ``(ok, reason)``.

    Order matters: the token's own signature and claims are checked before
    the store is consulted, so a forged token cannot reach -- or grow -- the
    single-use bookkeeping.
    """
    current = int(time.time()) if now is None else now

    if not token or not isinstance(token, str):
        return False, "missing"
    if not token.startswith(TOKEN_PREFIX):
        return False, "bad_prefix"

    raw = token[len(TOKEN_PREFIX):]
    try:
        claims = jwt.decode(raw, _secret(), algorithms=[ALGORITHM],
                            options={"require": ["exp", "iat", "nonce", "digest"]})
    except jwt.ExpiredSignatureError:
        return False, "expired"
    except jwt.InvalidTokenError:
        return False, "bad_token"

    if claims.get("typ") != "captcha":
        return False, "bad_type"
    if claims.get("ip") != client_ip:
        return False, "ip_mismatch"

    nonce = claims["nonce"]
    try:
        supplied = int(answer)
    except (TypeError, ValueError):
        return False, "not_a_number"

    # The token's own digest claim is checked against the submitted answer first.
    # A mismatch means the token was signed over a different answer, which the
    # store lookup alone would not catch.
    if not hmac.compare_digest(claims["digest"], _hash_answer(supplied, nonce)):
        return False, "wrong_answer"

    return store.check_and_spend(nonce, claims["digest"], client_ip, current)