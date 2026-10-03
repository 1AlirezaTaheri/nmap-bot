"""Admin authentication: bcrypt hashing and JWT issuance.

Deliberately separate from ``security/authentication.py``, which is the
Telegram allow-list. An admin has a password and a web role; a Telegram
user has a numeric ID. Merging them would let one compromise grant both
surfaces.

JWT is HS256 with a secret from the environment. If no secret is
configured a random one is generated per process, which invalidates
sessions on restart — loud and safe rather than silently signing with a
hardcoded key.
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from dataclasses import dataclass

import jwt
from passlib.context import CryptContext

log = logging.getLogger(__name__)

ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_SECONDS = 8 * 3600
COOKIE_NAME = "netsentinel_admin"
MIN_PASSWORD_LENGTH = 12

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Roles, weakest to strongest.
ROLE_RANK = {"viewer": 0, "admin": 1, "superadmin": 2}


class AuthError(Exception):
    """Authentication or authorisation failure; message is user-facing."""


@dataclass(frozen=True)
class Principal:
    id: int
    username: str
    role: str

    def has_role(self, required: str) -> bool:
        mine = ROLE_RANK.get(self.role, -1)
        needed = ROLE_RANK.get(required, 99)
        return mine >= needed


def hash_password(plain: str) -> str:
    """Hash a password. Enforces a minimum length before hashing."""
    if not plain or len(plain) < MIN_PASSWORD_LENGTH:
        raise AuthError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    return _pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its hash; never raises on bad input."""
    if not plain or not hashed:
        return False
    try:
        return bool(_pwd.verify(plain, hashed))
    except Exception:
        # An unreadable or malformed hash is a failure, not a 500.
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return bool(_pwd.needs_update(hashed))
    except Exception:  # pragma: no cover - defensive
        return True


def secret_key() -> str:
    """The signing secret, generating an ephemeral one if unset."""
    value = os.environ.get("ADMIN_JWT_SECRET", "").strip()
    if value:
        return value
    log.warning(
        "ADMIN_JWT_SECRET is not set; generating an ephemeral secret. "
        "Sessions will not survive a restart."
    )
    return _ephemeral_secret


_ephemeral_secret = secrets.token_urlsafe(48)


def issue_token(principal: Principal, ttl_seconds: int = ACCESS_TOKEN_TTL_SECONDS) -> str:
    """Create a signed JWT for ``principal``."""
    now = int(time.time())
    payload = {
        "sub": str(principal.id),
        "username": principal.username,
        "role": principal.role,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    token = jwt.encode(payload, secret_key(), algorithm=ALGORITHM)
    # PyJWT < 2 returned bytes; normalise so callers always get str.
    return token.decode() if isinstance(token, bytes) else token


def decode_token(token: str) -> Principal:
    """Validate a JWT and return its principal.

    Raises :class:`AuthError` for any invalid, expired, or malformed token.
    """
    if not token:
        raise AuthError("No token supplied.")
    try:
        payload = jwt.decode(token, secret_key(), algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Session expired. Please sign in again.") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid session token.") from exc

    subject = payload.get("sub")
    username = payload.get("username")
    role = payload.get("role")
    if subject is None or not username or role not in ROLE_RANK:
        raise AuthError("Malformed session token.")

    try:
        principal_id = int(subject)
    except (TypeError, ValueError) as exc:
        raise AuthError("Malformed session token.") from exc

    return Principal(id=principal_id, username=username, role=role)


class LoginRateLimiter:
    """Per-IP login throttling: 5 attempts per 60 seconds.

    In-memory, so it resets on restart. That is acceptable here: an
    attacker who can restart the container already has host access, and
    adding Redis is outside this project's "no new services" constraint.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: float = 60.0,
        *,
        clock=time.monotonic,
    ) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._clock = clock
        self._hits: dict[str, list[float]] = {}

    def check(self, ip: str) -> tuple[bool, int]:
        """Return ``(allowed, attempts_remaining)``."""
        now = self._clock()
        hits = [t for t in self._hits.get(ip, []) if now - t < self._window]
        if len(hits) >= self._max:
            self._hits[ip] = hits
            return False, 0
        hits.append(now)
        self._hits[ip] = hits
        return True, max(0, self._max - len(hits))

    def reset(self, ip: str) -> None:
        self._hits.pop(ip, None)

    def prune(self) -> None:
        """Drop entries outside the window so the map cannot grow forever."""
        now = self._clock()
        for ip in list(self._hits):
            hits = [t for t in self._hits[ip] if now - t < self._window]
            if hits:
                self._hits[ip] = hits
            else:
                self._hits.pop(ip, None)