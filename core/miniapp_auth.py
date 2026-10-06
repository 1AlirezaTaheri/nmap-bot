"""Stage B: core/miniapp_auth.py — Telegram initData validation.

Pure and dependency-free: no database, no network, no Telegram client. Given
a bot token and an initData blob it returns the user payload or raises. That
makes the signature check directly testable, which matters because it is the
only thing standing between a stranger and the whole admin API.

The scheme, per Telegram's spec:

    secret_key = HMAC_SHA256(key="WebAppData", msg=bot_token)
    check      = HMAC_SHA256(key=secret_key, msg=check_string)

where ``check_string`` is every initData field except ``hash``, sorted by key,
joined with "\\n", as ``key=value``. The two-argument HMAC is what makes this
safe: the bot token is used as a *message*, never as a key, so a leaked
signature cannot be turned back into the token.

Comparison uses ``hmac.compare_digest`` throughout. A plain ``==`` would leak
the signature a byte at a time through response timing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl

# Telegram's own constant, from the Mini Apps documentation.
WEBAPP_DATA_KEY = b"WebAppData"


class MiniAppAuthError(Exception):
    """Raised when initData is missing, malformed, stale or forged.

    Carries a machine-readable ``code`` so the route layer can log something
    useful without putting attacker-controlled text in an audit row.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MiniAppUser:
    """The authenticated Telegram user, as Telegram asserts it."""

    id: int
    first_name: str
    last_name: str | None
    username: str | None
    language_code: str | None
    is_premium: bool
    photo_url: str | None
    auth_date: int

    @property
    def display_name(self) -> str:
        parts = [self.first_name]
        if self.last_name:
            parts.append(self.last_name)
        return " ".join(parts)


def derive_secret_key(bot_token: str) -> bytes:
    """``HMAC_SHA256(key=b"WebAppData", msg=bot_token)``."""
    return hmac.new(WEBAPP_DATA_KEY, bot_token.encode(), hashlib.sha256).digest()


def build_check_string(fields: list[tuple[str, str]]) -> str:
    """Sorted, newline-joined ``key=value`` pairs, excluding ``hash``."""
    pairs = [(key, value) for key, value in fields if key != "hash"]
    pairs.sort(key=lambda item: item[0])
    return "\n".join(f"{key}={value}" for key, value in pairs)


def compute_signature(bot_token: str, check_string: str) -> str:
    """Hex HMAC of ``check_string`` under the derived secret key."""
    secret = derive_secret_key(bot_token)
    return hmac.new(secret, check_string.encode(), hashlib.sha256).hexdigest()


def sign_init_data(
    bot_token: str, fields: list[tuple[str, str]], *, auth_date: int | None = None
) -> str:
    """Build a valid initData blob.

    Only used by the tests and by anyone wanting to exercise the endpoints
    without Telegram; the Mini App itself receives initData from Telegram and
    never constructs it.
    """
    resolved = dict(fields)
    if auth_date is not None:
        resolved["auth_date"] = str(auth_date)
    if "hash" not in resolved:
        pairs = sorted(
            (key, value) for key, value in resolved.items() if key != "hash"
        )
        check_string = "\n".join(f"{key}={value}" for key, value in pairs)
        resolved["hash"] = compute_signature(bot_token, check_string)
    from urllib.parse import urlencode

    return urlencode(sorted(resolved.items()))


def parse_user_payload(raw: str | None) -> dict[str, Any]:
    """Read the ``user`` field out of initData.

    Not validated by the signature check: it is covered *by* it, since the
    whole blob is what gets signed. A blob with a valid hash but a
    non-JSON ``user`` is simply malformed.
    """
    if not raw:
        raise MiniAppAuthError("no_user", "initData carries no user")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MiniAppAuthError("bad_user", "user is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise MiniAppAuthError("bad_user", "user is not an object")
    if "id" not in payload:
        raise MiniAppAuthError("bad_user", "user has no id")
    try:
        int(payload["id"])
    except (TypeError, ValueError) as exc:
        raise MiniAppAuthError("bad_user", "user id is not numeric") from exc
    return payload


def validate_init_data(
    init_data: str,
    bot_token: str,
    *,
    max_age_seconds: int = 86400,
    now: int | None = None,
) -> dict[str, Any]:
    """Validate an initData blob and return Telegram's user payload.

    Raises :class:`MiniAppAuthError` for anything wrong. The order matters:
    signature first, then freshness, then payload. Checking freshness before
    the signature would let an attacker learn whether a blob they forged is
    merely stale.
    """
    if not init_data or not init_data.strip():
        raise MiniAppAuthError("missing", "no initData supplied")

    fields = parse_qsl(init_data, keep_blank_values=True, strict_parsing=False)
    if not fields:
        raise MiniAppAuthError("malformed", "initData is not a query string")

    hashes = [value for key, value in fields if key == "hash"]
    if not hashes:
        raise MiniAppAuthError("no_hash", "initData carries no hash")
    if len(hashes) > 1:
        # Telegram sends exactly one. build_check_string() drops every
        # `hash` field, so a trailing duplicate is invisible to the
        # check string and only the first value is compared. A parser
        # that took the last would disagree with this one, so the blob
        # is refused rather than resolved by precedence.
        raise MiniAppAuthError(
            "duplicate_hash", "initData carries more than one hash"
        )
    supplied_hash = hashes[0]

    expected = compute_signature(bot_token, build_check_string(fields))
    if not hmac.compare_digest(expected, supplied_hash):
        raise MiniAppAuthError("bad_signature", "signature does not match")

    # Freshness, only once the blob is known to be authentic.
    auth_date_raw = next(
        (value for key, value in fields if key == "auth_date"), None
    )
    if auth_date_raw is None:
        raise MiniAppAuthError("no_auth_date", "initData carries no auth_date")
    try:
        auth_date = int(auth_date_raw)
    except ValueError as exc:
        raise MiniAppAuthError("bad_auth_date", "auth_date is not an int") from exc

    current = now if now is not None else int(time.time())
    age = current - auth_date
    if age > max_age_seconds:
        raise MiniAppAuthError(
            "expired", f"initData is {age}s old (limit {max_age_seconds}s)"
        )
    # A future auth_date means a skewed clock or an attempt to buy extra life.
    # Reject it rather than treating a negative age as fresh.
    if age < -60:
        raise MiniAppAuthError(
            "bad_auth_date", f"auth_date is {-age}s in the future"
        )

    payload = parse_user_payload(
        next((value for key, value in fields if key == "user"), None)
    )
    return {
        "user": payload,
        "auth_date": auth_date,
        "start_param": next(
            (value for key, value in fields if key == "start_param"), None
        ),
    }


def mini_app_url(base_url: str, start_param: str | None = None) -> str:
    """Build the Mini App URL, appending a start parameter if present."""
    base = base_url.rstrip("/")
    if not base:
        return ""
    url = base + "/app"
    if start_param:
        from urllib.parse import quote

        url += f"?startapp={quote(start_param, safe='')}"
    return url


def is_miniapp_enabled(base_url: str | None) -> bool:
    """Whether Mini App affordances should be shown at all.

    Telegram requires HTTPS, so a value that is not https is treated as
    unconfigured rather than advertised and then failing to load.
    """
    if not base_url:
        return False
    return base_url.lower().startswith("https://")