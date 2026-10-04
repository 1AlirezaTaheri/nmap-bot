"""Parsing, validation and matching for rule values.

One module per concern: :mod:`core.rules` decides policy, this module only
knows how to read a rule's ``value`` column and how to match a parsed value
against a request. No database, no network, no policy decisions.

Every parser here is *total*: it either returns a normalized, typed value or
raises :class:`ValueError`. The engine catches that, logs a warning and skips
the offending rule, so one malformed rule can never block legitimate traffic.

Value grammar, by rule type:

===============  =========================================================
``allow_cidr``   comma-separated CIDRs — ``192.168.174.0/24,10.0.0.0/8``
``deny_cidr``    same
``allow_domain`` comma-separated domains — ``*.example.com,corp.test``
``deny_domain``  same
``allow_port``   comma-separated ports/ranges — ``22,80,8000-9000``
``deny_port``    same
``max_scan_time`` integer seconds — ``120``
``rate_limit``   integer seconds — ``60``
``time_window``  ``HH:MM-HH:MM`` in UTC — ``08:00-22:00``, ``22:00-06:00``
``user_quota``   ``N/period``, period in ``hour``/``day`` — ``50/day``
===============  =========================================================

All parsing is case-insensitive and tolerates surrounding whitespace, so a
value typed into the admin panel does not have to be byte-exact.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone

# Canonical rule types. Kept in step with database.models.RULE_TYPES, but
# declared here as well so this module has no database import; the test suite
# asserts the two agree.
CIDR_TYPES = ("allow_cidr", "deny_cidr")
DOMAIN_TYPES = ("allow_domain", "deny_domain")
PORT_TYPES = ("allow_port", "deny_port")
SECOND_TYPES = ("max_scan_time", "rate_limit")

# Quota periods, and how many seconds each one covers.
QUOTA_PERIODS: dict[str, int] = {"hour": 3600, "day": 86400}

MIN_PORT = 1
MAX_PORT = 65535

# A domain label: starts and ends alphanumeric, hyphens inside. One or more
# labels, so a single-label name ("localhost") is technically valid.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")

_SECONDS_RE = re.compile(r"^\d+$")
# Forgiving on input, canonical on output: 1-2 digit hours and optional spaces
# around the separator, so "8:00 - 9:30" typed into the panel is accepted and
# stored as "08:00-09:30". Ranges are still checked strictly below.
_TIME_WINDOW_RE = re.compile(r"^(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})$")
_QUOTA_RE = re.compile(r"^(\d+)/(\w+)$")


def _split(value: str) -> list[str]:
    """Split a comma-separated list, dropping empty items.

    Trailing commas are tolerated (``"22,80,"``) because that is a natural
    typo while editing a list in the panel.
    """
    return [part.strip() for part in (value or "").split(",") if part.strip()]


# ---------------------------------------------------------------------------
# CIDRs
# ---------------------------------------------------------------------------


def parse_cidrs(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse a comma-separated list of CIDRs or bare addresses.

    ``strict=False`` throughout: ``192.168.174.5/24`` is accepted and
    normalised to ``192.168.174.0/24``, matching how targets are parsed in
    :func:`security.targets.validate_target`.
    """
    parts = _split(value)
    if not parts:
        raise ValueError("no CIDRs given")

    networks = []
    for part in parts:
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid CIDR {part!r}: {exc}") from exc
    return tuple(networks)


def cidr_matches(
    networks: tuple, target: str
) -> bool:
    """True if ``target`` (an address or a network) falls inside ``networks``.

    A network target matches when it is *contained by* an allow/deny entry:
    scanning ``192.168.174.0/24`` should be refused by a ``192.168.174.128/25``
    deny rule rather than sneaking past it.
    """
    candidate = (target or "").strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if not candidate:
        return False

    try:
        if "/" in candidate:
            probe = ipaddress.ip_network(candidate, strict=False)
            return any(
                probe.version == net.version and probe.subnet_of(net)
                for net in networks
            )
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False

    return any(address in net for net in networks)


def target_is_ip(target: str) -> bool:
    """True if the target is an address or a CIDR (not a hostname).

    Decides which rule family applies: IPs are checked against CIDR rules,
    hostnames against domain rules.
    """
    candidate = (target or "").strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if not candidate:
        return False
    try:
        if "/" in candidate:
            ipaddress.ip_network(candidate, strict=False)
            return True
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DomainPattern:
    """A normalized domain rule.

    ``wildcard`` records that the operator wrote ``*.example.com``. That
    matches any subdomain at any depth but *not* the bare domain, which is
    the behaviour DNS wildcard records actually have.
    """

    domain: str
    wildcard: bool

    def matches(self, host: str) -> bool:
        candidate = _normalize_domain(host)
        if not candidate:
            return False
        if self.wildcard:
            return candidate.endswith("." + self.domain)
        return candidate == self.domain


def _normalize_domain(value: str) -> str:
    """Lowercase, strip a trailing dot, and reject an empty result."""
    text = (value or "").strip().lower().rstrip(".")
    return text


def parse_domains(value: str) -> tuple[DomainPattern, ...]:
    """Parse a comma-separated list of domains, optional ``*.`` wildcard."""
    parts = _split(value)
    if not parts:
        raise ValueError("no domains given")

    patterns = []
    for part in parts:
        text = _normalize_domain(part)
        if not text:
            raise ValueError(f"invalid domain {part!r}: empty after normalization")

        wildcard = text.startswith("*.")
        if wildcard:
            text = text[2:]
        # A bare "*" or "*." leaves nothing behind, so reject it rather than
        # matching everything.
        if not text:
            raise ValueError(f"invalid domain {part!r}: nothing after the wildcard")

        if not _DOMAIN_RE.match(text):
            raise ValueError(f"invalid domain {part!r}")

        patterns.append(DomainPattern(domain=text, wildcard=wildcard))

    return tuple(patterns)


def domain_matches(patterns: tuple[DomainPattern, ...], host: str) -> bool:
    """True if ``host`` satisfies any pattern."""
    return any(pattern.matches(host) for pattern in patterns)


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PortRange:
    """An inclusive port range. ``8000-9000`` covers 8000 and 9000."""

    start: int
    end: int

    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end


def parse_ports(value: str) -> tuple[PortRange, ...]:
    """Parse ``22,80,8000-9000`` into inclusive ranges.

    Reversed ranges (``9000-8000``) are rejected rather than silently
    swapped: a swapped range means the operator made a typo, and quietly
    widening it to cover 8000-9000 could deny more than they intended.
    """
    parts = _split(value)
    if not parts:
        raise ValueError("no ports given")

    ranges: list[PortRange] = []
    for part in parts:
        if "-" in part:
            raw_start, _, raw_end = part.partition("-")
            start = _parse_port(raw_start, part)
            end = _parse_port(raw_end, part)
            if start > end:
                raise ValueError(
                    f"reversed port range {part!r}: {start} > {end}"
                )
            ranges.append(PortRange(start=start, end=end))
        else:
            port = _parse_port(part, part)
            ranges.append(PortRange(start=port, end=port))

    return tuple(ranges)


def _parse_port(raw: str, original: str) -> int:
    text = raw.strip()
    if not _SECONDS_RE.match(text):
        raise ValueError(f"invalid port {original!r}: {raw.strip()!r} is not a number")
    port = int(text)
    if not (MIN_PORT <= port <= MAX_PORT):
        raise ValueError(
            f"port {port} out of range {MIN_PORT}-{MAX_PORT} in {original!r}"
        )
    return port


def ports_match(ranges: tuple[PortRange, ...], port: int) -> bool:
    """True if ``port`` falls inside any range."""
    return any(rng.contains(port) for rng in ranges)


# ---------------------------------------------------------------------------
# Seconds
# ---------------------------------------------------------------------------


def parse_seconds(value: str) -> int:
    """Parse a strictly positive number of seconds.

    Zero is rejected for both rule types that use it. A ``max_scan_time`` of 0
    would abort every scan, and a ``rate_limit`` of 0 is indistinguishable
    from "no limit", which is what leaving the rule out already means.
    """
    text = (value or "").strip()
    if not _SECONDS_RE.match(text):
        raise ValueError(
            f"invalid seconds {value!r}: expected a positive whole number"
        )
    seconds = int(text)
    if seconds < 1:
        raise ValueError(f"invalid seconds {value!r}: must be at least 1")
    return seconds


# ---------------------------------------------------------------------------
# Time windows
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimeWindow:
    """A UTC window as minutes since midnight.

    ``overnight`` is derived, not stored: a window whose end is earlier than
    its start wraps past midnight, so ``22:00-06:00`` covers 23:00 today and
    02:00 tomorrow.
    """

    start_minute: int
    end_minute: int

    @property
    def overnight(self) -> bool:
        return self.end_minute < self.start_minute

    def contains(self, minute_of_day: int) -> bool:
        if self.overnight:
            return minute_of_day >= self.start_minute or minute_of_day < self.end_minute
        return self.start_minute <= minute_of_day < self.end_minute


def parse_time_window(value: str) -> TimeWindow:
    """Parse ``HH:MM-HH:MM`` in UTC.

    Start and end must differ. An equal pair is ambiguous — it reads as
    "always" to one operator and "never" to another — so it is rejected and
    the operator must write the window out.
    """
    # All whitespace is removed first so "08:00 - 22:00" is accepted; the
    # canonical form is produced by validate_value().
    text = "".join((value or "").split())
    match = _TIME_WINDOW_RE.match(text)
    if not match:
        raise ValueError(
            f"invalid time window {value!r}: expected HH:MM-HH:MM"
        )

    start_hour, start_minute, end_hour, end_minute = (int(g) for g in match.groups())
    for label, hour, minute in (
        ("start", start_hour, start_minute),
        ("end", end_hour, end_minute),
    ):
        if hour > 23 or minute > 59:
            raise ValueError(
                f"invalid time window {value!r}: {label} {hour:02d}:{minute:02d} "
                "is out of range"
            )

    start = start_hour * 60 + start_minute
    end = end_hour * 60 + end_minute
    if start == end:
        raise ValueError(
            f"invalid time window {value!r}: start and end are identical"
        )

    return TimeWindow(start_minute=start, end_minute=end)


def minute_of_day(moment: datetime) -> int:
    """Minutes since midnight for ``moment``, normalized to UTC.

    Accepts naive datetimes and treats them as UTC, because the bot stores
    timestamps naive-UTC throughout.
    """
    aware = moment.astimezone(timezone.utc) if moment.tzinfo else moment.replace(
        tzinfo=timezone.utc
    )
    return aware.hour * 60 + aware.minute


# ---------------------------------------------------------------------------
# Quotas
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Quota:
    """``N/period`` — a cap on scans per hour or per day."""

    limit: int
    period: str

    @property
    def period_seconds(self) -> int:
        return QUOTA_PERIODS[self.period]


def parse_quota(value: str) -> Quota:
    """Parse ``50/day`` or ``10/hour``.

    A limit of zero is rejected: an operator wanting no quota leaves the rule
    out. Zero would instead mean "this user may never scan", which is better
    expressed as a disabled user than as a quota.
    """
    text = "".join((value or "").split()).lower()
    match = _QUOTA_RE.match(text)
    if not match:
        raise ValueError(f"invalid quota {value!r}: expected N/hour or N/day")

    raw_limit, period = match.groups()
    if period not in QUOTA_PERIODS:
        raise ValueError(
            f"invalid quota {value!r}: period must be one of "
            f"{', '.join(sorted(QUOTA_PERIODS))}"
        )

    limit = int(raw_limit)
    if limit < 1:
        raise ValueError(f"invalid quota {value!r}: limit must be at least 1")

    return Quota(limit=limit, period=period)


# ---------------------------------------------------------------------------
# The dispatcher the engine uses
# ---------------------------------------------------------------------------

# Rule types this module can parse. A type outside this set is unknown to the
# engine and is skipped with a warning.
KNOWN_TYPES = (
    CIDR_TYPES + DOMAIN_TYPES + PORT_TYPES + SECOND_TYPES
    + ("time_window", "user_quota")
)


def validate_value(rule_type: str, value: str) -> str:
    """Validate ``value`` for ``rule_type`` and return a normalized form.

    Raises :class:`ValueError` for an unknown type or a malformed value. The
    normalized string is what gets stored back, so the panel shows the
    canonical spelling rather than whatever the operator typed.
    """
    kind = (rule_type or "").strip()

    if kind in CIDR_TYPES:
        return ",".join(str(net) for net in parse_cidrs(value))
    if kind in DOMAIN_TYPES:
        return ",".join(
            ("*." if p.wildcard else "") + p.domain for p in parse_domains(value)
        )
    if kind in PORT_TYPES:
        return ",".join(
            f"{r.start}-{r.end}" if r.start != r.end else str(r.start)
            for r in parse_ports(value)
        )
    if kind in SECOND_TYPES:
        return str(parse_seconds(value))
    if kind == "time_window":
        window = parse_time_window(value)
        start = f"{window.start_minute // 60:02d}:{window.start_minute % 60:02d}"
        end = f"{window.end_minute // 60:02d}:{window.end_minute % 60:02d}"
        return f"{start}-{end}"
    if kind == "user_quota":
        quota = parse_quota(value)
        return f"{quota.limit}/{quota.period}"

    raise ValueError(f"unknown rule type {rule_type!r}")