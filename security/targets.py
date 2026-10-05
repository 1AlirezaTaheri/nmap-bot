"""Target validation and scope restriction.

Maps to "Target restrictions" in the architecture. Validation is strict on
purpose: the original bot checked ``target.replace('.', '')
.replace('-', '').replace('/', '').isalnum()``, which accepts arbitrary
words and, more importantly, accepts nothing that proves the string is a
host you are actually allowed to scan.
"""

from __future__ import annotations

import ipaddress
import re

# Hostname: up to 63 chars per label, labels start/end alphanumeric,
# hyphens allowed in the middle. Optional trailing dot.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

# Anything that could be interpreted as a CLI option or shell token.
_REJECTED_CHARS = set(" \t\n\r;&|<>()$`\\\"'!*?[]{}#~%")


# Ranges that are never a legitimate scan target, refused whether or not a
# scope allow-list is configured. Without this, in_scope() returned True for
# everything when ALLOWED_CIDRS was empty, which made the cloud metadata
# endpoint (169.254.169.254), the scanner's own loopback interface, and the
# catch-all 0.0.0.0/0 all scannable on a default install.
#
# "This host" (0.0.0.0/8 and ::/128) is included because nmap treats it as a
# local-subnet sweep. IPv6 link-local and loopback are the v6 equivalents of
# the v4 ranges above.
_ALWAYS_DENIED_NETWORKS = (
    "127.0.0.0/8",
    "::1/128",
    "169.254.0.0/16",
    "fe80::/10",
    "0.0.0.0/8",
    "::/128",
)

# Parsed once at import: ip_network() is not free and is_always_denied()
# runs on every scope check. Defined here, immediately after the strings
# it consumes -- building it earlier raised NameError at import time.
_ALWAYS_DENIED = tuple(
    ipaddress.ip_network(c) for c in _ALWAYS_DENIED_NETWORKS
)


class TargetValidationError(ValueError):
    """Raised when a scan target is malformed or rejected by policy."""


def validate_target(raw: str) -> str:
    """Validate ``raw`` and return it stripped.

    Accepts an IPv4/IPv6 address, a CIDR block, or a hostname.
    Raises :class:`TargetValidationError` otherwise.
    """
    target = (raw or "").strip()
    if not target:
        raise TargetValidationError("Target is empty.")

    # A leading '-' would make nmap read the target as an option.
    if target.startswith("-"):
        raise TargetValidationError("Targets may not start with '-'.")

    bad = _REJECTED_CHARS.intersection(set(target))
    if bad:
        raise TargetValidationError(
            f"Target contains rejected characters: {''.join(sorted(bad))}"
        )

    # IPv6 literals come bracketed from some clients.
    candidate = target
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]

    if "/" in candidate:
        try:
            ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise TargetValidationError(f"Invalid network: {candidate}") from exc
        return target

    try:
        ipaddress.ip_address(candidate)
        return target
    except ValueError:
        pass

    if _HOSTNAME_RE.match(candidate):
        return target

    raise TargetValidationError(f"Not a valid IP, CIDR, or hostname: {target}")


def is_always_denied(candidate: str) -> bool:
    """True if ``candidate`` is loopback, link-local, "this host" or catch-all.

    Checked before any allow-list, so it applies on a default install where
    ``ALLOWED_CIDRS`` is empty. A hostname returns False because it cannot be
    judged without resolving it, and resolving here would reintroduce the DNS
    dependency the rule engine deliberately avoids.
    """
    try:
        if "/" in candidate:
            net = ipaddress.ip_network(candidate, strict=False)
            return any(
                net.version == denied.version and net.overlaps(denied)
                for denied in _ALWAYS_DENIED
            )
        addr = ipaddress.ip_address(candidate)
        return any(
            addr in denied for denied in _ALWAYS_DENIED
            if denied.version == addr.version
        )
    except ValueError:
        return False


def in_scope(target: str, allowed_cidrs: tuple[str, ...]) -> bool:
    """Return True if ``target`` is permitted to be scanned.

    Loopback, link-local (including the 169.254.169.254 metadata endpoint),
    "this host" and catch-all ranges are always refused. Beyond that, when
    ``allowed_cidrs`` is empty anything not on that list is permitted, which
    preserves the original ad-hoc-scanning behaviour.

    Hostnames can never be proven in-scope without resolving them, so they are
    rejected when scope restrictions are configured -- a conservative default
    that fails closed rather than open.
    """
    candidate = target.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]

    if is_always_denied(candidate):
        return False

    if not allowed_cidrs:
        return True

    nets = [ipaddress.ip_network(c, strict=False) for c in allowed_cidrs]

    try:
        if "/" in candidate:
            net = ipaddress.ip_network(candidate, strict=False)
            return any(
                net.version == n.version and net.subnet_of(n) for n in nets
            )
        addr = ipaddress.ip_address(candidate)
        return any(addr in n for n in nets)
    except ValueError:
        return False