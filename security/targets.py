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


def in_scope(target: str, allowed_cidrs: tuple[str, ...]) -> bool:
    """Return True if ``target`` falls inside any of ``allowed_cidrs``.

    Hostnames can never be proven in-scope without resolving them, so they
    are rejected when scope restrictions are configured — a conservative
    default that fails closed rather than open.
    """
    if not allowed_cidrs:
        return True

    nets = [ipaddress.ip_network(c, strict=False) for c in allowed_cidrs]
    candidate = target.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]

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