"""Scan profiles — the Strategy pattern applied to nmap argument sets.

A profile is a *named, fixed* argument list. Users choose a profile by
name and can never contribute arguments themselves, which is what keeps
the CLI surface injection-proof while still exposing 2-3 scan depths.
"""

from __future__ import annotations

from dataclasses import dataclass


class UnknownProfileError(ValueError):
    pass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    args: tuple[str, ...]
    # Ports this profile will probe, when they can be enumerated.
    #
    # None means "nmap decides": the shipped profiles use -F and
    # --top-ports, which resolve to nmap's own port tables at run
    # time. Hardcoding a copy of those tables here would go stale
    # the moment nmap updates them, so the honest answer is that the
    # port list is unknown — and an unknown port list means port
    # rules cannot be evaluated (see core.rules). A profile that
    # declares an explicit -p list sets this, and port rules then
    # apply to it.
    ports: tuple[int, ...] | None = None

    def port_list(self) -> tuple[int, ...]:
        """Ports the rule engine can be told about."""
        return self.ports or ()


# Fixed catalogs — no user input ever reaches the argument list.
PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast scan of the top 100 ports",
        args=("-F", "-T4"),
    ),
    "service": ScanProfile(
        name="service",
        description="Top 100 ports with service/version detection",
        args=("-F", "-T4", "-sV", "--version-intensity", "2"),
    ),
    "deep": ScanProfile(
        name="deep",
        description="Top 1000 ports with service detection",
        args=("-T4", "-sV", "--top-ports", "1000"),
    ),
}

DEFAULT_PROFILE = "service"


def get_profile(name: str | None) -> ScanProfile:
    """Resolve a profile by name, falling back to the default."""
    key = (name or DEFAULT_PROFILE).strip().lower()
    if key not in PROFILES:
        known = ", ".join(sorted(PROFILES))
        raise UnknownProfileError(
            f"Unknown profile '{name}'. Available: {known}"
        )
    return PROFILES[key]


def profile_names() -> list[str]:
    return sorted(PROFILES)