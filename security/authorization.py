"""Authorization: *what is this caller allowed to do?*

Maps to "Allowed users / Target restrictions / Role-based access" in the
architecture. Roles are an ordered tuple on the Principal, so permission
checks are a single index comparison — no ORM model is needed in the MVP.
"""

from __future__ import annotations

import ipaddress

from security.authentication import Principal
from security.targets import TargetValidationError, in_scope, validate_target

# Ordered weakest → strongest. A principal satisfies a required role if its
# index is at least as high.
ROLE_ORDER: tuple[str, ...] = ("viewer", "operator", "admin")


class AuthorizationError(PermissionError):
    """Raised when a principal lacks the required role."""


class TargetNotAllowedError(PermissionError):
    """Raised when a target is malformed or outside the permitted scope."""


def _has_role(principal: Principal, required: str) -> bool:
    if principal.role not in ROLE_ORDER or required not in ROLE_ORDER:
        return False
    return ROLE_ORDER.index(principal.role) >= ROLE_ORDER.index(required)


class Authorizer:
    """Role checks plus target scope enforcement."""

    def __init__(self, allowed_cidrs: tuple[str, ...] = ()) -> None:
        self._nets = tuple(
            ipaddress.ip_network(c, strict=False) for c in allowed_cidrs
        )

    # -- roles -------------------------------------------------------
    def require_role(self, principal: Principal, action: str) -> None:
        if not _has_role(principal, "operator"):
            raise AuthorizationError(
                f"Role '{principal.role}' cannot {action} "
                f"(requires 'operator' or higher)."
            )

    def can_view(self, principal: Principal) -> bool:
        return _has_role(principal, "viewer")

    def can_scan(self, principal: Principal) -> bool:
        return _has_role(principal, "operator")

    # -- target scope ------------------------------------------------
    @property
    def allowed_cidrs(self) -> tuple[str, ...]:
        return tuple(str(n) for n in self._nets)

    def assert_target_permitted(self, target: str) -> str:
        """Validate ``target`` and enforce scope.

        Returns the normalized target on success. Fails closed: a target
        that cannot be proven in-scope is rejected when any scope is
        configured.
        """
        try:
            validated = validate_target(target)
        except TargetValidationError as exc:
            raise TargetNotAllowedError(str(exc)) from exc

        if not self._nets:
            return validated

        if not in_scope(validated, self.allowed_cidrs):
            raise TargetNotAllowedError(
                f"Target '{target}' is outside the allowed ranges: "
                f"{', '.join(self.allowed_cidrs)}"
            )
        return validated