"""Rule evaluation: the pure policy engine, run before every scan.

Answers one question — *may this request proceed, and under what limits?* —
from a list of rules and a :class:`RuleContext`. It performs no database
access, no DNS resolution and no I/O of any kind, which keeps it testable
without a fixture and makes it safe to call on the hot path.

Policy, in one place so it can be reviewed rather than inferred:

* **Ordering.** Rules are sorted by ``(priority, id)`` ascending. The id
  tiebreak makes the order total, so two rules at the same priority always
  evaluate the same way across requests and processes.

* **Deny wins, always.** Every rule is examined; the first one that *denies*
  short-circuits the evaluation and becomes the decision's rule. A deny at
  priority 100 still blocks a request that an allow at priority 1 already
  matched. Rules are not grouped by type first, so priority really is the
  only ordering that matters.

* **Allow gates fail closed.** For each gate family (CIDR for address
  targets, domain for hostname targets, ports for a port list) the question
  is asked independently: *did any allow rule of this family match?* If the
  family has allow rules and none matched, the request is denied with
  ``no matching allow rule``. If the family has no allow rules at all, that
  family imposes no restriction. Two allow families and a denied CIDR do not
  compensate for each other.

* **Nothing is resolved.** A hostname is judged by its own domain rules. A
  hostname that resolves to a denied address is *not* caught, because the
  engine never performs a DNS lookup. This is a documented limitation, not
  an oversight: resolution would make the decision depend on the network and
  on timing, and a policy check that can be slowed or steered by DNS is
  worse than one that is honest about its blind spot.

* **Broken rules are skipped, never enforced.** An unknown ``rule_type`` or a
  malformed ``value`` is logged and ignored, so a typo cannot deny
  legitimate traffic. The exception is an unrecognised ``scope`` on a *deny*
  rule, which is treated as ``global`` — for a restriction, an unreadable
  subject is not a reason to stand down.

Two limit rules resolve differently, on purpose:

* ``rate_limit`` — the **smallest matching rule wins**, falling back to
  ``RATE_LIMIT_SECONDS`` when none match. A rule may therefore relax the
  environment default.
* ``max_scan_time`` — ``min(SCAN_TIMEOUT_SECONDS, smallest matching rule)``.
  A rule can only ever *tighten* the ceiling, so a misconfigured rule cannot
  leave a scan unbounded.

A ``time_window`` is read as a permission: inside the window the request
passes, outside it is denied.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core import rule_values as rv

log = logging.getLogger(__name__)

# Why a request was allowed, when nothing blocked it.
ALLOWED_UNRESTRICTED = "no applicable rules"
ALLOWED_BY_GATE = "allowed by matching rule"


# ---------------------------------------------------------------------------
# Inputs and outputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleContext:
    """Everything the engine is allowed to know about a request.

    ``now`` is injectable so time-dependent rules can be tested without
    freezing the clock. ``last_scans`` and ``quota_usage`` are supplied by the
    caller because counting past scans is the caller's job, not the engine's:
    reading them from the database would break purity.
    """

    #: The scan target: an address, a CIDR, or a hostname. CIDR and domain
    #: matching both operate on this value.
    target: str
    #: Key a ``rate_limit`` is tracked under. Defaults to ``target``, which
    #: is right for a standalone caller. The bot overrides it with the
    #: target *name*, because the existing RateLimiter is keyed by name and
    #: a rule limit is meant to shadow that limiter rather than run beside
    #: it counting a different thing.
    target_key: str | None = None
    #: Telegram user id of the requester, or None for a scheduled run.
    actor_id: int | None = None
    #: Ports the scan will probe. Port rules only apply when this is set.
    ports: tuple[int, ...] = ()
    #: Request time. Naive values are read as UTC. Defaults to now.
    now: datetime | None = None
    #: Scans already used per period: ``{"hour": 12, "day": 40}``.
    quota_usage: Mapping[str, int] = field(default_factory=dict)
    #: Last scan time per rate-limit key; see :func:`rate_limit_key`.
    last_scans: Mapping[str, datetime] = field(default_factory=dict)
    #: Fallback for ``rate_limit`` when no rule matches.
    default_rate_limit_seconds: int | None = None
    #: Hard ceiling for ``max_scan_time``; a rule may only lower it.
    default_scan_timeout_seconds: int | None = None

    def resolved_now(self) -> datetime:
        return self.now or datetime.now(timezone.utc)

    def rate_key(self) -> str:
        """The value a per-target rate limit is keyed by."""
        return self.target_key or self.target


@dataclass(frozen=True)
class RuleDecision:
    """The outcome of one evaluation.

    ``rule_id``/``rule_name`` name the rule that decided the outcome: the
    deny that blocked the request, or the last allow that matched. Both are
    None when no gate applied, which is the case the panel should render as
    "no restriction configured" rather than as a failure.
    """

    allowed: bool
    reason: str
    rule_id: int | None = None
    rule_name: str | None = None
    effective_rate_limit_seconds: int | None = None
    effective_scan_timeout: int | None = None
    #: Rules that were skipped because they were unusable.
    warnings: tuple[str, ...] = ()

    @property
    def blocked(self) -> bool:
        return not self.allowed


def rate_limit_key(ctx: RuleContext, scope: str, scope_id: str | None) -> str:
    """The key a rate limit is tracked under.

    A ``user``-scoped limit is tracked per user; ``target`` and ``global``
    are both per target, because the existing rate limiter is keyed by target
    name and a global rule simply applies the same value to every target.

    Callers that supply ``last_scans`` must build their keys with this same
    function. Hand-writing an f-string here is how the two sides drift apart.
    """
    if scope == "user":
        return f"user:{scope_id}"
    return f"target:{ctx.rate_key()}"


# ---------------------------------------------------------------------------
# Reading rules, which may be ORM rows or plain dicts
# ---------------------------------------------------------------------------


def _field(rule: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from an ORM row or a dict.

    The engine is handed whatever the caller has: ``Rule`` instances from the
    repository, or dicts from a cache, a fixture or a CSV import. Supporting
    both here keeps that flexibility out of the policy code.
    """
    if isinstance(rule, Mapping):
        return rule.get(name, default)
    return getattr(rule, name, default)


def _order_key(rule: Any) -> tuple[int, int]:
    priority = _field(rule, "priority", 50)
    ident = _field(rule, "id", 0)
    # Coerce defensively: a bad row must not raise out of a sort key.
    try:
        priority_int = int(priority)
    except (TypeError, ValueError):
        priority_int = 50
    try:
        id_int = int(ident)
    except (TypeError, ValueError):
        id_int = 0
    return (priority_int, id_int)


def _scope_matches(rule: Any, ctx: RuleContext) -> bool:
    """Whether a rule applies to this request's actor and target.

    ``global`` matches everything. ``user`` matches only the named actor, and
    an unknown actor (``None``, as for a scheduled run) matches nothing —
    a user-scoped rule must not silently apply to the scheduler.
    ``target`` matches the exact target string.
    """
    scope = str(_field(rule, "scope", "global") or "global").strip().lower()
    scope_id = _field(rule, "scope_id")

    if scope == "global":
        return True
    if scope == "user":
        return ctx.actor_id is not None and scope_id is not None and str(
            ctx.actor_id
        ) == str(scope_id)
    if scope == "target":
        return scope_id is not None and str(scope_id) == ctx.target
    # Unrecognised scope: do not apply it. Callers get a warning, and for a
    # deny rule RuleEngine separately re-checks with a fail-closed fallback.
    return False


def _deny_scope_matches(rule: Any, ctx: RuleContext) -> bool:
    """Like :func:`_scope_matches`, but an unreadable scope means global.

    Fail closed for restrictions: if the subject of a deny rule cannot be
    understood, applying it everywhere is the safe reading, and standing it
    down because of a typo is the dangerous one.
    """
    scope = str(_field(rule, "scope", "global") or "global").strip().lower()
    if scope in ("global", "user", "target"):
        return _scope_matches(rule, ctx)
    return True


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


class RuleEngine:
    """Evaluates a request against a rule set.

    Construction sorts and parses once; :meth:`evaluate` is then safe to call
    per scan. A new rule set means a new engine, which keeps the hot path free
    of re-parsing and makes it obvious that rule edits need a reload.
    """

    def __init__(
        self, rules: Sequence[Any] | None = None, *, logger: logging.Logger | None = None
    ) -> None:
        self._logger = logger or log
        self._ordered = sorted(rules or [], key=_order_key)
        self._warnings: list[str] = []

    # -- introspection used by the panel -------------------------------
    @property
    def rule_count(self) -> int:
        return len(self._ordered)

    def warnings(self) -> tuple[str, ...]:
        """Problems found while loading this rule set."""
        return tuple(self._warnings)

    # -- loading ------------------------------------------------------
    def _load(self) -> list[tuple[Any, str, Any]]:
        """Return ``(rule, rule_type, parsed)`` for every usable rule.

        Skipped rules are logged and collected as warnings. Disabled rules are
        skipped silently: pausing a rule is a normal operator action, not a
        fault.
        """
        warnings: list[str] = []
        usable: list[tuple[Any, str, Any]] = []

        for rule in self._ordered:
            if not _field(rule, "enabled", True):
                continue

            name = _field(rule, "name", f"id={_field(rule, 'id')}")
            rule_type = str(_field(rule, "rule_type", "") or "").strip()

            if rule_type not in rv.KNOWN_TYPES:
                message = (
                    f"rule {name!r}: unknown rule_type {rule_type!r}, skipped"
                )
                warnings.append(message)
                self._logger.warning("%s", message)
                continue

            raw_value = _field(rule, "value", "")
            try:
                parsed = self._parse(rule_type, raw_value)
            except ValueError as exc:
                message = f"rule {name!r}: {exc}, skipped"
                warnings.append(message)
                self._logger.warning("%s", message)
                continue

            usable.append((rule, rule_type, parsed))

        self._warnings = warnings
        return usable

    @staticmethod
    def _parse(rule_type: str, raw_value: Any) -> Any:
        """Dispatch to the right parser. Raises ValueError on bad input."""
        text = str(raw_value or "")
        if rule_type in rv.CIDR_TYPES:
            return rv.parse_cidrs(text)
        if rule_type in rv.DOMAIN_TYPES:
            return rv.parse_domains(text)
        if rule_type in rv.PORT_TYPES:
            return rv.parse_ports(text)
        if rule_type in rv.SECOND_TYPES:
            return rv.parse_seconds(text)
        if rule_type == "time_window":
            return rv.parse_time_window(text)
        if rule_type == "user_quota":
            return rv.parse_quota(text)
        raise ValueError(f"unknown rule type {rule_type!r}")

    # -- evaluation ---------------------------------------------------
    def evaluate(self, ctx: RuleContext) -> RuleDecision:
        """Decide whether ``ctx`` may proceed, and under which limits."""
        rules = self._load()

        now = ctx.resolved_now()
        minute = rv.minute_of_day(now)
        is_ip = rv.target_is_ip(ctx.target)

        # Gate families are tracked separately: an unmatched allow_cidr must
        # not be excused by a matched allow_domain, so each family answers
        # "did an allow rule of *my* kind match?" on its own.
        cidr_allows = cidr_allow_hits = 0
        domain_allows = domain_allow_hits = 0
        port_allows = 0
        allowed_ports: set[int] = set()
        last_allow: tuple[Any, str] | None = None

        rate_limit: int | None = None
        rate_limit_scope: str | None = None
        rate_limit_scope_id: str | None = None
        scan_timeout: int | None = None

        ports = tuple(ctx.ports or ())
        if not ports and any(t in rv.PORT_TYPES for _, t, _ in rules):
            # Port rules need a port list to mean anything. Logged, and
            # documented: a deny_port rule is inert unless the caller supplies
            # the ports the scan will actually probe.
            self._logger.debug(
                "port rules skipped: context carries no ports for target %r",
                ctx.target,
            )

        # One pass in (priority, id) order. The first deny short-circuits.
        for rule, rule_type, parsed in rules:
            verdict = self._deny_for(
                rule, rule_type, parsed, ctx, minute, is_ip, ports
            )
            if verdict is not None:
                reason, rule_id, rule_name = verdict
                return RuleDecision(
                    allowed=False,
                    reason=reason,
                    rule_id=rule_id,
                    rule_name=rule_name,
                    effective_rate_limit_seconds=(
                        rate_limit if rate_limit is not None
                        else ctx.default_rate_limit_seconds
                    ),
                    effective_scan_timeout=self._effective_timeout(
                        scan_timeout, ctx.default_scan_timeout_seconds
                    ),
                    warnings=tuple(self._warnings),
                )

            if not _scope_matches(rule, ctx):
                continue

            if rule_type == "allow_cidr" and is_ip:
                cidr_allows += 1
                if rv.cidr_matches(parsed, ctx.target):
                    cidr_allow_hits += 1
                    last_allow = (rule, "allow_cidr")
            elif rule_type == "allow_domain" and not is_ip:
                domain_allows += 1
                if rv.domain_matches(parsed, ctx.target):
                    domain_allow_hits += 1
                    last_allow = (rule, "allow_domain")
            elif rule_type == "allow_port" and ports:
                port_allows += 1
                for port in ports:
                    if rv.ports_match(parsed, port):
                        allowed_ports.add(port)
                        last_allow = (rule, "allow_port")
            elif rule_type == "rate_limit":
                if rate_limit is None or parsed < rate_limit:
                    rate_limit = parsed
                    rate_limit_scope = str(
                        _field(rule, "scope", "global") or "global"
                    ).lower()
                    rate_limit_scope_id = _field(rule, "scope_id")
            elif rule_type == "max_scan_time":
                if scan_timeout is None or parsed < scan_timeout:
                    scan_timeout = parsed

        # -- fail-closed gates ----------------------------------------
        # Checked after the pass so that a deny anywhere outranks a gate
        # miss, and so a gate miss reports the family that failed.
        if is_ip and cidr_allows and not cidr_allow_hits:
            return self._deny(
                "no matching allow rule",
                None,
                rate_limit,
                ctx,
                scan_timeout,
            )
        if not is_ip and domain_allows and not domain_allow_hits:
            return self._deny(
                "no matching allow rule",
                None,
                rate_limit,
                ctx,
                scan_timeout,
            )
        if ports and port_allows and allowed_ports != set(ports):
            # Every probed port must be allowed. One disallowed port denies the
            # whole scan rather than narrowing it, because silently probing
            # less than the operator asked for is a worse failure than a
            # refused scan.
            return self._deny(
                "no matching allow rule for every requested port",
                None,
                rate_limit,
                ctx,
                scan_timeout,
            )

        effective_rate = (
            rate_limit if rate_limit is not None
            else ctx.default_rate_limit_seconds
        )

        # -- rate limit enforcement -----------------------------------
        # Only enforced when a rate_limit rule actually matched. With no such
        # rule the caller's own limiter stays responsible, which is what makes
        # a rule an override rather than a replacement.
        if effective_rate is not None and rate_limit_scope is not None:
            key = rate_limit_key(ctx, rate_limit_scope, rate_limit_scope_id)
            last = ctx.last_scans.get(key)
            if last is not None:
                elapsed = _elapsed_seconds(last, now)
                if elapsed < effective_rate:
                    remaining = int(round(effective_rate - elapsed))
                    rule_id = rule_name = None
                    for rule, rule_type, parsed in rules:
                        if rule_type == "rate_limit" and parsed == rate_limit:
                            rule_id = _field(rule, "id")
                            rule_name = _field(rule, "name")
                            break
                    return RuleDecision(
                        allowed=False,
                        reason=(
                            f"rate limit: {remaining}s remaining "
                            f"({effective_rate}s window)"
                        ),
                        rule_id=rule_id,
                        rule_name=rule_name,
                        effective_rate_limit_seconds=effective_rate,
                        effective_scan_timeout=self._effective_timeout(
                            scan_timeout, ctx.default_scan_timeout_seconds
                        ),
                        warnings=tuple(self._warnings),
                    )

        allow_rule, allow_reason = (None, ALLOWED_UNRESTRICTED)
        if last_allow is not None:
            allow_rule = last_allow[0]
            allow_reason = ALLOWED_BY_GATE

        return RuleDecision(
            allowed=True,
            reason=allow_reason,
            rule_id=_field(allow_rule, "id"),
            rule_name=_field(allow_rule, "name"),
            effective_rate_limit_seconds=effective_rate,
            effective_scan_timeout=self._effective_timeout(
                scan_timeout, ctx.default_scan_timeout_seconds
            ),
            warnings=tuple(self._warnings),
        )

    # -- helpers ------------------------------------------------------
    def _deny(
        self,
        reason: str,
        rule: Any,
        rate_limit: int | None,
        ctx: RuleContext,
        scan_timeout: int | None,
    ) -> RuleDecision:
        return RuleDecision(
            allowed=False,
            reason=reason,
            rule_id=_field(rule, "id"),
            rule_name=_field(rule, "name"),
            effective_rate_limit_seconds=(
                rate_limit if rate_limit is not None
                else ctx.default_rate_limit_seconds
            ),
            effective_scan_timeout=self._effective_timeout(
                scan_timeout, ctx.default_scan_timeout_seconds
            ),
            warnings=tuple(self._warnings),
        )

    @staticmethod
    def _effective_timeout(
        rule_value: int | None, default: int | None
    ) -> int | None:
        """``min(default, rule)`` — a rule can only tighten the ceiling.

        With no default configured the rule value stands alone.
        """
        if rule_value is None:
            return default
        if default is None:
            return rule_value
        return min(default, rule_value)

    def _deny_for(
        self,
        rule: Any,
        rule_type: str,
        parsed: Any,
        ctx: RuleContext,
        minute: int,
        is_ip: bool,
        ports: tuple[int, ...],
    ) -> tuple[str, Any, Any] | None:
        """Return ``(reason, rule_id, rule_name)`` if this rule denies.

        Every rule in the set reaches this function regardless of scope, so a
        deny is never skipped because its scope could not be read.
        """
        rule_id = _field(rule, "id")
        rule_name = _field(rule, "name")

        # -- hard denies ----------------------------------------------
        if rule_type == "deny_cidr":
            if is_ip and rv.cidr_matches(
                parsed, ctx.target
            ) and _deny_scope_matches(rule, ctx):
                return (
                    f"blocked by deny_cidr rule: {ctx.target} is in {_value(rule)}",
                    rule_id,
                    rule_name,
                )

        if rule_type == "deny_domain":
            if not is_ip and rv.domain_matches(
                parsed, ctx.target
            ) and _deny_scope_matches(rule, ctx):
                return (
                    f"blocked by deny_domain rule: {ctx.target} matches "
                    f"{_value(rule)}",
                    rule_id,
                    rule_name,
                )

        if rule_type == "deny_port" and ports and _deny_scope_matches(rule, ctx):
            for port in ports:
                if rv.ports_match(parsed, port):
                    return (
                        f"blocked by deny_port rule: port {port} is denied",
                        rule_id,
                        rule_name,
                    )

        if rule_type == "time_window":
            if _deny_scope_matches(rule, ctx) and not parsed.contains(minute):
                return (
                    f"blocked by time_window rule: {_value(rule)} is UTC and "
                    "the request is outside it",
                    rule_id,
                    rule_name,
                )

        if rule_type == "user_quota":
            if _scope_matches(rule, ctx):
                used = int(ctx.quota_usage.get(parsed.period, 0))
                if used >= parsed.limit:
                    return (
                        f"blocked by user_quota rule: {used}/{parsed.limit} "
                        f"scans used this {parsed.period}",
                        rule_id,
                        rule_name,
                    )

        return None


def _value(rule: Any) -> str:
    return str(_field(rule, "value", "") or "")


def _elapsed_seconds(start: datetime, end: datetime) -> float:
    """Seconds from ``start`` to ``end``, tolerant of naive vs aware datetimes.

    The bot stores naive UTC timestamps while callers may pass aware ones, so
    both are normalized before subtracting. A clock that appears to run
    backwards yields a negative elapsed time, which counts as "too soon" and
    therefore fails closed.
    """
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    else:
        start = start.astimezone(timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    else:
        end = end.astimezone(timezone.utc)
    return (end - start).total_seconds()