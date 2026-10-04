"""Tests for the rule evaluation engine (core/rules.py).

The engine is the security boundary this feature adds, so the tests
concentrate on the properties that must hold rather than on incidental
output: deny beats allow regardless of order, allow gates fail closed, a
broken rule cannot deny traffic, and limits resolve the way the spec says.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pytest

from core.rules import RuleContext, RuleDecision, RuleEngine, rate_limit_key

UTC = timezone.utc


def rule(
    rule_type: str,
    value: str,
    *,
    name: str | None = None,
    ident: int = 1,
    priority: int = 50,
    enabled: bool = True,
    scope: str = "global",
    scope_id: str | None = None,
) -> dict:
    """Build a rule as a plain dict, which the engine accepts alongside ORM rows."""
    return {
        "id": ident,
        "name": name or f"{rule_type}-{ident}",
        "rule_type": rule_type,
        "value": value,
        "priority": priority,
        "enabled": enabled,
        "scope": scope,
        "scope_id": scope_id,
    }


def at(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 6, 1, hour, minute, tzinfo=UTC)


class TestEmptyRuleSet:
    def test_no_rules_allows(self):
        decision = RuleEngine([]).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is True
        assert decision.rule_id is None
        assert decision.rule_name is None

    def test_no_rules_reports_unrestricted(self):
        decision = RuleEngine([]).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.reason == "no applicable rules"

    def test_engine_accepts_none(self):
        assert RuleEngine(None).rule_count == 0


class TestCidrGate:
    def test_allow_match(self):
        decision = RuleEngine(
            [rule("allow_cidr", "192.168.174.0/24")]
        ).evaluate(RuleContext(target="192.168.174.10"))
        assert decision.allowed is True
        assert decision.rule_name == "allow_cidr-1"

    def test_allow_no_match_is_denied_fail_closed(self):
        decision = RuleEngine(
            [rule("allow_cidr", "192.168.174.0/24")]
        ).evaluate(RuleContext(target="8.8.8.8"))
        assert decision.allowed is False
        assert decision.reason == "no matching allow rule"
        assert decision.rule_id is None, "a gate miss names no rule"

    def test_only_deny_rules_impose_no_allow_restriction(self):
        # No allow_cidr exists, so the CIDR family imposes nothing.
        decision = RuleEngine(
            [rule("deny_cidr", "10.0.0.0/8")]
        ).evaluate(RuleContext(target="192.168.174.10"))
        assert decision.allowed is True

    def test_allow_and_deny_both_must_pass(self):
        decision = RuleEngine(
            [
                rule("allow_cidr", "0.0.0.0/0", ident=1),
                rule("deny_cidr", "10.0.0.0/8", ident=2),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False
        assert decision.rule_name == "deny_cidr-2"

    def test_allow_matches_outside_the_deny(self):
        decision = RuleEngine(
            [
                rule("allow_cidr", "0.0.0.0/0", ident=1),
                rule("deny_cidr", "10.0.0.0/8", ident=2),
            ]
        ).evaluate(RuleContext(target="8.8.8.8"))
        assert decision.allowed is True

    def test_deny_cidr_applies_to_hostnames_not_at_all(self):
        # A hostname is judged by domain rules only.
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0")]
        ).evaluate(RuleContext(target="example.com"))
        assert decision.allowed is True

    def test_ipv4_deny_does_not_catch_ipv6(self):
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0")]
        ).evaluate(RuleContext(target="fd00::1"))
        assert decision.allowed is True, "an IPv4 /0 must not swallow IPv6"


class TestDomainGate:
    def test_exact_allow_match(self):
        decision = RuleEngine(
            [rule("allow_domain", "example.com")]
        ).evaluate(RuleContext(target="example.com"))
        assert decision.allowed is True

    def test_exact_allow_does_not_match_subdomain(self):
        decision = RuleEngine(
            [rule("allow_domain", "example.com")]
        ).evaluate(RuleContext(target="www.example.com"))
        assert decision.allowed is False

    def test_wildcard_allow_matches_subdomain(self):
        decision = RuleEngine(
            [rule("allow_domain", "*.example.com")]
        ).evaluate(RuleContext(target="www.example.com"))
        assert decision.allowed is True

    def test_deny_domain_match(self):
        decision = RuleEngine(
            [rule("deny_domain", "*.evil.test")]
        ).evaluate(RuleContext(target="a.evil.test"))
        assert decision.allowed is False
        assert "deny_domain" in decision.reason

    def test_domain_rules_ignored_for_ip_targets(self):
        decision = RuleEngine(
            [rule("deny_domain", "*.test")]
        ).evaluate(RuleContext(target="10.0.0.1"))
        assert decision.allowed is True

    def test_two_gate_families_do_not_compensate(self):
        # A matched allow_domain must not excuse an unmatched allow_cidr.
        # This is the "fail closed per family" rule.
        decision = RuleEngine(
            [
                rule("allow_cidr", "192.168.174.0/24", ident=1),
                rule("allow_domain", "example.com", ident=2),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False, "the CIDR family failed on its own"


class TestPriorityAndDenyWins:
    def test_deny_at_priority_1_beats_allow_at_50(self):
        decision = RuleEngine(
            [
                rule("allow_cidr", "0.0.0.0/0", ident=1, priority=50),
                rule("deny_cidr", "10.0.0.0/8", ident=2, priority=1),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False
        assert decision.rule_name == "deny_cidr-2"

    def test_deny_at_priority_100_still_beats_an_earlier_allow(self):
        # The spec's explicit case: an allow that runs first does not commit
        # the decision, because every rule is examined before allowing.
        decision = RuleEngine(
            [
                rule("allow_cidr", "0.0.0.0/0", ident=1, priority=1),
                rule("deny_cidr", "10.0.0.0/8", ident=2, priority=100),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False
        assert decision.rule_name == "deny_cidr-2"

    def test_first_matching_deny_in_priority_order_wins(self):
        # Two denies match; the one that evaluates first must be reported.
        decision = RuleEngine(
            [
                rule("deny_cidr", "0.0.0.0/0", ident=1, priority=5, name="broad"),
                rule("deny_cidr", "10.0.0.0/8", ident=2, priority=1, name="specific"),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.rule_name == "specific"

    def test_ties_broken_by_id(self):
        decision = RuleEngine(
            [
                rule("deny_cidr", "0.0.0.0/0", ident=9, priority=1, name="second"),
                rule("deny_cidr", "10.0.0.0/8", ident=3, priority=1, name="first"),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.rule_name == "first", "same priority must order by id"

    def test_last_matching_allow_is_reported(self):
        decision = RuleEngine(
            [
                rule("allow_cidr", "0.0.0.0/0", ident=1, priority=10, name="any"),
                rule("allow_cidr", "10.0.0.0/8", ident=2, priority=20, name="ten"),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.rule_name == "ten"


class TestPorts:
    def test_deny_port_blocks_the_scan(self):
        decision = RuleEngine(
            [rule("deny_port", "22")]
        ).evaluate(RuleContext(target="10.0.0.5", ports=(22, 80)))
        assert decision.allowed is False
        assert "port 22" in decision.reason

    def test_deny_port_absent_allows(self):
        decision = RuleEngine(
            [rule("deny_port", "22")]
        ).evaluate(RuleContext(target="10.0.0.5", ports=(80, 443)))
        assert decision.allowed is True

    def test_port_range_boundaries_are_inclusive(self):
        rules = [rule("deny_port", "8000-9000")]
        engine = RuleEngine(rules)
        assert engine.evaluate(
            RuleContext(target="10.0.0.5", ports=(8000,))
        ).allowed is False
        assert engine.evaluate(
            RuleContext(target="10.0.0.5", ports=(9000,))
        ).allowed is False
        assert engine.evaluate(
            RuleContext(target="10.0.0.5", ports=(7999, 9001))
        ).allowed is True

    def test_allow_port_gate(self):
        decision = RuleEngine(
            [rule("allow_port", "22,80")]
        ).evaluate(RuleContext(target="10.0.0.5", ports=(22, 80)))
        assert decision.allowed is True

    def test_allow_port_gate_denies_an_unlisted_port(self):
        decision = RuleEngine(
            [rule("allow_port", "22,80")]
        ).evaluate(RuleContext(target="10.0.0.5", ports=(22, 443)))
        assert decision.allowed is False
        assert "allow rule" in decision.reason

    def test_one_bad_port_denies_the_whole_scan(self):
        # Silently probing less than asked for is worse than refusing.
        decision = RuleEngine(
            [rule("allow_port", "22,80")]
        ).evaluate(RuleContext(target="10.0.0.5", ports=(22, 80, 443)))
        assert decision.allowed is False

    def test_port_rules_inert_without_ports(self):
        # Documented limitation: the engine cannot judge ports it was not
        # told about, so it does not pretend to.
        decision = RuleEngine(
            [rule("deny_port", "22")]
        ).evaluate(RuleContext(target="10.0.0.5", ports=()))
        assert decision.allowed is True


class TestTimeWindow:
    def test_inside_window_allowed(self):
        decision = RuleEngine(
            [rule("time_window", "08:00-22:00")]
        ).evaluate(RuleContext(target="10.0.0.5", now=at(12)))
        assert decision.allowed is True

    def test_outside_window_denied(self):
        decision = RuleEngine(
            [rule("time_window", "08:00-22:00")]
        ).evaluate(RuleContext(target="10.0.0.5", now=at(23)))
        assert decision.allowed is False
        assert "time_window" in decision.reason

    def test_before_window_denied(self):
        decision = RuleEngine(
            [rule("time_window", "08:00-22:00")]
        ).evaluate(RuleContext(target="10.0.0.5", now=at(7)))
        assert decision.allowed is False

    def test_overnight_before_midnight(self):
        decision = RuleEngine(
            [rule("time_window", "22:00-06:00")]
        ).evaluate(RuleContext(target="10.0.0.5", now=at(23)))
        assert decision.allowed is True

    def test_overnight_after_midnight(self):
        decision = RuleEngine(
            [rule("time_window", "22:00-06:00")]
        ).evaluate(RuleContext(target="10.0.0.5", now=at(2)))
        assert decision.allowed is True

    def test_overnight_outside(self):
        decision = RuleEngine(
            [rule("time_window", "22:00-06:00")]
        ).evaluate(RuleContext(target="10.0.0.5", now=at(12)))
        assert decision.allowed is False

    def test_window_is_evaluated_in_utc(self):
        # 07:00 UTC is 08:00 in a +01:00 zone; the window must use UTC.
        tz_plus_one = timezone(timedelta(hours=1))
        local_seven = datetime(2026, 6, 1, 7, 0, tzinfo=tz_plus_one)
        decision = RuleEngine(
            [rule("time_window", "08:00-22:00")]
        ).evaluate(RuleContext(target="10.0.0.5", now=local_seven))
        assert decision.allowed is False, "07:00 UTC is outside an 08:00 window"


class TestUserQuota:
    def test_under_quota_allowed(self):
        decision = RuleEngine(
            [rule("user_quota", "10/hour")]
        ).evaluate(
            RuleContext(
                target="10.0.0.5", actor_id=1, quota_usage={"hour": 9}
            )
        )
        assert decision.allowed is True

    def test_at_quota_denied(self):
        decision = RuleEngine(
            [rule("user_quota", "10/hour")]
        ).evaluate(
            RuleContext(
                target="10.0.0.5", actor_id=1, quota_usage={"hour": 10}
            )
        )
        assert decision.allowed is False
        assert "user_quota" in decision.reason

    def test_over_quota_denied(self):
        decision = RuleEngine(
            [rule("user_quota", "10/hour")]
        ).evaluate(
            RuleContext(
                target="10.0.0.5", actor_id=1, quota_usage={"hour": 25}
            )
        )
        assert decision.allowed is False

    def test_day_period(self):
        rules = [rule("user_quota", "50/day")]
        engine = RuleEngine(rules)
        assert engine.evaluate(
            RuleContext(
                target="10.0.0.5", actor_id=1, quota_usage={"day": 49}
            )
        ).allowed is True
        assert engine.evaluate(
            RuleContext(
                target="10.0.0.5", actor_id=1, quota_usage={"day": 50}
            )
        ).allowed is False

    def test_periods_are_independent(self):
        # Exhausting the hour quota must not consume the day quota.
        decision = RuleEngine(
            [rule("user_quota", "10/hour")]
        ).evaluate(
            RuleContext(
                target="10.0.0.5", actor_id=1, quota_usage={"hour": 99, "day": 1}
            )
        )
        assert decision.allowed is False

    def test_missing_usage_counts_as_zero(self):
        decision = RuleEngine(
            [rule("user_quota", "1/hour")]
        ).evaluate(RuleContext(target="10.0.0.5", actor_id=1))
        assert decision.allowed is True


class TestRateLimit:
    def test_effective_value_is_reported(self):
        decision = RuleEngine(
            [rule("rate_limit", "45")]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.effective_rate_limit_seconds == 45

    def test_smallest_matching_value_wins(self):
        decision = RuleEngine(
            [
                rule("rate_limit", "300", ident=1),
                rule("rate_limit", "60", ident=2),
                rule("rate_limit", "120", ident=3),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.effective_rate_limit_seconds == 60

    def test_falls_back_to_the_environment_default(self):
        decision = RuleEngine([]).evaluate(
            RuleContext(
                target="10.0.0.5", default_rate_limit_seconds=30
            )
        )
        assert decision.effective_rate_limit_seconds == 30

    def test_rule_value_replaces_the_default(self):
        # Unlike max_scan_time, the spec has rate_limit fall back rather than
        # take a minimum, so a rule may relax the environment default.
        decision = RuleEngine(
            [rule("rate_limit", "300")]
        ).evaluate(
            RuleContext(target="10.0.0.5", default_rate_limit_seconds=30)
        )
        assert decision.effective_rate_limit_seconds == 300

    def test_too_soon_is_denied(self):
        now = at(12)
        decision = RuleEngine(
            [rule("rate_limit", "60")]
        ).evaluate(
            RuleContext(
                target="10.0.0.5",
                now=now,
                last_scans={"target:10.0.0.5": now - timedelta(seconds=10)},
            )
        )
        assert decision.allowed is False
        assert "rate limit" in decision.reason

    def test_window_elapsed_is_allowed(self):
        now = at(12)
        decision = RuleEngine(
            [rule("rate_limit", "60")]
        ).evaluate(
            RuleContext(
                target="10.0.0.5",
                now=now,
                last_scans={"target:10.0.0.5": now - timedelta(seconds=61)},
            )
        )
        assert decision.allowed is True

    def test_no_previous_scan_is_allowed(self):
        decision = RuleEngine(
            [rule("rate_limit", "60")]
        ).evaluate(RuleContext(target="10.0.0.5", now=at(12)))
        assert decision.allowed is True

    def test_naive_timestamps_handled(self):
        # The bot stores naive UTC; the engine must not raise comparing them
        # against an aware `now`, and must judge them as UTC.
        now = at(12)
        decision = RuleEngine(
            [rule("rate_limit", "60")]
        ).evaluate(
            RuleContext(
                target="10.0.0.5",
                now=now,
                # 10s before `now`, naive UTC.
                last_scans={
                    "target:10.0.0.5": datetime(2026, 6, 1, 11, 59, 50)
                },
            )
        )
        assert decision.allowed is False

    def test_naive_elapsed_window_is_allowed(self):
        now = at(12)
        decision = RuleEngine(
            [rule("rate_limit", "60")]
        ).evaluate(
            RuleContext(
                target="10.0.0.5",
                now=now,
                last_scans={"target:10.0.0.5": datetime(2026, 6, 1, 11, 0)},
            )
        )
        assert decision.allowed is True


class TestRateLimitKeys:
    def test_target_scoped_key_uses_the_target(self):
        ctx = RuleContext(target="10.0.0.5", actor_id=1)
        assert rate_limit_key(ctx, "target", "10.0.0.5") == "target:10.0.0.5"

    def test_global_scoped_key_is_still_per_target(self):
        # "applies the value to all targets" means the same value everywhere,
        # tracked per target like the existing limiter.
        ctx = RuleContext(target="10.0.0.5", actor_id=1)
        assert rate_limit_key(ctx, "global", None) == "target:10.0.0.5"

    def test_user_scoped_key_uses_the_user(self):
        ctx = RuleContext(target="10.0.0.5", actor_id=7575983824)
        assert (
            rate_limit_key(ctx, "user", "7575983824") == "user:7575983824"
        )

    def test_user_scoped_limit_does_not_block_another_user(self):
        now = at(12)
        rules = [
            rule(
                "rate_limit", "60", scope="user", scope_id="1", name="alice"
            )
        ]
        decision = RuleEngine(rules).evaluate(
            RuleContext(
                target="10.0.0.5",
                actor_id=2,
                now=now,
                last_scans={"user:1": now - timedelta(seconds=5)},
            )
        )
        assert decision.allowed is True


class TestMaxScanTime:
    def test_reports_env_ceiling_without_rules(self):
        decision = RuleEngine([]).evaluate(
            RuleContext(target="10.0.0.5", default_scan_timeout_seconds=60)
        )
        assert decision.effective_scan_timeout == 60

    def test_rule_lowers_the_ceiling(self):
        decision = RuleEngine(
            [rule("max_scan_time", "120")]
        ).evaluate(
            RuleContext(target="10.0.0.5", default_scan_timeout_seconds=300)
        )
        assert decision.effective_scan_timeout == 120

    def test_rule_cannot_raise_the_ceiling(self):
        # The safety property: a rule can only tighten the timeout.
        decision = RuleEngine(
            [rule("max_scan_time", "9999")]
        ).evaluate(
            RuleContext(target="10.0.0.5", default_scan_timeout_seconds=300)
        )
        assert decision.effective_scan_timeout == 300

    def test_smallest_rule_wins(self):
        decision = RuleEngine(
            [
                rule("max_scan_time", "120", ident=1),
                rule("max_scan_time", "30", ident=2),
            ]
        ).evaluate(
            RuleContext(target="10.0.0.5", default_scan_timeout_seconds=300)
        )
        assert decision.effective_scan_timeout == 30

    def test_rule_alone_without_a_ceiling(self):
        decision = RuleEngine(
            [rule("max_scan_time", "45")]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.effective_scan_timeout == 45

    def test_never_denies_by_itself(self):
        # A timeout is not a gate: it only adjusts a value.
        decision = RuleEngine(
            [rule("max_scan_time", "1")]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is True


class TestScoping:
    def test_user_scope_applies_to_the_matching_user(self):
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0", scope="user", scope_id="1")]
        ).evaluate(RuleContext(target="10.0.0.5", actor_id=1))
        assert decision.allowed is False

    def test_user_scope_ignored_for_another_user(self):
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0", scope="user", scope_id="1")]
        ).evaluate(RuleContext(target="10.0.0.5", actor_id=2))
        assert decision.allowed is True

    def test_user_scope_ignored_when_there_is_no_actor(self):
        # A scheduled run must not inherit a specific user's deny.
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0", scope="user", scope_id="1")]
        ).evaluate(RuleContext(target="10.0.0.5", actor_id=None))
        assert decision.allowed is True

    def test_telegram_ids_compare_as_strings(self):
        # scope_id is text; the id must match as text, not by int() coercion.
        decision = RuleEngine(
            [
                rule(
                    "deny_cidr",
                    "0.0.0.0/0",
                    scope="user",
                    scope_id="7575983824",
                )
            ]
        ).evaluate(RuleContext(target="10.0.0.5", actor_id=7575983824))
        assert decision.allowed is False

    def test_target_scope_applies_to_that_target(self):
        # scope="target" matches the target string exactly. The target must be
        # an address for a CIDR rule to be the applicable family.
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0", scope="target", scope_id="10.0.0.5")]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False

    def test_target_scope_ignored_for_another_target(self):
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0", scope="target", scope_id="10.0.0.5")]
        ).evaluate(RuleContext(target="10.0.0.6"))
        assert decision.allowed is True

    def test_target_scope_does_not_apply_a_cidr_rule_to_a_hostname(self):
        # Correctly a no-op: "home" is a hostname, so domain rules govern it.
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0", scope="target", scope_id="home")]
        ).evaluate(RuleContext(target="home"))
        assert decision.allowed is True

    def test_target_scope_blocks_a_hostname_via_a_domain_rule(self):
        decision = RuleEngine(
            [rule("deny_domain", "*.evil.test", scope="target",
                  scope_id="a.evil.test")]
        ).evaluate(RuleContext(target="a.evil.test"))
        assert decision.allowed is False

    def test_quota_scoped_to_one_user(self):
        rules = [
            rule("user_quota", "1/hour", scope="user", scope_id="1")
        ]
        engine = RuleEngine(rules)
        assert engine.evaluate(
            RuleContext(
                target="10.0.0.5", actor_id=1, quota_usage={"hour": 5}
            )
        ).allowed is False
        assert engine.evaluate(
            RuleContext(
                target="10.0.0.5", actor_id=2, quota_usage={"hour": 5}
            )
        ).allowed is True

    def test_unknown_scope_on_a_deny_fails_closed(self):
        # An unreadable subject is not a reason to stand a restriction down.
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0", scope="galaxy", scope_id="x")]
        ).evaluate(RuleContext(target="10.0.0.5", actor_id=1))
        assert decision.allowed is False


class TestDisabledRules:
    def test_disabled_deny_is_skipped(self):
        decision = RuleEngine(
            [rule("deny_cidr", "0.0.0.0/0", enabled=False)]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is True

    def test_disabled_allow_does_not_create_a_gate(self):
        # A disabled allow must not turn into a fail-closed denial.
        decision = RuleEngine(
            [rule("allow_cidr", "192.168.174.0/24", enabled=False)]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is True

    def test_disabled_rate_limit_does_not_set_the_effective_value(self):
        decision = RuleEngine(
            [rule("rate_limit", "600", enabled=False)]
        ).evaluate(
            RuleContext(
                target="10.0.0.5", default_rate_limit_seconds=30
            )
        )
        assert decision.effective_rate_limit_seconds == 30


class TestBrokenRulesAreSkipped:
    def test_unknown_rule_type_is_skipped_and_does_not_deny(self, caplog):
        decision = RuleEngine(
            [rule("allow_everything", "yes")]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is True, "a typo must not deny traffic"
        assert any("unknown rule_type" in w for w in decision.warnings)

    def test_unknown_rule_type_logs_a_warning(self, caplog):
        with caplog.at_level(logging.WARNING):
            RuleEngine([rule("nonsense", "x")]).evaluate(
                RuleContext(target="10.0.0.5")
            )
        assert caplog.records, "skipping a rule must be visible in the log"

    @pytest.mark.parametrize(
        "rule_type,value",
        [
            ("allow_cidr", "not-a-cidr"),
            ("allow_domain", "bad domain"),
            ("allow_port", "70000"),
            ("max_scan_time", "0"),
            ("rate_limit", "abc"),
            ("time_window", "99:00-99:00"),
            ("user_quota", "10/week"),
        ],
    )
    def test_invalid_value_is_skipped_and_does_not_deny(self, rule_type, value):
        decision = RuleEngine(
            [rule(rule_type, value)]
        ).evaluate(RuleContext(target="10.0.0.5", actor_id=1))
        assert decision.allowed is True
        assert decision.warnings, "a rejected value must be reported"

    def test_broken_allow_does_not_create_a_gate(self):
        # A malformed allow must not fail closed and block everything.
        decision = RuleEngine(
            [rule("allow_cidr", "garbage")]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is True

    def test_broken_rule_does_not_shadow_a_valid_deny(self):
        decision = RuleEngine(
            [
                rule("allow_cidr", "garbage", ident=1),
                rule("deny_cidr", "10.0.0.0/8", ident=2),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False
        assert decision.rule_name == "deny_cidr-2"

    def test_warnings_are_available_before_evaluation(self):
        # The panel needs to show broken rules without issuing a decision.
        engine = RuleEngine([rule("allow_cidr", "garbage")])
        assert engine.warnings() == ()

    def test_a_valid_deny_still_wins_over_a_broken_allow(self):
        engine = RuleEngine(
            [
                rule("allow_cidr", "192.168.174.0/24", ident=1),
                rule("allow_cidr", "!!!", ident=2),
                rule("deny_cidr", "10.0.0.0/8", ident=3),
            ]
        )
        decision = engine.evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False
        assert decision.rule_name == "deny_cidr-3"
        assert len(decision.warnings) == 1


class TestInputTolerance:
    def test_accepts_orm_like_objects(self):
        # Real usage passes Rule rows, not dicts. A stand-in with attributes
        # proves the accessor path works.
        class Row:
            def __init__(self, **kw):
                self.__dict__.update(kw)

        decision = RuleEngine(
            [
                Row(
                    id=7,
                    name="deny-ten",
                    rule_type="deny_cidr",
                    value="10.0.0.0/8",
                    priority=1,
                    enabled=True,
                    scope="global",
                    scope_id=None,
                )
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False
        assert decision.rule_id == 7
        assert decision.rule_name == "deny-ten"

    def test_missing_fields_fall_back_to_defaults(self):
        decision = RuleEngine(
            [{"id": 1, "rule_type": "deny_cidr", "value": "10.0.0.0/8"}]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False

    def test_unusable_priority_does_not_break_the_sort(self):
        engine = RuleEngine(
            [
                {"id": 1, "rule_type": "deny_cidr", "value": "10.0.0.0/8",
                 "priority": None, "enabled": True},
            ]
        )
        assert engine.rule_count == 1
        assert engine.evaluate(RuleContext(target="10.0.0.5")).allowed is False

    def test_decision_is_immutable(self):
        decision = RuleEngine([]).evaluate(RuleContext(target="10.0.0.5"))
        assert isinstance(decision, RuleDecision)
        with pytest.raises(Exception):
            decision.allowed = False  # type: ignore[misc]


class TestReportedScenarios:
    """The three scenarios from the specification, pinned exactly."""

    def test_one_allowed(self):
        decision = RuleEngine(
            [rule("allow_cidr", "192.168.174.0/24")]
        ).evaluate(RuleContext(target="192.168.174.10"))
        assert decision.allowed is True
        assert decision.rule_id == 1
        assert decision.rule_name == "allow_cidr-1"

    def test_two_denied_by_the_gate(self):
        decision = RuleEngine(
            [rule("allow_cidr", "192.168.174.0/24")]
        ).evaluate(RuleContext(target="8.8.8.8"))
        assert decision.allowed is False
        assert decision.reason == "no matching allow rule"
        assert decision.rule_id is None

    def test_three_denied_by_the_deny_rule(self):
        decision = RuleEngine(
            [
                rule("allow_cidr", "0.0.0.0/0", ident=1),
                rule("deny_cidr", "10.0.0.0/8", ident=2),
            ]
        ).evaluate(RuleContext(target="10.0.0.5"))
        assert decision.allowed is False
        assert decision.rule_id == 2
        assert decision.rule_name == "deny_cidr-2"