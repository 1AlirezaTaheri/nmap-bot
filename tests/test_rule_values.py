"""Tests for the rule value parsers and matchers (core/rule_values.py).

Every parser is total — it returns a normalized value or raises ValueError —
so these tests pin both halves. The normalization assertions matter because
the engine stores the returned string back, and the panel shows it to the
operator: "8000-9000" typed as "9000 - 8000" must come back canonical.
"""

from __future__ import annotations

import pytest

from core import rule_values as rv


class TestParseCidrs:
    def test_single_cidr(self):
        nets = rv.parse_cidrs("192.168.174.0/24")
        assert str(nets[0]) == "192.168.174.0/24"

    def test_comma_separated(self):
        nets = rv.parse_cidrs("192.168.174.0/24,10.0.0.0/8")
        assert [str(n) for n in nets] == ["192.168.174.0/24", "10.0.0.0/8"]

    def test_mixed_cidr_and_bare_address(self):
        nets = rv.parse_cidrs("192.168.174.0/24,10.1.2.3")
        # A bare address is normalised to a host network.
        assert [str(n) for n in nets] == ["192.168.174.0/24", "10.1.2.3/32"]

    def test_host_bits_are_normalized_not_rejected(self):
        # strict=False, matching validate_target: /24 with host bits set is
        # the same network as /24 without them.
        assert str(rv.parse_cidrs("192.168.174.5/24")[0]) == "192.168.174.0/24"

    def test_whitespace_and_trailing_comma_tolerated(self):
        nets = rv.parse_cidrs(" 10.0.0.0/8 , 172.16.0.0/12 ,")
        assert len(nets) == 2

    def test_ipv6(self):
        assert str(rv.parse_cidrs("fd00::/8")[0]) == "fd00::/8"

    @pytest.mark.parametrize(
        "bad", ["not-a-cidr", "192.168.174.0/33", "", "   ", "10.0.0.0/8,bogus"]
    )
    def test_invalid_rejected(self, bad):
        with pytest.raises(ValueError):
            rv.parse_cidrs(bad)


class TestCidrMatches:
    def test_address_inside_network(self):
        nets = rv.parse_cidrs("192.168.174.0/24")
        assert rv.cidr_matches(nets, "192.168.174.10") is True

    def test_address_outside_network(self):
        nets = rv.parse_cidrs("192.168.174.0/24")
        assert rv.cidr_matches(nets, "8.8.8.8") is False

    def test_network_contained_by_rule_network(self):
        # Scanning a /24 must be caught by a /16 deny rule.
        nets = rv.parse_cidrs("10.0.0.0/8")
        assert rv.cidr_matches(nets, "10.1.0.0/16") is True

    def test_network_not_contained(self):
        nets = rv.parse_cidrs("10.0.0.0/8")
        assert rv.cidr_matches(nets, "192.168.0.0/16") is False

    def test_hostname_never_matches(self):
        nets = rv.parse_cidrs("0.0.0.0/0")
        # A hostname is not an IP; the engine must not coerce it.
        assert rv.cidr_matches(nets, "example.com") is False

    def test_ipv6_never_matches_ipv4_rule(self):
        nets = rv.parse_cidrs("0.0.0.0/0")
        assert rv.cidr_matches(nets, "::1") is False

    def test_garbage_does_not_raise(self):
        assert rv.cidr_matches(rv.parse_cidrs("10.0.0.0/8"), "!!!") is False


class TestTargetIsIp:
    @pytest.mark.parametrize(
        "target",
        ["10.0.0.1", "10.0.0.0/8", "fd00::1", "::1/64", "[::1]"],
    )
    def test_addresses_and_networks(self, target):
        assert rv.target_is_ip(target) is True

    @pytest.mark.parametrize(
        "target", ["example.com", "*.example.com", "localhost", "", "10.0.0.999"]
    )
    def test_hostnames_and_garbage(self, target):
        assert rv.target_is_ip(target) is False


class TestParseDomains:
    def test_exact_domain(self):
        patterns = rv.parse_domains("example.com")
        assert patterns[0].domain == "example.com"
        assert patterns[0].wildcard is False

    def test_wildcard_recorded(self):
        patterns = rv.parse_domains("*.example.com")
        assert patterns[0].domain == "example.com"
        assert patterns[0].wildcard is True

    def test_case_and_trailing_dot_normalized(self):
        patterns = rv.parse_domains("  EXAMPLE.COM. ")
        assert patterns[0].domain == "example.com"

    def test_comma_separated_mixed(self):
        patterns = rv.parse_domains("example.com,*.corp.test")
        assert [(p.domain, p.wildcard) for p in patterns] == [
            ("example.com", False),
            ("corp.test", True),
        ]

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "   ",
            "exa mple.com",
            "-example.com",
            "example-.com",
            "example..com",
            "*.",           # nothing after the wildcard
            "*",            # bare star
            "*..com",
            "example.com,bogus domain",
        ],
    )
    def test_invalid_rejected(self, bad):
        with pytest.raises(ValueError):
            rv.parse_domains(bad)


class TestDomainMatches:
    def test_exact_matches_itself_only(self):
        patterns = rv.parse_domains("example.com")
        assert patterns[0].matches("example.com") is True
        assert patterns[0].matches("www.example.com") is False

    def test_wildcard_matches_subdomain(self):
        patterns = rv.parse_domains("*.example.com")
        assert patterns[0].matches("a.example.com") is True

    def test_wildcard_matches_deep_subdomain(self):
        patterns = rv.parse_domains("*.example.com")
        assert patterns[0].matches("a.b.example.com") is True

    def test_wildcard_does_not_match_bare_domain(self):
        # The behaviour real DNS wildcard records have.
        patterns = rv.parse_domains("*.example.com")
        assert patterns[0].matches("example.com") is False

    def test_wildcard_does_not_match_suffix_confusion(self):
        # "notexample.com" must not satisfy "*.example.com".
        patterns = rv.parse_domains("*.example.com")
        assert patterns[0].matches("notexample.com") is False

    def test_trailing_dot_on_the_candidate_is_stripped(self):
        patterns = rv.parse_domains("example.com")
        assert patterns[0].matches("example.com.") is True

    def test_case_insensitive(self):
        patterns = rv.parse_domains("example.com")
        assert patterns[0].matches("EXAMPLE.COM") is True

    def test_helper_matches_any_pattern(self):
        patterns = rv.parse_domains("a.test,*.b.test")
        assert rv.domain_matches(patterns, "x.b.test") is True
        assert rv.domain_matches(patterns, "a.test") is True
        assert rv.domain_matches(patterns, "c.test") is False


class TestParsePorts:
    def test_single_port(self):
        assert rv.parse_ports("22") == (rv.PortRange(22, 22),)

    def test_comma_separated(self):
        ranges = rv.parse_ports("22,80,443")
        assert [r.start for r in ranges] == [22, 80, 443]

    def test_range(self):
        assert rv.parse_ports("8000-9000") == (rv.PortRange(8000, 9000),)

    def test_mixed_ports_and_ranges(self):
        ranges = rv.parse_ports("22,80,8000-9000")
        assert len(ranges) == 3
        assert ranges[-1].contains(8500) is True

    def test_whitespace_tolerated(self):
        assert len(rv.parse_ports(" 22 , 80 ")) == 2

    def test_boundaries_accepted(self):
        assert rv.parse_ports("1,65535")

    @pytest.mark.parametrize(
        "bad",
        [
            "0",              # below the valid range
            "65536",          # above it
            "9000-8000",      # reversed
            "22-",            # open-ended
            "-22",            # open-ended
            "abc",
            "22,abc",
            "",
            "22-abc",
        ],
    )
    def test_invalid_rejected(self, bad):
        with pytest.raises(ValueError):
            rv.parse_ports(bad)


class TestPortsMatch:
    def test_range_includes_both_ends(self):
        ranges = rv.parse_ports("8000-9000")
        assert rv.ports_match(ranges, 8000) is True, "lower bound must be included"
        assert rv.ports_match(ranges, 9000) is True, "upper bound must be included"

    def test_outside_range(self):
        ranges = rv.parse_ports("8000-9000")
        assert rv.ports_match(ranges, 7999) is False
        assert rv.ports_match(ranges, 9001) is False

    def test_inside_range(self):
        assert rv.ports_match(rv.parse_ports("8000-9000"), 8500) is True


class TestParseSeconds:
    def test_positive(self):
        assert rv.parse_seconds("120") == 120
        assert rv.parse_seconds("1") == 1

    def test_whitespace_tolerated(self):
        assert rv.parse_seconds(" 60 ") == 60

    @pytest.mark.parametrize("bad", ["0", "-5", "abc", "1.5", "", "1e3", "  "])
    def test_invalid_rejected(self, bad):
        with pytest.raises(ValueError):
            rv.parse_seconds(bad)


class TestParseTimeWindow:
    def test_daytime_window(self):
        window = rv.parse_time_window("08:00-22:00")
        assert window.start_minute == 8 * 60
        assert window.end_minute == 22 * 60
        assert window.overnight is False

    def test_overnight_window_detected(self):
        window = rv.parse_time_window("22:00-06:00")
        assert window.overnight is True

    def test_single_digit_hour_accepted_and_padded_on_output(self):
        # Forgiving on input, canonical on output: the panel stores
        # "08:00-09:30" whatever the operator typed.
        window = rv.parse_time_window("8:00-9:30")
        assert window.start_minute == 480
        assert window.end_minute == 570

    def test_whitespace_around_the_separator_tolerated(self):
        assert rv.parse_time_window(" 08:00 - 22:00 ").start_minute == 480

    @pytest.mark.parametrize(
        "bad",
        [
            "8:0-22:00",      # single-digit minute
            "08:00-22:00:00",  # seconds present
            "25:00-26:00",     # hour out of range
            "08:60-09:00",     # minute out of range
            "08:00",           # no range
            "08:00_22:00",     # wrong separator
            "08:00-08:00",     # identical ends
            "",
        ],
    )
    def test_invalid_rejected(self, bad):
        with pytest.raises(ValueError):
            rv.parse_time_window(bad)


class TestTimeWindowContains:
    def _minutes(self, hour: int, minute: int = 0) -> int:
        return hour * 60 + minute

    def test_inside_daytime_window(self):
        window = rv.parse_time_window("08:00-22:00")
        assert window.contains(self._minutes(12)) is True

    def test_outside_daytime_window(self):
        window = rv.parse_time_window("08:00-22:00")
        assert window.contains(self._minutes(23)) is False
        assert window.contains(self._minutes(7)) is False

    def test_start_inclusive_end_exclusive(self):
        window = rv.parse_time_window("08:00-22:00")
        assert window.contains(self._minutes(8)) is True
        assert window.contains(self._minutes(22)) is False, "end must be exclusive"

    def test_overnight_before_midnight(self):
        window = rv.parse_time_window("22:00-06:00")
        assert window.contains(self._minutes(23)) is True

    def test_overnight_after_midnight(self):
        window = rv.parse_time_window("22:00-06:00")
        assert window.contains(self._minutes(2)) is True

    def test_overnight_outside(self):
        window = rv.parse_time_window("22:00-06:00")
        assert window.contains(self._minutes(12)) is False
        assert window.contains(self._minutes(6)) is False, "end must be exclusive"


class TestParseQuota:
    def test_hour(self):
        quota = rv.parse_quota("10/hour")
        assert (quota.limit, quota.period) == (10, "hour")

    def test_day(self):
        quota = rv.parse_quota("50/day")
        assert (quota.limit, quota.period) == (50, "day")
        assert quota.period_seconds == 86400

    def test_case_and_whitespace(self):
        assert rv.parse_quota(" 5 / DAY ").period == "day"

    @pytest.mark.parametrize(
        "bad",
        [
            "10/week",     # unsupported period
            "10",          # no period
            "/day",        # no count
            "0/day",       # zero quota
            "-1/day",      # negative
            "abc/day",
            "",
        ],
    )
    def test_invalid_rejected(self, bad):
        with pytest.raises(ValueError):
            rv.parse_quota(bad)


class TestMinuteOfDay:
    def test_naive_treated_as_utc(self):
        from datetime import datetime

        assert rv.minute_of_day(datetime(2026, 1, 1, 13, 45)) == 13 * 60 + 45

    def test_aware_converted_to_utc(self):
        from datetime import datetime, timezone, timedelta

        # 14:00 in a +01:00 zone is 13:00 UTC.
        moment = datetime(
            2026, 1, 1, 14, 0, tzinfo=timezone(timedelta(hours=1))
        )
        assert rv.minute_of_day(moment) == 13 * 60


class TestValidateValue:
    @pytest.mark.parametrize(
        "rule_type,raw,expected",
        [
            ("allow_cidr", "192.168.174.0/24", "192.168.174.0/24"),
            ("allow_cidr", " 10.0.0.0/8 , 172.16.0.0/12 ", "10.0.0.0/8,172.16.0.0/12"),
            ("deny_cidr", "10.1.2.3/24", "10.1.2.0/24"),
            ("allow_domain", "EXAMPLE.COM.", "example.com"),
            ("allow_domain", "*.Example.com", "*.example.com"),
            ("deny_port", "22", "22"),
            ("deny_port", "8000-9000", "8000-9000"),
            ("deny_port", "22,8000-9000", "22,8000-9000"),
            ("max_scan_time", " 120 ", "120"),
            ("rate_limit", "60", "60"),
            ("time_window", " 8:00 - 9:30 ", "08:00-09:30"),
            ("time_window", "22:00-06:00", "22:00-06:00"),
            ("user_quota", "50/DAY", "50/day"),
            ("user_quota", " 5 / day ", "5/day"),
        ],
    )
    def test_normalizes(self, rule_type, raw, expected):
        assert rv.validate_value(rule_type, raw) == expected

    @pytest.mark.parametrize("bad_type", ["", "nonsense", "allow_everything"])
    def test_unknown_type_rejected(self, bad_type):
        with pytest.raises(ValueError, match="unknown rule type"):
            rv.validate_value(bad_type, "anything")

    @pytest.mark.parametrize(
        "rule_type,raw",
        [
            ("allow_cidr", "nope"),
            ("allow_domain", "bad domain"),
            ("allow_port", "70000"),
            ("max_scan_time", "0"),
            ("rate_limit", "abc"),
            ("time_window", "25:00-26:00"),
            ("user_quota", "10/week"),
        ],
    )
    def test_bad_value_rejected(self, rule_type, raw):
        with pytest.raises(ValueError):
            rv.validate_value(rule_type, raw)


class TestKnownTypes:
    def test_every_declared_type_is_parseable(self):
        # Guards against a type being added to the model vocabulary without a
        # parser, which would make it silently skip at evaluation time.
        assert set(rv.KNOWN_TYPES) == {
            "allow_cidr", "deny_cidr", "allow_domain", "deny_domain",
            "allow_port", "deny_port", "max_scan_time", "rate_limit",
            "time_window", "user_quota",
        }

    def test_agrees_with_the_database_vocabulary(self):
        # The two lists are declared separately so this module needs no
        # database import; they must not drift apart.
        from database.models import RULE_TYPES

        assert set(rv.KNOWN_TYPES) == set(RULE_TYPES)