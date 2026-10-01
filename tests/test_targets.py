"""Tests for the security layer."""

from __future__ import annotations

import pytest

from security.targets import TargetValidationError, in_scope, validate_target


class TestValidateTarget:
    @pytest.mark.parametrize(
        "target",
        ["192.168.1.1", "10.0.0.0/8", "scanme.nmap.org", "8.8.8.8"],
    )
    def test_accepts_valid(self, target):
        assert validate_target(target) == target

    @pytest.mark.parametrize(
        "target",
        [
            "",
            "-sV",
            "-sV 8.8.8.8",
            "192.168.1.1; cat /etc/passwd",
            "8.8.8.8 && rm -rf /",
            "$(whoami)",
            "not a host",
            "evil|id",
        ],
    )
    def test_rejects_malicious(self, target):
        with pytest.raises(TargetValidationError):
            validate_target(target)


class TestScope:
    ALLOWED = ("192.168.0.0/16",)

    def test_in_scope(self):
        assert in_scope("192.168.1.1", self.ALLOWED)

    def test_out_of_scope(self):
        assert not in_scope("8.8.8.8", self.ALLOWED)

    def test_hostname_never_provably_in_scope(self):
        # Conservative: hostnames are rejected when scope is configured.
        assert not in_scope("example.com", self.ALLOWED)

    def test_empty_scope_allows_everything(self):
        assert in_scope("8.8.8.8", ())

    def test_netmask_cannot_smuggle(self):
        # A /0 would match everything — the operator must write it, so it
        # is honoured as configured rather than silently widened.
        assert in_scope("8.8.8.8", ("0.0.0.0/0",))
