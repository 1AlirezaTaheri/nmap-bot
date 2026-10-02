"""Tests for authentication and authorization."""

from __future__ import annotations

import pytest

from config.settings import Settings
from security.authentication import Authenticator, Principal
from security.authorization import (
    AuthorizationError,
    Authorizer,
    TargetNotAllowedError,
)


def make_settings(ids=(100, 200)):
    return Settings(
        telegram_bot_token="x",
        allowed_user_ids=ids,
        allowed_cidrs=(),
        database_url="sqlite://",
        nmap_binary="nmap",
        scan_timeout_seconds=10,
        max_concurrent_scans=1,
        default_profile="service",
        schedule_enabled=False,
        schedule_interval_hours=6,
        schedule_profile="service",
        retention_days=30,
        retention_max_scans_per_target=100,
        export_max_scans=20,
        rate_limit_seconds=30,
    )


class TestAuthenticator:
    def test_known_user_is_authenticated(self):
        auth = Authenticator(make_settings())
        p = auth.authenticate(100, "alice")
        assert p is not None and p.user_id == 100

    def test_unknown_user_is_rejected(self):
        auth = Authenticator(make_settings())
        assert auth.authenticate(999) is None


class TestRoles:
    def test_operator_can_scan(self):
        assert Authorizer().can_scan(Principal(user_id=1, username=None))

    def test_viewer_cannot_scan(self):
        viewer = Principal(user_id=1, username=None, role="viewer")
        assert not Authorizer().can_scan(viewer)

    def test_authorization_error_on_require_role(self):
        viewer = Principal(user_id=1, username=None, role="viewer")
        with pytest.raises(AuthorizationError):
            Authorizer().require_role(viewer, "start a scan")

    def test_unknown_role_is_denied(self):
        bogus = Principal(user_id=1, username=None, role="root")
        assert not Authorizer().can_scan(bogus)


class TestScope:
    def test_in_scope_target_passes(self):
        authz = Authorizer(allowed_cidrs=("192.168.0.0/16",))
        assert authz.assert_target_permitted("192.168.1.1") == "192.168.1.1"

    def test_out_of_scope_target_raises(self):
        authz = Authorizer(allowed_cidrs=("192.168.0.0/16",))
        with pytest.raises(TargetNotAllowedError):
            authz.assert_target_permitted("8.8.8.8")

    def test_injection_target_raises(self):
        with pytest.raises(TargetNotAllowedError):
            Authorizer().assert_target_permitted("8.8.8.8; cat /etc/passwd")
