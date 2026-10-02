"""Tests for V1: rate limiter, exporter serializers, reporter, logging."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from core.exporters import (
    CSV_HEADER,
    HostRow,
    ScanRow,
    ServiceRow,
    ChangeRow,
    build_scan_rows,
    render,
    to_csv,
    to_json,
)
from core.rate_limit import RateLimiter
from core.reporter import build_summary
from core.structured_logging import (
    REQUEST_ID,
    RequestIdFilter,
    bind,
    get_request_id,
    new_id,
)


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class TestRateLimiter:
    def test_first_attempt_allowed(self):
        rl = RateLimiter(30, clock=FakeClock())
        assert rl.check("home").allowed is True

    def test_second_attempt_within_window_blocked(self):
        clock = FakeClock()
        rl = RateLimiter(30, clock=clock)
        rl.check("home")
        clock.advance(5)
        decision = rl.check("home")
        assert decision.allowed is False
        assert 20 < decision.retry_after <= 25
        assert "Rate limited" in decision.reason

    def test_allowed_after_window(self):
        clock = FakeClock()
        rl = RateLimiter(30, clock=clock)
        rl.check("home")
        clock.advance(31)
        assert rl.check("home").allowed is True

    def test_limits_are_per_target(self):
        clock = FakeClock()
        rl = RateLimiter(30, clock=clock)
        assert rl.check("home").allowed is True
        assert rl.check("lab").allowed is True

    def test_blocked_attempt_does_not_extend_window(self):
        """A rejected request must not push the timer forward, otherwise a
        user could lock themselves out forever by retrying."""
        clock = FakeClock()
        rl = RateLimiter(30, clock=clock)
        rl.check("home")
        clock.advance(10)
        assert rl.check("home").allowed is False
        clock.advance(21)
        assert rl.check("home").allowed is True

    def test_zero_interval_allows_everything(self):
        clock = FakeClock()
        rl = RateLimiter(0, clock=clock)
        assert rl.check("home").allowed is True
        assert rl.check("home").allowed is True

    def test_peek_and_reset(self):
        clock = FakeClock()
        rl = RateLimiter(30, clock=clock)
        assert rl.peek("home") is None
        rl.check("home")
        clock.advance(4)
        assert rl.peek("home") == pytest.approx(4)
        rl.reset()
        assert rl.peek("home") is None

    def test_map_is_bounded(self):
        rl = RateLimiter(0, clock=FakeClock())
        for i in range(700):
            rl.check(f"t{i}")
        assert len(rl._last) <= 512


def _scan_row(scan_id=1, changes=(), hosts=()):
    return ScanRow(
        id=scan_id,
        target="home",
        target_value="192.168.174.0/24",
        profile="service",
        status="succeeded",
        source="manual",
        started_at="2026-10-03 10:00:00",
        finished_at="2026-10-03 10:00:11",
        duration_ms=11000,
        host_count=len(hosts) or 1,
        service_count=1,
        error=None,
        hosts=list(hosts),
        changes=list(changes),
    )


class TestExporters:
    def test_json_roundtrip(self):
        host = HostRow(
            address="192.168.174.1",
            hostname="gateway",
            state="up",
            services=[
                ServiceRow(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service_name="ssh",
                    product="OpenSSH",
                    version="8.2",
                )
            ],
        )
        row = _scan_row(
            7,
            changes=[
                ChangeRow(
                    change_type="new_host",
                    host="192.168.174.1",
                    port=None,
                    protocol=None,
                    old_value=None,
                    new_value=None,
                )
            ],
            hosts=[host],
        )
        text = to_json([row])
        data = json.loads(text)

        assert data["scan_count"] == 1
        scan = data["scans"][0]
        assert scan["id"] == 7
        assert scan["target"] == "home"
        assert scan["hosts"][0]["services"][0]["port"] == 22
        assert scan["changes"][0]["change_type"] == "new_host"

    def test_csv_has_header_and_service_rows(self):
        host = HostRow(
            address="10.0.0.1",
            hostname=None,
            state="up",
            services=[
                ServiceRow(
                    port=443,
                    protocol="tcp",
                    state="open",
                    service_name="https",
                    product=None,
                    version=None,
                )
            ],
        )
        text = to_csv([_scan_row(1, hosts=[host])])
        lines = text.strip().splitlines()

        assert lines[0] == ",".join(CSV_HEADER)
        assert len(lines) == 2
        assert lines[1].startswith("service,1,home")
        assert "443" in lines[1]

    def test_csv_emits_change_rows(self):
        text = to_csv(
            [
                _scan_row(
                    3,
                    changes=[
                        ChangeRow(
                            change_type="service_change",
                            host="10.0.0.5",
                            port=80,
                            protocol="tcp",
                            old_value="Apache",
                            new_value="nginx",
                        )
                    ],
                )
            ]
        )
        assert "change,3,home" in text
        assert "service_change" in text
        assert "Apache" in text and "nginx" in text

    def test_csv_marks_empty_scan(self):
        text = to_csv([_scan_row(5)])
        lines = text.strip().splitlines()
        assert lines[1].startswith("scan,5,home")

    def test_render_returns_filename_and_mime(self):
        content, suffix, mime = render([_scan_row()], "json")
        assert suffix == "json"
        assert mime == "application/json"
        assert json.loads(content)["scan_count"] == 1

        content, suffix, mime = render([_scan_row()], "csv")
        assert suffix == "csv"
        assert mime == "text/csv"
        assert content.splitlines()[0].startswith("record_type")

    def test_render_rejects_unknown_format(self):
        with pytest.raises(ValueError):
            render([_scan_row()], "xml")

    def test_build_scan_rows_tolerates_detached(self):
        class Hostile:
            id = 1
            target = None
            profile = "quick"
            status = "failed"
            source = "manual"
            started_at = None
            finished_at = None
            duration_ms = None
            host_count = 0
            service_count = 0
            error = "boom"

            @property
            def hosts(self):
                raise RuntimeError("detached")

        rows = build_scan_rows([Hostile()], {})
        assert rows[0].target == "?"
        assert rows[0].hosts == []


class FakeService:
    def __init__(self, port, name):
        self.port = port
        self.protocol = "tcp"
        self.state = "open"
        self.service_name = name
        self.product = None
        self.version = None


class FakeHost:
    def __init__(self, address, ports):
        self.address = address
        self.hostname = None
        self.state = "up"
        self.services = [FakeService(p, n) for p, n in ports]


class FakeScan:
    def __init__(self, scan_id, status, hosts):
        self.id = scan_id
        self.status = status
        self.hosts = hosts
        self.started_at = datetime.utcnow()


class FakeChange:
    def __init__(self, change_type, host):
        self.change_type = change_type
        self.host = host
        self.port = None
        self.protocol = None
        self.old_value = None
        self.new_value = None


class TestReporter:
    def test_counts_scans_and_assets(self):
        scans = [
            FakeScan(1, "succeeded", [FakeHost("10.0.0.1", [(22, "ssh")])]),
            FakeScan(2, "failed", []),
            FakeScan(3, "succeeded", [FakeHost("10.0.0.2", [(80, "http")])]),
        ]
        summary = build_summary("home", "192.168.1.0/24", scans, [])

        assert summary.total_scans == 3
        assert summary.succeeded == 2
        assert summary.failed == 1
        assert summary.unique_hosts == 2
        assert summary.unique_services == 2

    def test_groups_change_events(self):
        changes = [
            FakeChange("new_host", "10.0.0.1"),
            FakeChange("new_host", "10.0.0.2"),
            FakeChange("service_change", "10.0.0.1"),
            FakeChange("closed_port", "10.0.0.9"),
        ]
        summary = build_summary("home", "10.0.0.0/24", [FakeScan(1, "succeeded", [])], changes)

        assert summary.change_counts["new_host"] == 2
        assert summary.change_counts["service_change"] == 1
        assert summary.change_counts["closed_port"] == 1

    def test_top_changed_hosts_ranked(self):
        changes = [FakeChange("new_port", "10.0.0.1") for _ in range(5)]
        changes += [FakeChange("new_port", "10.0.0.2")]
        summary = build_summary("home", "10.0.0.0/24", [FakeScan(1, "succeeded", [])], changes)

        assert summary.top_changed_hosts[0] == ("10.0.0.1", 5)
        assert len(summary.top_changed_hosts) == 2

    def test_empty_input_renders(self):
        text = build_summary("home", "10.0.0.0/24", [], []).text()
        assert "no change events recorded" in text
        assert "(none)" in text

    def test_success_ratio(self):
        mixed = [FakeScan(1, "succeeded", []), FakeScan(2, "failed", [])]
        assert "1/2 (50%)" in build_summary("h", "v", mixed, []).success_ratio

        all_ok = [FakeScan(1, "succeeded", []), FakeScan(2, "succeeded", [])]
        assert "2/2 (100%)" in build_summary("h", "v", all_ok, []).success_ratio

        assert build_summary("h", "v", [], []).success_ratio == "n/a"


class TestStructuredLogging:
    def test_bind_assigns_and_restores(self):
        before = get_request_id()
        with bind("job") as rid:
            assert rid.startswith("job-")
            assert get_request_id() == rid
        assert get_request_id() == before

    def test_ids_are_unique(self):
        assert new_id() != new_id()

    def test_filter_adds_attribute(self):
        import logging as _logging

        record = _logging.LogRecord("x", _logging.INFO, "p", 1, "m", None, None)
        RequestIdFilter().filter(record)
        assert hasattr(record, "request_id")

    def test_filter_fills_current_context(self):
        import logging as _logging

        with bind("job") as rid:
            record = _logging.LogRecord("x", _logging.INFO, "p", 1, "m", None, None)
            RequestIdFilter().filter(record)
            assert record.request_id == rid