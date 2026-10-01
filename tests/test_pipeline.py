"""End-to-end pipeline tests: repository, scan manager, profiles."""

from __future__ import annotations

import pytest

from core.change_detector import NEW_HOST, NEW_PORT, detect
from core.profiles import DEFAULT_PROFILE, UnknownProfileError, get_profile
from core.scan_manager import ScanManager
from database.database import Database
from database.repository import (
    RepositoryError,
    ScanRepository,
    TargetRepository,
)
from parser.xml_parser import NmapXmlError


def xml_for(*hosts: tuple[str, list[tuple[int, str]]]) -> str:
    """Build a minimal nmap XML document from (address, [ports]) pairs."""
    parts = ['<?xml version="1.0"?><nmaprun scanner="nmap">']
    for address, ports in hosts:
        parts.append('<host><status state="up"/>')
        parts.append(f'<address addr="{address}" addrtype="ipv4"/>')
        parts.append("<ports>")
        for port, name in ports:
            parts.append(
                f'<port protocol="tcp" portid="{port}"><state state="open"/>'
                f'<service name="{name}"/></port>'
            )
        parts.append("</ports></host>")
    parts.append("</nmaprun>")
    return "".join(parts)


class FakeRunner:
    """Deterministic stand-in for nmap so tests never touch the network."""

    def __init__(self) -> None:
        self.queue: list[str] = []
        self.calls: list[tuple[str, list[str]]] = []

    def run(self, target: str, args: list[str]):
        self.calls.append((target, args))
        if not self.queue:
            raise AssertionError("FakeRunner queue empty")
        return type("R", (), {"xml": self.queue.pop(0), "duration_ms": 42,
                              "returncode": 0, "stderr": ""})()


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/t.db")
    database.create_all()
    yield database
    database.dispose()


class TestProfiles:
    def test_default_resolves(self):
        assert get_profile(None).name == DEFAULT_PROFILE

    def test_unknown_profile_raises(self):
        with pytest.raises(UnknownProfileError):
            get_profile("insane")

    def test_args_are_fixed_and_contain_target_free_flags(self):
        for name, profile in [("quick", get_profile("quick")),
                              ("service", get_profile("service")),
                              ("deep", get_profile("deep"))]:
            assert profile.args, f"{name} has no args"
            assert all(a.startswith("-") or a.isdigit() for a in profile.args)


class TestTargetRepository:
    def test_add_and_get(self, db):
        with db.session() as s:
            TargetRepository(s).add("lab", "192.168.1.0/24", "core")
        with db.session() as s:
            row = TargetRepository(s).get_by_name("lab")
            assert row.value == "192.168.1.0/24"
            assert row.group_name == "core"

    def test_duplicate_name_rejected(self, db):
        with db.session() as s:
            TargetRepository(s).add("lab", "10.0.0.1")
        with pytest.raises(RepositoryError):
            with db.session() as s:
                TargetRepository(s).add("lab", "10.0.0.2")

    def test_get_or_create_by_value_is_idempotent(self, db):
        with db.session() as s:
            repo = TargetRepository(s)
            first = repo.get_or_create_by_value("8.8.8.8")
        with db.session() as s:
            second = TargetRepository(s).get_or_create_by_value("8.8.8.8")
        assert first.id == second.id


class TestScanManagerPipeline:
    def _manager(self, db) -> tuple[ScanManager, FakeRunner]:
        runner = FakeRunner()
        return ScanManager(db, runner), runner

    def test_scan_persists_snapshot(self, db):
        manager, runner = self._manager(db)
        runner.queue.append(xml_for(("10.0.0.1", [(22, "ssh")])))

        outcome = manager.execute("10.0.0.1", get_profile("quick"))

        assert outcome.host_count == 1
        assert outcome.service_count == 1
        assert outcome.duration_ms == 42

        with db.session() as s:
            scan = ScanRepository(s).get(outcome.scan_id)
            assert scan.status == "succeeded"
            assert [h.address for h in scan.hosts] == ["10.0.0.1"]

    def test_first_scan_is_baseline(self, db):
        manager, runner = self._manager(db)
        runner.queue.append(xml_for(("10.0.0.1", [(22, "ssh")])))
        outcome = manager.execute("10.0.0.1", get_profile("quick"))
        assert outcome.is_first_scan is True
        assert outcome.baseline_scan_id is None

    def test_second_scan_detects_change(self, db):
        manager, runner = self._manager(db)
        runner.queue.append(xml_for(("10.0.0.1", [(22, "ssh")])))
        manager.execute("10.0.0.1", get_profile("quick"))

        runner.queue.append(
            xml_for(("10.0.0.1", [(22, "ssh")]), ("10.0.0.2", [(80, "http")]))
        )
        second = manager.execute("10.0.0.1", get_profile("quick"))

        assert second.is_first_scan is False
        assert second.baseline_scan_id is not None
        assert [c.change_type for c in second.changes] == [NEW_HOST]
        assert second.changes[0].host == "10.0.0.2"

        # change events persisted
        with db.session() as s:
            events = ScanRepository(s).get(second.scan_id).changes
            assert len(events) == 1
            assert events[0].change_type == NEW_HOST

    def test_failed_nmap_marks_scan_failed(self, db):
        class Boom:
            def run(self, target, args):
                raise NmapXmlError("bad xml")

        manager = ScanManager(db, Boom())
        outcome = manager.execute("10.0.0.1", get_profile("quick"))
        with db.session() as s:
            scan = ScanRepository(s).get(outcome.scan_id)
            assert scan.status == "failed"
            assert "bad xml" in scan.error

    def test_profiles_reach_runner_unchanged(self, db):
        manager, runner = self._manager(db)
        runner.queue.append(xml_for())
        manager.execute("10.0.0.1", get_profile("deep"))
        _, args = runner.calls[0]
        assert "--top-ports" in args and "1000" in args