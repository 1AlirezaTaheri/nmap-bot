"""V1 integration tests: scheduler lifecycle, worker sharing, change alerts."""

from __future__ import annotations

import asyncio

import pytest

from core.change_detector import NEW_HOST, SERVICE_CHANGE
from core.profiles import get_profile
from core.scheduler import JOB_PREFIX, RETENTION_JOB_ID, ScanScheduler
from core.target_manager import TargetRegistry
from database.database import Database
from database.models import Scan
from database.repository import (
    ChangeRepository,
    OperatorChatRepository,
    ScanRepository,
    ScheduleRepository,
    TargetRepository,
)
from workers.scan_worker import ScanJob, ScanWorker

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def xml_for(*hosts):
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


class StubRunner:
    def __init__(self):
        self.queue = []
        self.calls = []

    def run(self, target, args):
        self.calls.append((target, list(args)))
        if not self.queue:
            raise AssertionError("StubRunner queue empty")
        return type(
            "R",
            (),
            {"xml": self.queue.pop(0), "duration_ms": 25, "returncode": 0,
             "stderr": ""},
        )()


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/t.db")
    database.create_all()
    yield database
    database.dispose()


def make_worker(db, runner=None, concurrency=2):
    from core.scan_manager import ScanManager

    runner = runner or StubRunner()
    manager = ScanManager(db, runner)
    return ScanWorker(scan_manager=manager, max_concurrency=concurrency), runner


def make_scheduler(db, worker, *, enabled=True):
    return ScanScheduler(
        db,
        worker,
        enabled=enabled,
        default_interval_hours=6,
        default_profile="service",
        retention_days=30,
        retention_max_per_target=100,
    )


class TestScheduleRepository:
    def test_upsert_creates_then_updates(self, db):
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        with db.session() as s:
            repo = ScheduleRepository(s)
            first = repo.upsert(tid, "quick", 2)
            sid = first.id
        with db.session() as s:
            second = ScheduleRepository(s).upsert(tid, "deep", 9)
            assert second.id == sid
            assert second.profile == "deep"
            assert second.interval_hours == 9
            assert second.enabled is True

    def test_enabled_filters_paused(self, db):
        with db.session() as s:
            a = TargetRepository(s).add("a", "10.0.0.0/24").id
            b = TargetRepository(s).add("b", "10.1.0.0/24").id
        with db.session() as s:
            repo = ScheduleRepository(s)
            repo.upsert(a, "quick", 1)
            repo.upsert(b, "quick", 1)
        with db.session() as s:
            ScheduleRepository(s).set_enabled(a, False)

        with db.session() as s:
            enabled = ScheduleRepository(s).enabled()
            all_rows = ScheduleRepository(s).all()

        assert [r.target_id for r in enabled] == [b]
        assert len(all_rows) == 2

    def test_set_all_enabled(self, db):
        with db.session() as s:
            a = TargetRepository(s).add("a", "10.0.0.0/24").id
            b = TargetRepository(s).add("b", "10.1.0.0/24").id
        with db.session() as s:
            repo = ScheduleRepository(s)
            repo.upsert(a, "quick", 1)
            repo.upsert(b, "quick", 1)

        with db.session() as s:
            assert ScheduleRepository(s).set_all_enabled(False) == 2
        with db.session() as s:
            assert ScheduleRepository(s).count_enabled() == 0

    def test_delete(self, db):
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        with db.session() as s:
            ScheduleRepository(s).upsert(tid, "quick", 1)
        with db.session() as s:
            assert ScheduleRepository(s).delete_for_target(tid) is True
        with db.session() as s:
            assert ScheduleRepository(s).delete_for_target(tid) is False

    def test_mark_run_sets_timestamps(self, db):
        from datetime import datetime

        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        with db.session() as s:
            sid = ScheduleRepository(s).upsert(tid, "quick", 1).id
        now = datetime.utcnow()
        with db.session() as s:
            ScheduleRepository(s).mark_run(sid, now, now)
        with db.session() as s:
            row = ScheduleRepository(s).all()[0]
            assert row.last_run_at is not None
            assert row.next_run_at is not None


class TestOperatorChat:
    def test_remembers_and_returns_primary(self, db):
        with db.session() as s:
            OperatorChatRepository(s).remember(111, 111, "alice")
        with db.session() as s:
            OperatorChatRepository(s).remember(222, 222, "bob")

        with db.session() as s:
            primary = OperatorChatRepository(s).primary()
            everyone = OperatorChatRepository(s).list()

        assert primary.chat_id == 111  # earliest registered
        assert len(everyone) == 2

    def test_remember_is_idempotent_per_chat(self, db):
        with db.session() as s:
            OperatorChatRepository(s).remember(111, 111, "alice")
        with db.session() as s:
            OperatorChatRepository(s).remember(111, 111, "alice2")
        with db.session() as s:
            assert len(OperatorChatRepository(s).list()) == 1


@pytest.mark.asyncio
class TestSchedulerLifecycle:
    async def test_disabled_scheduler_registers_nothing(self, db):
        worker, _ = make_worker(db)
        scheduler = make_scheduler(db, worker, enabled=False)
        await scheduler.start()
        assert scheduler.running is False
        await scheduler.stop()

    async def test_enabled_scheduler_registers_jobs(self, db):
        worker, _ = make_worker(db)
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        with db.session() as s:
            ScheduleRepository(s).upsert(tid, "service", 2)

        scheduler = make_scheduler(db, worker)
        await scheduler.start()
        try:
            jobs = scheduler.scheduler.get_jobs()
            ids = [j.id for j in jobs]
            assert RETENTION_JOB_ID in ids
            assert any(i.startswith(JOB_PREFIX) for i in ids)
            assert scheduler.running is True
        finally:
            await scheduler.stop()

    async def test_paused_schedule_is_not_registered(self, db):
        worker, _ = make_worker(db)
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        with db.session() as s:
            ScheduleRepository(s).upsert(tid, "service", 2)
        with db.session() as s:
            ScheduleRepository(s).set_enabled(tid, False)

        scheduler = make_scheduler(db, worker)
        await scheduler.start()
        try:
            scan_jobs = [
                j for j in scheduler.scheduler.get_jobs()
                if j.id.startswith(JOB_PREFIX)
            ]
            assert scan_jobs == []
        finally:
            await scheduler.stop()

    async def test_shutdown_leaves_no_pending_tasks(self, db):
        worker, _ = make_worker(db)
        scheduler = make_scheduler(db, worker)
        await scheduler.start()
        await scheduler.stop()

        assert scheduler.running is False
        remaining = [
            t for t in asyncio.all_tasks()
            if "scan-worker" in (t.get_name() or "")
        ]
        assert remaining == []

    async def test_stop_is_safe_when_never_started(self, db):
        worker, _ = make_worker(db)
        scheduler = make_scheduler(db, worker, enabled=False)
        await scheduler.stop()  # must not raise
        assert scheduler.running is False

    async def test_status_reports_schedules(self, db):
        worker, _ = make_worker(db)
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        with db.session() as s:
            ScheduleRepository(s).upsert(tid, "service", 3)

        scheduler = make_scheduler(db, worker)
        await scheduler.start()
        try:
            status = scheduler.status()
            assert status.running is True
            assert status.schedule_count == 1
            assert status.jobs_registered == 1
            assert status.next_run_at is not None
            assert "Scheduler: running" in status.text()
        finally:
            await scheduler.stop()

    async def test_scheduled_job_queues_a_scan(self, db):
        worker, runner = make_worker(db)
        runner.queue.append(xml_for(("10.0.0.1", [(22, "ssh")])))
        with db.session() as s:
            tid = TargetRepository(s).add("home", "10.0.0.0/24").id
        with db.session() as s:
            ScheduleRepository(s).upsert(tid, "quick", 1)

        scheduler = make_scheduler(db, worker)
        await scheduler.start()

        delivered = []

        async def handler(job, outcome, error):
            delivered.append((job, outcome, error))

        await worker.start(handler)
        try:
            job = ScanJob(
                job_id=await worker.next_job_id(),
                chat_id=0,
                target_name="home",
                target_value="10.0.0.0/24",
                profile=get_profile("quick"),
                source="scheduled",
            )
            await worker.submit(job)
            await asyncio.sleep(0.4)
        finally:
            await worker.stop()
            await scheduler.stop()

        assert len(delivered) == 1
        submitted, outcome, error = delivered[0]
        assert submitted.source == "scheduled"
        assert error is None
        assert outcome is not None and outcome.host_count == 1

    async def test_scheduled_alert_needs_operator_chat(self, db):
        worker, _ = make_worker(db)
        scheduler = make_scheduler(db, worker)
        sent = []

        async def sink(chat_id, text):
            sent.append((chat_id, text))

        await scheduler.start(sink)
        try:
            # no operator chat recorded yet
            assert await scheduler.send_scheduled_alert("hello") is False
            assert sent == []
        finally:
            await scheduler.stop()

    async def test_scheduled_alert_delivers_to_operator(self, db):
        worker, _ = make_worker(db)
        with db.session() as s:
            OperatorChatRepository(s).remember(4242, 42, "op")

        scheduler = make_scheduler(db, worker)
        sent = []

        async def sink(chat_id, text):
            sent.append((chat_id, text))

        await scheduler.start(sink)
        try:
            assert await scheduler.send_scheduled_alert("alert body") is True
            assert sent == [(4242, "alert body")]
        finally:
            await scheduler.stop()


@pytest.mark.asyncio
class TestSharedWorker:
    async def test_manual_and_scheduled_share_concurrency_cap(self, db):
        worker, runner = make_worker(db, concurrency=2)
        for _ in range(4):
            runner.queue.append(xml_for(("10.0.0.1", [(22, "ssh")])))

        results = []

        async def handler(job, outcome, error):
            results.append((job.source, error))

        await worker.start(handler)
        try:
            for source in ("manual", "scheduled", "manual", "scheduled"):
                await worker.submit(
                    ScanJob(
                        job_id=await worker.next_job_id(),
                        chat_id=1,
                        target_name="home",
                        target_value="10.0.0.0/24",
                        profile=get_profile("quick"),
                        source=source,
                    )
                )
            await asyncio.sleep(1.0)
        finally:
            await worker.stop()

        assert len(results) == 4
        assert {r[0] for r in results} == {"manual", "scheduled"}
        assert all(r[1] is None for r in results)
        assert worker.task_count == 0

    async def test_source_is_persisted_on_scan_row(self, db):
        worker, runner = make_worker(db)
        runner.queue.append(xml_for(("10.0.0.1", [(22, "ssh")])))

        async def handler(job, outcome, error):
            pass

        await worker.start(handler)
        try:
            await worker.submit(
                ScanJob(
                    job_id=await worker.next_job_id(),
                    chat_id=1,
                    target_name="home",
                    target_value="10.0.0.0/24",
                    profile=get_profile("quick"),
                    source="scheduled",
                )
            )
            await asyncio.sleep(0.4)
        finally:
            await worker.stop()

        with db.session() as s:
            scan = s.query(Scan).order_by(Scan.id.desc()).first()
            assert scan.source == "scheduled"


class TestChangeDetectionIntegration:
    """Scan -> change -> persisted event -> alert text."""

    def test_second_scan_persists_change_events_and_renders_alert(self, db):
        from bot.messages import reports
        from core.scan_manager import ScanManager

        runner = StubRunner()
        runner.queue.append(xml_for(("10.0.0.1", [(80, "http")])))
        runner.queue.append(
            xml_for(("10.0.0.1", [(80, "nginx")]), ("10.0.0.2", [(22, "ssh")]))
        )
        manager = ScanManager(db, runner)
        profile = get_profile("service")

        first = manager.execute("10.0.0.0/24", profile)
        assert first.is_first_scan is True

        second = manager.execute("10.0.0.0/24", profile)
        assert second.is_first_scan is False
        assert second.baseline_scan_id == first.scan_id

        types = {c.change_type for c in second.changes}
        assert NEW_HOST in types
        assert SERVICE_CHANGE in types

        with db.session() as s:
            stored = ChangeRepository(s).for_scan(second.scan_id)
        assert len(stored) == len(second.changes)

        alert = reports.scheduled_alert(second)
        assert "NETWORK CHANGES DETECTED" in alert
        assert "New host: 10.0.0.2" in alert
        assert "Summary:" in alert

    def test_unchanged_network_produces_quiet_alert(self, db):
        from bot.messages import reports
        from core.scan_manager import ScanManager

        runner = StubRunner()
        runner.queue.append(xml_for(("10.0.0.1", [(22, "ssh")])))
        runner.queue.append(xml_for(("10.0.0.1", [(22, "ssh")])))
        manager = ScanManager(db, runner)

        manager.execute("10.0.0.0/24", get_profile("service"))
        second = manager.execute("10.0.0.0/24", get_profile("service"))

        assert second.changes == []
        alert = reports.scheduled_alert(second)
        assert "no changes" in alert
        assert "NETWORK CHANGES" not in alert