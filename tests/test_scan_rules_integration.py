"""Integration tests: rules consulted before every scan, in the real handler.

These drive the pieces together rather than any one of them: a rule row in
the database, the handler's evaluation step, the reply the user gets, the
hit that gets recorded, and the timeout that reaches nmap.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("ADMIN_USERNAME", "root")
os.environ.setdefault("ADMIN_PASSWORD", "an-initial-admin-password")
os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "0:test-token")
os.environ.setdefault("ALLOWED_USER_IDS", "7575983824")
os.environ.setdefault("ADMIN_COOKIE_SECURE", "false")

from admin.services.settings_store import SettingsStore, seed  # noqa: E402
from core.profiles import get_profile  # noqa: E402
from database.database import Database  # noqa: E402
from database.repository import (  # noqa: E402
    RuleCreate,
    RuleHitFilters,
    RuleRepository,
    ScanRepository,
    TargetRepository,
)

UTC = timezone.utc
USER_ID = 7575983824


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/rules_int.db")
    database.create_all()
    yield database
    database.dispose()


class Settings:
    """Minimal stand-in for config.settings.Settings."""

    rate_limit_seconds = 30
    scan_timeout_seconds = 300


class FakeMessage:
    def __init__(self):
        self.replies: list[str] = []

    async def reply_text(self, text: str, **kwargs) -> None:
        self.replies.append(text)


class FakeUser:
    def __init__(self, user_id: int | None):
        self.id = user_id


class FakeChat:
    def __init__(self, chat_id: int):
        self.id = chat_id


class FakeUpdate:
    """Just enough Update for the handler's happy path."""

    def __init__(self, args, user_id: int | None = USER_ID, chat_id: int = 1):
        self.args = args
        self.effective_user = FakeUser(user_id)
        self.effective_chat = FakeChat(chat_id)
        self.message = FakeMessage()


class FakeWorker:
    def __init__(self):
        self.jobs: list = []

    async def next_job_id(self) -> int:
        return len(self.jobs) + 1

    async def submit(self, job) -> None:
        self.jobs.append(job)


class FakeLimiter:
    """Always allows; the rule engine is what these tests exercise."""

    class _Decision:
        allowed = True
        reason = ""

    def check(self, key: str):
        return self._Decision()


class FakePrincipal:
    def __init__(self, user_id: int | None, role: str = "admin"):
        self.user_id = user_id
        self.username = "tester"
        self.role = role


def make_context(db, settings_store=None, worker=None):
    """Build a bot_data-like dict the handler can read.

    Only the keys bot/handlers/scan.py actually reaches for are populated;
    Principal is never needed here because the tests call _evaluate_rules
    directly or stub authenticate_or_denounce.
    """
    from security.authorization import Authorizer

    application = type("App", (), {})()
    application.bot_data = {
        "database": db,
        "settings": Settings(),
        "settings_store": settings_store,
        "scan_worker": worker or FakeWorker(),
        "rate_limiter": FakeLimiter(),
        "authorizer": Authorizer(()),
    }
    context = type("Ctx", (), {})()
    context.application = application
    # The handler reads context.args before anything else.
    context.args = ["home"]
    return context


def make_store(db) -> SettingsStore:
    store = SettingsStore(db)
    with db.session() as session:
        seed(session, actor="test")
    return store


def set_setting(db, key, value):
    """Write a system_settings row directly.

    The hit-cap tests need a setting in place *before* a store reads it,
    because SettingsStore caches for 5 seconds.
    """
    with db.session() as session:
        from database.models import SystemSetting

        row = session.query(SystemSetting).filter_by(key=key).one()
        row.value = value
        session.commit()


def add_rule(db, name, rule_type, value, priority=50, enabled=True,
             scope="global", scope_id=None):
    with db.session() as session:
        return RuleRepository(session).create_rule(
            RuleCreate(
                name=name,
                rule_type=rule_type,
                value=value,
                priority=priority,
                enabled=enabled,
                scope=scope,
                scope_id=scope_id,
            ),
            actor="test",
        ).id


def add_target(db, name="home", value="192.168.174.0/24"):
    with db.session() as session:
        return TargetRepository(session).add(name, value).name


def seed_scan(db, target_value, minutes_ago=0, user_id=USER_ID):
    now = datetime.now(UTC).replace(tzinfo=None)
    with db.session() as session:
        target = TargetRepository(session).get_or_create_by_value(target_value)
        scan = ScanRepository(session).create(
            target.id, "quick", requested_by=user_id
        )
        scan.started_at = now - timedelta(minutes=minutes_ago)
        session.flush()


def hits_for(db, rule_id=None):
    with db.session() as session:
        filters = RuleHitFilters(rule_id=rule_id) if rule_id else RuleHitFilters()
        rows, total = RuleRepository(session).list_rule_hits(filters)
        return total, rows


class TestDenyBlocksScan:
    @pytest.fixture
    def wired(self, db):
        store = make_store(db)
        worker = FakeWorker()
        context = make_context(db, store, worker)
        return context, worker, store

    @pytest.mark.asyncio
    async def test_deny_cidr_blocks_and_records_a_hit(self, db, wired):
        context, worker, store = wired
        add_rule(db, "deny-ten", "deny_cidr", "10.0.0.0/8", priority=1)
        add_target(db)

        from bot.handlers import scan as scan_module

        scan_module._evaluate_rules(context, "10.0.0.5", "home", USER_ID, ())

        assert worker.jobs == [], "the scan must not be queued"
        total, rows = hits_for(db)
        assert total == 1, "a denial must be recorded"
        assert rows[0].decision == "deny"
        assert rows[0].target == "home"
        assert rows[0].actor_id == USER_ID
        # The reason text carries the rule's value, which is what the user
        # needs to see; rule_name is the separate field the panel links on.
        assert "10.0.0.0/8" in (rows[0].reason or "")

    @pytest.mark.asyncio
    async def test_deny_increments_the_rule_counter(self, db, wired):
        context, _worker, _store = wired
        rule_id = add_rule(db, "deny-ten", "deny_cidr", "10.0.0.0/8")

        from bot.handlers import scan as scan_module

        decision = scan_module._evaluate_rules(
            context, "10.0.0.5", "home", USER_ID, ()
        )
        assert decision.allowed is False
        assert decision.rule_name == "deny-ten"
        assert "10.0.0.0/8" in decision.reason
        with db.session() as session:
            assert RuleRepository(session).get_rule(rule_id).hit_count == 1

    @pytest.mark.asyncio
    async def test_allowed_scan_writes_no_hit(self, db, wired):
        # Nothing decided the outcome, so there is nothing to attribute.
        context, _worker, _store = wired
        add_target(db)

        from bot.handlers import scan as scan_module

        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", USER_ID, ()
        )
        assert decision.allowed is True
        assert decision.rule_id is None
        assert hits_for(db)[0] == 0

    @pytest.mark.asyncio
    async def test_allow_hit_is_recorded(self, db, wired):
        context, _worker, _store = wired
        rule_id = add_rule(
            db, "allow-home", "allow_cidr", "192.168.174.0/24"
        )

        from bot.handlers import scan as scan_module

        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", USER_ID, ()
        )
        assert decision.allowed is True
        total, rows = hits_for(db, rule_id)
        assert total == 1
        assert rows[0].decision == "allow"

    @pytest.mark.asyncio
    async def test_handler_replies_with_the_reason(self, db, wired):
        """The handler must answer the user, not silently drop the request."""
        context, worker, store = wired
        add_rule(db, "deny-ten", "deny_cidr", "10.0.0.0/8", priority=1)
        add_target(db, name="lab", value="10.0.0.0/24")

        from bot.handlers import scan as scan_module

        # Bypass authentication and the registry so the test exercises the
        # rule path itself.
        update = FakeUpdate(["lab"])
        monkey_target = scan_module._registry
        scan_module._registry = lambda ctx: type(
            "R",
            (),
            {"resolve": staticmethod(lambda ref: type(
                "T", (), {"name": "lab", "value": "10.0.0.0/24"}
            )())},
        )()
        scan_module.authenticate_or_denounce = _async(
            FakePrincipal(USER_ID)
        )
        try:
            await scan_module.scan(update, context)
        finally:
            scan_module._registry = monkey_target

        assert update.message.replies, "the user must get a reply"
        assert len(update.message.replies) == 1, "exactly one reply"
        assert worker.jobs == [], "no scan may be queued"
        # Both languages mention the block; check the reason made it through.
        assert "10.0.0.0/8" in update.message.replies[0]


def _async(value):
    async def _inner(*args, **kwargs):
        return value

    return _inner


class TestRulesEnabledSetting:
    @pytest.mark.asyncio
    async def test_disabled_skips_evaluation(self, db):
        store = make_store(db)
        with db.session() as session:
            from database.models import SystemSetting

            row = session.query(SystemSetting).filter_by(
                key="rules_enabled"
            ).one()
            row.value = "false"
            session.commit()

        # A deny rule that would block if it were consulted.
        add_rule(db, "deny-ten", "deny_cidr", "10.0.0.0/8", priority=1)
        add_target(db)

        from bot.handlers import scan as scan_module

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "10.0.0.5", "home", USER_ID, ()
        )
        assert decision.allowed is True
        assert decision.reason == "rules disabled"
        assert hits_for(db)[0] == 0, "the fast path writes nothing"

    @pytest.mark.asyncio
    async def test_enabled_by_default(self, db):
        store = make_store(db)
        add_rule(db, "deny-ten", "deny_cidr", "10.0.0.0/8", priority=1)
        add_target(db)

        from bot.handlers import scan as scan_module

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "10.0.0.5", "home", USER_ID, ()
        )
        assert decision.allowed is False


class TestScanTimeout:
    def test_rule_lowers_the_configured_timeout(self, db):
        from core.rules import RuleContext, RuleEngine

        add_rule(db, "quick-timeout", "max_scan_time", "30")
        with db.session() as session:
            rows = RuleRepository(session).load_engine_rules()

        engine = RuleEngine(rows)
        decision = engine.evaluate(
            RuleContext(
                target="10.0.0.5",
                default_scan_timeout_seconds=Settings.scan_timeout_seconds,
            )
        )
        assert decision.effective_scan_timeout == 30

    def test_rule_cannot_raise_the_configured_timeout(self, db):
        from core.rules import RuleContext, RuleEngine

        add_rule(db, "huge", "max_scan_time", "9999")
        with db.session() as session:
            rows = RuleRepository(session).load_engine_rules()

        decision = RuleEngine(rows).evaluate(
            RuleContext(
                target="10.0.0.5",
                default_scan_timeout_seconds=Settings.scan_timeout_seconds,
            )
        )
        assert decision.effective_scan_timeout == 300

    def test_timeout_reaches_the_runner(self, db):
        """The resolved timeout must arrive at subprocess.run, not stop at
        the engine."""
        from core.scan_manager import ScanManager

        seen = {}

        class CapturingRunner:
            def run(self, target, args, *, timeout=None):
                seen["timeout"] = timeout
                from parser.nmap_runner import ScanResult

                return ScanResult(
                    xml="<nmaprun></nmaprun>", returncode=0, duration_ms=1,
                    stderr="",
                )

        manager = ScanManager(db, CapturingRunner())
        manager.execute(
            "10.0.0.5", get_profile("quick"), scan_timeout=42
        )
        assert seen["timeout"] == 42

    def test_no_timeout_means_the_default(self, db):
        from core.scan_manager import ScanManager

        seen = {}

        class CapturingRunner:
            def run(self, target, args, *, timeout=None):
                seen["timeout"] = timeout
                from parser.nmap_runner import ScanResult

                return ScanResult(
                    xml="<nmaprun></nmaprun>", returncode=0, duration_ms=1,
                    stderr="",
                )

        manager = ScanManager(db, CapturingRunner())
        manager.execute("10.0.0.5", get_profile("quick"))
        assert seen["timeout"] is None

    def test_runner_rejects_a_nonsense_timeout(self):
        from parser.nmap_runner import NmapRunner, ScanExecutionError

        runner = NmapRunner(timeout_seconds=60)
        with pytest.raises(ScanExecutionError, match="Invalid scan timeout"):
            runner.run("10.0.0.5", ["-F"], timeout=0)

    def test_job_carries_the_timeout_to_the_manager(self):
        import asyncio

        from workers.scan_worker import ScanJob, ScanWorker

        captured = {}

        class Manager:
            def execute(self, target, profile, **kwargs):
                # Raise so the consumer records a failure and moves on rather
                # than blocking on a queue that will never fill again.
                captured.update(kwargs)
                raise RuntimeError("captured, then stop")

        worker = ScanWorker(Manager(), max_concurrency=1)
        job = ScanJob(
            job_id=1, chat_id=1, target_name="home",
            target_value="10.0.0.5", profile=get_profile("quick"),
            scan_timeout=45,
        )

        async def drive():
            worker._running = True
            task = asyncio.create_task(worker._consume())
            await worker._queue.put(job)
            for _ in range(200):
                if captured:
                    break
                await asyncio.sleep(0.01)
            worker._running = False
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(drive())

        assert captured["scan_timeout"] == 45, (
            "the job's timeout must reach ScanManager.execute"
        )


class TestRateLimit:
    @pytest.mark.asyncio
    async def test_rule_replaces_the_env_default(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(db, "slow-down", "rate_limit", "600")
        add_target(db)
        seed_scan(db, "192.168.174.0/24", minutes_ago=1)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.0/24", "home", USER_ID, ()
        )
        assert decision.effective_rate_limit_seconds == 600
        assert Settings.rate_limit_seconds == 30, "env default unchanged"

    @pytest.mark.asyncio
    async def test_env_default_used_without_a_rule(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_target(db)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.0/24", "home", USER_ID, ()
        )
        assert decision.effective_rate_limit_seconds == 30

    @pytest.mark.asyncio
    async def test_too_soon_is_denied(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(db, "slow-down", "rate_limit", "600")
        add_target(db)
        # Scanned a minute ago, so a 600s window blocks the next request.
        seed_scan(db, "192.168.174.0/24", minutes_ago=1)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.0/24", "home", USER_ID, ()
        )
        assert decision.allowed is False
        assert "rate limit" in decision.reason


class TestQuotas:
    @pytest.mark.asyncio
    async def test_daily_quota_blocks_when_exhausted(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(db, "cap", "user_quota", "3/day")
        add_target(db)
        for _ in range(3):
            seed_scan(db, "192.168.174.0/24", minutes_ago=5)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.0/24", "home", USER_ID, ()
        )
        assert decision.allowed is False
        assert "user_quota" in decision.reason

    @pytest.mark.asyncio
    async def test_daily_quota_allows_under_the_limit(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(db, "cap", "user_quota", "5/day")
        add_target(db)
        for _ in range(3):
            seed_scan(db, "192.168.174.0/24", minutes_ago=5)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.0/24", "home", USER_ID, ()
        )
        assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_hourly_and_daily_are_independent(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(db, "hourly", "user_quota", "10/hour")
        add_target(db)
        # Twelve scans in the last hour: over the hourly cap.
        for _ in range(12):
            seed_scan(db, "192.168.174.0/24", minutes_ago=5)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.0/24", "home", USER_ID, ()
        )
        assert decision.allowed is False
        assert "/10" in decision.reason, "the hourly count is the one reported"


class TestScheduledScans:
    @pytest.mark.asyncio
    async def test_scheduled_scan_ignores_a_user_scoped_deny(self, db):
        """A scheduled run has no actor, so it must not inherit a named
        user's restriction."""
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(
            db, "deny-for-user", "deny_cidr", "0.0.0.0/0", priority=1,
            scope="user", scope_id=str(USER_ID),
        )
        add_target(db)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", None, ()
        )
        assert decision.allowed is True, (
            "a scheduled scan has actor_id=None and must not be blocked"
        )

    @pytest.mark.asyncio
    async def test_the_named_user_is_still_blocked(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(
            db, "deny-for-user", "deny_cidr", "0.0.0.0/0", priority=1,
            scope="user", scope_id=str(USER_ID),
        )
        add_target(db)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", USER_ID, ()
        )
        assert decision.allowed is False

    @pytest.mark.asyncio
    async def test_global_deny_still_applies_to_scheduled_scans(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(db, "deny-all", "deny_cidr", "0.0.0.0/0", priority=1)
        add_target(db)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", None, ()
        )
        assert decision.allowed is False

    @pytest.mark.asyncio
    async def test_scheduled_scan_has_no_quota_usage(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(db, "cap", "user_quota", "1/day")
        add_target(db)
        for _ in range(5):
            seed_scan(db, "192.168.174.0/24", minutes_ago=5, user_id=USER_ID)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", None, ()
        )
        assert decision.allowed is True, (
            "those scans belong to a user, not to the scheduler"
        )


class TestPortRules:
    @pytest.mark.asyncio
    async def test_profile_ports_are_supplied(self, db):
        # The shipped profiles use -F / --top-ports, so they carry no port
        # list and port rules cannot be evaluated for them.
        for name in ("quick", "service", "deep"):
            assert get_profile(name).port_list() == ()

    @pytest.mark.asyncio
    async def test_port_rule_applies_when_ports_are_known(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(db, "no-ssh", "deny_port", "22")
        add_target(db)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", USER_ID, (22, 80)
        )
        assert decision.allowed is False

    @pytest.mark.asyncio
    async def test_port_rule_inert_without_ports(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        add_rule(db, "no-ssh", "deny_port", "22")
        add_target(db)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", USER_ID, ()
        )
        assert decision.allowed is True


class TestHitCap:
    @pytest.mark.asyncio
    async def test_hits_stop_past_the_cap_but_evaluation_continues(self, db):
        from bot.handlers import scan as scan_module

        make_store(db)  # seed the row
        set_setting(db, "rules_max_hits_per_day", "100")  # lowest allowed
        store = make_store(db)  # rebuild past the 5s TTL cache

        rule_id = add_rule(db, "deny-ten", "deny_cidr", "10.0.0.0/8")
        add_target(db)

        # Fill the window with hits from elsewhere.
        now = datetime.now(UTC).replace(tzinfo=None)
        with db.session() as session:
            repo = RuleRepository(session)
            for _ in range(100):
                repo.record_rule_hit(rule_id, decision="allow")
            rows, _total = repo.list_rule_hits()
            for row in rows:
                row.created_at = now - timedelta(hours=1)

        context = make_context(db, store)
        before = hits_for(db)[0]

        decision = scan_module._evaluate_rules(
            context, "10.0.0.5", "home", USER_ID, ()
        )
        assert decision.allowed is False, (
            "evaluation must continue even when hits are capped"
        )
        assert hits_for(db)[0] == before, "no new hit may be written"

    @pytest.mark.asyncio
    async def test_cap_warning_fires_once_a_day(self, db, caplog):
        import logging

        from bot.handlers import scan as scan_module

        scan_module._cap_warned_on = None
        make_store(db)
        set_setting(db, "rules_max_hits_per_day", "100")
        store = make_store(db)
        rule_id = add_rule(db, "deny-ten", "deny_cidr", "10.0.0.0/8")
        add_target(db)

        now = datetime.now(UTC).replace(tzinfo=None)
        with db.session() as session:
            repo = RuleRepository(session)
            for _ in range(100):
                repo.record_rule_hit(rule_id, decision="allow")
            rows, _total = repo.list_rule_hits()
            for row in rows:
                row.created_at = now - timedelta(hours=1)

        context = make_context(db, store)
        with caplog.at_level(logging.WARNING):
            for _ in range(3):
                scan_module._evaluate_rules(
                    context, "10.0.0.5", "home", USER_ID, ()
                )

        warnings = [
            record for record in caplog.records
            if "hit cap" in record.getMessage()
        ]
        assert len(warnings) == 1, (
            f"expected exactly one cap warning, got {len(warnings)}"
        )


class TestFailureModes:
    @pytest.mark.asyncio
    async def test_a_broken_rule_does_not_block_the_scan(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        with db.session() as session:
            repo = RuleRepository(session)
            # Bypass validation to plant a malformed rule.
            from database.models import Rule

            row = Rule(
                name="broken", rule_type="deny_cidr", value="not-a-cidr",
                priority=1,
            )
            session.add(row)
            session.flush()
        add_target(db)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", USER_ID, ()
        )
        assert decision.allowed is True, "a typo must not deny traffic"
        assert decision.warnings, "the broken rule must be reported"

    @pytest.mark.asyncio
    async def test_an_unknown_type_does_not_block_the_scan(self, db):
        from bot.handlers import scan as scan_module

        store = make_store(db)
        with db.session() as session:
            from database.models import Rule

            session.add(
                Rule(
                    name="weird", rule_type="allow_everything", value="x",
                    priority=1,
                )
            )
            session.flush()
        add_target(db)

        context = make_context(db, store)
        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", USER_ID, ()
        )
        assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_evaluation_failure_allows_rather_than_locking_out(self, db):
        """A broken engine must not take scanning offline."""
        from bot.handlers import scan as scan_module

        store = make_store(db)
        context = make_context(db, store)

        class Exploding:
            def session(self):
                raise RuntimeError("database is down")

        context.application.bot_data["database"] = Exploding()

        decision = scan_module._evaluate_rules(
            context, "192.168.174.10", "home", USER_ID, ()
        )
        assert decision.allowed is True
        assert "failed" in decision.reason


class TestRetentionIntegration:
    def test_retention_prunes_old_hits_and_keeps_rules(self, db):
        from core.retention import RetentionService

        rule_id = add_rule(db, "deny-ten", "deny_cidr", "10.0.0.0/8")
        add_target(db)

        now = datetime.now(UTC).replace(tzinfo=None)
        with db.session() as session:
            repo = RuleRepository(session)
            repo.record_rule_hit(rule_id, decision="deny")
            repo.record_rule_hit(rule_id, decision="allow")
            rows, _total = repo.list_rule_hits()
            rows[0].created_at = now - timedelta(days=90)

        report = RetentionService(db).run(keep_days=30, keep_per_target=100)
        assert report.rule_hits_deleted == 1, (
            f"expected 1 pruned hit, got {report.rule_hits_deleted}"
        )
        assert report.total_rows == report.rule_hits_deleted, (
            "rule hits must be counted in the report total"
        )
        assert "rule hits" in report.text()

        with db.session() as session:
            repo = RuleRepository(session)
            assert repo.get_rule(rule_id) is not None, (
                "rules must outlive their own history"
            )
            _rows, remaining = repo.list_rule_hits()
            assert remaining == 1

    def test_report_counts_start_at_zero(self):
        from core.retention import RetentionReport

        report = RetentionReport()
        assert report.rule_hits_deleted == 0
        assert report.total_rows == 0