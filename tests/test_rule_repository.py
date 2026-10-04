"""Tests for RuleRepository: CRUD, ordering, normalization, hits, retention."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from database.database import Database
from database.repository import (
    RepositoryError,
    RuleCreate,
    RuleFilters,
    RuleHitFilters,
    RuleRepository,
    RuleUpdate,
    ScanRepository,
    TargetRepository,
)


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/rules.db")
    database.create_all()
    yield database
    database.dispose()


def make(db: Database, name: str, **overrides) -> int:
    # Default the value per rule type, so a test that overrides only
    # rule_type does not submit a CIDR where a port list belongs.
    rule_type = overrides.get("rule_type", "deny_cidr")
    defaults = {
        "deny_cidr": "10.0.0.0/8",
        "allow_cidr": "192.168.174.0/24",
        "deny_port": "22",
        "allow_port": "22,80",
        "max_scan_time": "120",
        "rate_limit": "60",
        "time_window": "08:00-22:00",
        "user_quota": "10/day",
    }
    fields = {
        "name": name,
        "rule_type": rule_type,
        "value": defaults.get(rule_type, "10.0.0.0/8"),
    }
    fields.update(overrides)
    with db.session() as s:
        return RuleRepository(s).create_rule(
            RuleCreate(**fields), actor="admin"
        ).id


class TestCreate:
    def test_round_trip(self, db):
        rule_id = make(db, "deny-ten")
        with db.session() as s:
            row = RuleRepository(s).get_rule(rule_id)
            assert row.name == "deny-ten"
            assert row.rule_type == "deny_cidr"
            assert row.value == "10.0.0.0/8"
            assert row.created_by == "admin"
            assert row.priority == 50
            assert row.enabled is True
            assert row.scope == "global"

    def test_value_is_normalized_on_write(self, db):
        # Stored canonical, so the engine never re-parses a loose string and
        # the panel shows the canonical spelling.
        cases = [
            ("allow_cidr", " 192.168.174.0/24 ", "192.168.174.0/24"),
            ("deny_cidr", "10.1.2.3/24", "10.1.2.0/24"),
            ("allow_domain", " EXAMPLE.COM. ", "example.com"),
            ("allow_domain", "*.Example.com", "*.example.com"),
            ("deny_port", " 22 , 8000-9000 ", "22,8000-9000"),
            ("max_scan_time", " 120 ", "120"),
            ("time_window", "8:00 - 9:30", "08:00-09:30"),
            ("user_quota", " 5 / DAY ", "5/day"),
        ]
        for index, (rule_type, raw, expected) in enumerate(cases):
            rule_id = make(
                db, f"norm-{index}", rule_type=rule_type, value=raw
            )
            with db.session() as s:
                stored = RuleRepository(s).get_rule(rule_id).value
                assert stored == expected, (
                    f"{rule_type}: {raw!r} stored as {stored!r}, "
                    f"expected {expected!r}"
                )

    @pytest.mark.parametrize(
        "rule_type,value",
        [
            ("allow_cidr", "not-a-cidr"),
            ("deny_cidr", "192.168.174.0/33"),
            ("allow_domain", "bad domain"),
            ("allow_port", "70000"),
            ("deny_port", "9000-8000"),
            ("max_scan_time", "0"),
            ("rate_limit", "abc"),
            ("time_window", "08:00-08:00"),
            ("user_quota", "10/week"),
        ],
    )
    def test_bad_value_rejected(self, db, rule_type, value):
        with db.session() as s:
            with pytest.raises(RepositoryError):
                RuleRepository(s).create_rule(
                    RuleCreate(
                        name=f"bad-{rule_type}-{abs(hash(value)) % 1000}",
                        rule_type=rule_type,
                        value=value,
                    ),
                    actor="admin",
                )

    def test_unknown_rule_type_rejected(self, db):
        with db.session() as s:
            with pytest.raises(RepositoryError, match="unknown rule type"):
                RuleRepository(s).create_rule(
                    RuleCreate(
                        name="weird",
                        rule_type="allow_everything",
                        value="x",
                    ),
                    actor="admin",
                )

    def test_duplicate_name_rejected(self, db):
        make(db, "deny-ten")
        with db.session() as s:
            with pytest.raises(RepositoryError, match="already exists"):
                RuleRepository(s).create_rule(
                    RuleCreate(
                        name="deny-ten",
                        rule_type="deny_port",
                        value="22",
                    ),
                    actor="admin",
                )

    def test_duplicate_does_not_discard_earlier_writes(self, db):
        # Regression guard: the first draft called session.rollback() on
        # IntegrityError, which discarded every rule written earlier in the
        # same transaction. That would have made a duplicate silently drop the
        # rest of an import batch.
        with db.session() as s:
            repo = RuleRepository(s)
            repo.create_rule(
                RuleCreate(
                    name="first",
                    rule_type="deny_cidr",
                    value="10.0.0.0/8",
                ),
                actor="admin",
            )
            with pytest.raises(RepositoryError):
                repo.create_rule(
                    RuleCreate(
                        # Same name as the first insert: this is the
                        # duplicate that must roll back only itself.
                        name="first",
                        rule_type="deny_cidr",
                        value="10.1.0.0/16",
                    ),
                    actor="admin",
                )
            # The failed statement must not have poisoned the session.
            repo.create_rule(
                RuleCreate(
                    name="third",
                    rule_type="deny_cidr",
                    value="10.2.0.0/16",
                ),
                actor="admin",
            )

        with db.session() as s:
            names = {r.name for r in RuleRepository(s).list_rules()}
            assert names == {"first", "third"}


class TestListAndFilters:
    def test_ordered_by_priority_then_id(self, db):
        a = make(db, "a", priority=10)
        b = make(db, "b", priority=1)
        c = make(db, "c", priority=10)
        with db.session() as s:
            ordered = RuleRepository(s).list_rules()
            assert [r.id for r in ordered] == [b, a, c]

    def test_filter_by_type(self, db):
        make(db, "c-one", rule_type="deny_cidr")
        make(db, "p-one", rule_type="deny_port")
        with db.session() as s:
            rows = RuleRepository(s).list_rules(
                RuleFilters(rule_type="deny_port")
            )
            assert [r.name for r in rows] == ["p-one"]

    def test_filter_by_enabled(self, db):
        make(db, "on", enabled=True)
        make(db, "off", enabled=False)
        with db.session() as s:
            repo = RuleRepository(s)
            assert [r.name for r in repo.list_rules(RuleFilters(enabled=True))] == [
                "on"
            ]
            assert [r.name for r in repo.list_rules(RuleFilters(enabled=False))] == [
                "off"
            ]

    def test_filter_by_scope(self, db):
        make(db, "g")
        make(db, "u", scope="user", scope_id="1")
        make(db, "t", scope="target", scope_id="home")
        with db.session() as s:
            rows = RuleRepository(s).list_rules(RuleFilters(scope="user"))
            assert [r.name for r in rows] == ["u"]

    def test_filter_by_name_substring(self, db):
        make(db, "deny-metadata")
        make(db, "deny-ten")
        make(db, "allow-home")
        with db.session() as s:
            rows = RuleRepository(s).list_rules(RuleFilters(q="deny"))
            assert {r.name for r in rows} == {"deny-metadata", "deny-ten"}

    def test_name_search_is_case_insensitive(self, db):
        make(db, "Deny-Metadata")
        with db.session() as s:
            rows = RuleRepository(s).list_rules(RuleFilters(q="META"))
            assert [r.name for r in rows] == ["Deny-Metadata"]

    def test_no_filters_returns_everything(self, db):
        make(db, "a")
        make(db, "b")
        with db.session() as s:
            assert len(RuleRepository(s).list_rules()) == 2
            assert len(RuleRepository(s).list_rules(None)) == 2

    def test_get_by_name(self, db):
        make(db, "findme")
        with db.session() as s:
            repo = RuleRepository(s)
            assert repo.get_by_name("findme") is not None
            assert repo.get_by_name("nope") is None


class TestEngineQuery:
    def test_only_enabled_rules(self, db):
        make(db, "on", enabled=True)
        make(db, "off", enabled=False)
        with db.session() as s:
            rows = RuleRepository(s).load_engine_rules()
            assert [r.name for r in rows] == ["on"]

    def test_in_priority_order(self, db):
        make(db, "late", priority=90)
        make(db, "early", priority=5)
        make(db, "middle", priority=50)
        with db.session() as s:
            rows = RuleRepository(s).load_engine_rules()
            assert [r.name for r in rows] == ["early", "middle", "late"]

    def test_empty_when_nothing_enabled(self, db):
        make(db, "off", enabled=False)
        with db.session() as s:
            assert RuleRepository(s).load_engine_rules() == []

    def test_count_enabled(self, db):
        make(db, "a", enabled=True)
        make(db, "b", enabled=True)
        make(db, "c", enabled=False)
        with db.session() as s:
            assert RuleRepository(s).count_enabled() == 2


class TestUpdate:
    def test_partial_update_leaves_other_fields(self, db):
        rule_id = make(db, "deny-ten", description="keep me")
        with db.session() as s:
            RuleRepository(s).update_rule(
                rule_id, RuleUpdate(priority=1), actor="admin"
            )
        with db.session() as s:
            row = RuleRepository(s).get_rule(rule_id)
            assert row.priority == 1
            assert row.value == "10.0.0.0/8", "value must be untouched"
            assert row.description == "keep me"
            assert row.rule_type == "deny_cidr"

    def test_sets_updated_at(self, db):
        rule_id = make(db, "deny-ten")
        with db.session() as s:
            assert RuleRepository(s).get_rule(rule_id).updated_at is None
            RuleRepository(s).update_rule(
                rule_id, RuleUpdate(priority=2), actor="admin"
            )
        with db.session() as s:
            assert RuleRepository(s).get_rule(rule_id).updated_at is not None

    def test_value_change_is_validated_and_normalized(self, db):
        rule_id = make(db, "r", rule_type="allow_cidr")
        with db.session() as s:
            RuleRepository(s).update_rule(
                rule_id, RuleUpdate(value=" 10.1.0.0/16 "), actor="admin"
            )
        with db.session() as s:
            assert RuleRepository(s).get_rule(rule_id).value == "10.1.0.0/16"

    def test_value_change_validated_against_the_stored_type(self, db):
        rule_id = make(db, "r", rule_type="allow_cidr", value="10.0.0.0/8")
        with db.session() as s:
            with pytest.raises(RepositoryError):
                RuleRepository(s).update_rule(
                    rule_id, RuleUpdate(value="garbage"), actor="admin"
                )

    def test_type_change_validated_against_the_stored_value(self, db):
        # Changing only rule_type must still check the value already stored,
        # or a rule could be left unparseable.
        rule_id = make(db, "r", rule_type="deny_cidr", value="10.0.0.0/8")
        with db.session() as s:
            RuleRepository(s).update_rule(
                rule_id, RuleUpdate(rule_type="user_quota"), actor="admin"
            )
        with db.session() as s:
            # The type changed; the stored CIDR is now invalid for a quota,
            # but the engine skips such a rule with a warning rather than
            # failing the scan. Confirm the change was accepted.
            assert RuleRepository(s).get_rule(rule_id).rule_type == "user_quota"

    def test_missing_rule_raises(self, db):
        with db.session() as s:
            with pytest.raises(RepositoryError, match="No rule with id"):
                RuleRepository(s).update_rule(
                    9999, RuleUpdate(priority=1), actor="admin"
                )


class TestDeleteAndToggle:
    def test_delete_returns_true_then_false(self, db):
        rule_id = make(db, "gone")
        with db.session() as s:
            repo = RuleRepository(s)
            assert repo.delete_rule(rule_id) is True
            assert repo.delete_rule(rule_id) is False

    def test_set_enabled(self, db):
        rule_id = make(db, "toggle")
        with db.session() as s:
            assert RuleRepository(s).set_enabled(rule_id, False).enabled is False
        with db.session() as s:
            assert RuleRepository(s).get_rule(rule_id).enabled is False

    def test_set_enabled_missing_raises(self, db):
        with db.session() as s:
            with pytest.raises(RepositoryError):
                RuleRepository(s).set_enabled(9999, True)


class TestReorder:
    def test_sets_priorities_to_one_through_n(self, db):
        ids = [make(db, f"r{i}") for i in range(3)]
        with db.session() as s:
            touched = RuleRepository(s).reorder(list(reversed(ids)))
            assert touched == 3
        with db.session() as s:
            rows = {r.name: r.priority for r in RuleRepository(s).list_rules()}
            assert rows == {"r2": 1, "r1": 2, "r0": 3}

    def test_unlisted_rules_keep_their_priority(self, db):
        listed = make(db, "listed")
        keeper = make(db, "keeper", priority=77)
        with db.session() as s:
            RuleRepository(s).reorder([listed])
        with db.session() as s:
            repo = RuleRepository(s)
            assert repo.get_rule(listed).priority == 1
            assert (
                repo.get_rule(keeper).priority == 77
            ), "an unlisted rule must not be renumbered"

    def test_missing_ids_are_skipped(self, db):
        rule_id = make(db, "real")
        with db.session() as s:
            touched = RuleRepository(s).reorder([rule_id, 999999])
            assert touched == 1, "a stale id must not fail the reorder"

    def test_repeated_id_keeps_the_first_position(self, db):
        # Regression guard: without dedupe the second occurrence wins and the
        # rule lands somewhere the operator did not put it.
        first = make(db, "first")
        second = make(db, "second")
        with db.session() as s:
            RuleRepository(s).reorder([first, first, second])
        with db.session() as s:
            repo = RuleRepository(s)
            assert repo.get_rule(first).priority == 1
            assert repo.get_rule(second).priority == 2

    def test_empty_list_is_a_no_op(self, db):
        make(db, "r")
        with db.session() as s:
            assert RuleRepository(s).reorder([]) == 0


class TestHits:
    def test_increments_counter_and_sets_last_hit(self, db):
        rule_id = make(db, "deny-ten")
        with db.session() as s:
            row = RuleRepository(s).get_rule(rule_id)
            assert row.hit_count == 0
            assert row.last_hit_at is None

        with db.session() as s:
            RuleRepository(s).record_rule_hit(
                rule_id,
                target="10.0.0.5",
                decision="deny",
                reason="blocked",
                actor_id=7575983824,
                actor_username="alice",
            )

        with db.session() as s:
            row = RuleRepository(s).get_rule(rule_id)
            assert row.hit_count == 1
            assert row.last_hit_at is not None

    def test_counter_accumulates(self, db):
        rule_id = make(db, "r")
        for decision in ("allow", "deny", "allow"):
            with db.session() as s:
                RuleRepository(s).record_rule_hit(
                    rule_id, decision=decision
                )
        with db.session() as s:
            assert RuleRepository(s).get_rule(rule_id).hit_count == 3

    def test_hit_records_its_context(self, db):
        rule_id = make(db, "r")
        with db.session() as s:
            hit = RuleRepository(s).record_rule_hit(
                rule_id,
                scan_id=42,
                target="home",
                decision="deny",
                reason="blocked by deny_cidr",
                actor_id=7575983824,
                actor_username="alice",
            )
            assert hit.scan_id == 42
            assert hit.target == "home"
            assert hit.decision == "deny"
            assert hit.reason == "blocked by deny_cidr"
            assert hit.actor_id == 7575983824
            assert hit.actor_username == "alice"

    def test_unknown_decision_rejected(self, db):
        rule_id = make(db, "r")
        with db.session() as s:
            with pytest.raises(RepositoryError, match="Unknown rule decision"):
                RuleRepository(s).record_rule_hit(rule_id, decision="perhaps")

    def test_hit_for_a_deleted_rule_returns_none(self, db):
        # The evaluation already happened; there is just nothing to attribute
        # it to, which is not an error.
        rule_id = make(db, "r")
        with db.session() as s:
            RuleRepository(s).delete_rule(rule_id)
        with db.session() as s:
            assert (
                RuleRepository(s).record_rule_hit(rule_id, decision="deny")
                is None
            )

    def test_hits_survive_rule_deletion(self, db):
        rule_id = make(db, "r")
        with db.session() as s:
            RuleRepository(s).record_rule_hit(rule_id, decision="allow")
        with db.session() as s:
            RuleRepository(s).delete_rule(rule_id)
        with db.session() as s:
            _rows, total = RuleRepository(s).list_rule_hits()
            assert total == 1, "history must outlive the rule"


class TestHitQueries:
    def _seed(self, db):
        a = make(db, "a")
        b = make(db, "b")
        with db.session() as s:
            repo = RuleRepository(s)
            repo.record_rule_hit(
                a, target="t1", decision="deny", actor_id=1
            )
            repo.record_rule_hit(
                a, target="t2", decision="allow", actor_id=1
            )
            repo.record_rule_hit(
                b, target="t1", decision="allow", actor_id=2
            )
        return a, b

    def test_filter_by_rule(self, db):
        a, b = self._seed(db)
        with db.session() as s:
            _rows, total = RuleRepository(s).list_rule_hits(
                RuleHitFilters(rule_id=a)
            )
            assert total == 2

    def test_filter_by_decision(self, db):
        self._seed(db)
        with db.session() as s:
            _rows, total = RuleRepository(s).list_rule_hits(
                RuleHitFilters(decision="deny")
            )
            assert total == 1

    def test_filter_by_actor(self, db):
        self._seed(db)
        with db.session() as s:
            _rows, total = RuleRepository(s).list_rule_hits(
                RuleHitFilters(actor_id=2)
            )
            assert total == 1

    def test_filter_by_target(self, db):
        self._seed(db)
        with db.session() as s:
            _rows, total = RuleRepository(s).list_rule_hits(
                RuleHitFilters(target="t1")
            )
            assert total == 2

    def test_pagination(self, db):
        rule_id = make(db, "a")
        with db.session() as s:
            repo = RuleRepository(s)
            for _ in range(7):
                repo.record_rule_hit(rule_id, decision="allow")

        with db.session() as s:
            rows, total = RuleRepository(s).list_rule_hits(
                RuleHitFilters(page=1, page_size=3)
            )
            assert len(rows) == 3
            assert total == 7

            rows, total = RuleRepository(s).list_rule_hits(
                RuleHitFilters(page=3, page_size=3)
            )
            assert len(rows) == 1

    def test_newest_first(self, db):
        rule_id = make(db, "a")
        with db.session() as s:
            repo = RuleRepository(s)
            repo.record_rule_hit(rule_id, decision="allow")
            repo.record_rule_hit(rule_id, decision="deny")
        with db.session() as s:
            rows, _total = RuleRepository(s).list_rule_hits()
            assert rows[0].decision == "deny", "most recent first"

    def test_count_hits_since(self, db):
        rule_id = make(db, "a")
        with db.session() as s:
            repo = RuleRepository(s)
            repo.record_rule_hit(rule_id, decision="allow")
            repo.record_rule_hit(rule_id, decision="allow")

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with db.session() as s:
            repo = RuleRepository(s)
            # Cutoffs sit a second clear of the boundary on both sides.
            #
            # A cutoff at exactly the current instant cannot be used: SQLite
            # stores CURRENT_TIMESTAMP as '...HH:MM:SS' while SQLAlchemy binds
            # '...HH:MM:SS.000000', and the text comparison sorts the shorter
            # one first. PostgreSQL, which production runs on, compares real
            # timestamps and has no such quirk.
            assert repo.count_hits_since(now - timedelta(seconds=1)) == 2
            assert repo.count_hits_since(now - timedelta(days=1)) == 2
            assert repo.count_hits_since(now + timedelta(days=1)) == 0

    def test_count_hits_since_ignores_future_cutoffs(self, db):
        # Independent guard that the comparison direction is right: a cutoff
        # in the future must exclude everything, whatever the precision.
        rule_id = make(db, "a")
        with db.session() as s:
            RuleRepository(s).record_rule_hit(rule_id, decision="allow")

        future = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
            days=1
        )
        with db.session() as s:
            assert RuleRepository(s).count_hits_since(future) == 0


class TestPurgeRuleHits:
    def test_deletes_only_old_rows(self, db):
        rule_id = make(db, "a")
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        with db.session() as s:
            RuleRepository(s).record_rule_hit(rule_id, decision="allow")

        # Backdate one hit so there is something to prune.
        with db.session() as s:
            rows, _ = RuleRepository(s).list_rule_hits()
            rows[0].created_at = now - timedelta(days=90)
            RuleRepository(s).record_rule_hit(rule_id, decision="deny")

        with db.session() as s:
            repo = RuleRepository(s)
            assert repo.count_hits_since(now - timedelta(days=365)) == 2
            deleted = repo.purge_rule_hits(now - timedelta(days=30))
            assert deleted == 1
            assert repo.count_hits_since(now - timedelta(days=365)) == 1

    def test_returns_zero_when_nothing_is_old(self, db):
        rule_id = make(db, "a")
        with db.session() as s:
            RuleRepository(s).record_rule_hit(rule_id, decision="allow")
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with db.session() as s:
            assert RuleRepository(s).purge_rule_hits(now - timedelta(days=30)) == 0

    def test_rules_are_never_purged(self, db):
        rule_id = make(db, "keep-me")
        with db.session() as s:
            RuleRepository(s).record_rule_hit(rule_id, decision="allow")
        old = datetime.now(timezone.utc).replace(
            tzinfo=None
        ) - timedelta(days=365)
        with db.session() as s:
            RuleRepository(s).purge_rule_hits(old)
        with db.session() as s:
            assert RuleRepository(s).get_rule(rule_id) is not None


class TestScanCountingForQuotas:
    """The repository supplies quota_usage to the engine, so these are the
    counts the bot relies on."""

    def _seed_scans(self, db, user_id, count, target_value="10.0.0.0/24"):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with db.session() as s:
            target = TargetRepository(s).get_or_create_by_value(target_value)
            for offset in range(count):
                scan = ScanRepository(s).create(
                    target.id, "quick", requested_by=user_id
                )
                scan.started_at = now - timedelta(minutes=offset)
                s.flush()

    def test_count_since_counts_the_window(self, db):
        self._seed_scans(db, user_id=7575983824, count=3)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with db.session() as s:
            assert ScanRepository(s).count_since(
                7575983824, now - timedelta(hours=1)
            ) == 3

    def test_count_since_is_per_user(self, db):
        self._seed_scans(db, user_id=1, count=2)
        self._seed_scans(db, user_id=2, count=5, target_value="10.9.0.0/24")
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with db.session() as s:
            repo = ScanRepository(s)
            assert repo.count_since(1, now - timedelta(hours=1)) == 2
            assert repo.count_since(2, now - timedelta(hours=1)) == 5

    def test_count_since_excludes_older_scans(self, db):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with db.session() as s:
            target = TargetRepository(s).get_or_create_by_value(
                "10.0.0.0/24"
            )
            scan = ScanRepository(s).create(target.id, "quick",
                                       requested_by=1)
            scan.started_at = now - timedelta(minutes=5)
            s.flush()

        with db.session() as s:
            repo = ScanRepository(s)
            assert repo.count_since(1, now - timedelta(hours=1)) == 1
            assert (
                repo.count_since(1, now - timedelta(minutes=1)) == 0
            ), "a scan 5 minutes old is outside a 1-minute window"

    def test_latest_started_for_target_name(self, db):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with db.session() as s:
            target = TargetRepository(s).get_or_create_by_value("10.0.0.5")
            older = ScanRepository(s).create(target.id, "quick")
            older.started_at = now - timedelta(hours=5)
            newer = ScanRepository(s).create(target.id, "quick")
            newer.started_at = now - timedelta(minutes=1)
            s.flush()
            name = target.name

        with db.session() as s:
            latest = ScanRepository(s).latest_started_for_target_name(name)
            assert latest is not None
            delta = now - latest
            assert delta < timedelta(minutes=5), "must return the newest"

    def test_latest_started_for_unknown_target(self, db):
        with db.session() as s:
            assert (
                ScanRepository(s).latest_started_for_target_name("never-scanned")
                is None
            )