"""Tests for the Rule data model: shape, defaults, constraints, ordering.

The model is the contract the evaluator and the panel both build on, so
these tests pin the parts a refactor could silently change: the column set,
the client-side defaults, the unique name, and the fact that scope_id is
*not* a foreign key (a rule must be able to outlive, and predate, its
subject).
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from database.database import Database
from database.models import RULE_SCOPES, RULE_TYPES, Rule


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/rules.db")
    database.create_all()
    yield database
    database.dispose()


def make_rule(db: Database, name: str = "r", **overrides) -> int:
    fields = {
        "name": name,
        "rule_type": "deny_cidr",
        "value": "10.0.0.0/8",
    }
    fields.update(overrides)
    with db.session() as s:
        rule = Rule(**fields)
        s.add(rule)
        s.flush()
        return rule.id


class TestTableShape:
    def test_columns_are_exactly_the_spec_set(self):
        # Guards against an accidental column rename or a silent addition:
        # the evaluator, the panel and the CSV export all name these.
        assert [c.name for c in Rule.__table__.columns] == [
            "id", "name", "rule_type", "value", "priority", "enabled",
            "scope", "scope_id", "description", "created_by", "created_at",
            "updated_at", "hit_count", "last_hit_at",
        ]

    def test_indexes_cover_the_evaluators_hot_path(self):
        # ix_rules_enabled_priority serves "enabled rules for this context,
        # in evaluation order"; ix_rules_scope serves listing a subject's
        # rules in the panel.
        indexes = {
            i.name: [c.name for c in i.columns]
            for i in Rule.__table__.indexes
        }
        assert indexes["ix_rules_enabled_priority"] == ["enabled", "priority"]
        assert indexes["ix_rules_scope"] == ["scope", "scope_id"]

    def test_value_and_rule_type_are_not_nullable(self):
        # A rule with no payload cannot be evaluated, so it must be
        # impossible to persist.
        columns = {c.name: c for c in Rule.__table__.columns}
        assert columns["value"].nullable is False
        assert columns["rule_type"].nullable is False
        assert columns["name"].nullable is False

    def test_scope_id_is_deliberately_not_a_foreign_key(self):
        # If this ever becomes an FK, a rule could not be created for a
        # target that does not exist yet, nor deleted while its subject
        # lives. That would be a silent behaviour change.
        assert not Rule.__table__.foreign_keys


class TestDefaults:
    def test_omitted_fields_get_neutral_defaults(self, db):
        rule_id = make_rule(db)
        with db.session() as s:
            rule = s.get(Rule, rule_id)
            assert rule.priority == 50, "priority must default to neutral 50"
            assert rule.enabled is True
            assert rule.scope == "global"
            assert rule.hit_count == 0
            assert rule.scope_id is None
            assert rule.updated_at is None
            assert rule.last_hit_at is None
            assert rule.description is None
            assert rule.created_by is None

    def test_created_at_is_filled_by_the_server(self, db):
        rule_id = make_rule(db)
        with db.session() as s:
            assert s.get(Rule, rule_id).created_at is not None

    def test_supplied_values_are_not_overwritten(self, db):
        rule_id = make_rule(
            db,
            priority=1,
            enabled=False,
            scope="user",
            scope_id="7575983824",
            description="deny this user entirely",
            created_by="admin",
            hit_count=17,
        )
        with db.session() as s:
            rule = s.get(Rule, rule_id)
            assert rule.priority == 1
            assert rule.enabled is False
            assert rule.scope == "user"
            assert rule.scope_id == "7575983824"
            assert rule.description == "deny this user entirely"
            assert rule.created_by == "admin"
            assert rule.hit_count == 17


class TestConstraints:
    def test_duplicate_name_is_rejected_by_the_database(self, db):
        make_rule(db, name="deny-metadata")
        with pytest.raises(IntegrityError):
            make_rule(db, name="deny-metadata", rule_type="deny_port")
        # The failed insert must not poison the session for later use.
        with db.session() as s:
            assert len(s.scalars(select(Rule)).all()) == 1

    def test_null_value_is_rejected(self, db):
        with pytest.raises(IntegrityError):
            make_rule(db, value=None)

    def test_a_64_char_telegram_id_fits_scope_id(self, db):
        # Scope ids are stored as text because they are polymorphic, so the
        # column must actually hold a full-length id without truncating.
        big = "9" * 64
        rule_id = make_rule(db, scope="user", scope_id=big)
        with db.session() as s:
            assert s.get(Rule, rule_id).scope_id == big


class TestVocabularies:
    def test_rule_types_are_the_declared_ten(self):
        assert set(RULE_TYPES) == {
            "allow_cidr", "deny_cidr", "allow_domain", "deny_domain",
            "allow_port", "deny_port", "max_scan_time", "rate_limit",
            "time_window", "user_quota",
        }

    def test_no_duplicate_rule_types(self):
        assert len(RULE_TYPES) == len(set(RULE_TYPES))

    def test_scopes_are_the_declared_three(self):
        assert RULE_SCOPES == ("global", "user", "target")

    def test_every_rule_type_is_storable(self, db):
        # Guards against a typo in RULE_TYPES that would make a type
        # documented but unusable. Validation belongs in the service layer,
        # so the column must accept every declared type.
        for index, rule_type in enumerate(RULE_TYPES):
            make_rule(
                db,
                name=f"rule-{index}",
                rule_type=rule_type,
                value="1",
            )
        with db.session() as s:
            stored = {r.rule_type for r in s.scalars(select(Rule)).all()}
            assert stored == set(RULE_TYPES)


class TestEvaluationOrder:
    def test_rules_sort_by_priority_then_id(self, db):
        # The evaluator's contract: priority ascending, id as a stable
        # tiebreak so ordering is deterministic across requests.
        later = make_rule(db, name="b", priority=10)
        earlier = make_rule(db, name="a", priority=1)
        tie_low = make_rule(db, name="c", priority=10)

        with db.session() as s:
            ordered = s.scalars(
                select(Rule).order_by(Rule.priority, Rule.id)
            ).all()
            assert [r.id for r in ordered] == [earlier, later, tie_low]

    def test_disabled_rules_can_still_be_persisted_and_re_enabled(self, db):
        # Disabling must not delete a rule: the operator expects to pause
        # one and resume it with its counters intact.
        rule_id = make_rule(db, enabled=False, hit_count=5)
        with db.session() as s:
            rule = s.get(Rule, rule_id)
            assert rule.enabled is False
            rule.enabled = True
        with db.session() as s:
            rule = s.get(Rule, rule_id)
            assert rule.enabled is True
            assert rule.hit_count == 5, "hit_count must survive a pause"


class TestPersistence:
    def test_round_trip_through_the_database(self, db):
        rule_id = make_rule(
            db,
            name="allow-home",
            rule_type="allow_cidr",
            value="192.168.174.0/24",
            description="the home network",
        )
        with db.session() as s:
            rule = s.get(Rule, rule_id)
            assert rule.name == "allow-home"
            assert rule.rule_type == "allow_cidr"
            assert rule.value == "192.168.174.0/24"
            assert rule.description == "the home network"

    def test_rules_are_listable_per_subject(self, db):
        # Backs the panel's "rules for this user/target" listing.
        make_rule(db, name="g", scope="global")
        make_rule(db, name="u1", scope="user", scope_id="111")
        make_rule(db, name="u2", scope="user", scope_id="222")

        with db.session() as s:
            subject = s.scalars(
                select(Rule)
                .where(Rule.scope == "user", Rule.scope_id == "111")
                .order_by(Rule.priority)
            ).all()
            assert [r.name for r in subject] == ["u1"]