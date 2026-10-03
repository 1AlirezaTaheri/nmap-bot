"""Tests for audit logging and the runtime settings store."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from admin.services import audit as audit_service
from admin.services.audit import AuditEntry, AuditQuery, record, record_standalone
from admin.services.settings_store import (
    SETTING_SPECS,
    SettingError,
    SettingsStore,
    coerce,
    seed,
)
from database.database import Database
from sqlalchemy import select

from database.models import AuditLog, SystemSetting


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite+pysqlite:///{tmp_path}/t.db")
    database.create_all()
    yield database
    database.dispose()


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class TestAuditRecord:
    def test_writes_a_row(self, db):
        with db.session() as s:
            row = record(s, AuditEntry(action="target.add", actor_id=1))
            assert row is not None
            assert row.id is not None

    def test_details_are_json_encoded(self, db):
        with db.session() as s:
            row = record(
                s, AuditEntry(action="x", details={"profile": "quick", "n": 1})
            )
            assert '"profile": "quick"' in row.details

    def test_unicode_survives_encoding(self, db):
        with db.session() as s:
            row = record(s, AuditEntry(action="x", details={"note": "مهدف"}))
            assert "مهدف" in row.details

    def test_success_defaults_true(self, db):
        with db.session() as s:
            assert record(s, AuditEntry(action="x")).success is True

    def test_failure_is_recorded(self, db):
        with db.session() as s:
            row = record(s, AuditEntry(action="x", success=False))
            assert row.success is False

    def test_target_id_is_stringified(self, db):
        with db.session() as s:
            row = record(s, AuditEntry(action="x", target_id=42))
            assert row.target_id == "42"

    def test_never_raises_on_bad_details(self, db):
        class Unserialisable:
            pass

        # json.dumps has a default=str fallback, so this must not raise.
        with db.session() as s:
            row = record(s, AuditEntry(action="x", details={"o": Unserialisable()}))
            assert row is not None

    def test_standalone_uses_its_own_session(self, db):
        record_standalone(
            db, AuditEntry(action="scan.requested", actor_type="telegram_user")
        )
        with db.session() as s:
            assert s.query(AuditLog).count() == 1


class TestAuditQuery:
    def _seed(self, db):
        with db.session() as s:
            record(s, AuditEntry(action="a", actor_id=1, success=True))
            record(s, AuditEntry(action="b", actor_id=2, success=False))
            record(s, AuditEntry(action="a", actor_id=1, success=False))

    def test_returns_all_by_default(self, db):
        self._seed(db)
        with db.session() as s:
            rows, total = audit_service.query(s, AuditQuery())
        assert total == 3
        assert len(rows) == 3

    def test_filters_by_actor(self, db):
        self._seed(db)
        with db.session() as s:
            rows, total = audit_service.query(s, AuditQuery(actor_id=1))
        assert total == 2

    def test_filters_by_action(self, db):
        self._seed(db)
        with db.session() as s:
            rows, total = audit_service.query(s, AuditQuery(action="b"))
        assert total == 1
        assert rows[0].action == "b"

    def test_filters_by_success(self, db):
        self._seed(db)
        with db.session() as s:
            _rows, total = audit_service.query(s, AuditQuery(success=False))
        assert total == 2

    def test_combines_filters(self, db):
        self._seed(db)
        with db.session() as s:
            _rows, total = audit_service.query(
                s, AuditQuery(action="a", success=False)
            )
        assert total == 1

    def test_paginates(self, db):
        self._seed(db)
        with db.session() as s:
            rows, total = audit_service.query(s, AuditQuery(page=1, page_size=2))
        assert total == 3
        assert len(rows) == 2

    def test_second_page(self, db):
        self._seed(db)
        with db.session() as s:
            page1, _ = audit_service.query(s, AuditQuery(page=1, page_size=2))
            page2, _ = audit_service.query(s, AuditQuery(page=2, page_size=2))
        assert len(page2) == 1
        assert page1[0].id != page2[0].id

    def test_page_size_is_capped(self, db):
        self._seed(db)
        with db.session() as s:
            rows, _ = audit_service.query(s, AuditQuery(page_size=10_000))
        assert len(rows) <= 200

    def test_date_filter(self, db):
        self._seed(db)
        future = datetime.utcnow() + timedelta(days=1)
        with db.session() as s:
            _rows, total = audit_service.query(s, AuditQuery(since=future))
        assert total == 0


class TestAuditCsv:
    def test_includes_header(self, db):
        with db.session() as s:
            record(s, AuditEntry(action="x", actor_id=1))
        with db.session() as s:
            rows, _ = audit_service.query(s, AuditQuery())
        text = audit_service.to_csv(rows)
        assert "actor_type" in text.splitlines()[0]
        assert "success" in text

    def test_renders_bool_as_text(self, db):
        with db.session() as s:
            record(s, AuditEntry(action="x", success=False))
        with db.session() as s:
            rows, _ = audit_service.query(s, AuditQuery())
        assert "false" in audit_service.to_csv(rows)

    def test_details_are_flattened(self, db):
        with db.session() as s:
            record(s, AuditEntry(action="x", details={"a": 1}))
        with db.session() as s:
            rows, _ = audit_service.query(s, AuditQuery())
        text = audit_service.to_csv(rows)
        # one line per row, so embedded newlines must not break the column count
        assert len(text.strip().splitlines()) == 2


# ---------------------------------------------------------------------------
# Settings store
# ---------------------------------------------------------------------------


class TestCoerce:
    def test_bool_true(self):
        assert coerce("schedule_enabled", "true") is True
        assert coerce("schedule_enabled", "1") is True

    def test_bool_false(self):
        assert coerce("schedule_enabled", "false") is False
        assert coerce("schedule_enabled", "no") is False

    def test_bool_rejects_garbage(self):
        with pytest.raises(SettingError):
            coerce("schedule_enabled", "maybe")

    def test_int_parses(self):
        assert coerce("retention_days", "45") == 45

    def test_int_rejects_garbage(self):
        with pytest.raises(SettingError):
            coerce("retention_days", "soon")

    def test_int_range_enforced(self):
        with pytest.raises(SettingError):
            coerce("retention_days", "0")
        with pytest.raises(SettingError):
            coerce("retention_days", "99999")

    def test_choice_validated(self):
        assert coerce("bot_language", "en") == "en"
        with pytest.raises(SettingError):
            coerce("bot_language", "de")

    def test_profile_choice(self):
        assert coerce("default_profile", "deep") == "deep"
        with pytest.raises(SettingError):
            coerce("default_profile", "insane")

    def test_unknown_key_rejected(self):
        with pytest.raises(SettingError):
            coerce("nonexistent_key", "x")

    def test_string_passes_through(self):
        assert coerce("allowed_cidrs", "10.0.0.0/8") == "10.0.0.0/8"


class TestSettingsStore:
    def test_seed_inserts_every_spec(self, db):
        with db.session() as s:
            added = seed(s, actor="test")
        assert added == len(SETTING_SPECS)

    def test_seed_is_idempotent(self, db):
        with db.session() as s:
            seed(s)
        with db.session() as s:
            assert seed(s) == 0

    def test_get_returns_default_when_table_empty(self, db):
        store = SettingsStore(db)
        assert store.get("retention_days") == 30
        assert store.get("bot_language") == "fa"

    def test_set_then_get(self, db):
        with db.session() as s:
            seed(s)
        store = SettingsStore(db)
        with db.session() as s:
            store.set(s, "retention_days", 7, "admin")
        store.invalidate()
        assert store.get("retention_days") == 7

    def test_set_validates(self, db):
        store = SettingsStore(db)
        with db.session() as s:
            seed(s)
        with pytest.raises(SettingError):
            with db.session() as s:
                store.set(s, "retention_days", -5, "admin")

    def test_set_many_is_atomic_on_validation_error(self, db):
        """A bad value must reject the whole batch, not apply it halfway."""
        store = SettingsStore(db)
        with db.session() as s:
            seed(s)
        with pytest.raises(SettingError):
            with db.session() as s:
                store.set_many(
                    s, {"retention_days": 5, "bot_language": "de"}, "admin"
                )
        store.invalidate()
        # neither change should have landed
        assert store.get("retention_days") == 30

    def test_corrupt_stored_value_falls_back_to_default(self, db):
        with db.session() as s:
            seed(s)
        # Overwrite the seeded value with something invalid.
        with db.session() as s:
            row = s.scalar(
                select(SystemSetting).where(SystemSetting.key == "retention_days")
            )
            row.value = "not-a-number"
        store = SettingsStore(db)
        store.invalidate()
        assert store.get("retention_days") == 30  # default, not an exception

    def test_invalidate_forces_reread(self, db):
        store = SettingsStore(db, ttl_seconds=999)
        with db.session() as s:
            seed(s)
        assert store.get("retention_days") == 30
        # direct write bypassing the store
        with db.session() as s:
            row = s.scalar(
                select(SystemSetting).where(SystemSetting.key == "retention_days")
            )
            row.value = "11"
        store.invalidate()
        assert store.get("retention_days") == 11

    def test_all_returns_every_key(self, db):
        with db.session() as s:
            seed(s)
        values = SettingsStore(db).all()
        for key in SETTING_SPECS:
            assert key in values

    def test_database_failure_falls_back_to_defaults(self, tmp_path):
        """An unreachable database must not break message handling."""
        broken = Database(f"sqlite+pysqlite:///{tmp_path}/missing/x.db")
        store = SettingsStore(broken)
        # This raises inside _load_locked; the fallback should still yield defaults.
        try:
            assert store.get("retention_days") == 30
        finally:
            broken.dispose()