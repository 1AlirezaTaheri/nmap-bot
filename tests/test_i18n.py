"""Tests for the i18n layer."""

from __future__ import annotations

import json

import pytest

from core.i18n import (
    DEFAULT_LANG,
    FALLBACK_LANG,
    Translator,
    available_languages,
    normalize_lang,
    reload_translations,
    t,
    translator,
)


@pytest.fixture(autouse=True)
def fresh():
    reload_translations()
    yield
    reload_translations()


class TestBasicLookup:
    def test_known_key_in_default_language(self):
        assert t("auth.denied", "fa").startswith("⛔")
        assert "ALLOWED_USER_IDS" in t("auth.denied", "fa")

    def test_english_returns_english(self):
        text = t("auth.denied", "en")
        assert "Not recognised" in text
        assert "ALLOWED_USER_IDS" in text

    def test_placeholder_interpolation(self):
        text = t("target.not_found", "en", name="lab")
        assert "'lab'" in text
        assert "{name}" not in text

    def test_persian_and_english_differ(self):
        assert t("auth.denied", "fa") != t("auth.denied", "en")

    def test_unknown_key_returns_the_key(self):
        assert t("no.such.key", "fa") == "no.such.key"

    def test_unknown_key_prefers_fallback_language(self):
        """A key present only in en still resolves when asking for fa."""
        assert t("help.cmd.status", "fa") != "help.cmd.status"


class TestLanguageNormalisation:
    def test_supported_passthrough(self):
        assert normalize_lang("fa") == "fa"
        assert normalize_lang("en") == "en"

    def test_case_and_whitespace_tolerated(self):
        assert normalize_lang("  EN  ") == "en"

    def test_unsupported_falls_back_to_default(self):
        assert normalize_lang("de") == DEFAULT_LANG
        assert normalize_lang(None) == DEFAULT_LANG
        assert normalize_lang("") == DEFAULT_LANG

    def test_lang_table_lookup_is_case_insensitive(self):
        assert t("auth.denied", "FA") == t("auth.denied", "fa")


class TestFallbackBehaviour:
    def test_missing_in_primary_uses_english(self, tmp_path):
        # The key exists ONLY in en, so asking for fa must fall back.
        (tmp_path / "fa.json").write_text(
            json.dumps({"present.fa": "فارسی"}), encoding="utf-8"
        )
        (tmp_path / "en.json").write_text(
            json.dumps({"present.fa": "fa", "en.only": "english only"}),
            encoding="utf-8",
        )
        tr = Translator(tmp_path)
        assert tr.t("en.only", "fa") == "english only"
        assert tr.t("present.fa", "fa") == "فارسی"  # present in both

    def test_key_missing_everywhere_returns_key(self, tmp_path):
        (tmp_path / "fa.json").write_text("{}", encoding="utf-8")
        (tmp_path / "en.json").write_text("{}", encoding="utf-8")
        assert Translator(tmp_path).t("nope", "fa") == "nope"

    def test_missing_language_file_does_not_raise(self, tmp_path):
        tr = Translator(tmp_path)
        assert tr.t("anything", "zz") == "anything"

    def test_malformed_json_is_survivable(self, tmp_path):
        (tmp_path / "fa.json").write_text("{not json", encoding="utf-8")
        (tmp_path / "en.json").write_text(
            json.dumps({"k": "v"}), encoding="utf-8"
        )
        tr = Translator(tmp_path)
        assert tr.t("k", "fa") == "v"


class TestPlaceholderSafety:
    def test_missing_placeholder_does_not_raise(self):
        # A string with {x} rendered without x must not blow up the handler.
        text = t("target.not_found", "en")  # no name= given
        assert text  # something was returned

    def test_extra_placeholders_ignored(self):
        text = t("auth.denied", "en", unused="value")
        assert "Not recognised" in text


class TestCaching:
    def test_tables_are_cached(self):
        tr = translator()
        first = tr.load("fa")
        second = tr.load("fa")
        assert first is second

    def test_reload_clears_the_cache(self, tmp_path):
        (tmp_path / "fa.json").write_text(
            json.dumps({"k": "first"}), encoding="utf-8"
        )
        tr = Translator(tmp_path)
        assert tr.t("k", "fa") == "first"

        (tmp_path / "fa.json").write_text(
            json.dumps({"k": "second"}), encoding="utf-8"
        )
        assert tr.t("k", "fa") == "first"  # still cached
        tr.reload()
        assert tr.t("k", "fa") == "second"


class TestCompleteness:
    def test_both_languages_available(self):
        langs = available_languages()
        assert "fa" in langs
        assert "en" in langs

    def test_no_missing_keys_between_languages(self):
        """Both shipped files must be complete — the point of the check."""
        tr = translator()
        assert tr.missing_keys("fa") == []
        assert tr.missing_keys("en") == []

    def test_shipped_files_have_the_same_key_count(self):
        tr = translator()
        assert len(tr.keys("fa")) == len(tr.keys("en"))

    def test_every_command_message_exists_in_both(self):
        keys = (
            "start.greeting", "help.title", "auth.denied", "scan.usage",
            "scan.started", "scan.completed", "change.header",
            "target.list_header", "target.added", "purge.confirm_prompt",
            "schedule.list_header", "history.header", "status.header",
            "health.title", "cleanup.title", "export.usage",
            "report.title", "error.unhandled",
        )
        tr = translator()
        for key in keys:
            assert tr.has(key, "fa"), f"missing fa: {key}"
            assert tr.has(key, "en"), f"missing en: {key}"


class TestRealisticRendering:
    def test_change_line_renders_in_persian(self):
        assert t("change.new_port", "fa", host="10.0.0.1", port=8080) == \
            "پورت جدید: 10.0.0.1:8080"

    def test_change_line_renders_in_english(self):
        assert t("change.new_port", "en", host="10.0.0.1", port=8080) == \
            "New port: 10.0.0.1:8080"

    def test_service_change_renders_arrow(self):
        out = t("change.service_changed", "en", host="10.0.0.1", port=80,
                old="Apache", new="nginx")
        assert "Apache" in out and "nginx" in out

    def test_language_name_is_translatable(self):
        assert t("lang.name", "fa") == "فارسی"
        assert t("lang.name", "en") == "English"