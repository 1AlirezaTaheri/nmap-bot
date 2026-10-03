"""Bot internationalisation.

Translations live in ``core/translations/{lang}.json`` and are flat
key → string maps. Lookup rules:

1. the requested language;
2. ``en`` as a fallback, so a missing Persian string still renders
   something usable rather than a raw key;
3. the key itself, so a missing string is visible instead of blank.

Tables are cached after first read. ``reload()`` exists so tests — or a
future "reload translations" admin action — can pick up edits without a
restart.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

TRANSLATIONS_DIR = Path(__file__).parent / "translations"
DEFAULT_LANG = "fa"
FALLBACK_LANG = "en"
SUPPORTED = ("fa", "en")


class Translator:
    def __init__(self, directory: Path | None = None) -> None:
        self._dir = Path(directory) if directory else TRANSLATIONS_DIR
        self._cache: dict[str, dict[str, str]] = {}

    # -- loading ------------------------------------------------------
    def available(self) -> list[str]:
        """Languages that have a file on disk."""
        if not self._dir.is_dir():
            return []
        return sorted(p.stem for p in self._dir.glob("*.json"))

    def load(self, lang: str) -> dict[str, str]:
        """Return the translation map for ``lang``, cached."""
        lang = (lang or DEFAULT_LANG).strip().lower()
        if lang in self._cache:
            return self._cache[lang]

        path = self._dir / f"{lang}.json"
        data: object
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            log.warning("No translation file for '%s' at %s", lang, path)
            data = {}
        except json.JSONDecodeError as exc:
            log.error("Malformed translation file %s: %s", path, exc)
            data = {}

        if not isinstance(data, dict):  # pragma: no cover - defensive
            log.error("Translation file %s is not an object", path)
            data = {}

        self._cache[lang] = {str(k): str(v) for k, v in data.items()}
        return self._cache[lang]

    def reload(self) -> None:
        self._cache.clear()

    # -- lookup -------------------------------------------------------
    def t(self, key: str, lang: str = DEFAULT_LANG, **kwargs) -> str:
        """Translate ``key``, interpolating ``{placeholders}``."""
        text = self._lookup(key, lang)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except (KeyError, IndexError, ValueError) as exc:
                # A missing placeholder must not blank the whole message.
                log.warning("Bad placeholder for %s: %s", key, exc)
        return text

    def _lookup(self, key: str, lang: str) -> str:
        lang = (lang or DEFAULT_LANG).strip().lower()

        table = self.load(lang)
        if key in table:
            return table[key]

        fallback = self.load(FALLBACK_LANG)
        if key in fallback:
            return fallback[key]

        log.debug("Untranslated key %r for lang %r", key, lang)
        return key

    def has(self, key: str, lang: str) -> bool:
        lang = (lang or DEFAULT_LANG).strip().lower()
        return key in self.load(lang) or key in self.load(FALLBACK_LANG)

    def missing_keys(self, lang: str) -> list[str]:
        """Keys in ``en`` but absent from ``lang`` — a translation gap report."""
        fallback = set(self.load(FALLBACK_LANG))
        table = set(self.load(lang))
        return sorted(fallback - table)

    def keys(self, lang: str) -> set[str]:
        return set(self.load(lang))


# Module-level singleton, matching how the rest of the codebase reaches
# configuration: one object, not a factory per call site.
_translator = Translator()


def t(key: str, lang: str = DEFAULT_LANG, **kwargs) -> str:
    """Translate ``key`` for ``lang``."""
    return _translator.t(key, lang, **kwargs)


def translator() -> Translator:
    return _translator


def available_languages() -> list[str]:
    return _translator.available()


def reload_translations() -> None:
    _translator.reload()


def normalize_lang(value: str | None) -> str:
    """Coerce arbitrary input to a supported language code."""
    candidate = (value or DEFAULT_LANG).strip().lower()
    return candidate if candidate in SUPPORTED else DEFAULT_LANG