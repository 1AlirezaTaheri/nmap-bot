"""NetSentinel entry point.

Loads and validates configuration, builds the Telegram application, then
starts polling. Configuration errors are reported plainly instead of
producing a traceback, because they are almost always an operator mistake
(a missing variable) rather than a code bug.
"""

from __future__ import annotations

import logging
import sys

from bot.app import build_application
from config.settings import ConfigError, Settings

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("netsentinel")


def main() -> int:
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        return 1

    app = build_application(settings)
    log.info(
        "Starting NetSentinel | %d allowed user(s) | default profile=%s",
        len(settings.allowed_user_ids),
        settings.default_profile,
    )
    app.run_polling()
    return 0


if __name__ == "__main__":
    sys.exit(main())
