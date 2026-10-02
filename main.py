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
from core.structured_logging import (
    RequestIdFilter,
    RequestIdFormatter,
    set_request_id,
)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# python-telegram-bot logs every HTTP call at INFO, and httpx echoes the
# full request URL — which embeds the bot token in the path
# (/bot<TOKEN>/getMe). Anyone able to read `docker logs` would otherwise
# obtain a working token. Raise both loggers to WARNING so the token
# cannot leak through routine polling. APScheduler and asyncio are added
# because their INFO chatter is noisy and, like httpx, not useful here.
for _noisy in ("httpx", "telegram", "telegram.ext", "apscheduler", "asyncio"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

# Correlate every log line with the unit of work that produced it.
_handler = logging.StreamHandler()
_handler.setFormatter(RequestIdFormatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
_handler.addFilter(RequestIdFilter())
log = logging.getLogger("netsentinel")
log.handlers.clear()
log.addHandler(_handler)
log.propagate = False


def main() -> int:
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        return 1

    app = build_application(settings)
    log.info(
        "Starting NetSentinel | %d allowed user(s) | profile=%s | "
        "schedule=%s | retention=%dd/%d | rate_limit=%ds",
        len(settings.allowed_user_ids),
        settings.default_profile,
        "on" if settings.schedule_enabled else "off",
        settings.retention_days,
        settings.retention_max_scans_per_target,
        settings.rate_limit_seconds,
    )

    # Bind a process-wide id so startup lines are traceable too.
    set_request_id("boot")
    app.run_polling()
    return 0


if __name__ == "__main__":
    sys.exit(main())