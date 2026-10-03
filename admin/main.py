"""Uvicorn entry point for the admin panel.

Kept separate from ``admin/services/bootstrap.py`` so importing the
application factory never starts a server (which would break tests).
"""

from __future__ import annotations

import logging
import os
import sys

from admin.services.bootstrap import create_app
from config.settings import ConfigError, Settings
from core.structured_logging import RequestIdFilter, RequestIdFormatter

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)

# Same token-leak protection as the bot: httpx and the web stack would
# otherwise echo credentials in request URLs.
for _noisy in ("httpx", "httpcore", "urllib3", "uvicorn.access"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

_handler = logging.StreamHandler()
_handler.setFormatter(
    RequestIdFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")
)
_handler.addFilter(RequestIdFilter())
log = logging.getLogger("netsentinel.admin")
log.handlers.clear()
log.addHandler(_handler)
log.propagate = False


def main() -> int:
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        return 1

    try:
        app = create_app(settings)
    except RuntimeError as exc:
        # Bootstrap failures (missing ADMIN_USERNAME, weak password) must
        # be loud and immediate, not a half-working panel.
        log.error("Admin bootstrap failed: %s", exc)
        return 1

    import uvicorn

    host = os.environ.get("ADMIN_HOST", "0.0.0.0")
    port = settings.admin_port
    log.info("Starting admin panel on %s:%s", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info", access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())