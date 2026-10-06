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

    # proxy_headers must follow the same switch as the application's
    # own client_ip(). Uvicorn's middleware rewrites scope["client"]
    # from X-Forwarded-For *before* the app runs, so leaving it on by
    # default meant ADMIN_TRUST_FORWARDED_FOR=false did not actually
    # stop header trust -- it only stopped the app's second opinion.
    # Anything else would let a client pick its own rate-limit bucket.
    trust_forwarded = bool(getattr(settings, "admin_trust_forwarded_for", False))
    if trust_forwarded:
        log.warning(
            "ADMIN_TRUST_FORWARDED_FOR is enabled: client IPs are taken "
            "from X-Forwarded-For. Only correct when a trusted proxy "
            "overwrites that header and nothing else can reach this port."
        )
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=False,
        proxy_headers=trust_forwarded,
        # Empty unless explicitly configured: the default trusts the whole
        # loopback range, which includes any process on this host.
        forwarded_allow_ips=(
            os.environ.get("FORWARDED_ALLOW_IPS", "") if trust_forwarded else None
        ),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())