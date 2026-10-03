"""NetSentinel admin panel — FastAPI service."""

from __future__ import annotations

import logging

__all__ = ["create_app"]

log = logging.getLogger(__name__)


def create_app(settings=None):
    """Lazy re-export.

    Imported on demand so that merely importing this package (for
    example from a test that only wants the settings store) does not
    drag in FastAPI and the whole route graph.
    """
    from admin.services.bootstrap import create_app as _create

    return _create(settings)