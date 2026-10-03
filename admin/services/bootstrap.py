"""FastAPI application factory for the admin panel."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from admin.services import auth as auth_service
from admin.services import users as user_service
from admin.services.settings_store import SettingsStore, seed as seed_settings
from config.settings import Settings
from database.database import Database

log = logging.getLogger(__name__)

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
# admin/ -- the parent of this package. The built SPA lives at
# admin/frontend/dist, so resolve from the package root; joining onto
# PACKAGE_DIR would yield admin/services/frontend/dist.
ADMIN_DIR = os.path.dirname(PACKAGE_DIR)
FRONTEND_DIST = os.path.join(ADMIN_DIR, "frontend", "dist")
SPA_INDEX = os.path.join(FRONTEND_DIST, "index.html")


@dataclass
class AdminContext:
    """Shared state, hung off ``app.state`` so no module globals."""

    settings: Settings
    database: Database
    settings_store: SettingsStore
    login_limiter: auth_service.LoginRateLimiter
    # Shared so the panel enforces the same CIDR scope as the bot.
    authorizer: Any = None
    principal: object | None = field(default=None, init=False)


def bootstrap_admin(database, settings: Settings) -> int:
    """Create the first superadmin from the environment if none exists.

    Fails loudly rather than defaulting: a panel reachable with a
    predictable credential is worse than a panel that refuses to start.
    Returns the number of admins created (0 or 1).
    """
    with database.session() as session:
        if user_service.admin_count(session):
            return 0

    username = os.environ.get("ADMIN_USERNAME", "").strip()
    password = os.environ.get("ADMIN_PASSWORD", "")

    if not username or not password:
        raise RuntimeError(
            "No admin_users exist and ADMIN_USERNAME / ADMIN_PASSWORD are not "
            "set. Create the first administrator before starting the panel."
        )

    try:
        password_hash = auth_service.hash_password(password)
    except auth_service.AuthError as exc:
        raise RuntimeError(f"ADMIN_PASSWORD rejected: {exc}") from exc

    with database.session() as session:
        user_service.create_admin(
            session, username, password_hash, role="superadmin"
        )
    log.warning("Created initial superadmin '%s' from environment", username)
    return 1


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = Settings.from_env()

    database = Database(settings.database_url)
    database.create_all()

    # Settings table must exist before the store reads it.
    with database.session() as session:
        seed_settings(session, actor="bootstrap")

    store = SettingsStore(database)
    created = bootstrap_admin(database, settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        log.info("Admin panel starting on :%s", settings.admin_port)
        log.info(
            "Settings: bot_language=%s default_profile=%s",
            store.get("bot_language"), store.get("default_profile"),
        )
        yield
        database.dispose()
        log.info("Admin panel stopped")

    app = FastAPI(
        title="NetSentinel Admin",
        description="Web administration for the NetSentinel bot",
        version="2.0.0",
        lifespan=lifespan,
    )

    from security.authorization import Authorizer

    ctx = AdminContext(
        settings=settings,
        database=database,
        settings_store=store,
        login_limiter=auth_service.LoginRateLimiter(),
        # The panel must not be able to register a target the bot would
        # refuse to scan.
        authorizer=Authorizer(settings.allowed_cidrs),
    )
    app.state.ctx = ctx
    app.state.created_admins = created

    # /api/* is registered first and is unchanged by the SPA migration.
    from admin.routes import api

    app.include_router(api.router, prefix="/api")

    _mount_spa(app)

    @app.exception_handler(500)
    async def server_error(request: Request, exc: Exception):  # pragma: no cover
        log.exception("Unhandled error on %s", request.url.path, exc_info=exc)
        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )

    return app


def _mount_spa(app: FastAPI) -> None:
    """Serve the built React SPA under /admin.

    Registration order matters. The hashed asset directory is mounted
    first, so a request for /admin/assets/app-<hash>.js is answered by
    StaticFiles with a JavaScript content type. If the catch-all ran
    first it would swallow that request and return index.html with
    text/html, and the browser would refuse the module.
    """
    if not os.path.isdir(FRONTEND_DIST):
        # Not fatal: the API stays usable and the message says how to fix
        # it, which beats a container that dies on a missing npm build.
        log.warning(
            "Frontend build missing at %s - /admin will return instructions "
            "instead of the app. Build it with: cd admin/frontend && "
            "npm ci && npm run build",
            FRONTEND_DIST,
        )

        @app.get("/admin", include_in_schema=False)
        @app.get("/admin/{path:path}", include_in_schema=False)
        async def _spa_missing(path: str = ""):  # pragma: no cover
            return JSONResponse(
                status_code=503,
                content={
                    "detail": (
                        "Admin frontend is not built. Run: "
                        "cd admin/frontend && npm ci && npm run build"
                    )
                },
            )

        return

    assets_dir = os.path.join(FRONTEND_DIST, "assets")
    if os.path.isdir(assets_dir):
        app.mount(
            "/admin/assets",
            StaticFiles(directory=assets_dir),
            name="spa-assets",
        )

    spa_router = APIRouter()

    @spa_router.get("/admin", include_in_schema=False)
    @spa_router.get("/admin/{path:path}", include_in_schema=False)
    async def _spa(path: str = ""):
        """Return index.html for every SPA route.

        Client-side routing owns /admin/users and friends, so an unknown
        path under /admin must return the shell rather than a 404 - the
        browser needs index.html to resolve the route.
        """
        return FileResponse(SPA_INDEX, headers={"Cache-Control": "no-store"})

    app.include_router(spa_router)
    log.info("Serving SPA from %s", FRONTEND_DIST)
