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
from admin.services import captcha as captcha_service
from admin.services import users as user_service
from admin.services.settings_store import SettingsStore, seed as seed_settings
from config.settings import Settings
from database.database import Database
from core.rate_limit import RateLimiter

log = logging.getLogger(__name__)

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
# admin/ -- the parent of this package. The built SPA lives at
# admin/frontend/dist, so resolve from the package root; joining onto
# PACKAGE_DIR would yield admin/services/frontend/dist.
ADMIN_DIR = os.path.dirname(PACKAGE_DIR)
FRONTEND_DIST = os.path.join(ADMIN_DIR, "frontend", "dist")
SPA_INDEX = os.path.join(FRONTEND_DIST, "index.html")

# The Telegram Mini App is a separate frontend with its own build.
PROJECT_DIR = os.path.dirname(ADMIN_DIR)
MINIAPP_DIST = os.path.join(PROJECT_DIR, "mini-app", "dist")
MINIAPP_INDEX = os.path.join(MINIAPP_DIST, "index.html")


@dataclass
class AdminContext:
    """Shared state, hung off ``app.state`` so no module globals."""

    settings: Settings
    database: Database
    settings_store: SettingsStore
    login_limiter: auth_service.LoginRateLimiter
    # Single-use bookkeeping for CAPTCHA challenges. In-process, like
    # the rate limiter, so a restart clears it: correct, because a
    # restart already invalidates every session and an outstanding
    # challenge expires in five minutes anyway.
    captcha_store: captcha_service.CaptchaStore = field(
        default_factory=captcha_service.CaptchaStore
    )
    # Shared so the panel enforces the same CIDR scope as the bot.
    authorizer: Any = None
    # The Mini App can queue scans, so this process needs a worker and the
    # same rate limiter the bot uses. Separate from the bot's instances:
    # they are different processes. See the module docstring.
    scan_worker: Any = None
    rate_limiter: Any = None
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
        await _start_miniapp_worker(app, settings, database)
        log.info(
            "Settings: bot_language=%s default_profile=%s",
            store.get("bot_language"), store.get("default_profile"),
        )
        yield
        await _stop_miniapp_worker(app)
        database.dispose()
        log.info("Admin panel stopped")

    app = FastAPI(
        title="NetSentinel Admin",
        description="Web administration for the NetSentinel bot",
        version="2.0.0",
        lifespan=lifespan,
    )

    # Applied here rather than inside the lifespan so the middleware is in
    # place before any route or mount is registered, and therefore wraps
    # the SPA mounts and /miniapp as well as /api.
    add_security_headers(app, settings)

    from security.authorization import Authorizer

    ctx = AdminContext(
        settings=settings,
        database=database,
        settings_store=store,
        login_limiter=auth_service.LoginRateLimiter(),
        # The panel must not be able to register a target the bot would
        # refuse to scan.
        authorizer=Authorizer(settings.allowed_cidrs),
        rate_limiter=RateLimiter(settings.rate_limit_seconds),
    )
    app.state.ctx = ctx
    app.state.created_admins = created

    # /api/* is registered first and is unchanged by the SPA migration.
    from admin.routes import api

    app.include_router(api.router, prefix="/api")

    # Routers with a single responsibility, still under /api.
    from admin.routes import miniapp, rule_hits, rules

    app.include_router(rules.router, prefix="/api/rules")
    app.include_router(rule_hits.router, prefix="/api/rule-hits")
    app.include_router(miniapp.router, prefix="/miniapp")

    _mount_spa(app)
    _mount_mini_app(app)

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


async def _notify_miniapp_scan(job, outcome, error):
    # NOTE the arity: ScanWorker invokes the completion handler as
    # `await self._on_complete(job, outcome, error)` -- three positional
    # arguments. This used to take `app` as well, so it raised TypeError on
    # every completed Mini App scan. The worker catches handler failures, so
    # scans still succeeded and the breakage was only visible as a traceback
    # in the admin log.
    #
    """Completion sink for Mini App scans.

    Silently succeeds: a scan that ran and stored its results must not be
    reported as failed because a notification could not be delivered. The
    Mini App polls /miniapp/scans/{id} for the outcome instead of relying on
    a push, so this only exists so ScanWorker has somewhere to call.
    """
    log.info(
        "Mini App scan %s finished: %s",
        job.target_name,
        "error" if error else "ok",
    )


def _build_miniapp_worker(app: FastAPI, settings: Settings, database) -> None:
    """Start a ScanWorker in this process for Mini App scans.

    The bot and the admin service are separate containers, so the admin
    service cannot reach the bot's worker. Running one here keeps Mini App
    scans on the same pipeline (same rules, same repositories, same change
    detection) without introducing a queue.

    Concurrency is deliberately low: two processes can now scan, so
    MAX_CONCURRENT_SCANS no longer bounds the deployment on its own. The real
    ceiling is the sum of both workers.
    """
    try:
        from core.scan_manager import ScanManager
        from parser.nmap_runner import NmapRunner
        from workers.scan_worker import ScanWorker

        concurrency = max(
            1, min(int(os.environ.get("MINIAPP_WORKER_CONCURRENCY", "1")), 4)
        )
        runner = NmapRunner(
            settings.nmap_binary, settings.scan_timeout_seconds
        )
        worker = ScanWorker(
            scan_manager=ScanManager(database, runner),
            max_concurrency=concurrency,
        )
        app.state.ctx.scan_worker = worker
        app.state.miniapp_worker = worker
        log.info("Mini App scan worker prepared (%d slot)", concurrency)
    except Exception:
        # Not fatal. Without a worker the Mini App answers 503 on /scan and
        # every other tab still works.
        log.warning("Could not prepare the Mini App worker", exc_info=True)


async def _start_miniapp_worker(app: FastAPI, settings: Settings, database):
    """Build the worker, then start it on the running event loop."""
    _build_miniapp_worker(app, settings, database)
    worker = getattr(app.state, "miniapp_worker", None)
    if worker is None:
        return
    try:
        await worker.start(_notify_miniapp_scan)
    except Exception:
        log.warning("Mini App worker failed to start", exc_info=True)


async def _stop_miniapp_worker(app: FastAPI) -> None:
    worker = getattr(app.state, "miniapp_worker", None)
    if worker is None:
        return
    try:
        await worker.stop()
    except Exception:
        log.warning("Mini App worker failed to stop cleanly", exc_info=True)


def _mount_mini_app(app: FastAPI) -> None:
    """Serve the Telegram Mini App under /app.

    Same ordering rule as the web panel: hashed assets are mounted before the
    catch-all, or a request for a .js file would be answered with index.html
    and the browser would refuse the module.
    """
    if not os.path.isdir(MINIAPP_DIST):
        log.warning(
            "Mini App build missing at %s - /app will return instructions. "
            "Build it with: cd mini-app && npm ci && npm run build",
            MINIAPP_DIST,
        )

        @app.get("/app", include_in_schema=False)
        @app.get("/app/{path:path}", include_in_schema=False)
        async def _miniapp_missing(path: str = ""):  # pragma: no cover
            return JSONResponse(
                status_code=503,
                content={
                    "detail": (
                        "Mini App is not built. Run: cd mini-app && "
                        "npm ci && npm run build"
                    )
                },
            )

        return

    assets_dir = os.path.join(MINIAPP_DIST, "assets")
    if os.path.isdir(assets_dir):
        app.mount(
            "/app/assets",
            StaticFiles(directory=assets_dir),
            name="miniapp-assets",
        )

    mini_router = APIRouter()

    @mini_router.get("/app", include_in_schema=False)
    @mini_router.get("/app/{path:path}", include_in_schema=False)
    async def _miniapp_spa(path: str = ""):
        """index.html for every Mini App route.

        Telegram opens the app inside a WebView at whatever path the user
        navigated to, so client-side routes must resolve to the shell.
        """
        return FileResponse(
            MINIAPP_INDEX, headers={"Cache-Control": "no-store"}
        )

    app.include_router(mini_router)
    log.info("Serving Mini App from %s", MINIAPP_DIST)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

# script-src must name https://telegram.org: the Mini App loads the Telegram
# WebApp SDK from there, and a bare 'self' blocks the one script it cannot
# work without. This is the single deviation from the policy originally
# proposed for this change, and it is deliberate -- a CSP that is not tested
# against the real pages is not hardening, it is an outage.
#
# style-src carries 'unsafe-inline' because the login page sets an inline
# background gradient through the style attribute.
#
# frame-ancestors 'none' plus X-Frame-Options: DENY keep the panel out of
# anyone else's iframe (clickjacking).
CSP = (
    "default-src 'self'; "
    "script-src 'self' https://telegram.org; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def add_security_headers(app: FastAPI, settings: Settings) -> None:
    """Attach conservative security headers to every response.

    Strict-Transport-Security is emitted only when ADMIN_COOKIE_SECURE is
    true. The panel is normally reached over plain HTTP on the LAN, and
    advertising HSTS there would pin the browser to https and lock the
    operator out of their own panel with no way back.
    """

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=()",
        )
        response.headers.setdefault(
            "Cross-Origin-Opener-Policy", "same-origin"
        )
        if getattr(settings, "admin_cookie_secure", False):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response
