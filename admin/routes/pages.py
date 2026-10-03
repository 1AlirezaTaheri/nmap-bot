"""Server-rendered pages."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from admin.deps import client_ip, current_principal
from admin.services import audit as audit_service
from admin.services import stats as stats_service
from admin.services import users as user_service
from admin.services.auth import AuthError
from admin.services.bootstrap import AdminContext
from admin.services.settings_store import SETTING_SPECS
from admin.templates import TEMPLATE_ENV

log = logging.getLogger(__name__)
router = APIRouter()

PAGES = (
    ("dashboard", "/admin"),
    ("users", "/admin/users"),
    ("targets", "/admin/targets"),
    ("audit", "/admin/audit"),
    ("settings", "/admin/settings"),
)


def _ctx(request: Request) -> AdminContext:
    return request.app.state.ctx


def _nav(active: str) -> str:
    """Render the sidebar with the current page marked."""
    labels = {
        "dashboard": "Dashboard",
        "users": "Telegram Users",
        "targets": "Targets",
        "audit": "Audit Log",
        "settings": "Settings",
    }
    items = []
    for key, _href in PAGES:
        cls = "nav-item active" if key == active else "nav-item"
        items.append(
            f'<a class="{cls}" href="/admin{"" if key == "dashboard" else "/" + key}">'
            f"{labels[key]}</a>"
        )
    return "".join(items)


def _fmt(value: datetime | None, fallback: str = "—") -> str:
    if value is None:
        return fallback
    if isinstance(value, str):
        return value
    return value.strftime("%Y-%m-%d %H:%M")


def _page(template: str, active: str, request: Request, principal, **ctx) -> HTMLResponse:
    return HTMLResponse(
        TEMPLATE_ENV.get_template(template).render(
            nav=_nav(active),
            active=active,
            principal=principal,
            request_path=request.url.path,
            **ctx,
        )
    )


@router.get("/", include_in_schema=False)
async def root():
    """Send anonymous visitors to the login page."""
    return RedirectResponse(url="/admin/login")


@router.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return HTMLResponse(
        TEMPLATE_ENV.get_template("login.html").render(
            error=request.query_params.get("error"),
            next=request.query_params.get("next", "/admin"),
        )
    )


@router.post("/admin/logout")
async def logout_page(request: Request):
    """Form-friendly logout: clears the cookie then redirects to login.

    ``/api/logout`` returns JSON, which would render as raw text in the
    browser when posted from the sidebar form.
    """
    from admin.services import auth as auth_service

    response = RedirectResponse(url="/admin/login", status_code=303)
    response.delete_cookie(auth_service.COOKIE_NAME, path="/")
    return response


@router.get("/admin", response_class=HTMLResponse)
async def dashboard(request: Request):
    principal = _optional_principal(request)
    if principal is None:
        return RedirectResponse(url="/admin/login?next=/admin")

    context = _ctx(request)
    with context.database.session() as session:
        stats = stats_service.dashboard(session)
        breakdown = stats_service.change_breakdown(session)
        recent = stats_service.recent_audit(session)
        opchat = stats_service.operator_chat(session)

    return _page(
        "dashboard.html",
        "dashboard",
        request,
        principal,
        stats=stats,
        breakdown=breakdown,
        recent=recent,
        operator_chat=opchat,
        fmt=_fmt,
    )


@router.get("/admin/users", response_class=HTMLResponse)
async def users_page(request: Request):
    principal = _optional_principal(request)
    if principal is None:
        return RedirectResponse(url="/admin/login?next=/admin/users")

    context = _ctx(request)
    with context.database.session() as session:
        rows = user_service.list_telegram_users(session)
        admins = user_service.list_admins(session)

    return _page(
        "users.html",
        "users",
        request,
        principal,
        users=rows,
        admins=admins,
        fmt=_fmt,
        roles=("viewer", "operator", "admin"),
        languages=("fa", "en"),
    )


@router.get("/admin/targets", response_class=HTMLResponse)
async def targets_page(request: Request):
    principal = _optional_principal(request)
    if principal is None:
        return RedirectResponse(url="/admin/login?next=/admin/targets")

    context = _ctx(request)
    with context.database.session() as session:
        rows = stats_service.targets_with_counts(session)

    return _page("targets.html", "targets", request, principal, targets=rows, fmt=_fmt)


@router.get("/admin/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    principal = _optional_principal(request)
    if principal is None:
        return RedirectResponse(url="/admin/login?next=/admin/audit")

    context = _ctx(request)
    action = request.query_params.get("action") or None
    success_raw = request.query_params.get("success")
    success = None
    if success_raw in ("true", "false"):
        success = success_raw == "true"

    with context.database.session() as session:
        entries, total = audit_service.query(
            session,
            audit_service.AuditQuery(action=action, success=success, page_size=100),
        )

    return _page(
        "audit.html",
        "audit",
        request,
        principal,
        entries=entries,
        total=total,
        actions=audit_service.ACTIONS,
        fmt=_fmt,
        selected_action=action or "",
        selected_success=success_raw or "",
    )


@router.get("/admin/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    principal = _optional_principal(request)
    if principal is None:
        return RedirectResponse(url="/admin/login?next=/admin/settings")

    context = _ctx(request)
    values = context.settings_store.all()

    return _page(
        "settings.html",
        "settings",
        request,
        principal,
        settings=values,
        specs=SETTING_SPECS,
        languages=("fa", "en"),
        profiles=("quick", "service", "deep"),
    )


def _optional_principal(request: Request):
    """Resolve the session cookie, or None when absent/invalid."""
    from admin.services import auth as auth_service

    token = request.cookies.get(auth_service.COOKIE_NAME)
    if not token:
        return None
    try:
        principal = auth_service.decode_token(token)
    except AuthError:
        return None
    return principal