"""FastAPI dependencies: cookie auth and role gates."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from admin.services import auth as auth_service
from admin.services.auth import AuthError, Principal
from admin.services.bootstrap import AdminContext


def ctx(request: Request) -> AdminContext:
    return request.app.state.ctx


def client_ip(request: Request) -> str:
    """Best-effort client IP.

    ``X-Forwarded-For`` is only trusted when the app is configured to sit
    behind a proxy; otherwise a client could spoof it to evade the login
    rate limit.
    """
    context = ctx(request)
    if getattr(context.settings, "admin_trust_forwarded_for", False):
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _cookie_token(request: Request) -> str | None:
    return request.cookies.get(auth_service.COOKIE_NAME)


def current_principal(request: Request) -> Principal:
    """Require a valid session cookie.

    The account is re-checked against the database on every request, so
    disabling an admin takes effect immediately instead of at token expiry.
    """
    token = _cookie_token(request)
    if not token:
        # Accept a bearer token too, so the API can be scripted.
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            token = header[7:].strip()

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    try:
        principal = auth_service.decode_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    from admin.services import users as user_service

    context = ctx(request)
    with context.database.session() as session:
        row = user_service.get_admin(session, principal.id)

    if row is None:
        raise HTTPException(status_code=401, detail="Account no longer exists.")
    if not row.enabled:
        raise HTTPException(status_code=403, detail="Account disabled.")
    # Trust the database for the role, not the token: a role change must
    # take effect without waiting for the token to expire.
    if row.role != principal.role:
        principal = Principal(
            id=row.id, username=row.username, role=row.role
        )

    return principal


def require_role(required: str):
    """Dependency factory enforcing a minimum role."""

    def _guard(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.has_role(required):
            raise HTTPException(
                status_code=403,
                detail=f"Requires '{required}' role or higher.",
            )
        return principal

    _guard.__name__ = f"require_{required}"
    return _guard