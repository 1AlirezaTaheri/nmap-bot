"""JSON API routes for the admin panel."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from admin.services import audit as audit_service

from admin.services import auth as auth_service
from admin.services import captcha as captcha_service
from admin.services import stats as stats_service
from admin.services import users as user_service
from admin.services.auth import AuthError
from admin.services.bootstrap import AdminContext
from admin.services.settings_store import SETTING_SPECS, SettingError
from admin.deps import client_ip, current_principal, require_role
from core.target_manager import TargetRegistry
from database.repository import RepositoryError
from security.authorization import TargetNotAllowedError
from security.targets import TargetValidationError, validate_target

log = logging.getLogger(__name__)
router = APIRouter()

# Telegram user IDs are 32-bit today and documented to stay inside
# 52 bits. See the Field() bound below that depends on this.
MAX_TELEGRAM_USER_ID = 2 ** 52


def ctx(request: Request) -> AdminContext:
    return request.app.state.ctx


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)

    # Optional on purpose. Whether they are *required* is decided by
    # CAPTCHA_ENABLED at request time, so turning the setting off must
    # not start rejecting a payload shape that was valid before.
    captcha_token: str | None = Field(default=None, max_length=4096)
    captcha_answer: str | None = Field(default=None, max_length=64)


class PasswordBody(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class TelegramUserBody(BaseModel):
    # gt=0: a Telegram user id is a positive integer. A bare `int` accepted
    # 0 and negatives, producing rows the bot could never match.
    # Telegram IDs fit well inside 52 bits. The upper bound is what
    # keeps an absurd value out of PostgreSQL, where it would be an
    # unhandled `bigint out of range` DataError and a 500.
    telegram_user_id: int = Field(gt=0, le=MAX_TELEGRAM_USER_ID)
    username: str | None = Field(default=None, max_length=64)
    role: str | None = None
    language: str | None = None


class TelegramUserPatch(BaseModel):
    role: str | None = None
    language: str | None = None
    enabled: bool | None = None
    notifications_enabled: bool | None = None
    timezone: str | None = Field(default=None, max_length=64)


class SettingsPatch(BaseModel):
    values: dict[str, str]


class TargetBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=255)
    group: str | None = Field(default=None, max_length=64)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CAPTCHA
# ---------------------------------------------------------------------------


@router.get("/captcha")
async def get_captcha(request: Request):
    """Issue a login challenge.

    Unauthenticated by necessity -- it is the login page that needs it --
    so it shares the login rate limiter. Otherwise this endpoint would be
    a free, unthrottled way for a script to pull challenges in bulk.

    It answers whether or not CAPTCHA_ENABLED is set. A client may have a
    cached page; one extra cheap request beats a skew between what the
    page expects and what login will accept. The token is only *accepted*
    when the setting is on.
    """
    context = ctx(request)
    ip = client_ip(request)

    allowed, _remaining = context.login_limiter.check(ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Try again shortly.",
        )

    challenge = captcha_service.issue_challenge(ip, context.captcha_store)
    return {
        "question": challenge.question,
        "token": challenge.token,
        "expires_in": captcha_service.TOKEN_TTL_SECONDS,
    }


@router.post("/login")
async def login(request: Request, response: Response, body: LoginBody):
    """Authenticate an admin and set the session cookie."""
    context = ctx(request)
    ip = client_ip(request)
    ua = request.headers.get("user-agent")

    allowed, remaining = context.login_limiter.check(ip)
    if not allowed:
        # record_standalone, not `with database.session()`: raising inside the
        # block would roll the audit row back with the exception, so a
        # throttled attempt would leave no trace at all.
        audit_service.record_standalone(
            context.database,
            audit_service.AuditEntry(
                action="auth.login_failed",
                actor_type=audit_service.ACTOR_ADMIN,
                actor_username=body.username,
                details={"reason": "rate_limited"},
                ip_address=ip,
                user_agent=ua,
                success=False,
            ),
        )
        raise HTTPException(
            status_code=429, detail="Too many login attempts. Try again shortly."
        )

    def _reject(action_detail: str, admin_id: int | None, admin_name: str | None):
        """Persist a failed-login audit, then raise.

        Deliberately outside any transaction: an exception raised inside
        ``database.session()`` rolls back the audit row too, which would
        erase the record of exactly the attempts worth recording.
        """
        audit_service.record_standalone(
            context.database,
            audit_service.AuditEntry(
                action="auth.login_failed",
                actor_id=admin_id,
                actor_username=admin_name,
                actor_type=audit_service.ACTOR_ADMIN,
                details={"reason": action_detail},
                ip_address=ip,
                user_agent=ua,
                success=False,
            ),
        )

    if context.settings.captcha_enabled:
        # After the rate limiter, before the password. The order is the
        # point:
        #
        #  * the limiter runs first, so a flood of wrong answers still
        #    costs the attacker a slot rather than being free;
        #  * the challenge runs before verify_password, so a wrong answer
        #    never reaches bcrypt at cost 12.
        #
        # With the setting off nothing is read and the path is identical
        # to before: same statuses, same audit rows.
        captcha_ok, captcha_reason = captcha_service.verify_challenge(
            body.captcha_token or "",
            body.captcha_answer or "",
            ip,
            context.captcha_store,
        )
        if not captcha_ok:
            # Audited like a bad password: a run of failed challenges is
            # exactly what is worth seeing afterwards. Neither the
            # supplied answer nor the expected one is recorded.
            _reject(f"captcha_{captcha_reason}", None, body.username)
            raise HTTPException(
                status_code=400,
                detail="Incorrect or expired CAPTCHA. Please try again.",
            )

    with context.database.session() as session:
        row = user_service.get_admin_by_username(session, body.username)

        if row is None or not auth_service.verify_password(
            body.password, row.password_hash
        ):
            # Same response for unknown user and bad password, so the
            # endpoint cannot be used to enumerate usernames.
            _reject("bad_credentials", None, body.username)
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        if not row.enabled:
            _reject("disabled", row.id, row.username)
            raise HTTPException(status_code=403, detail="Account disabled.")

        if auth_service.needs_rehash(row.password_hash):
            try:
                row.password_hash = auth_service.hash_password(body.password)
            except AuthError:
                pass  # short password: keep the existing hash

        user_service.touch_login(session, row.id)
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="auth.login",
                actor_id=row.id,
                actor_username=row.username,
                actor_type=audit_service.ACTOR_ADMIN,
                details={"role": row.role},
                ip_address=ip,
                user_agent=ua,
                success=True,
            ),
        )
        principal = auth_service.Principal(
            id=row.id, username=row.username, role=row.role
        )

    token = auth_service.issue_token(principal)
    context.login_limiter.reset(ip)

    response.set_cookie(
        key=auth_service.COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=context.settings.admin_cookie_secure,
        max_age=auth_service.ACCESS_TOKEN_TTL_SECONDS,
        path="/",
    )
    return {
        "username": principal.username,
        "role": principal.role,
        "csrf_required": False,
    }


@router.post("/logout")
async def logout(request: Request, response: Response,
                 principal=Depends(current_principal)):
    context = ctx(request)
    with context.database.session() as session:
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="auth.logout",
                actor_id=principal.id,
                actor_username=principal.username,
                actor_type=audit_service.ACTOR_ADMIN,
                ip_address=client_ip(request),
                user_agent=request.headers.get("user-agent"),
            ),
        )
    response.delete_cookie(auth_service.COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
async def me(principal=Depends(current_principal)):
    return {
        "id": principal.id,
        "username": principal.username,
        "role": principal.role,
    }


@router.post("/password")
async def change_password(request: Request, body: PasswordBody,
                          principal=Depends(current_principal)):
    """Change the signed-in admin's own password."""
    context = ctx(request)
    with context.database.session() as session:
        row = user_service.get_admin(session, principal.id)
        if row is None:
            raise HTTPException(status_code=404, detail="Admin not found.")
        if not auth_service.verify_password(body.password, row.password_hash):
            raise HTTPException(status_code=400, detail="Current password is wrong.")
    try:
        new_hash = auth_service.hash_password(body.password)
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with context.database.session() as session:
        user_service.set_password(session, principal.id, new_hash)
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="user.update",
                actor_id=principal.id,
                actor_username=principal.username,
                actor_type=audit_service.ACTOR_ADMIN,
                target_type="admin_user",
                target_id=str(principal.id),
                details={"field": "password"},
                ip_address=client_ip(request),
            ),
        )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Telegram users
# ---------------------------------------------------------------------------


@router.get("/users", deprecated=True)
@router.get("/telegram-users")
async def list_users(request: Request, principal=Depends(require_role("admin"))):
    """Telegram users, annotated with real bot access.

    `in_allow_list` and `effective_access` exist because the bot enforces two
    independent gates: the telegram_users row must be enabled AND the id must
    appear in ALLOWED_USER_IDS. Without these an operator could enable a user
    who the bot would still refuse with "auth.denied" and no explanation.
    """
    context = ctx(request)
    allowed = set(context.settings.allowed_user_ids)
    with context.database.session() as session:
        rows = user_service.list_telegram_users(session)
    for row in rows:
        row["in_allow_list"] = row["telegram_user_id"] in allowed
        row["effective_access"] = bool(row["enabled"]) and row["in_allow_list"]
    return {"users": rows, "allow_list_size": len(allowed)}


@router.post("/users", deprecated=True)
@router.post("/telegram-users")
async def add_user(request: Request, body: TelegramUserBody,
                   principal=Depends(require_role("superadmin"))):
    """Create a Telegram user. superadmin only: this grants bot access.

    Deliberately does NOT touch ALLOWED_USER_IDS. That file is the bot's own
    gate, editing it from the panel would need a bot restart to take effect,
    and the requirement is to leave it untouched. The response reports
    `in_allow_list` so the panel can say plainly that access is still
    pending rather than implying it was granted.
    """
    context = ctx(request)
    with context.database.session() as session:
        if user_service.get_telegram_user(session, body.telegram_user_id) is not None:
            raise HTTPException(
                status_code=409,
                detail=f"User {body.telegram_user_id} already exists.",
            )
        row = user_service.upsert_telegram_user(
            session,
            body.telegram_user_id,
            username=body.username,
            role=body.role,
            language=body.language,
        )
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="telegram_user.created",
                actor_id=principal.id,
                actor_username=principal.username,
                actor_type=audit_service.ACTOR_ADMIN,
                target_type="telegram_user",
                target_id=str(body.telegram_user_id),
                details={"role": row.role, "language": row.language},
                ip_address=client_ip(request),
            ),
        )
        in_allow = row.telegram_user_id in set(context.settings.allowed_user_ids)
        return {"telegram_user_id": row.telegram_user_id, "role": row.role,
                "language": row.language, "enabled": row.enabled,
                "in_allow_list": in_allow,
                "effective_access": bool(row.enabled) and in_allow}


@router.patch("/users/{telegram_user_id}", deprecated=True)
@router.patch("/telegram-users/{telegram_user_id}")
async def patch_user(request: Request, telegram_user_id: int,
                     body: TelegramUserPatch,
                     principal=Depends(require_role("admin"))):
    context = ctx(request)
    with context.database.session() as session:
        try:
            row = user_service.update_telegram_user(
                session,
                telegram_user_id,
                role=body.role,
                language=body.language,
                enabled=body.enabled,
                notifications_enabled=body.notifications_enabled,
                timezone=body.timezone,
            )
        except user_service.UserError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="telegram_user.updated",
                actor_id=principal.id,
                actor_username=principal.username,
                actor_type=audit_service.ACTOR_ADMIN,
                target_type="telegram_user",
                target_id=str(telegram_user_id),
                details=body.model_dump(exclude_none=True),
                ip_address=client_ip(request),
            ),
        )
        in_allow = row.telegram_user_id in set(context.settings.allowed_user_ids)
        return {
            "telegram_user_id": row.telegram_user_id,
            "role": row.role,
            "language": row.language,
            "enabled": row.enabled,
            "notifications_enabled": row.notifications_enabled,
            "in_allow_list": in_allow,
            "effective_access": bool(row.enabled) and in_allow,
        }


@router.delete("/users/{telegram_user_id}", deprecated=True)
@router.delete("/telegram-users/{telegram_user_id}")
async def delete_user(request: Request, telegram_user_id: int,
                      confirm: bool = False,
                      principal=Depends(require_role("superadmin"))):
    """Remove a Telegram user. superadmin only.

    The row is discarded entirely, so any telegram role the operator held
    is lost with it.
    """
    context = ctx(request)
    with context.database.session() as session:
        if not confirm:
            raise HTTPException(
                status_code=400,
                detail="Pass confirm=true to remove this user.",
            )
        removed = user_service.delete_telegram_user(session, telegram_user_id)
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="telegram_user.deleted",
                actor_id=principal.id,
                actor_username=principal.username,
                actor_type=audit_service.ACTOR_ADMIN,
                target_type="telegram_user",
                target_id=str(telegram_user_id),
                details={"removed": removed},
                ip_address=client_ip(request),
                success=removed,
            ),
        )
    if not removed:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


@router.get("/audit")
async def list_audit(
    request: Request,
    actor_id: int | None = None,
    actor_type: str | None = None,
    action: str | None = None,
    success: bool | None = None,
    since: str | None = None,
    until: str | None = None,
    page: int = 1,
    page_size: int = 50,
    principal=Depends(current_principal),
):
    context = ctx(request)
    since_dt = _parse_dt(since)
    until_dt = _parse_dt(until)

    with context.database.session() as session:
        rows, total = audit_service.query(
            session,
            audit_service.AuditQuery(
                actor_id=actor_id,
                actor_type=actor_type,
                action=action,
                success=success,
                since=since_dt,
                until=until_dt,
                page=page,
                page_size=page_size,
            ),
        )
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "entries": [_audit_row(r) for r in rows],
        }


@router.get("/audit/export.csv")
async def export_audit(
    request: Request,
    action: str | None = None,
    success: bool | None = None,
    actor_id: int | None = None,
    principal=Depends(require_role("admin")),
):
    context = ctx(request)
    with context.database.session() as session:
        rows, _total = audit_service.query(
            session,
            audit_service.AuditQuery(
                actor_id=actor_id, action=action, success=success, page_size=200,
            ),
        )
        csv_text = audit_service.to_csv(rows)

    from fastapi.responses import Response as R

    return R(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="netsentinel-audit.csv"'
        },
    )


def _audit_row(row) -> dict:
    import json

    details = None
    if row.details:
        try:
            details = json.loads(row.details)
        except json.JSONDecodeError:
            details = row.details
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "actor_type": row.actor_type,
        "actor_id": row.actor_id,
        "actor_username": row.actor_username,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "details": details,
        "ip_address": row.ip_address,
        "success": row.success,
    }


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise HTTPException(status_code=400, detail=f"Bad timestamp: {value}")


# ---------------------------------------------------------------------------
# System settings
# ---------------------------------------------------------------------------


@router.get("/settings")
async def get_settings(request: Request,
                        principal=Depends(current_principal)):
    context = ctx(request)
    values = context.settings_store.all()
    with context.database.session() as session:
        from sqlalchemy import select

        from database.models import SystemSetting

        updated = {
            r.key: (r.updated_at, r.updated_by)
            for r in session.scalars(select(SystemSetting))
        }
    return {
        "settings": {
            key: {
                "value": value,
                "default": spec[0],
                "kind": spec[1],
                "description": spec[2],
                "updated_at": (
                    updated.get(key, (None, None))[0].isoformat()
                    if updated.get(key, (None, None))[0] is not None
                    else None
                ),
                "updated_by": updated.get(key, (None, None))[1],
            }
            for key, spec in SETTING_SPECS.items()
            for value in [values.get(key, spec[0])]
        }
    }


@router.patch("/settings")
async def patch_settings(request: Request, body: SettingsPatch,
                         principal=Depends(require_role("admin"))):
    """Update settings. Takes effect without a bot restart."""
    context = ctx(request)
    unknown = [k for k in body.values if k not in SETTING_SPECS]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown setting(s): {', '.join(sorted(unknown))}",
        )
    with context.database.session() as session:
        try:
            applied = context.settings_store.set_many(
                session, body.values, principal.username
            )
        except SettingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="settings.update",
                actor_id=principal.id,
                actor_username=principal.username,
                actor_type=audit_service.ACTOR_ADMIN,
                details={"applied": applied},
                ip_address=client_ip(request),
            ),
        )
    return {"settings": applied}


# ---------------------------------------------------------------------------
# Live dashboard series (Phase 2)
#
# New paths only. /api/stats keeps its exact response so nothing existing
# breaks; the dashboard calls these alongside it.
# ---------------------------------------------------------------------------


@router.get("/stats/top-targets")
async def stats_top_targets(
    request: Request,
    days: int = 7,
    limit: int = 5,
    principal=Depends(current_principal),
):
    """Targets with the most change events, worst first.

    `days` is clamped for the same reason as in /api/stats: it feeds a date
    arithmetic subtraction, and an unbounded value would walk far enough back
    to be a slow query rather than an error.
    """
    del principal  # authentication only; this is not per-user
    days = max(1, min(days, 90))
    limit = max(1, min(limit, 25))
    context = ctx(request)
    with context.database.session() as session:
        return {
            "targets": stats_service.top_changed_targets(
                session, days=days, limit=limit
            ),
            "days": days,
        }


@router.get("/stats/worker")
async def stats_worker(request: Request,
                       principal=Depends(current_principal)):
    """Live counters from the admin process's own scan worker.

    Reports `available: false` with null counters when this process runs no
    worker, which is the normal case -- the bot process owns the queue and runs
    its own worker instance. Returning zeros there would read as "idle" and be
    wrong.
    """
    del principal  # authentication only
    context = ctx(request)
    return stats_service.worker_status(
        getattr(context, "scan_worker", None)
    )


@router.get("/stats/schedule")
async def stats_schedule(request: Request,
                         principal=Depends(current_principal)):
    """The scheduler switch and its interval.

    `next_run_at` is always null and `next_run_known` false: nothing stores a
    next-run time, and deriving one from the interval would be a guess dressed
    as data. The dashboard says so rather than showing a plausible number.
    """
    del principal  # authentication only
    context = ctx(request)
    return stats_service.schedule_status(context.settings_store)


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


@router.get("/targets")
async def list_targets(request: Request,
                       principal=Depends(current_principal)):
    context = ctx(request)
    with context.database.session() as session:
        return {"targets": stats_service.targets_with_counts(session)}


@router.post("/targets")
async def add_target(request: Request, body: TargetBody,
                     principal=Depends(require_role("admin"))):
    context = ctx(request)
    registry = TargetRegistry(context.database, context.authorizer)
    try:
        target = registry.add(body.name, body.value, body.group)
    except (TargetValidationError, TargetNotAllowedError) as exc:
        # Malformed or out-of-scope: a client error, not a conflict.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RepositoryError as exc:
        # Duplicate name — genuinely a conflict.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    with context.database.session() as session:
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="target.add",
                actor_id=principal.id,
                actor_username=principal.username,
                actor_type=audit_service.ACTOR_ADMIN,
                target_type="target",
                target_id=target.name,
                details={"value": target.value},
                ip_address=client_ip(request),
            ),
        )
    return {"name": target.name, "value": target.value}


@router.delete("/targets/{target_id}")
async def purge_target(request: Request, target_id: int, confirm: bool = False,
                       principal=Depends(require_role("superadmin"))):
    """Purge a target and all history. Superadmin only.

    Irreversible, and it destroys the security record, so it is gated
    above plain admin and demands an explicit ``confirm``.
    """
    context = ctx(request)
    from database.models import Target
    from database.repository import TargetRepository

    with context.database.session() as session:
        repo = TargetRepository(session)
        row = repo.get(target_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Target not found.")
        name = row.name
        if not confirm:
            pending = repo.pending_counts(target_id)
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Pass confirm=true. This deletes {pending['scans']} scan(s), "
                    f"{pending['hosts']} host(s), {pending['services']} service(s), "
                    f"{pending['change_events']} change event(s)."
                ),
            )
        counts = repo.purge_by_id(target_id)
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="target.purge",
                actor_id=principal.id,
                actor_username=principal.username,
                actor_type=audit_service.ACTOR_ADMIN,
                target_type="target",
                target_id=str(target_id),
                details={"name": name, **counts},
                ip_address=client_ip(request),
            ),
        )
    return {"purged": name, "counts": counts}


@router.get("/targets/{target_id}/scans")
async def target_scans(request: Request, target_id: int, limit: int = 25,
                       principal=Depends(current_principal)):
    context = ctx(request)
    with context.database.session() as session:
        return {"scans": stats_service.target_scans(session, target_id, limit)}


@router.get("/targets/{target_id}/changes")
async def target_changes(request: Request, target_id: int, limit: int = 100,
                         principal=Depends(current_principal)):
    context = ctx(request)
    with context.database.session() as session:
        return {"changes": stats_service.target_changes(session, target_id, limit)}


# ---------------------------------------------------------------------------
# Dashboard data
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_stats(request: Request, days: int = 7,
                    principal=Depends(current_principal)):
    context = ctx(request)
    with context.database.session() as session:
        stats = stats_service.dashboard(session, days=days)
        return {
            "targets": stats.targets,
            "scans": stats.scans,
            "scans_24h": stats.scans_24h,
            "scans_24h_failed": stats.scans_24h_failed,
            "changes": stats.changes,
            "changes_24h": stats.changes_24h,
            "telegram_users": stats.telegram_users,
            "admins": stats.admins,
            "hosts": stats.hosts,
            "services": stats.services,
            "last_scan_at": (
                stats.last_scan_at.isoformat() if stats.last_scan_at else None
            ),
            "series": stats.series,
            "change_breakdown": stats_service.change_breakdown(session, days),
            "recent_audit": stats_service.recent_audit(session),
            "operator_chat": stats_service.operator_chat(session),
        }


@router.get("/stats/series")
async def stats_series(request: Request, days: int = 7,
                       principal=Depends(current_principal)):
    """Daily scans + change events, without the rest of the dashboard.

    The chart fetches this on its own so it can extend the window (30/90
    days) without re-downloading every counter on the page.
    """
    del principal  # authentication only; the series is not per-user
    days = max(1, min(days, 365))
    context = ctx(request)
    with context.database.session() as session:
        return {"series": stats_service.daily_series(session, days=days)}


@router.get("/health")
async def health(request: Request):
    """Liveness probe. No auth: the container healthcheck uses it."""
    context = ctx(request)
    db_ok = True
    db_error = None
    try:
        from sqlalchemy import text

        with context.database.session() as session:
            session.execute(text("SELECT 1"))
    except Exception as exc:
        db_ok = False
        db_error = f"{type(exc).__name__}: {exc}"
    return {
        "status": "ok" if db_ok else "degraded",
        "database": "ok" if db_ok else db_error,
    }