"""Telegram Mini App API, mounted at /miniapp.

Authenticated by Telegram's signed ``initData`` rather than the admin
session cookie, so there is no password to phish and no login form: Telegram
asserts the user's identity and this module verifies the signature.

Authorization is layered on top of authentication, and the layering matters:

* the user must be in ``ALLOWED_USER_IDS`` (mirroring ``/scan`` in the bot);
* the account must not be disabled in ``telegram_users``;
* writes that the bot gates behind the ``operator`` role are gated here too.

Every read reuses the existing services (``admin.services.stats``,
``database.repository``, ``core.rules``). There is no second copy of any
query, so the Mini App and the web panel can never disagree about what the
database says.

Scan requests go through the same rule engine and the same rate limiter the
bot uses, reached through the worker that is already running in the admin
process. A Mini App scan is therefore indistinguishable from a ``/scan`` for
every policy and limit that applies.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from admin.deps import client_ip, ctx
from admin.routes.rules import _hit_json, _iso
from admin.services import audit as audit_service
from admin.services import stats as stats_service
from admin.services import users as user_service
from admin.services.users import UserError
from core import miniapp_auth
from core.miniapp_auth import MiniAppAuthError, MiniAppUser
from core.profiles import get_profile, profile_names
from core.rules import RuleContext, RuleEngine
from core.target_manager import TargetRegistry
from database.repository import (
    RepositoryError,
    RuleRepository,
    ScanRepository,
)
from security.authorization import TargetNotAllowedError
from security.targets import TargetValidationError

log = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class MiniTargetBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=255)
    group: str | None = Field(default=None, max_length=64)


class MiniScanBody(BaseModel):
    target: str = Field(min_length=1, max_length=64)
    profile: str | None = Field(default=None, max_length=32)


class MiniSettingsBody(BaseModel):
    # 16, not 4: Telegram sends regional codes ("en-US", "fa-IR") and
    # the handler below reduces them to the primary subtag. A 4-char cap
    # rejected the very input this field exists to accept.
    language: str | None = Field(default=None, max_length=16)
    notifications_enabled: bool | None = None


class MiniRuleTestBody(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    ports: list[int] | None = None
    actor_id: int | None = None
    now: str | None = Field(default=None, max_length=64)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def _settings(request: Request):
    return ctx(request).settings


def miniapp_user(request: Request) -> MiniAppUser:
    """Validate ``X-Telegram-Init-Data`` and return the Telegram user.

    Raises 401 for anything untrustworthy. The failure is audited with a
    machine-readable code rather than the attacker's text, so a probe cannot
    write arbitrary content into the audit log.
    """
    settings = _settings(request)
    header = request.headers.get("x-telegram-init-data", "")
    context = ctx(request)

    try:
        result = miniapp_auth.validate_init_data(
            header,
            settings.telegram_bot_token,
            max_age_seconds=settings.miniapp_max_age_seconds,
        )
    except MiniAppAuthError as exc:
        audit_service.record_standalone(
            context.database,
            audit_service.AuditEntry(
                action="miniapp.auth_failed",
                actor_type=audit_service.ACTOR_TELEGRAM,
                details={"code": exc.code},
                ip_address=client_ip(request),
                success=False,
            ),
        )
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    payload = result["user"]
    telegram_id = int(payload["id"])

    if telegram_id not in settings.allowed_user_ids:
        audit_service.record_standalone(
            context.database,
            audit_service.AuditEntry(
                action="miniapp.auth_failed",
                actor_id=telegram_id,
                actor_username=payload.get("username"),
                actor_type=audit_service.ACTOR_TELEGRAM,
                details={"code": "not_allowed"},
                ip_address=client_ip(request),
                success=False,
            ),
        )
        raise HTTPException(
            status_code=403, detail="This account may not use the dashboard."
        )

    # Ensure the row exists before checking `enabled`: a user in
    # ALLOWED_USER_IDS who has never run /start has no row yet, and only the
    # bot's startup syncs those.
    #
    # The locale is passed ONLY when creating the row. upsert_telegram_user
    # applies a supplied language on every call, not just on insert, so
    # passing it unconditionally would stamp over the choice someone saved in
    # Settings on their very next request.
    resolved_name = payload.get("username")
    with context.database.session() as session:
        existing = user_service.get_telegram_user(session, telegram_id)
        row = user_service.upsert_telegram_user(
            session,
            telegram_id,
            username=resolved_name,
            language=(
                None
                if existing is not None
                else _seed_language_from_locale(payload.get("language_code"))
            ),
        )
        if not row.enabled:
            audit_service.record_standalone(
                context.database,
                audit_service.AuditEntry(
                    action="miniapp.auth_failed",
                    actor_id=telegram_id,
                    actor_username=resolved_name,
                    actor_type=audit_service.ACTOR_TELEGRAM,
                    details={"code": "disabled"},
                    ip_address=client_ip(request),
                    success=False,
                ),
            )
            raise HTTPException(
                status_code=403, detail="Account disabled."
            )

    return MiniAppUser(
        id=telegram_id,
        first_name=str(payload.get("first_name") or "there"),
        last_name=payload.get("last_name"),
        username=resolved_name,
        language_code=payload.get("language_code"),
        is_premium=bool(payload.get("is_premium")),
        photo_url=payload.get("photo_url"),
        auth_date=result["auth_date"],
    )


def _seed_language_from_locale(language_code: str | None) -> str | None:
    """Map Telegram's locale onto a supported language.

    Returns None when Telegram did not say, which leaves the default in place
    rather than guessing.
    """
    from core.i18n import SUPPORTED

    if not language_code:
        return None
    code = language_code.split("-")[0].lower()
    return code if code in SUPPORTED else None


def _require_operator(session, user: MiniAppUser) -> dict:
    """Fetch the user's row and refuse anything below operator."""
    row = user_service.get_telegram_user(session, user.id)
    if row is None:  # pragma: no cover - miniapp_user upserts first
        raise HTTPException(
            status_code=403, detail="Account not registered."
        )
    if not row.enabled:
        raise HTTPException(status_code=403, detail="Account disabled.")
    if row.role not in ("operator", "admin"):
        raise HTTPException(
            status_code=403, detail="This account cannot make changes."
        )
    return {
        "telegram_user_id": row.telegram_user_id,
        "username": row.username,
        "role": row.role,
        "language": row.language,
        "notifications_enabled": row.notifications_enabled,
    }


# ---------------------------------------------------------------------------
# Identity and settings
# ---------------------------------------------------------------------------


@router.get("/me")
async def me(request: Request, user: MiniAppUser = Depends(miniapp_user)):
    context = ctx(request)

    # Read only. The miniapp_user dependency has already created the row if it
    # was missing, refreshed the username, and refused the request if the
    # account is disabled -- so there is nothing left to write here.
    #
    # This handler used to upsert, and passed Telegram's language_code along.
    # upsert_telegram_user applies a supplied language on EVERY call, not only
    # on insert, so that silently overwrote the language someone had chosen in
    # Settings on their very next request. Creating the row belongs in exactly
    # one place; this is not it.
    with context.database.session() as session:
        row = user_service.get_telegram_user(session, user.id)
        # Unreachable: the dependency guarantees a row. Falling back to
        # defaults keeps a None from turning into an AttributeError 500.
        role = row.role if row is not None else "viewer"
        language = row.language if row is not None else "fa"
        notifications = (
            bool(row.notifications_enabled) if row is not None else True
        )
        enabled = bool(row.enabled) if row is not None else False

    audit_service.record_standalone(
        context.database,
        audit_service.AuditEntry(
            action="miniapp.auth",
            actor_id=user.id,
            actor_username=user.username,
            actor_type=audit_service.ACTOR_TELEGRAM,
            ip_address=client_ip(request),
        ),
    )

    return {
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "username": user.username,
        "display_name": user.display_name,
        "photo_url": user.photo_url,
        "is_premium": user.is_premium,
        "language_code": user.language_code,
        "role": role,
        "language": language,
        "notifications_enabled": notifications,
        "enabled": enabled,
    }


@router.patch("/settings")
async def update_settings(
    request: Request,
    body: MiniSettingsBody,
    user: MiniAppUser = Depends(miniapp_user),
):
    from core.i18n import available_languages, normalize_lang

    context = ctx(request)
    updates: dict[str, Any] = {}
    if body.language is not None:
        # normalize_lang() coerces anything unknown to the default, so
        # validating with it would accept "en-US" and quietly store
        # Persian. Check the primary subtag against the vocabulary
        # instead: Telegram sends regional codes like "en-US".
        supported = tuple(available_languages()) or ("fa", "en")
        primary = body.language.strip().split("-")[0].lower()
        if primary not in supported:
            raise HTTPException(
                status_code=400,
                detail=f"language must be one of {', '.join(supported)}",
            )
        updates["language"] = primary
    if body.notifications_enabled is not None:
        updates["notifications_enabled"] = bool(body.notifications_enabled)

    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update.")

    with context.database.session() as session:
        try:
            user_service.update_telegram_user(session, user.id, **updates)
        except UserError as exc:
            # Unreachable now that /me upserts, but a 403 says "not
            # permitted" where a bare UserError would become a 500.
            raise HTTPException(
                status_code=403, detail=str(exc)
            ) from exc
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="miniapp.settings_update",
                actor_id=user.id,
                actor_username=user.username,
                actor_type=audit_service.ACTOR_TELEGRAM,
                details=updates,
                ip_address=client_ip(request),
            ),
        )

    return {"updated": updates}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@router.get("/stats")
async def stats(request: Request, days: int = 7,
                user: MiniAppUser = Depends(miniapp_user)):
    days = max(1, min(days, 90))
    context = ctx(request)
    with context.database.session() as session:
        data = stats_service.dashboard(session, days=days)
        breakdown = stats_service.change_breakdown(session, days)
    return {
        "targets": data.targets,
        "scans": data.scans,
        "scans_24h": data.scans_24h,
        "scans_24h_failed": data.scans_24h_failed,
        "changes": data.changes,
        "changes_24h": data.changes_24h,
        "hosts": data.hosts,
        "services": data.services,
        "last_scan_at": _iso(data.last_scan_at),
        "series": data.series,
        "change_breakdown": breakdown,
    }


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


@router.get("/targets")
async def list_targets(request: Request,
                       user: MiniAppUser = Depends(miniapp_user)):
    context = ctx(request)
    with context.database.session() as session:
        rows = stats_service.targets_with_counts(session)
    return {"targets": [_mini_target(r) for r in rows], "total": len(rows)}


def _mini_target(row: dict) -> dict:
    """Target shape for the Mini App, with the host counts for the sparkline."""
    return {
        "id": row["id"],
        "name": row["name"],
        "value": row["value"],
        "group": row["group"],
        "scan_count": row["scan_count"],
        "succeeded_count": row["succeeded_count"],
        "failed_count": row["failed_count"],
        "last_scan_at": _iso(row["last_scan_at"]),
        "created_at": _iso(row["created_at"]),
        "schedule": (
            {
                "profile": row["schedule"]["profile"],
                "interval_hours": row["schedule"]["interval_hours"],
                "enabled": row["schedule"]["enabled"],
                "next_run_at": _iso(row["schedule"]["next_run_at"]),
            }
            if row.get("schedule")
            else None
        ),
    }


@router.post("/targets", status_code=201)
async def add_target(request: Request, body: MiniTargetBody,
                     user: MiniAppUser = Depends(miniapp_user)):
    context = ctx(request)
    with context.database.session() as session:
        _require_operator(session, user)

    registry = TargetRegistry(context.database, context.authorizer)
    try:
        target = registry.add(body.name, body.value, body.group)
    except (TargetValidationError, TargetNotAllowedError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RepositoryError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    with context.database.session() as session:
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="miniapp.target_add",
                actor_id=user.id,
                actor_username=user.username,
                actor_type=audit_service.ACTOR_TELEGRAM,
                target_type="target",
                target_id=target.name,
                details={"value": target.value},
                ip_address=client_ip(request),
            ),
        )
    return {"id": None, "name": target.name, "value": target.value}


@router.get("/targets/{target_id}/scans")
async def target_scans(request: Request, target_id: int, limit: int = 10,
                       user: MiniAppUser = Depends(miniapp_user)):
    limit = max(1, min(limit, 50))
    context = ctx(request)
    with context.database.session() as session:
        scans = stats_service.target_scans(session, target_id, limit)
    return {
        "scans": [
            {
                "id": s["id"],
                "profile": s["profile"],
                "status": s["status"],
                "source": s["source"],
                "started_at": _iso(s["started_at"]),
                "finished_at": _iso(s["finished_at"]),
                "duration_ms": s["duration_ms"],
                "host_count": s["host_count"],
                "service_count": s["service_count"],
                "error": s["error"],
            }
            for s in scans
        ]
    }


@router.get("/targets/{target_id}/changes")
async def target_changes(request: Request, target_id: int, limit: int = 50,
                         user: MiniAppUser = Depends(miniapp_user)):
    limit = max(1, min(limit, 200))
    context = ctx(request)
    with context.database.session() as session:
        changes = stats_service.target_changes(session, target_id, limit)
    return {"changes": [_mini_change(c) for c in changes]}


def _mini_change(row: dict) -> dict:
    return {
        "id": row["id"],
        "scan_id": row["scan_id"],
        "change_type": row["change_type"],
        "host": row["host"],
        "port": row["port"],
        "protocol": row["protocol"],
        "old_value": row["old_value"],
        "new_value": row["new_value"],
        "created_at": _iso(row["created_at"]),
    }


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


@router.post("/scan", status_code=202)
async def start_scan(request: Request, body: MiniScanBody,
                     user: MiniAppUser = Depends(miniapp_user)):
    """Queue a scan through the shared worker, applying every rule.

    The Mini App is a second front door onto the same pipeline, so it goes
    through the same gates the bot does: role, target scope, the rule engine,
    then the rate limiter. Skipping any of them would make the panel a way to
    bypass policy.
    """
    context = ctx(request)
    worker = getattr(context, "scan_worker", None)
    if worker is None:
        # The admin process does not run a worker; scans are queued by the bot
        # process. Say so plainly rather than pretending to accept the job.
        raise HTTPException(
            status_code=503,
            detail=(
                "Scans are queued by the bot process. Start the bot service, "
                "or run the scan from Telegram with /scan."
            ),
        )

    with context.database.session() as session:
        principal_row = _require_operator(session, user)

    try:
        profile = get_profile(body.profile)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    registry = TargetRegistry(context.database, context.authorizer)
    target = registry.get(body.target) or registry.resolve(body.target)
    if target is None:
        raise HTTPException(status_code=404, detail=f"No target named '{body.target}'.")

    # Target scope, same check the bot applies.
    try:
        context.authorizer.assert_target_permitted(target.value)
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    now = datetime.now(timezone.utc)
    settings = context.settings
    store = context.settings_store

    if store is not None and store.get("rules_enabled") is not False:
        with context.database.session() as session:
            rules = RuleRepository(session).load_engine_rules()
            quota = {
                "hour": ScanRepository(session).count_since(
                    user.id, now - timedelta(hours=1)
                ),
                "day": ScanRepository(session).count_since(
                    user.id, now - timedelta(days=1)
                ),
            }
            last = ScanRepository(
                session
            ).latest_started_for_target_name(target.name)

        from core.rules import rate_limit_key

        rule_ctx = RuleContext(
            target=target.value,
            target_key=target.name,
            actor_id=user.id,
            ports=profile.port_list(),
            now=now,
            quota_usage=quota,
            default_rate_limit_seconds=settings.rate_limit_seconds,
            default_scan_timeout_seconds=settings.scan_timeout_seconds,
        )
        if last is not None:
            rule_ctx = type(rule_ctx)(
                **{
                    **{f: getattr(rule_ctx, f) for f in rule_ctx.__dataclass_fields__},
                    "last_scans": {
                        rate_limit_key(rule_ctx, "target", target.name): last
                    },
                }
            )

        decision = RuleEngine(rules).evaluate(rule_ctx)
        if not decision.allowed:
            with context.database.session() as session:
                audit_service.record(
                    session,
                    audit_service.AuditEntry(
                        action="miniapp.scan_requested",
                        actor_id=user.id,
                        actor_username=user.username,
                        actor_type=audit_service.ACTOR_TELEGRAM,
                        target_type="target",
                        target_id=target.name,
                        details={
                            "result": "blocked_by_rule",
                            "reason": decision.reason,
                            "rule_name": decision.rule_name,
                        },
                        ip_address=client_ip(request),
                        success=False,
                    ),
                )
            raise HTTPException(status_code=403, detail=decision.reason)

        scan_timeout = decision.effective_scan_timeout
        effective_rate = decision.effective_rate_limit_seconds
    else:
        scan_timeout = None
        effective_rate = settings.rate_limit_seconds

    # Rate limit last, after policy, so a denial is not reported as a wait.
    limiter = getattr(context, "rate_limiter", None)
    if limiter is not None:
        rate_decision = limiter.check(target.name)
        if not rate_decision.allowed:
            raise HTTPException(status_code=429, detail=rate_decision.reason)
    elif effective_rate:
        raise HTTPException(status_code=503, detail="Rate limiter unavailable.")

    from workers.scan_worker import ScanJob

    job = ScanJob(
        job_id=await worker.next_job_id(),
        # 0 means "resolve the operator chat at delivery time", matching how
        # the scheduler queues a job with no originating conversation.
        chat_id=0,
        target_name=target.name,
        target_value=target.value,
        profile=profile,
        source="manual",
        requested_by=user.id,
        actor_username=user.username,
        lang=principal_row["language"],
        scan_timeout=scan_timeout,
    )
    await worker.submit(job)

    with context.database.session() as session:
        audit_service.record(
            session,
            audit_service.AuditEntry(
                action="miniapp.scan_requested",
                actor_id=user.id,
                actor_username=user.username,
                actor_type=audit_service.ACTOR_TELEGRAM,
                target_type="target",
                target_id=target.name,
                details={
                    "profile": profile.name,
                    "job_id": job.job_id,
                    "scan_timeout": scan_timeout,
                },
                ip_address=client_ip(request),
            ),
        )

    return {
        "job_id": job.job_id,
        "target": target.name,
        "profile": profile.name,
        "state": "queued",
    }


@router.get("/scans/active")
async def active_scan(request: Request,
                      user: MiniAppUser = Depends(miniapp_user)):
    """The caller's most recent scan that has not finished, if any.

    Polled by the Mini App's progress card. Scoped to the requesting user so
    one operator's phone never shows another's job.
    """
    context = ctx(request)
    with context.database.session() as session:
        scan = session.scalar(
            _active_scan_query(user.id)
        )
        if scan is None:
            return {"scan": None}
        payload = {
            "id": scan.id,
            "target_id": scan.target_id,
            "profile": scan.profile,
            "status": scan.status,
            "source": scan.source,
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
            "duration_ms": scan.duration_ms,
            "host_count": scan.host_count,
            "service_count": scan.service_count,
            "error": scan.error,
        }
    return {"scan": payload}


def _active_scan_query(user_id: int):
    from sqlalchemy import desc, select

    from database.models import Scan, Target

    return (
        select(Scan)
        .join(Target, Scan.target_id == Target.id)
        .where(
            Scan.requested_by == user_id,
            Scan.status.in_(("running", "queued")),
        )
        .order_by(desc(Scan.id))
        .limit(1)
    )


@router.get("/scans/{scan_id}")
async def get_scan(request: Request, scan_id: int,
                   user: MiniAppUser = Depends(miniapp_user)):
    from sqlalchemy import func, select

    from database.models import ChangeEvent, Scan, Target

    context = ctx(request)
    with context.database.session() as session:
        row = session.execute(
            select(Scan, Target.name, Target.value, func.count(ChangeEvent.id))
            .join(Target, Scan.target_id == Target.id)
            .outerjoin(ChangeEvent, ChangeEvent.scan_id == Scan.id)
            .where(Scan.id == scan_id)
            .group_by(Scan.id, Target.name, Target.value)
        ).one_or_none()

        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found.")

        scan, target_name, target_value, change_count = row
        payload = {
            "id": scan.id,
            "target": target_name,
            "target_value": target_value,
            "profile": scan.profile,
            "status": scan.status,
            "source": scan.source,
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
            "duration_ms": scan.duration_ms,
            "host_count": scan.host_count,
            "service_count": scan.service_count,
            "error": scan.error,
            "change_count": int(change_count or 0),
        }
    return {"scan": payload}


# ---------------------------------------------------------------------------
# Changes
# ---------------------------------------------------------------------------


@router.get("/changes")
async def list_changes(
    request: Request,
    change_type: str | None = None,
    target_id: int | None = None,
    page: int = 1,
    page_size: int = 40,
    user: MiniAppUser = Depends(miniapp_user),
):
    """Change events across every target, newest first.

    Joined to the scan and its target in one query so each row can say which
    target it came from, rather than issuing a query per row.
    """
    from sqlalchemy import desc, func, select

    from database.models import ChangeEvent, Scan, Target

    page = max(1, page)
    size = max(1, min(page_size, 200))

    context = ctx(request)
    with context.database.session() as session:
        filters = []
        if change_type:
            filters.append(ChangeEvent.change_type == change_type)
        if target_id is not None:
            filters.append(Scan.target_id == target_id)

        base = select(func.count()).select_from(ChangeEvent).join(
            Scan, ChangeEvent.scan_id == Scan.id
        )
        for condition in filters:
            base = base.where(condition)
        total = int(session.scalar(base) or 0)

        stmt = (
            select(ChangeEvent, Target.name, Target.value)
            .join(Scan, ChangeEvent.scan_id == Scan.id)
            .join(Target, Scan.target_id == Target.id)
        )
        for condition in filters:
            stmt = stmt.where(condition)

        rows = list(
            session.execute(
                stmt.order_by(
                    desc(ChangeEvent.created_at), desc(ChangeEvent.id)
                )
                .offset((page - 1) * size)
                .limit(size)
            ).all()
        )

    changes = []
    for change, target_name, target_value in rows:
        payload = _mini_change(
            {
                "id": change.id,
                "scan_id": change.scan_id,
                "change_type": change.change_type,
                "host": change.host,
                "port": change.port,
                "protocol": change.protocol,
                "old_value": change.old_value,
                "new_value": change.new_value,
                "created_at": change.created_at,
            }
        )
        payload["target"] = target_name
        payload["target_value"] = target_value
        changes.append(payload)

    return {
        "changes": changes,
        "total": total,
        "page": page,
        "page_size": size,
    }


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@router.get("/rules")
async def list_rules(request: Request,
                     user: MiniAppUser = Depends(miniapp_user)):
    """Read-only rule listing for the MVP."""
    from database.models import RULE_TYPES

    context = ctx(request)
    with context.database.session() as session:
        rows = RuleRepository(session).list_rules()
    return {
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "rule_type": r.rule_type,
                "value": r.value,
                "priority": r.priority,
                "enabled": r.enabled,
                "scope": r.scope,
                "scope_id": r.scope_id,
                "description": r.description,
                "hit_count": r.hit_count,
                "last_hit_at": _iso(r.last_hit_at),
                "created_at": _iso(r.created_at),
            }
            for r in rows
        ],
        "total": len(rows),
        "rule_types": list(RULE_TYPES),
    }


@router.get("/rules/{rule_id}/hits")
async def rule_hits(request: Request, rule_id: int, limit: int = 20,
                    user: MiniAppUser = Depends(miniapp_user)):
    from database.repository import RuleHitFilters

    limit = max(1, min(limit, 100))
    context = ctx(request)
    with context.database.session() as session:
        repo = RuleRepository(session)
        if repo.get_rule(rule_id) is None:
            raise HTTPException(status_code=404, detail="Rule not found.")
        rows, total = repo.list_rule_hits(
            RuleHitFilters(rule_id=rule_id, page_size=limit)
        )
    return {
        "hits": [_hit_json(r) for r in rows],
        "total": total,
    }


@router.post("/rules/test")
async def test_rules(request: Request, body: MiniRuleTestBody,
                     user: MiniAppUser = Depends(miniapp_user)):
    """Dry run the rule set. No side effects, exactly like the web panel."""
    context = ctx(request)
    now: datetime | None = None
    if body.now:
        try:
            now = datetime.fromisoformat(body.now)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"now must be ISO-8601: {exc}"
            ) from exc

    with context.database.session() as session:
        rows = RuleRepository(session).load_engine_rules()

    decision = RuleEngine(rows).evaluate(
        RuleContext(
            target=body.target,
            actor_id=body.actor_id if body.actor_id is not None else user.id,
            ports=tuple(body.ports or ()),
            now=now,
        )
    )
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "rule_id": decision.rule_id,
        "rule_name": decision.rule_name,
        "effective_rate_limit_seconds": decision.effective_rate_limit_seconds,
        "effective_scan_timeout": decision.effective_scan_timeout,
        "warnings": list(decision.warnings),
        "rules_considered": len(rows),
        "side_effects": "none",
    }


@router.get("/profiles")
async def list_profiles(request: Request,
                        user: MiniAppUser = Depends(miniapp_user)):
    return {"profiles": profile_names()}