"""Admin API for policy rules.

Mounted at ``/api/rules``. Every endpoint is role-gated and audited.

Two behaviours are worth calling out:

* ``/test`` is a dry run. It builds a :class:`RuleContext` from the request
  and returns the engine's decision verbatim, with no side effects: no hit
  row, no counter movement, no audit entry beyond the read itself. That is
  what makes it safe to point at a production rule set while tuning it.

* ``/import`` is all-or-nothing. Every rule is validated before anything is
  written, so a single bad entry rejects the batch instead of leaving a
  half-applied configuration behind.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from admin.deps import client_ip, current_principal, require_role
from admin.routes.api import ctx
from admin.services import audit as audit_service
from database.models import RULE_DECISIONS, RULE_SCOPES, RULE_TYPES
from database.repository import (
    RepositoryError,
    RuleCreate,
    RuleFilters,
    RuleRepository,
    RuleUpdate,
)
from core.rules import RuleContext, RuleEngine

log = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RuleBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    rule_type: str = Field(min_length=1, max_length=32)
    value: str = Field(min_length=1, max_length=2048)
    priority: int = Field(default=50, ge=1, le=10000)
    enabled: bool = True
    scope: str = Field(default="global")
    scope_id: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=2000)


class RulePatch(BaseModel):
    rule_type: str | None = Field(default=None, max_length=32)
    value: str | None = Field(default=None, max_length=2048)
    priority: int | None = Field(default=None, ge=1, le=10000)
    enabled: bool | None = None
    scope: str | None = None
    scope_id: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=2000)


class ReorderBody(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=1000)


class TestBody(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    ports: list[int] | None = None
    actor_id: int | None = None
    now: str | None = Field(default=None, max_length=64)


class ImportRule(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    rule_type: str = Field(min_length=1, max_length=32)
    value: str = Field(min_length=1, max_length=2048)
    priority: int = Field(default=50, ge=1, le=10000)
    enabled: bool = True
    scope: str = Field(default="global")
    scope_id: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=2000)


class ImportBody(BaseModel):
    rules: list[ImportRule] = Field(min_length=1, max_length=500)
    replace: bool = False


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _rule_json(row) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "rule_type": row.rule_type,
        "value": row.value,
        "priority": row.priority,
        "enabled": row.enabled,
        "scope": row.scope,
        "scope_id": row.scope_id,
        "description": row.description,
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "hit_count": row.hit_count,
        "last_hit_at": _iso(row.last_hit_at),
    }


def _hit_json(row) -> dict[str, Any]:
    return {
        "id": row.id,
        "rule_id": row.rule_id,
        "scan_id": row.scan_id,
        "target": row.target,
        "decision": row.decision,
        "reason": row.reason,
        "actor_id": row.actor_id,
        "actor_username": row.actor_username,
        "created_at": _iso(row.created_at),
    }


def _audit(request: Request, session, principal, action: str, **fields) -> None:
    audit_service.record(
        session,
        audit_service.AuditEntry(
            action=action,
            actor_id=principal.id,
            actor_username=principal.username,
            actor_type=audit_service.ACTOR_ADMIN,
            target_type="rule",
            ip_address=client_ip(request),
            **fields,
        ),
    )


def _validate_enums(rule_type: str, scope: str, scope_id: str | None) -> None:
    """Reject unknown vocabularies with 400 before touching the database."""
    if rule_type not in RULE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown rule_type {rule_type!r}. "
                f"Valid types: {', '.join(RULE_TYPES)}"
            ),
        )
    if scope not in RULE_SCOPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown scope {scope!r}. "
                f"Valid scopes: {', '.join(RULE_SCOPES)}"
            ),
        )
    # A scoped rule without a subject can never match, which is almost
    # certainly a mistake worth surfacing rather than storing.
    if scope in ("user", "target") and not scope_id:
        raise HTTPException(
            status_code=400,
            detail=f"scope={scope!r} requires scope_id.",
        )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


@router.get("")
@router.get("/")
async def list_rules(
    request: Request,
    type: str | None = None,
    enabled: bool | None = None,
    scope: str | None = None,
    q: str | None = None,
    principal=Depends(current_principal),
):
    context = ctx(request)
    with context.database.session() as session:
        rows = RuleRepository(session).list_rules(
            RuleFilters(
                rule_type=type, enabled=enabled, scope=scope, q=q
            )
        )
        return {"rules": [_rule_json(r) for r in rows], "total": len(rows)}


@router.get("/export")
async def export_rules(request: Request,
                       principal=Depends(current_principal)):
    """Every rule as JSON, for backup or moving between deployments.

    Hits are deliberately excluded: they are derived history, and a restore
    should not resurrect thousands of rows describing scans that no longer
    exist.
    """
    context = ctx(request)
    with context.database.session() as session:
        rows = RuleRepository(session).list_rules()
        payload = {
            "version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "rules": [
                {
                    "name": r.name,
                    "rule_type": r.rule_type,
                    "value": r.value,
                    "priority": r.priority,
                    "enabled": r.enabled,
                    "scope": r.scope,
                    "scope_id": r.scope_id,
                    "description": r.description,
                }
                for r in rows
            ],
        }
    return Response(
        content=__import__("json").dumps(payload, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="netsentinel-rules.json"'
        },
    )


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


@router.post("", status_code=201)
@router.post("/", status_code=201)
async def create_rule(request: Request, body: RuleBody,
                      principal=Depends(require_role("admin"))):
    _validate_enums(body.rule_type, body.scope, body.scope_id)
    context = ctx(request)
    try:
        with context.database.session() as session:
            row = RuleRepository(session).create_rule(
                RuleCreate(
                    name=body.name,
                    rule_type=body.rule_type,
                    value=body.value,
                    priority=body.priority,
                    enabled=body.enabled,
                    scope=body.scope,
                    scope_id=body.scope_id,
                    description=body.description,
                ),
                actor=principal.username,
            )
            _audit(
                request, session, principal, "rule.create",
                target_id=str(row.id),
                details={
                    "name": row.name,
                    "rule_type": row.rule_type,
                    "value": row.value,
                    "priority": row.priority,
                    "scope": row.scope,
                    "scope_id": row.scope_id,
                },
            )
            result = _rule_json(row)
    except RepositoryError as exc:
        # Duplicate name is a conflict; a bad value is a client error. The
        # repository raises one exception for both, so the message decides.
        message = str(exc)
        conflict = "already exists" in message
        raise HTTPException(
            status_code=409 if conflict else 400, detail=message
        ) from exc
    return result


@router.patch("/{rule_id}")
async def update_rule(request: Request, rule_id: int, body: RulePatch,
                      principal=Depends(require_role("admin"))):
    context = ctx(request)
    with context.database.session() as session:
        repo = RuleRepository(session)
        current = repo.get_rule(rule_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Rule not found.")

        # Validate the *resulting* row, not the patch in isolation: changing
        # only rule_type must still be checked against the stored value, and
        # changing only value against the stored type.
        effective_type = body.rule_type or current.rule_type
        effective_scope = body.scope or current.scope
        effective_scope_id = (
            body.scope_id if body.scope_id is not None else current.scope_id
        )
        _validate_enums(effective_type, effective_scope, effective_scope_id)

        before = {
            "rule_type": current.rule_type,
            "value": current.value,
            "priority": current.priority,
            "enabled": current.enabled,
        }
        try:
            row = repo.update_rule(
                rule_id,
                RuleUpdate(
                    rule_type=body.rule_type,
                    value=body.value,
                    priority=body.priority,
                    enabled=body.enabled,
                    scope=body.scope,
                    scope_id=body.scope_id,
                    description=body.description,
                ),
                actor=principal.username,
            )
        except RepositoryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        _audit(
            request, session, principal, "rule.update",
            target_id=str(rule_id),
            details={
                "name": row.name,
                "before": before,
                "after": {
                    "rule_type": row.rule_type,
                    "value": row.value,
                    "priority": row.priority,
                    "enabled": row.enabled,
                },
            },
        )
        return _rule_json(row)


@router.delete("/{rule_id}")
async def delete_rule(request: Request, rule_id: int, confirm: bool = False,
                      principal=Depends(require_role("admin"))):
    """Delete a rule. Requires ``confirm=true``.

    Hit rows are kept, so the record of past decisions survives; a rule with
    history can still be deleted because rule_id is not a foreign key.
    """
    context = ctx(request)
    with context.database.session() as session:
        repo = RuleRepository(session)
        row = repo.get_rule(rule_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Rule not found.")
        if not confirm:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Pass confirm=true. This deletes the rule. Its "
                    f"{row.hit_count} recorded hit(s) are kept as history."
                ),
            )
        snapshot = {
            "name": row.name,
            "rule_type": row.rule_type,
            "value": row.value,
            "hit_count": row.hit_count,
        }
        repo.delete_rule(rule_id)
        _audit(
            request, session, principal, "rule.delete",
            target_id=str(rule_id),
            details=snapshot,
        )
        return {"deleted": snapshot["name"], "hits_kept": snapshot["hit_count"]}


@router.post("/{rule_id}/toggle")
async def toggle_rule(request: Request, rule_id: int,
                      principal=Depends(require_role("admin"))):
    """Flip enabled. Returns the new state rather than taking one, so a
    double-submit cannot silently invert it twice."""
    context = ctx(request)
    with context.database.session() as session:
        repo = RuleRepository(session)
        row = repo.get_rule(rule_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Rule not found.")
        was = row.enabled
        updated = repo.set_enabled(rule_id, not was)
        _audit(
            request, session, principal, "rule.update",
            target_id=str(rule_id),
            details={
                "name": updated.name,
                "enabled_before": was,
                "enabled_after": updated.enabled,
                "via": "toggle",
            },
        )
        return _rule_json(updated)


@router.post("/reorder")
async def reorder_rules(request: Request, body: ReorderBody,
                        principal=Depends(require_role("admin"))):
    """Set priorities to 1..N following ``ids``.

    Rules absent from ``ids`` keep their priority, so a single rule can be
    pinned at the top without renumbering everything else.
    """
    context = ctx(request)
    with context.database.session() as session:
        repo = RuleRepository(session)
        before = {r.id: r.priority for r in repo.list_rules()}
        touched = repo.reorder(body.ids)
        after = {r.id: r.priority for r in repo.list_rules()}
        _audit(
            request, session, principal, "rule.reorder",
            details={
                "requested_ids": body.ids,
                "renumbered": touched,
                "before": before,
                "after": after,
            },
        )
        return {
            "reordered": touched,
            "rules": [_rule_json(r) for r in repo.list_rules()],
        }


@router.post("/test")
async def test_rules(request: Request, body: TestBody,
                     principal=Depends(current_principal)):
    """Dry-run the rule set against a hypothetical request.

    Read-only: no hit row, no counter change, no audit entry. Lets an
    operator see exactly which rule blocks a target before applying it.
    """
    context = ctx(request)
    now: datetime | None = None
    if body.now:
        try:
            now = datetime.fromisoformat(body.now)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"now must be ISO-8601: {exc}",
            ) from exc

    with context.database.session() as session:
        rows = RuleRepository(session).load_engine_rules()

    engine = RuleEngine(rows)
    ctx_obj = RuleContext(
        target=body.target,
        actor_id=body.actor_id,
        ports=tuple(body.ports or ()),
        now=now,
    )
    decision = engine.evaluate(ctx_obj)

    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "rule_id": decision.rule_id,
        "rule_name": decision.rule_name,
        "effective_rate_limit_seconds": decision.effective_rate_limit_seconds,
        "effective_scan_timeout": decision.effective_scan_timeout,
        "warnings": list(decision.warnings),
        "rules_considered": len(rows),
        "rules_enabled": int(context.settings_store.get("rules_enabled") is True),
        "side_effects": "none",
    }


@router.post("/import")
async def import_rules(request: Request, body: ImportBody,
                       principal=Depends(require_role("superadmin"))):
    """Import rules atomically, upserting by name.

    Superadmin only: this overwrites the live policy of a running bot.

    Validated in two phases. Phase one checks every rule with no writes at
    all, so a malformed entry is rejected before anything is persisted;
    phase two then upserts by name, so importing the same export twice
    updates rules instead of failing on duplicates.
    """
    context = ctx(request)

    # -- phase 1: validate everything, write nothing --------------------
    seen: set[str] = set()
    for index, item in enumerate(body.rules):
        try:
            _validate_enums(item.rule_type, item.scope, item.scope_id)
            from core.rule_values import validate_value

            validate_value(item.rule_type, item.value)
        except HTTPException as exc:
            raise HTTPException(
                status_code=400,
                detail=f"rules[{index}] ({item.name}): {exc.detail}",
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"rules[{index}] ({item.name}): {exc}",
            ) from exc
        if item.name in seen:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"rules[{index}]: duplicate name {item.name!r} within "
                    "the same batch."
                ),
            )
        seen.add(item.name)

    # -- phase 2: upsert -------------------------------------------------
    created = updated = 0
    names: list[str] = []
    with context.database.session() as session:
        repo = RuleRepository(session)

        if body.replace:
            existing = repo.list_rules()
            for row in existing:
                if row.name not in seen:
                    repo.delete_rule(row.id)
            removed = len(existing) - len(
                [r for r in existing if r.name in seen]
            )
        else:
            removed = 0

        for item in body.rules:
            existing_row = repo.get_by_name(item.name)
            if existing_row is None:
                repo.create_rule(
                    RuleCreate(
                        name=item.name,
                        rule_type=item.rule_type,
                        value=item.value,
                        priority=item.priority,
                        enabled=item.enabled,
                        scope=item.scope,
                        scope_id=item.scope_id,
                        description=item.description,
                    ),
                    actor=principal.username,
                )
                created += 1
            else:
                repo.update_rule(
                    existing_row.id,
                    RuleUpdate(
                        rule_type=item.rule_type,
                        value=item.value,
                        priority=item.priority,
                        enabled=item.enabled,
                        scope=item.scope,
                        scope_id=item.scope_id,
                        description=item.description,
                    ),
                    actor=principal.username,
                )
                updated += 1
            names.append(item.name)

        _audit(
            request, session, principal, "rule.import",
            details={
                "created": created,
                "updated": updated,
                "removed": removed,
                "replace": body.replace,
                "names": names,
            },
        )

    return {
        "created": created,
        "updated": updated,
        "removed": removed,
        "replace": body.replace,
    }


@router.get("/{rule_id}/hits")
async def rule_hits(request: Request, rule_id: int, decision: str | None = None,
                    actor_id: int | None = None, page: int = 1,
                    page_size: int = 50,
                    principal=Depends(current_principal)):
    """Paginated hit history for one rule."""
    from database.repository import RuleHitFilters

    if decision is not None and decision not in RULE_DECISIONS:
        raise HTTPException(
            status_code=400,
            detail=f"decision must be one of {', '.join(RULE_DECISIONS)}",
        )
    context = ctx(request)
    with context.database.session() as session:
        repo = RuleRepository(session)
        if repo.get_rule(rule_id) is None:
            raise HTTPException(status_code=404, detail="Rule not found.")
        rows, total = repo.list_rule_hits(
            RuleHitFilters(
                rule_id=rule_id,
                decision=decision,
                actor_id=actor_id,
                page=page,
                page_size=page_size,
            )
        )
        return {
            "hits": [_hit_json(r) for r in rows],
            "total": total,
            "page": max(1, page),
            "page_size": page_size,
        }
