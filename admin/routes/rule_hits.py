"""Admin API for rule-hit history. Mounted at ``/api/rule-hits``.

Separated from the rules router because hits are read-only and grow far
faster than rules: the panel lists them on their own screen and never needs
to load them alongside the rule set.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from admin.deps import current_principal
from admin.routes.api import ctx
from database.models import RULE_DECISIONS
from database.repository import RuleHitFilters, RuleRepository

log = logging.getLogger(__name__)
router = APIRouter()


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
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("")
@router.get("/")
async def list_rule_hits(
    request: Request,
    rule_id: int | None = None,
    decision: str | None = None,
    actor_id: int | None = None,
    target: str | None = None,
    since: str | None = None,
    until: str | None = None,
    page: int = 1,
    page_size: int = 50,
    principal=Depends(current_principal),
):
    """One page of rule hits across all rules, newest first."""
    if decision is not None and decision not in RULE_DECISIONS:
        raise HTTPException(
            status_code=400,
            detail=f"decision must be one of {', '.join(RULE_DECISIONS)}",
        )

    def parse_dt(raw: str | None, field: str) -> datetime | None:
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"{field} must be ISO-8601: {exc}"
            ) from exc

    context = ctx(request)
    with context.database.session() as session:
        rows, total = RuleRepository(session).list_rule_hits(
            RuleHitFilters(
                rule_id=rule_id,
                decision=decision,
                actor_id=actor_id,
                target=target,
                since=parse_dt(since, "since"),
                until=parse_dt(until, "until"),
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
