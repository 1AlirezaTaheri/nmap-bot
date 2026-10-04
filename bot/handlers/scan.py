"""/scan` — authenticated, scope-checked, rule-checked, rate-limited, queued.

The handler validates, acknowledges immediately, then hands off to the
shared background worker. It never blocks the event loop: nmap runs in a
worker thread and the result comes back through the completion callback.

Order of checks, and why:

1. authentication and argument validation — cheapest first, and nothing
   below should run for a caller who is not allowed to ask;
2. role and target scope — same reasoning;
3. **policy rules** — a deny here is a stronger and more explanatory answer
   than a rate limit, and much cheaper than enqueueing a scan;
4. rate limit — last, so a policy denial neither is misreported as a wait
   nor consumes the target's allowance.

Rule evaluation is isolated in :func:`_evaluate_rules`, which never raises.
A failure there degrades to "allow, and say so in the audit log", because an
infrastructure fault must not take scanning offline. That is deliberately the
opposite of the engine's own fail-closed behaviour: the engine fails closed
when policy *data* is restrictive, and fails open when the engine itself is
broken. A typo in a rule must not deny traffic, and a dead database must not
either — the difference is that here we log loudly instead of silently.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import (
    audit,
    authenticate_or_denounce,
    authorizer,
    database,
    lang_of_update,
    settings_store,
)
from bot.messages import reports
from core.profiles import UnknownProfileError, get_profile, profile_names
from core.rules import (
    RuleContext,
    RuleDecision,
    RuleEngine,
    rate_limit_key,
)
from core.target_manager import TargetView
from database.repository import RuleRepository, ScanRepository
from security.authorization import AuthorizationError, TargetNotAllowedError
from workers.scan_worker import ScanJob

log = logging.getLogger(__name__)

MAX_TARGET_LENGTH = 255

# Fallback when the settings row is unreadable, mirroring the compiled-in
# default for rules_max_hits_per_day.
DEFAULT_HIT_CAP = 10000

# Module scope so the cap warning fires once per day for the process, rather
# than once per scan on a busy target.
_cap_warned_on: str | None = None


def _registry(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data["target_registry"]


def _limiter(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data["rate_limiter"]


def _settings(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data.get("settings")


def _max_hits_per_day(context: ContextTypes.DEFAULT_TYPE) -> int:
    store = settings_store(context)
    if store is None:
        return DEFAULT_HIT_CAP
    try:
        return int(store.get("rules_max_hits_per_day"))
    except (TypeError, ValueError):
        return DEFAULT_HIT_CAP


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------


def _quota_usage(session, user_id: int | None, now: datetime) -> dict[str, int]:
    """Scans this user started in the last hour and the last day.

    Two counts because a quota rule may name either period. Read-only, and
    the SQL lives in the repository so the engine stays query-free.
    """
    if user_id is None:
        return {"hour": 0, "day": 0}
    repo = ScanRepository(session)
    return {
        "hour": repo.count_since(user_id, now - timedelta(hours=1)),
        "day": repo.count_since(user_id, now - timedelta(days=1)),
    }


def _evaluate_rules(
    context: ContextTypes.DEFAULT_TYPE,
    target_value: str,
    target_name: str,
    actor_id: int | None,
    ports: tuple[int, ...],
) -> RuleDecision:
    """Evaluate the rule set for one scan request.

    Never raises: any failure returns an allowing decision and logs, so an
    infrastructure fault cannot lock operators out of scanning.
    """
    store = settings_store(context)
    if store is not None and store.get("rules_enabled") is False:
        # Fast path: no rule query, no engine, no hit writes.
        return RuleDecision(allowed=True, reason="rules disabled")

    settings = _settings(context)
    now = datetime.now(timezone.utc)
    db = database(context)

    try:
        with db.session() as session:
            rules = RuleRepository(session).load_engine_rules()
            quota = _quota_usage(session, actor_id, now)
            # Keyed by target *name*, matching both the engine's rate_limit_key
            # and the existing RateLimiter, so a rule and the limiter see the
            # same history.
            last = ScanRepository(
                session
            ).latest_started_for_target_name(target_name)

        # target_key is the target *name*, not its value: a rate_limit rule
        # is meant to shadow the existing RateLimiter, which is keyed by
        # name. The key shape itself comes from rate_limit_key() so the
        # handler and the engine cannot drift apart again.
        rule_ctx = RuleContext(
            target=target_value,
            target_key=target_name,
            actor_id=actor_id,
            ports=ports,
            now=now,
            quota_usage=quota,
            default_rate_limit_seconds=getattr(
                settings, "rate_limit_seconds", None
            ),
            default_scan_timeout_seconds=getattr(
                settings, "scan_timeout_seconds", None
            ),
        )
        if last is not None:
            # RuleContext is frozen, so rebuild rather than mutate.
            rule_ctx = replace(
                rule_ctx,
                last_scans={
                    rate_limit_key(rule_ctx, "target", target_name): last
                },
            )

        engine = RuleEngine(rules)
        decision = engine.evaluate(rule_ctx)

        _record_decision(context, decision, target_name, actor_id, now)
        return decision

    except Exception:
        log.exception(
            "Rule evaluation failed for target %s; allowing the scan",
            target_name,
        )
        return RuleDecision(
            allowed=True,
            reason="rule evaluation failed; allowed to avoid an outage",
        )


def _record_decision(
    context: ContextTypes.DEFAULT_TYPE,
    decision: RuleDecision,
    target_name: str,
    actor_id: int | None,
    now: datetime,
) -> None:
    """Persist a hit when a rule decided the outcome.

    Nothing is written when no rule applied, so the table answers "what did
    this rule set actually do?" rather than recording every scan. Past the
    daily cap, hits stop being written but evaluation continues — losing
    history is survivable, losing enforcement is not.
    """
    if decision.rule_id is None:
        return

    db = database(context)
    try:
        with db.session() as session:
            repo = RuleRepository(session)
            cutoff = (now - timedelta(days=1)).replace(tzinfo=None)
            if repo.count_hits_since(cutoff) >= _max_hits_per_day(context):
                _warn_cap_once(context, _max_hits_per_day(context))
                return

            repo.record_rule_hit(
                decision.rule_id,
                target=target_name,
                decision="deny" if not decision.allowed else "allow",
                reason=decision.reason,
                actor_id=actor_id,
            )
    except Exception:
        # Losing a hit row must never cost the user their scan.
        log.warning("Could not record rule hit", exc_info=True)


def _warn_cap_once(context: ContextTypes.DEFAULT_TYPE, cap: int) -> None:
    """Log the hit-cap notice at most once a day."""
    global _cap_warned_on

    today = datetime.now(timezone.utc).date().isoformat()
    if _cap_warned_on == today:
        return
    _cap_warned_on = today

    log.warning(
        "Rule hit cap of %d/day reached; rules are still evaluated but hits "
        "are no longer recorded",
        cap,
    )
    audit(
        context,
        "rule.hit_cap",
        details={"cap": cap},
        success=False,
    )


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang = lang_of_update(update, context)

    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text(
            reports.scan_usage(lang, profile_names())
        )
        return

    reference = context.args[0]

    # Length bound first: an absurdly long string is never a valid target
    # and would otherwise reach the resolver and the database.
    if len(reference) > MAX_TARGET_LENGTH:
        await update.message.reply_text(
            reports.scan_reference_too_long(lang, len(reference), MAX_TARGET_LENGTH)
        )
        return

    try:
        profile = get_profile(context.args[1] if len(context.args) > 1 else None)
    except UnknownProfileError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return

    target: TargetView | None = _registry(context).resolve(reference)
    if target is None:
        await update.message.reply_text(
            reports.scan_unknown_target(lang, reference)
        )
        return

    if len(target.value) > MAX_TARGET_LENGTH:
        await update.message.reply_text(
            reports.scan_value_too_long(lang, len(target.value), MAX_TARGET_LENGTH)
        )
        return

    try:
        authz = authorizer(context)
        authz.require_role(principal, "start a scan")
        authz.assert_target_permitted(target.value)
    except (AuthorizationError, TargetNotAllowedError) as exc:
        await update.message.reply_text(reports.forbidden(lang, str(exc)))
        return

    # -- policy rules ------------------------------------------------
    decision = _evaluate_rules(
        context,
        target.value,
        target.name,
        principal.user_id,
        profile.port_list(),
    )

    if not decision.allowed:
        await update.message.reply_text(
            reports.scan_blocked_by_rule(
                lang, decision.reason, decision.rule_name
            )
        )
        audit(
            context,
            "rule.denied",
            actor_id=principal.user_id,
            actor_username=principal.username,
            target_type="target",
            target_id=target.name,
            details={
                "reason": decision.reason,
                "rule_id": decision.rule_id,
                "rule_name": decision.rule_name,
                "profile": profile.name,
            },
            success=False,
        )
        return

    # Rate limit per target, checked only after authorization so a denied
    # user cannot burn another target's allowance, and after the rules so a
    # policy denial is not reported as a wait.
    limiter = _limiter(context)
    rate_decision = limiter.check(target.name)
    if not rate_decision.allowed:
        await update.message.reply_text(
            reports.scan_rate_limited(lang, rate_decision.reason)
        )
        audit(
            context,
            "scan.requested",
            actor_id=principal.user_id,
            actor_username=principal.username,
            target_type="target",
            target_id=target.name,
            details={"result": "rate_limited", "profile": profile.name},
            success=False,
        )
        return

    worker = context.application.bot_data["scan_worker"]
    job = ScanJob(
        job_id=await worker.next_job_id(),
        chat_id=update.effective_chat.id,
        target_name=target.name,
        target_value=target.value,
        profile=profile,
        source="manual",
        requested_by=principal.user_id,
        lang=lang,
        # Resolved by the rule engine. None keeps the configured timeout; a
        # max_scan_time rule only ever lowers it.
        scan_timeout=decision.effective_scan_timeout,
    )
    await worker.submit(job)

    audit(
        context,
        "scan.requested",
        actor_id=principal.user_id,
        actor_username=principal.username,
        target_type="target",
        target_id=target.name,
        details={
            "profile": profile.name,
            "job_id": job.job_id,
            "lang": lang,
            "rule_id": decision.rule_id,
            "rule_name": decision.rule_name,
            "scan_timeout": decision.effective_scan_timeout,
            "rate_limit": decision.effective_rate_limit_seconds,
        },
    )

    await update.message.reply_text(
        reports.scan_started(lang, target.name, target.value, profile.name)
    )
