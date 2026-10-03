"""`/scan` — authenticated, scope-checked, rate-limited, queued.

The handler validates, acknowledges immediately, then hands off to the
shared background worker. It never blocks the event loop: nmap runs in a
worker thread and the result comes back through the completion callback.
"""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from admin.services import audit as audit_service
from bot.handlers.common import (
    audit,
    authenticate_or_denounce,
    authorizer,
    lang_of_update,
)
from bot.messages import reports
from core.profiles import UnknownProfileError, get_profile, profile_names
from core.target_manager import TargetView
from security.authorization import AuthorizationError, TargetNotAllowedError
from workers.scan_worker import ScanJob

MAX_TARGET_LENGTH = 255


def _registry(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data["target_registry"]


def _limiter(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data["rate_limiter"]


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

    # Rate limit per target, checked only after authorization so a denied
    # user cannot burn another target's allowance.
    limiter = _limiter(context)
    decision = limiter.check(target.name)
    if not decision.allowed:
        await update.message.reply_text(reports.scan_rate_limited(lang, decision.reason))
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
    )
    await worker.submit(job)

    audit(
        context,
        "scan.requested",
        actor_id=principal.user_id,
        actor_username=principal.username,
        target_type="target",
        target_id=target.name,
        details={"profile": profile.name, "job_id": job.job_id, "lang": lang},
    )

    await update.message.reply_text(
        reports.scan_started(lang, target.name, target.value, profile.name)
    )