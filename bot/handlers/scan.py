"""`/scan` — authenticated, scope-checked, queued to the background worker.

The handler validates, acknowledges immediately, then hands off. It never
blocks the event loop: nmap runs in a worker thread and the result comes
back through the completion callback, which sends the finished report and
any change alerts to the originating chat.
"""

from __future__ import annotations

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import authenticate_or_denounce, authorizer
from bot.messages import reports
from core.profiles import UnknownProfileError, get_profile, profile_names
from core.target_manager import TargetView
from security.authorization import AuthorizationError, TargetNotAllowedError
from workers.scan_worker import ScanJob


def _registry(context: ContextTypes.DEFAULT_TYPE):
    return context.application.bot_data["target_registry"]


async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text(
            "Usage: /scan <target|name> [profile]\n"
            f"Profiles: {', '.join(profile_names())}\n"
            "Example: /scan lab service"
        )
        return

    try:
        profile = get_profile(context.args[1] if len(context.args) > 1 else None)
    except UnknownProfileError as exc:
        await update.message.reply_text(f"❌ {exc}")
        return

    reference = context.args[0]
    target: TargetView | None = _registry(context).resolve(reference)
    if target is None:
        await update.message.reply_text(
            f"❌ Unknown target '{reference}'.\n"
            "Register it first: /addtarget <name> <value>"
        )
        return

    try:
        authz = authorizer(context)
        authz.require_role(principal, "start a scan")
        authz.assert_target_permitted(target.value)
    except (AuthorizationError, TargetNotAllowedError) as exc:
        await update.message.reply_text(f"⛔ {exc}")
        return

    worker = context.application.bot_data["scan_worker"]
    job = ScanJob(
        job_id=await worker.next_job_id(),
        chat_id=update.effective_chat.id,
        target_name=target.name,
        target_value=target.value,
        profile=profile,
    )
    await worker.submit(job)

    await update.message.reply_text(
        reports.scan_started(target.name, target.value, profile.name)
    )