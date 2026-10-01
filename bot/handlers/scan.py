"""`/scan` — authenticated, target-validated nmap run.

Phase 1 keeps the original synchronous text scan so behaviour stays
comparable with the legacy ``bot.py``. XML output, background execution,
persistence and change detection land in later phases.
"""

from __future__ import annotations

import io
import subprocess

from telegram import Update
from telegram.ext import ContextTypes

from bot.handlers.common import (
    authenticate_or_denounce,
    authenticator,
    authorizer,
)
from security.authorization import AuthorizationError, TargetNotAllowedError

MAX_TEXT_LEN = 4000


async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    principal = await authenticate_or_denounce(update, context)
    if principal is None:
        return

    if not context.args:
        await update.message.reply_text("مثال: /scan 192.168.1.1")
        return

    settings = context.application.bot_data["settings"]
    target = context.args[0]

    # Role check + scope check happen before any process is spawned.
    authz = authorizer(context)
    try:
        authz.require_role(principal, "start a scan")
        target = authz.assert_target_permitted(target)
    except (AuthorizationError, TargetNotAllowedError) as exc:
        await update.message.reply_text(f"⛔ {exc}")
        return

    await update.message.reply_text(f"در حال اسکن {target} ...")

    command = [settings.nmap_binary, "-F", "-T4", target]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        await update.message.reply_text("اسکن طول کشید و متوقف شد.")
        return
    except FileNotFoundError:
        await update.message.reply_text("خطا: nmap پیدا نشد.")
        return
    except Exception as exc:  # noqa: BLE001 — surface any failure to the chat
        await update.message.reply_text(f"خطا: {exc}")
        return

    output = result.stdout
    if result.stderr:
        output += "\n" + result.stderr

    if len(output) > MAX_TEXT_LEN:
        safe_target = "".join(
            c for c in target if c.isalnum() or c in ".-_"
        )[:64] or "target"
        payload = io.BytesIO(output.encode("utf-8"))
        payload.name = f"nmap_{safe_target}.txt"
        await update.message.reply_document(
            document=payload,
            filename=payload.name,
            caption=(
                "خروجی کامل اسکن %s (%d کاراکتر) "
                "به‌صورت فایل ارسال شد."
            ) % (target, len(output)),
        )
    else:
        await update.message.reply_text(output)
