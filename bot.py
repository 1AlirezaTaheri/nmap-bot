import subprocess
import logging
import io
import os
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError(
        "متغیر محیطی TELEGRAM_BOT_TOKEN تنظیم نشده است. "
        "توکن را از @BotFather بگیرید و آن را export کنید."
    )

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "سلام! من ربات اسکنر nmap هستم.\n"
        "برای اسکن: /scan <IP or domain>\n"
        "مثال: /scan scanme.nmap.org"
    )

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("مثال: /scan 192.168.1.1")
        return

    target = context.args[0]

    if not target.replace('.', '').replace('-', '').replace('/', '').isalnum():
        await update.message.reply_text("آدرس نامعتبر است.")
        return

    await update.message.reply_text(f"در حال اسکن {target} ...")

    command = ["nmap", "-F", "-T4", target]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )

        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr

        # Telegram rejects messages longer than 4096 chars and nmap output can
        # easily exceed that, so long output is sent as a file instead.
        MAX_TEXT_LEN = 4000
        if len(output) > MAX_TEXT_LEN:
            safe_target = "".join(
                c for c in target if c.isalnum() or c in ".-_"
            )[:64] or "target"
            payload = io.BytesIO(output.encode("utf-8"))
            payload.name = "nmap_%s.txt" % safe_target
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

    except subprocess.TimeoutExpired:
        await update.message.reply_text("اسکن طول کشید و متوقف شد.")
    except FileNotFoundError:
        await update.message.reply_text("خطا: nmap پیدا نشد.")
    except Exception as e:
        await update.message.reply_text(f"خطا: {str(e)}")

if __name__ == '__main__':
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan))
    print("ربات در حال اجراست...")
    app.run_polling()
