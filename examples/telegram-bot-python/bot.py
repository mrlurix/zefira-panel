"""
Zefira reseller bot (Python) - sell VPN accounts over Telegram.

Setup:
    pip install -r requirements.txt
    set TELEGRAM_BOT_TOKEN=...      (from @BotFather)
    set ZEFIRA_URL=https://panel.example.com
    set ZEFIRA_API_TOKEN=zfp_...    (Panel -> Settings -> API Tokens)
    python bot.py

Flow: /buy -> pick a plan -> bot creates the VPN user -> replies with the
subscription link. /my shows your existing account.
"""
import logging
import os

import requests
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

TG_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
PANEL = os.environ.get("ZEFIRA_URL", "").rstrip("/")
SUB_BASE = os.environ.get("ZEFIRA_SUB_BASE", PANEL + "/sub").rstrip("/")
HEADERS = {"Authorization": f"Bearer {os.environ['ZEFIRA_API_TOKEN']}", "Content-Type": "application/json"}

PLANS = [
    ("10GB / 30 days", 10, 30),
    ("30GB / 30 days", 30, 30),
    ("50GB / 90 days", 50, 90),
]
PROTOS = ["vless"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("zefira-bot")


def api(method: str, path: str, body: dict | None = None) -> tuple:
    try:
        r = requests.request(method, PANEL + path, headers=HEADERS,
                             json=body, timeout=15)
    except requests.RequestException as exc:
        return 0, {"detail": f"panel unreachable: {exc}"}
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {"detail": r.text[:200]}


def uname(tg_id: int) -> str:
    return f"tg{tg_id}"


async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Welcome to Zefira VPN shop!\nUse /buy to get an account, /my to see yours.")


async def buy(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    kb = [[InlineKeyboardButton(label, callback_data=f"buy:{i}")]
          for i, (label, _, _) in enumerate(PLANS)]
    await update.message.reply_text("Pick a plan:", reply_markup=InlineKeyboardMarkup(kb))


async def my(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    st, data = api("GET", f"/api/users?q={uname(update.effective_user.id)}")
    if st != 200:
        await update.message.reply_text("Panel error, try later.")
        return
    mine = [u for u in data.get("items", []) if u.get("username") == uname(update.effective_user.id)]
    if not mine:
        await update.message.reply_text("No account yet. Use /buy.")
        return
    u = mine[0]
    await update.message.reply_text(
        f"Your account: {u['username']}\n"
        f"Volume: {u['used_gb']} / {u['volume_gb']} GB\n"
        f"Expires: {u['expires_at']}\n\n"
        f"Subscription:\n{SUB_BASE}/{u['token']}")


async def on_buy(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    try:
        label, vol, days = PLANS[int(q.data.split(":", 1)[1])]
    except (IndexError, ValueError):
        return
    name = uname(q.from_user.id)
    st, data = api("POST", "/api/users", {
        "username": name, "protocols": PROTOS, "volume_gb": vol, "days": days,
        "note": f"telegram:{q.from_user.id}",
    })
    if st == 409:
        await q.message.reply_text("You already have an account. Use /my.")
        return
    if st != 200 or not data.get("token"):
        log.warning("create failed %s %s", st, data)
        await q.message.reply_text("Could not create the account, try later.")
        return
    await q.message.reply_text(
        f"Done! {label}\n\nSubscription (tap to copy):\n"
        f"`{SUB_BASE}/{data['token']}`\n\n"
        f"Paste it into v2rayNG / Streisand / Clash.",
        parse_mode="Markdown")


def main() -> None:
    app = Application.builder().token(TG_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("buy", buy))
    app.add_handler(CommandHandler("my", my))
    app.add_handler(CallbackQueryHandler(on_buy, pattern=r"^buy:"))
    log.info("bot polling...")
    app.run_polling()


if __name__ == "__main__":
    main()
