"""
Zefira reseller bot (Python) - sell VPN accounts over Telegram.

Setup:
    pip install -r requirements.txt
    set TELEGRAM_BOT_TOKEN=...      (from @BotFather)
    set ZEFIRA_URL=https://panel.example.com
    set ZEFIRA_API_TOKEN=zfp_...    (Panel -> Settings -> API Tokens -> Create with scope "bot")
    python bot.py

Flow: /buy -> pick a plan -> bot creates the VPN user -> replies with the
subscription link. /my shows your existing account.

Security: use a "bot"-scoped token (least privilege: can only list/create
users + read stats/templates). A "full" token works but can delete users,
restore backups, and manage settings: never ship it in a bot.
"""
import logging
import os
import re

import requests
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

def _missing_env(name: str) -> str:
    raise SystemExit(f"Set {name} first (see README.md).")


TG_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN") or _missing_env("TELEGRAM_BOT_TOKEN")
PANEL = (os.environ.get("ZEFIRA_URL") or _missing_env("ZEFIRA_URL")).rstrip("/")
ZEFIRA_TOKEN = os.environ.get("ZEFIRA_API_TOKEN") or _missing_env("ZEFIRA_API_TOKEN")
if not PANEL.startswith(("http://", "https://")):
    raise SystemExit("ZEFIRA_URL must start with http:// or https://")
SUB_BASE = os.environ.get("ZEFIRA_SUB_BASE", PANEL + "/sub").rstrip("/")
HEADERS = {"Authorization": f"Bearer {ZEFIRA_TOKEN}", "Content-Type": "application/json"}

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


def md(text) -> str:
    # Telegram legacy-Markdown: usernames/URLs may contain _ * ` [ ] etc.
    # Unescaped, the API rejects the whole message (400). Escape everything
    # we interpolate; static template text has no specials.
    return re.sub(r"([_*\[\]()~`>#+\-=|{}.!])", r"\\\1", str(text))


async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Welcome to Zefira VPN shop!\nUse /buy to get an account, /my to see yours.")


async def buy(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    kb = [[InlineKeyboardButton(label, callback_data=f"buy:{i}")]
          for i, (label, _, _) in enumerate(PLANS)]
    await update.message.reply_text("Pick a plan:", reply_markup=InlineKeyboardMarkup(kb))


def panel_msg(st: int) -> str:
    """Actionable per-status message; the owner gets the detail in logs."""
    if st == 0:
        return "Panel unreachable — try again in a minute."
    if st in (401, 403):
        return "Shop unavailable (bot credentials rejected) — tell the shop owner."
    if st == 413:
        return "No capacity right now — please try again later."
    if st == 429:
        return "Too many attempts — please wait a minute and retry."
    return "Panel error, try later."


async def my(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    st, data = api("GET", f"/api/users?q={uname(update.effective_user.id)}")
    if st != 200:
        await update.message.reply_text(panel_msg(st))
        return
    mine = [u for u in data.get("items", []) if u.get("username") == uname(update.effective_user.id)]
    if not mine:
        await update.message.reply_text("No account yet. Use /buy.")
        return
    u = mine[0]
    # .get() with fallbacks: a future panel schema change must not 500 here.
    await update.message.reply_text(
        f"Your account: {md(u.get('username'))}\n"
        f"Volume: {md(u.get('used_gb', 0))} / {md(u.get('volume_gb', 0))} GB\n"
        f"Expires: {md(u.get('expires_at') or '?')}\n\n"
        f"Subscription:\n`{md(SUB_BASE)}/{md(u.get('token', ''))}`",
        parse_mode="Markdown")


async def on_buy(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    try:
        idx = int(q.data.split(":", 1)[1])
        label, vol, days = PLANS[idx]
    except (IndexError, ValueError):
        # Stale inline button (bot restarted with a different plan list):
        # answer instead of leaving the spinner hanging forever.
        await q.message.reply_text("Plan list changed — send /buy again.")
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
        await q.message.reply_text(panel_msg(st))
        return
    await q.message.reply_text(
        f"Done! {md(label)}\n\nSubscription (tap to copy):\n"
        f"`{md(SUB_BASE)}/{md(data['token'])}`\n\n"
        f"Paste it into v2rayNG / Streisand / Clash.",
        parse_mode="Markdown")
    # Hide the buttons so a second tap cannot hit "already have".
    try:
        await q.edit_message_reply_markup(reply_markup=InlineKeyboardMarkup([]))
    except Exception:
        pass


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
