# Zefira reseller bot (Python)

Telegram shop bot for the Zefira panel. See `bot.py` (one file, ~120 lines).

```bash
pip install -r requirements.txt
set TELEGRAM_BOT_TOKEN=...       # from @BotFather (Windows: set, Linux: export)
set ZEFIRA_URL=https://panel.example.com
set ZEFIRA_API_TOKEN=zfp_...    # Panel -> Settings -> API Tokens -> Create with scope "bot"
set TG_PROVIDER_TOKEN=...       # from @BotFather, Stars - enables paid plans
python bot.py
```

Commands: `/start` `/buy` (plan keyboard) `/my` (your link).

**Private chat only.** Subscription links are bearer credentials, so the bot
refuses to answer in groups or channels — otherwise a customer's link would be
posted where every member (and any forwarded message) can read it.

Edit `PLANS` / `PROTOS` at the top of `bot.py` to change what you sell.

Payments: set `TG_PROVIDER_TOKEN` (from @BotFather, Stars) to sell paid plans.
`/buy` then sends a Telegram Stars invoice; on approval (`pre_checkout_query`)
the bot creates the customer with the chosen plan and delivers the subscription
link. Without the token the shop answers "Payments are not configured …".

To take real money, add your own payment step (check a database/Stars payment)
before the user object is created in the pre-checkout handler (`on_pre_checkout`),
e.g. verify the payment server-side first.

Management: the bot itself can list/create customers (bot-scoped token) and
answer `/my`. Destructive management (delete, reset usage, restore backup,
settings) needs an admin token — hold it yourself (`ZEFIRA_ADMIN_TOKEN` style)
and connect the bot to your own admin API; never ship an admin token in a bot.
