# Zefira reseller bot (Python)

Telegram shop bot for the Zefira panel. See `bot.py` (one file, ~120 lines).

```bash
pip install -r requirements.txt
set TELEGRAM_BOT_TOKEN=...       # from @BotFather (Windows: set, Linux: export)
set ZEFIRA_URL=https://panel.example.com
set ZEFIRA_API_TOKEN=zfp_...    # Panel -> Settings -> API Tokens -> Create with scope "bot"
python bot.py
```

Commands: `/start` `/buy` (plan keyboard) `/my` (your link).

Edit `PLANS` / `PROTOS` at the top of `bot.py` to change what you sell.
No payment step included — add yours where the user object is created
(`on_buy`), e.g. check a database/Stars payment before calling the panel.
