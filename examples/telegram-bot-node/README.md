# Zefira reseller bot (Node.js)

Telegram shop bot for the Zefira panel. See `bot.js` (one file, ~120 lines).

```bash
npm install
set TELEGRAM_BOT_TOKEN=...       # from @BotFather (Windows: set, Linux: export)
set ZEFIRA_URL=https://panel.example.com
set ZEFIRA_API_TOKEN=zfp_...    # Panel -> Settings -> API Tokens
node bot.js
```

Commands: `/start` `/buy` (plan keyboard) `/my` (your link).

Edit `PLANS` / `PROTOS` at the top of `bot.js` to change what you sell.
No payment step included — add yours where the user object is created
(`callback_query` handler), e.g. check a database/crypto payment first.
