"use strict";
/**
 * Zefira reseller bot (Node.js) - sell VPN accounts over Telegram.
 *
 * Requires Node.js 24 LTS or newer and node-telegram-bot-api 2.x.
 *
 * Setup:
 *   npm ci
 *   set TELEGRAM_BOT_TOKEN=...      (from @BotFather; Linux: export)
 *   set ZEFIRA_URL=https://panel.example.com
 *   set ZEFIRA_API_TOKEN=zfp_...    (Panel -> Settings -> API Tokens -> scope "bot")
 *   node bot.js
 *
 * Flow: /buy -> pick a plan -> bot creates the VPN user -> replies with the
 * subscription link. /my shows your existing account.
 *
 * Security: use a "bot"-scoped token (least privilege). A "full" token can
 * delete users, restore backups and manage settings: never ship it in a bot.
 */
const { Bot } = require("node-telegram-bot-api");

const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const PANEL = (process.env.ZEFIRA_URL || "").replace(/\/+$/, "");
const SUB_BASE = (process.env.ZEFIRA_SUB_BASE || PANEL + "/sub").replace(/\/+$/, "");
const HEADERS = {
  Authorization: `Bearer ${process.env.ZEFIRA_API_TOKEN || ""}`,
  "Content-Type": "application/json",
};

const PLANS = [
  { label: "10GB / 30 days", volume_gb: 10, days: 30 },
  { label: "30GB / 30 days", volume_gb: 30, days: 30 },
  { label: "50GB / 90 days", volume_gb: 50, days: 90 },
];
const PROTOS = ["vless"];

async function api(method, path, body) {
  try {
    const res = await fetch(PANEL + path, {
      method,
      headers: HEADERS,
      body: body ? JSON.stringify(body) : undefined,
      // A hung panel must not leave the promise pending forever: every
      // in-flight request holds a socket, and a shop bot sees constant traffic.
      signal: AbortSignal.timeout(15000),
    });
    let data = {};
    try {
      data = await res.json();
    } catch (_) {
      data = {};
    }
    return [res.status, data];
  } catch (err) {
    return [0, { detail: `panel unreachable: ${err.message}` }];
  }
}

// Subscription links are bearer credentials. If this bot sits in a group,
// /buy and /my would post the customer's token where every member (and every
// forwarded message) can read it, so everything is private-chat only.
const notPrivate = (chat) => !chat || chat.type !== "private";
const PRIVATE_ONLY =
  "For your privacy this shop only works in a private chat with me - open a DM with this bot and try again.";

const uname = (tgId) => `tg${tgId}`;
const panelMsg = (st) => {
  if (st === 0) return "Panel unreachable - try again in a minute.";
  if (st === 401 || st === 403) return "Shop unavailable (bot credentials rejected) - tell the shop owner.";
  if (st === 413) return "No capacity right now - please try again later.";
  if (st === 429) return "Too many attempts - please wait a minute and retry.";
  return "Panel error, try later.";
};
const md = (s) =>
  // Telegram legacy-Markdown: escape everything interpolated (usernames and
  // URLs may contain _ * ` [ ] etc., which would otherwise 400 the message).
  String(s).replace(/([_*[\]()~`>#+\-=|{}.!])/g, "\\$1");

function createBot(token) {
  const bot = new Bot(token);

  bot.command("start", (ctx) => {
    if (notPrivate(ctx.chat)) return ctx.reply(PRIVATE_ONLY);
    return ctx.reply("Welcome to Zefira VPN shop!\nUse /buy to get an account, /my to see yours.");
  });

  bot.command("buy", (ctx) => {
    if (notPrivate(ctx.chat)) return ctx.reply(PRIVATE_ONLY);
    return ctx.reply("Pick a plan:", {
      reply_markup: {
        inline_keyboard: PLANS.map((p, i) => [{ text: p.label, callback_data: `buy:${i}` }]),
      },
    });
  });

  bot.command("my", async (ctx) => {
    if (notPrivate(ctx.chat)) return ctx.reply(PRIVATE_ONLY);
    if (!ctx.from) return;
    const name = uname(ctx.from.id);
    const [st, data] = await api("GET", `/api/users?q=${encodeURIComponent(name)}`);
    if (st !== 200) {
      await ctx.reply(panelMsg(st));
      return;
    }
    const mine = (data.items || []).find((u) => u.username === name);
    if (!mine) {
      await ctx.reply("No account yet. Use /buy.");
      return;
    }
    // Optional chaining with fallbacks: a future panel schema change must not
    // crash here.
    await ctx.reply(
      `Your account: ${md(mine.username)}\nVolume: ${md(mine.used_gb ?? 0)} / ${md(mine.volume_gb ?? 0)} GB\nExpires: ${md(mine.expires_at || "?")}\n\nSubscription:\n\`${md(SUB_BASE)}/${md(mine.token || "")}\``,
      { parse_mode: "Markdown" }
    );
  });

  bot.on("callback_query", async (ctx) => {
    const q = ctx.callbackQuery;
    if (!q) return;
    const m = /^buy:(\d+)$/.exec(q.data || "");
    // Stale inline button (bot restarted with a different plan list): answer
    // instead of leaving the user's spinner hanging forever.
    if (!m || !PLANS[Number(m[1])]) {
      await ctx.answerCallbackQuery({ text: "Plan list changed - send /buy again." }).catch(() => {});
      return;
    }
    const plan = PLANS[Number(m[1])];
    if (notPrivate(ctx.chat)) {
      await ctx.answerCallbackQuery({ text: PRIVATE_ONLY }).catch(() => {});
      return;
    }
    if (!ctx.from) return;
    const name = uname(ctx.from.id);
    await ctx.answerCallbackQuery();
    const [st, data] = await api("POST", "/api/users", {
      username: name,
      protocols: PROTOS,
      volume_gb: plan.volume_gb,
      days: plan.days,
      note: `telegram:${ctx.from.id}`,
    });
    if (st === 409) {
      await ctx.reply("You already have an account. Use /my.");
      return;
    }
    if (st !== 200 || !data.token) {
      console.warn("create failed", st, data);
      await ctx.reply(panelMsg(st));
      return;
    }
    await ctx.reply(
      `Done! ${md(plan.label)}\n\nSubscription (tap to copy):\n\`${md(SUB_BASE)}/${md(data.token)}\`\n\nPaste it into v2rayNG / Streisand / Clash.`,
      { parse_mode: "Markdown" }
    );
    // Hide the buttons so a second tap cannot hit "already have".
    if (q.message) {
      await ctx.api
        .editMessageReplyMarkup({
          chat_id: q.message.chat.id,
          message_id: q.message.message_id,
          reply_markup: { inline_keyboard: [] },
        })
        .catch(() => {});
    }
  });

  return bot;
}

if (require.main === module) {
  if (!TG_TOKEN || !PANEL || !process.env.ZEFIRA_API_TOKEN) {
    console.error("Set TELEGRAM_BOT_TOKEN, ZEFIRA_URL and ZEFIRA_API_TOKEN first.");
    process.exit(1);
  }
  const bot = createBot(TG_TOKEN);
  bot.catch((err, ctx) => console.error("update failed", ctx.update.update_id, err));
  console.log("bot polling...");
  bot.startPolling().catch((err) => {
    console.error("polling stopped:", err);
    process.exitCode = 1;
  });
}

module.exports = { createBot, PLANS, PROTOS, notPrivate, uname, md };
