"use strict";
/**
 * Zefira reseller bot (Node.js) - sell VPN accounts over Telegram.
 *
 * Setup:
 *   npm install
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
const TelegramBot = require("node-telegram-bot-api");

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

if (!TG_TOKEN || !PANEL || !process.env.ZEFIRA_API_TOKEN) {
  console.error("Set TELEGRAM_BOT_TOKEN, ZEFIRA_URL and ZEFIRA_API_TOKEN first.");
  process.exit(1);
}

async function api(method, path, body) {
  try {
    const res = await fetch(PANEL + path, {
      method,
      headers: HEADERS,
      body: body ? JSON.stringify(body) : undefined,
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

const uname = (tgId) => `tg${tgId}`;
const panelMsg = (st) => {
  if (st === 0) return "Panel unreachable — try again in a minute.";
  if (st === 401 || st === 403) return "Shop unavailable (bot credentials rejected) — tell the shop owner.";
  if (st === 413) return "No capacity right now — please try again later.";
  if (st === 429) return "Too many attempts — please wait a minute and retry.";
  return "Panel error, try later.";
};
const md = (s) =>
  // Telegram legacy-Markdown: escape everything interpolated (usernames and
  // URLs may contain _ * ` [ ] etc., which would otherwise 400 the message).
  String(s).replace(/([_*[\]()~`>#+\-=|{}.!])/g, "\\$1");
const bot = new TelegramBot(TG_TOKEN, { polling: true });

bot.onText(/^\/start$/, (msg) => {
  bot.sendMessage(msg.chat.id, "Welcome to Zefira VPN shop!\nUse /buy to get an account, /my to see yours.");
});

bot.onText(/^\/buy$/, (msg) => {
  bot.sendMessage(msg.chat.id, "Pick a plan:", {
    reply_markup: {
      inline_keyboard: PLANS.map((p, i) => [{ text: p.label, callback_data: `buy:${i}` }]),
    },
  });
});

bot.onText(/^\/my$/, async (msg) => {
  const name = uname(msg.from.id);
  const [st, data] = await api("GET", `/api/users?q=${encodeURIComponent(name)}`);
  if (st !== 200) {
    bot.sendMessage(msg.chat.id, panelMsg(st));
    return;
  }
  const mine = (data.items || []).find((u) => u.username === name);
  if (!mine) {
    bot.sendMessage(msg.chat.id, "No account yet. Use /buy.");
    return;
  }
  // .get() with fallbacks: a future panel schema change must not crash here.
  bot.sendMessage(
    msg.chat.id,
    `Your account: ${md(mine.username)}\nVolume: ${md(mine.used_gb ?? 0)} / ${md(mine.volume_gb ?? 0)} GB\nExpires: ${md(mine.expires_at || "?")}\n\nSubscription:\n\`${md(SUB_BASE)}/${md(mine.token || "")}\``,
    { parse_mode: "Markdown" }
  );
});

bot.on("callback_query", async (q) => {
  const m = /^buy:(\d+)$/.exec(q.data || "");
  // Stale inline button (bot restarted with a different plan list): answer
  // instead of leaving the user's spinner hanging forever.
  if (!m || !PLANS[Number(m[1])]) {
    await bot.answerCallbackQuery(q.id, { text: "Plan list changed — send /buy again." }).catch(() => {});
    return;
  }
  const plan = PLANS[Number(m[1])];
  const name = uname(q.from.id);
  await bot.answerCallbackQuery(q.id);
  const [st, data] = await api("POST", "/api/users", {
    username: name,
    protocols: PROTOS,
    volume_gb: plan.volume_gb,
    days: plan.days,
    note: `telegram:${q.from.id}`,
  });
  if (st === 409) {
    bot.sendMessage(q.message.chat.id, "You already have an account. Use /my.");
    return;
  }
  if (st !== 200 || !data.token) {
    console.warn("create failed", st, data);
    bot.sendMessage(q.message.chat.id, panelMsg(st));
    return;
  }
  bot.sendMessage(
    q.message.chat.id,
    `Done! ${md(plan.label)}\n\nSubscription (tap to copy):\n\`${md(SUB_BASE)}/${md(data.token)}\`\n\nPaste it into v2rayNG / Streisand / Clash.`,
    { parse_mode: "Markdown" }
  );
  // Hide the buttons so a second tap cannot hit "already have".
  bot.editMessageReplyMarkup({ chat_id: q.message.chat.id, message_id: q.message.message_id })
    .catch(() => {});
});

console.log("bot polling...");
