/**
 * ZEFIRA DONATE WORKER (Cloudflare Workers, free tier)
 * ----------------------------------------------------
 * Holds your Shieldz SECRET key (never put sk_live_... in the static site -
 * GitHub Pages source is public and anyone could steal it).
 *
 * Deploy (5 minutes, free):
 *   1. https://dash.cloudflare.com -> Workers & Pages -> Create Worker
 *   2. Paste this whole file as the worker code -> Deploy
 *   3. Worker Settings -> Variables -> Add variable:
 *        Name  = SHIELDZ_API_KEY
 *        Value = sk_live_... (from merchant.shieldz.cash -> Developer mode)
 *      (Use sk_test_... first to try test mode.)
 *   4. Copy the worker URL, e.g. https://zefira-donate.YOU.workers.dev
 *   5. Put it in docs/assets/donate-config.json ("api" field), commit+push.
 *
 * Flow: donate page --POST {amount_usd}--> this worker --creates invoice-->
 *       returns {pay_url} --> buyer redirected to Shieldz hosted checkout.
 * Donations need no webhook (nothing to fulfill). For test mode just swap
 * the secret to sk_test_ and use the dashboard simulate-payment tool.
 */

const ALLOWED_ORIGIN = "https://mrlurix.github.io"; // your Pages site (change if you use a custom domain)
const MIN_CENTS = 100; // $1
const MAX_CENTS = 100000; // $1000
const WINDOW_MS = 60 * 1000;
const MAX_HITS = 10;

const hits = new Map(); // ip -> [timestamps]; best-effort abuse throttle

function throttled(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();
  return arr.length > MAX_HITS;
}

function json(body, status, cors) {
  return new Response(JSON.stringify(body), { status, headers: cors });
}

export default {
  async fetch(req, env) {
    const cors = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json",
    };
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "POST") return json({ error: "method not allowed" }, 405, cors);
    if (!env.SHIELDZ_API_KEY) return json({ error: "server not configured" }, 500, cors);

    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    if (throttled(ip)) return json({ error: "too many requests, slow down" }, 429, cors);

    let cents = NaN;
    try {
      const body = await req.json();
      cents = Math.round(Number(body.amount_usd) * 100);
    } catch (_) {
      return json({ error: "bad request" }, 400, cors);
    }
    if (!Number.isFinite(cents) || cents < MIN_CENTS || cents > MAX_CENTS) {
      return json({ error: "amount must be between $1 and $1000" }, 400, cors);
    }

    let r;
    try {
      r = await fetch("https://shieldz.cash/api/v1/invoices", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + env.SHIELDZ_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          amount_usd_cents: cents,
          memo: "Zefira donation",
          idempotency_key: crypto.randomUUID(),
        }),
      });
    } catch (_) {
      return json({ error: "payment provider unreachable" }, 502, cors);
    }
    if (!r.ok) return json({ error: "payment provider rejected the request" }, 502, cors);
    let inv = null;
    try {
      inv = await r.json();
    } catch (_) {
      return json({ error: "payment provider bad response" }, 502, cors);
    }
    if (!inv || typeof inv.pay_url !== "string" || !inv.pay_url.startsWith("https://")) {
      return json({ error: "payment provider bad response" }, 502, cors);
    }
    return json({ pay_url: inv.pay_url }, 200, cors);
  },
};
