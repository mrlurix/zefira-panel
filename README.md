# Zefira

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-live-brightgreen)](https://mrlurix.github.io/zefira-panel/)
[![Pentest](https://img.shields.io/badge/pentest-117%2F117-success)](https://github.com/mrlurix/zefira-panel/blob/main/security_test.py)

> 📚 **Documentation: [mrlurix.github.io/zefira-panel](https://mrlurix.github.io/zefira-panel/)** — install guide, user manual, API reference, FAQ.

Simple panel for managing and selling VPN accounts. Started as a private tool for my own servers and cleaned up for public use.

Works with VLESS, VLESS-REALITY, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard, OpenVPN, L2TP/IPsec, Cisco AnyConnect and SOCKS5. One user can have multiple protocols at once and gets a single subscription link.

Built with FastAPI + SQLite. No Docker required, just Python.

### Screenshots

![Login](screenshots/screenshot-login.png)
![Dashboard](screenshots/screenshot-dashboard.png)
![User dashboard](screenshots/screenshot-user-dashboard.png)
![Appearance settings](screenshots/screenshot-appearance.png)

### Install on a server

```bash
curl -fsSLO https://raw.githubusercontent.com/mrlurix/zefira-panel/main/install.sh
less install.sh          # read it: it runs as root
sudo bash install.sh
```

> Why not `sudo bash <(curl ...)`? Because piping a remote script straight into
> a root shell means whatever is on the `main` branch at that moment runs as
> root with no review step. Downloading first lets you read it, and pinning a
> release tag (`.../v1.13.6/install.sh`) makes the install reproducible.

The script installs Python deps, creates a systemd service and stores your
first-run credentials in `instance/first-run-credentials.txt` (mode 600) -
`sudo cat` it, then delete it after the first login. Works on Ubuntu / Debian /
Alma / Rocky (needs Python 3.10+).

With the nginx option enabled the panel binds `127.0.0.1` only and the firewall
opens just 80/443; without it the panel answers plain HTTP on the chosen port,
so put TLS in front of it before you use real accounts.

To remove later: `sudo bash install.sh --uninstall`

### Manual install

```bash
git clone https://github.com/mrlurix/zefira-panel.git
cd zefira-panel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header --no-proxy-headers
```

Bind `127.0.0.1` and put a TLS reverse proxy in front of it. `--host 0.0.0.0`
publishes the admin login in clear text (no Secure cookies, no HSTS).

First run writes the admin username/password to
`instance/first-run-credentials.txt` (mode 600) and prints only the path. If
you set `ZEFIRA_ADMIN_PASSWORD` before starting, it will use that instead.

> **Run exactly one worker.** Rate limiters, the restore/update locks, the node monitor loop and the settings cache live in process memory — `--workers N` multiplies rate-limit budgets and can interleave restores. Scale with more machines, not more workers.

Default login: `http://YOUR_SERVER_IP:8000`

### What you get

- Users with traffic limit, expiry date, and notes. Start-on-first-use is supported if you want the timer to start only after the first connection. Pencil button per row edits note, volume, expiry, device limit.
- Multiple protocols per user, all in one subscription. Supports normal base64 subs and Clash YAML (`?format=clash`). Link remarks show the plain username.
- Browser dashboard: opening a subscription link in a browser shows usage, links, QR and apps; VPN clients always get raw bytes.
- Inbounds: define extra ports/hosts per protocol and every user gets links for all of them. Pin inbounds to server nodes — offline nodes are auto-excluded from links.
- Server nodes: register remote servers with 5-minute health checks, latency and uptime; on-demand check, enable/disable, safe delete.
- Anti-censorship: generate REALITY keys inside the panel, links use `xtls-rprx-vision` and rotate SNI automatically.
- BackPack tunnel nodes: create tunnels for your Iran/Kharej servers, download the setup guide with the token already filled in, and check if the Iran side is reachable.
- QR codes for every subscription, ZIP download for configs.
- AI assistant bubble: panel-only helper (Groq-first, OpenAI/Anthropic/Gemini/Ollama) for beginners.
- One-click updates from GitHub with changelog preview, right inside the panel.
- API tokens (`zfp_…` bearer) for Telegram bots and dashboards — no CSRF header needed. Scopes: `full` or least-privilege `bot` (list/create users only).
- Full personalization: theme colors, brand name, dashboard message.
- Strong password gate on sensitive actions, full audit log, system stats, Telegram notifications if you want.
- JSON backup / restore (both password confirmed), optional encrypted backups. Also imports/exports all settings.
- Runs as an unprivileged `zefira` systemd user (never root); volume quota enforced on subscriptions.

Full guides live on the docs site (link at the top).

### Settings you might want to change

Most things are in the panel itself: **Settings -> Server / Hosts Settings** (domain, ports, DNS, REALITY settings) and **Settings -> Remote Access** (public URL, trusted proxies).

If you prefer env files, copy `.env.example` to `.env`. Env vars are only used as defaults on first start.

### Security

I tried to keep it tight: scrypt for passwords, JWT in HttpOnly cookies, rate limits on login (per source IP, checked before any hashing), CSRF checks, strict CSP, parameterized queries, no innerHTML for user data, and audit logging.

**What is encrypted:** the Telegram/AI credentials, REALITY and WireGuard host
keys, tunnel tokens and encrypted backups (AES/Fernet with
`instance/secret.key`). **What is not:** the per-customer VPN credentials in
the database (`secret_data`) - they are plain JSON in `instance/zefira.db` and
in an unencrypted backup, by design so the panel can rebuild links without a
decrypt round-trip. Treat the database and unencrypted backups as customer
credentials: keep `instance/` at `700`, use encrypted backups or full-disk
encryption, and see [SECURITY.md](SECURITY.md).

There are four test suites that hit the running panel from the outside. Start
the panel, then run each one (restart the panel between suites):

```bash
python security_test.py    http://127.0.0.1:8000 admin YOURPASS   # 119 abuse/defense checks
python functional_test.py  http://127.0.0.1:8000 admin YOURPASS   #  60 end-to-end flows
python feature_test.py     http://127.0.0.1:8000 admin YOURPASS   # 177 feature-coverage checks
python attack_test.py      http://127.0.0.1:8000 admin YOURPASS   #  99 live attack probes
python attack_quota_test.py http://127.0.0.1:8000 admin YOURPASS #  46 quota/schema boundary checks
```

`feature_test.py` walks all 62 API routes across the 10 panel sections and
asserts each capability is actually usable (real links in a subscription, a
decodable QR, a working config archive, the bot-scope matrix, backup/restore
round-trips…), not merely reachable. `attack_test.py` fires the hostile
traffic itself: header spoofing, stored XSS, path traversal, oversized/over-
nested bodies, unicode/encoding tricks, timing oracles, login floods, limiter
eviction attempts, the full auth matrix. `attack_quota_test.py` covers the
accounting paths a customer actually hits: quota/expiry gating per client type,
start-on-first-use, device limits, and every Pydantic boundary on create and
patch. All five restore the panel to its shipped defaults afterwards, so the
suites are order-independent and can run against a live panel (or all five in
one go with `python run_all_tests.py admin YOURPASS`). A green run prints
`119/119`, `60/60`, `177/177`, `99/99` and `46/46` - if not, open an issue.

### API

It's a normal REST API, all under `/api/*`. Check the Docs page in the panel for the full table, or just open browser devtools while using the panel.

### License

MIT - see [LICENSE](LICENSE). Do what you want, just keep the notice.

### Donation

If Zefira helps you, consider supporting it: wallet addresses on the [donate page](https://mrlurix.github.io/zefira-panel/donate.html).

```text
TRX BEP-20:    0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18
ETH BEP-20:    0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18
USDC BEP-20:   0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18
```

---

If you like it, give it a star. Issues and PRs are welcome.
