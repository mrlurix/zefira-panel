# Zefira

Simple panel for managing and selling VPN accounts. Started as a private tool for my own servers and cleaned up for public use.

Works with VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard and OpenVPN. You can also enable VLESS-REALITY for anti-filter setups. One user can have multiple protocols at once and gets a single subscription link.

Built with FastAPI + SQLite. No Docker required, just Python.

### Install on a server (one line)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mrlurix/zefira/main/install.sh)
```

The script installs Python deps, creates a systemd service and prints your login URL + password. Works on Ubuntu / Debian / Alma / Rocky.

To remove later: `sudo bash install.sh --uninstall`

### Manual install

```bash
git clone https://github.com/mrlurix/zefira.git
cd zefira
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --no-server-header --no-proxy-headers
```

First run prints the admin username/password in the terminal. If you set `ZEFIRA_ADMIN_PASSWORD` before starting, it will use that instead.

Default login: `http://YOUR_SERVER_IP:8000`

### What you get

- Users with traffic limit, expiry date, and notes. Start-on-first-use is supported if you want the timer to start only after the first connection.
- Multiple protocols per user, all in one subscription. Supports normal base64 subs and Clash YAML (`?format=clash`).
- Inbounds: define extra ports/hosts per protocol and every user gets links for all of them.
- Anti-censorship: generate REALITY keys inside the panel, links use `xtls-rprx-vision` and rotate SNI automatically.
- BackPack tunnel nodes: create tunnels for your Iran/Kharej servers, download the setup guide with the token already filled in, and check if the Iran side is reachable.
- QR codes for every subscription, ZIP download for configs.
- 2FA with any authenticator app, full audit log, system stats, Telegram notifications if you want.
- JSON backup / restore (password confirmed). Also imports/exports all settings.

All docs are also inside the panel under **Docs** (left menu).

### Settings you might want to change

Most things are in the panel itself: **Settings -> Server / Hosts Settings** (domain, ports, DNS, REALITY settings) and **Settings -> Remote Access** (public URL, trusted proxies).

If you prefer env files, copy `.env.example` to `.env`. Env vars are only used as defaults on first start.

### Security

I tried to keep it tight: scrypt for passwords, JWT in HttpOnly cookies, rate limits on login, CSRF checks, strict CSP, parameterized queries, no innerHTML for user data, encrypted secrets at rest, and audit logging. 

There is a test suite with 60+ checks that hits the running panel from the outside:

```bash
python security_test.py http://127.0.0.1:8000 admin YOURPASS
```

It should print `62/62 checks passed` or similar - if not, open an issue.

### API

It's a normal REST API, all under `/api/*`. Check the Docs page in the panel for the full table, or just open browser devtools while using the panel.

### License

MIT - see [LICENSE](LICENSE). Do what you want, just keep the notice.

---

If you like it, give it a star. Issues and PRs are welcome.
