# ZEFIRA PANEL

**Multi-protocol proxy sales & management panel** — red/black themed, security-hardened, single-file SQLite.

`FastAPI + uvicorn + SQLAlchemy` · VLESS-REALITY / VMess / Trojan / Shadowsocks / Hysteria2 / WireGuard / OpenVPN · Clash subscriptions · TOTP 2FA · BackPack tunnel manager · Telegram alerts

---

## ⚡ One-command install (Ubuntu/Debian/Alma/Rocky)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/USERNAME/zefira/main/install.sh)
```

> Replace `USERNAME` with the GitHub account the repo is pushed to (or set `ZEFIRA_REPO_URL`).
> The installer creates `/opt/zefira`, a systemd service, a random admin password and prints the login URL.

Uninstall: `sudo bash install.sh --uninstall`

## 🛡️ Security-first

41→**67 automated attack checks** ship in `security_test.py` (SQLi, XSS, JWT tampering, CSRF, brute-force,
XFF spoofing, path traversal, memory-DoS, mass-assignment, input fuzzing...). Run it against your own instance:

```bash
.venv\Scripts\python security_test.py http://127.0.0.1:8000 admin YOURPASS   # Windows
.venv/bin/python security_test.py http://127.0.0.1:8000 admin YOURPASS       # Linux
```

Latest result: **67/67 PASS**

## 📖 Full documentation

Everything (protocols, inbounds, tunnels, REALITY keys, backups, API reference) is documented **inside the panel**
under **Docs**, and mirrored in this README below.

---

ZEFIRA PANEL

Supported protocols (multi-select per user)
--------------------------------------------
VLESS-REALITY (anti-censorship) - X25519 REALITY keypair generated in-panel,
    masquerade SNI rotation (yahoo/samsung/microsoft), xtls-rprx-vision flow
VLESS / VMess / Trojan (TLS+WS) - subscription links, v2rayNG/NekoBox/Streisand compatible
Shadowsocks (AES-256-GCM)
Hysteria2
WireGuard   - real X25519 keys per user, ready wg .conf
OpenVPN     - panel-managed CA + per-user signed certificates, complete .ovpn

Subscription formats
---------------------
/sub/{token}              base64 v2ray links (or plain text when WG/OVPN included)
/sub/{token}?format=clash Clash/ClashMeta YAML (auto-detected from User-Agent too)

Marzban/PasarGuard-style features
----------------------------------
- Multi-protocol single user, one subscription for all
- VLESS-REALITY anti-filter protocol with in-panel key management
- Start-on-first-use expiry strategy (counts down from first connection)
- Limited status when volume is exhausted; manual usage editing via PATCH add_used_gb
- User templates (save/load/delete presets in Add-User dialog)
- Clash/ClashMeta subscription output
- Hosts/server settings editable from dashboard (incl. REALITY port & SNI list)
- System monitoring widget, JSON backup/restore (password-confirmed), audit log

Remote access & tunneling
--------------------------
Settings -> "Remote Access & Tunneling":
- Public base URL: used in subscription links / QR codes behind any tunnel
- Trusted proxies: ONLY these IPs/CIDRs may set X-Forwarded-For (anti-spoofing)
- One-click ready scripts: SSH forward, SSH reverse, socat, gost, realm

Typical flows:
  Normal tunnel  (panel on server):  ssh -N -L 8000:127.0.0.1:8000 user@SERVER
  Reverse tunnel (panel behind NAT): ssh -N -R 0.0.0.0:8000:127.0.0.1:8000 user@VPS
                                     (+ GatewayPorts yes in sshd_config)
IMPORTANT: always run uvicorn with --no-proxy-headers so only OUR trusted_proxies
logic decides which X-Forwarded-For values are honored (uvicorn's default proxy
middleware would otherwise let ANY local client spoof their IP).

Security test suite
--------------------
security_test.py fires ~38 attacks: auth boundary, CSRF, SQLi payloads,
JWT alg=none/tampering/bad-signature, brute-force throttling, XFF spoof bypass,
path traversal, stored XSS, oversized payloads, method abuse, sub-token probing,
2FA guessing limits. Run against your own instance:

    .venv\\Scripts\\python security_test.py http://127.0.0.1:8000 admin YOURPASS

Current status: 38/38 PASS.

Install & run
--------------
cd zefira
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.\start.bat        <- auto-installs deps and opens the browser

Manual run:
.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-server-header

On first run the admin password is printed to the console,
or preset it with environment variables:
    $env:ZEFIRA_ADMIN_USERNAME="admin"
    $env:ZEFIRA_ADMIN_PASSWORD="YourStrongPass123"

Server settings
---------------
Preferred way: Settings -> "Server / Hosts Settings" inside the panel (stored in DB).
Environment variables are used only as initial defaults:
    ZEFIRA_DOMAIN, ZEFIRA_SUB_PORT, ZEFIRA_HY2_PORT, ZEFIRA_WG_PORT,
    ZEFIRA_DNS, ZEFIRA_OVPN_PORT, ZEFIRA_OVPN_PROTO, ZEFIRA_SESSION_TTL

Security implemented
---------------------
1. TOTP 2FA (local QR, Fernet-encrypted secret at rest)
2. scrypt hashing + timing-safe compare + dummy-hash anti-enumeration
3. JWT session in HttpOnly SameSite=Strict cookie; global invalidation on password change/restore
4. Login rate limit: 8 tries / 15 min per IP+user (includes 2FA failures)
5. CSRF guard on POST/PATCH/DELETE + 1 MB request body cap
6. Strict CSP (no inline scripts/styles), frame-ancestors none, noindex
7. Parameterized SQLAlchemy queries + strict Pydantic validation
8. Safe DOM rendering (no innerHTML for user data) against XSS
9. Audit log of security events (login ok/fail, user CRUD, settings, backup/restore)
10. 256-bit random subscription tokens; token reset regenerates ALL protocol secrets

Deployment checklist (real world)
----------------------------------
- Serve behind Nginx/Caddy with HTTPS so cookies become Secure automatically
- Keep uvicorn single-worker (in-memory rate limiter) or move limiting to Nginx
- Protect instance/ca.key and instance/secret.key; backup instance/zefira.db regularly
- Harden your actual VPN servers separately (firewall, fail2ban, updates)

API summary
------------
POST   /api/login | /api/logout | /api/change-password
GET    /api/me | /api/stats | /api/system | /api/users?q= | /api/audit | /api/settings | /api/backup
PUT    /api/settings
POST   /api/users | /api/restore | /api/users/{id}/reset-token | /api/2fa/setup|enable|disable
PATCH  /api/users/{id}
DELETE /api/users/{id}
GET    /api/users/{id}/config   (single file or ZIP bundle)
GET    /api/users/{id}/qr       (QR of subscription link)
GET    /sub/{token}             public subscription endpoint
```

## License

Released under the **MIT License** — see [LICENSE](LICENSE).
