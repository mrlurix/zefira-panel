# Security Policy

Zefira takes security seriously: scrypt password hashing, HttpOnly
SameSite cookies, rate-limited login, CSRF + CSP headers, audit logging, and
four test suites that run against a live panel: `security_test.py` (119
penetration/abuse checks), `feature_test.py` (177 feature checks),
`functional_test.py` (60 end-to-end checks) and `attack_test.py` (80 live
adversarial probes).

## What is encrypted, and what is not

Encrypted at rest with `instance/secret.key` (AES/Fernet):

- Telegram bot token, AI API key
- REALITY / WireGuard host private keys
- Tunnel (BackPack) tokens
- Encrypted backups

**Not** encrypted: the per-customer VPN credentials in `vpn_users.secret_data`
(generated UUIDs, per-protocol passwords, WireGuard/OpenVPN client keys). They
are stored as plain JSON in the SQLite database and are therefore also present
in plain form in an unencrypted backup JSON.

Treat the database and every unencrypted backup as customer credential material:

- keep `instance/` mode `700` and the database `600` (the installer does);
- use encrypted backups (`POST /api/backup {"encrypt": true}`) or full-disk
  encryption;
- never send an unencrypted backup over chat or email;
- a leaked database is a leaked customer account, not just panel data.

## Reporting a vulnerability

**Do NOT open a public issue.** Report privately via
[GitHub Security Advisories](https://github.com/mrlurix/zefira-panel/security/advisories/new)
so it can be fixed before disclosure.

Please include:
- Panel version (`Update` section or `VERSION` file) and install type
- Steps to reproduce (redact tokens, passwords, backup files)
- What you expected vs. what happened

## Scope notes

- Change your admin password immediately if you suspect exposure;
  logout and password change invalidate all other sessions.
- Never share backup JSON files: they contain password hashes and secrets.
- Back up `instance/secret.key` offline — without it, encrypted data
  (tunnel tokens, REALITY keys, Telegram/AI credentials) is unrecoverable.
- One panel = one reseller trust domain: any `bot`-scoped API token can
  list all users and renew anyone's plan (by design for a single
  reseller). Never give bot tokens to two independent resellers on the
  same panel.
