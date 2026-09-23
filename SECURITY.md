# Security Policy

Zefira takes security seriously: scrypt password hashing, HttpOnly
SameSite cookies, rate-limited login, CSRF + CSP headers, encrypted secrets
at rest, audit logging, and a `security_test.py` penetration suite (119/119
checks, plus 60/60 functional and a permanent i18n-coverage suite) that
runs against a live panel.

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
