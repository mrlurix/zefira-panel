# Security Policy

Zefira takes security seriously: scrypt password hashing, HttpOnly
SameSite cookies, rate-limited login, CSRF + CSP headers, audit logging, and
a test suite that runs against a live panel. Run it with:

```sh
python run_all_tests.py <admin> <password>
```

The suites are listed in the READMEs. Count them there rather than here: this
file used to state a total and a check count for each of seven suites, and
every one of those numbers was stale within a few releases - a document that
overstates its own coverage is worse than one that says nothing.
`security_doc_test.py` now fails if such a figure reappears here, because the
runner is the only place that knows the true count.

## What is encrypted, and what is not

Encrypted at rest with `instance/secret.key` (AES/Fernet):

- Telegram bot token, AI API key
- REALITY private key
- Tunnel (BackPack) tokens
- Per-customer credentials in `vpn_users.secret_data` (WireGuard private key,
  OpenVPN client keypair, L2TP PSK, per-protocol passwords) - encrypted since
  v1.15.27
- Customer subscription tokens, since v1.15.29. The column holds a Fernet blob
  and a separate HMAC digest column provides the indexed lookup `/sub/{token}`.
  This one was measured, not suspected: a token read straight out of
  `zefira.db` answered `/sub/{token}` with 200 and the customer's private key,
  and an unencrypted backup carried the same token in cleartext.
- Encrypted backups

Not stored by the panel at all: the WireGuard **host** private key. The panel
never reads or writes it, so there is nothing to encrypt.

**Not** encrypted: customer-facing display names, notes, usage counters and
timestamps. These are billing data, not credentials, and they are readable in
an unencrypted backup by design.

Treat the database and every unencrypted backup as customer credential material:

- keep `instance/` mode `700` and the database `600` (the installer does);
- use encrypted backups (`POST /api/backup {"encrypt": true}`) or full-disk
  encryption;
- never send an unencrypted backup over chat or email;
- a leaked database is a leaked customer account, not just panel data.


## The AI assistant, and what it sends

Two different things wear the name "assistant". They have nothing in common
risk-wise, so they are separated here.

**The assistant on the documentation site** has no backend, no API key and no
network call. It scores your typed words against a JSON file that ships in the
repository, and it renders with `textContent` only. Nothing you type leaves the
browser, and nothing can be injected into the page through it.

**The assistant in the panel** (`POST /api/ai/chat`) is the opposite: it calls
a provider you configure (`base_url` + API key) and sends it customer context -
the rows the tools need to answer "reset usage for alice". The consequences,
stated plainly:

- It is admin-only. A `bot`-scoped API token is rejected at the route, so an
  integration token cannot drive it.
- Customer names, notes, usage counters and configuration do leave your host,
  to whichever provider you pointed `base_url` at. If that matters to you, do
  not configure an AI provider; nothing else in the panel depends on it.
- A restore cannot plant an `ai_extra` block. The whole AI configuration is
  excluded from restore, because a crafted backup could otherwise inject
  prompt content that later runs with admin authority.
- The provider URL is checked before every request: scheme, userinfo, port
  range, resolved addresses against a blocked list, a pinned dial address to
  close the DNS-rebinding window, and no redirect following.
- Errors from the provider are scrubbed of the API key before they are logged.

If you enable it, treat it the way you would treat any third party you hand
customer data to.

## Reporting a vulnerability

**Do NOT open a public issue.** Report privately via
[GitHub Security Advisories](https://github.com/mrlurix/zefira-panel/security/advisories/new)
so it can be fixed before disclosure.

Please include:
- Panel version (`Update` section or `VERSION` file) and install type
- Steps to reproduce (redact tokens, passwords, backup files)
- What you expected vs. what happened

## Bug bounty

**No cash is promised, because none is funded.** There is no escrow behind this
repository. Anything that named a figure would be a promise this project cannot
keep, made to exactly the people most likely to do the difficult work of
finding real bugs. So the reward is severity and recognition today, and payment
if and when a programme is funded - which will be announced here, not implied.

### Safe harbour

If you follow this policy you have our permission to research this panel, and
we will not pursue legal action against you for it. You may:

- test against a panel **you run yourself**, which is the only kind of testing
  we ask for;
- read the source, including the release history, freely;
- use automated scanners, read the database, and craft any input you like
  against your own instance;
- publish a write-up of what you found, once a fix has shipped or 90 days have
  passed since the report, whichever is sooner.

Out of scope, even under safe harbour: testing any panel you do not own,
denial of service, social engineering of the operator, and exfiltrating data
that is not yours. Everything else is fair game.

### How to report

Use the repository's **Report a vulnerability** button, which opens a private
advisory: [security/advisories/new](https://github.com/mrlurix/zefira-panel/security/advisories/new).

A private advisory is visible only to you and the maintainer. It does not
create a public issue, and no other researcher can see that it exists.

### What counts

| severity | meaning |
|---|---|
| **Critical** | unauthenticated access to customer credentials, or remote code execution in the panel process |
| **High** | authentication bypass; privilege escalation from a `bot`-scoped token to full admin; any path that reads a customer's WireGuard private key, OpenVPN client key or L2TP PSK without the operator's action |
| **Medium** | stored XSS in the panel; CSRF that changes state; a rate limit that can be bypassed to make bulk customer operations cheap |
| **Low** | information disclosure that does not expose a credential; a guard that can be tripped by a hand-edited database |

Every report gets an acknowledgement. A confirmed fix is credited in the
release notes unless you ask otherwise.

### Known trade-offs, not defects

Reporting any of these is a duplicate of a documented decision. They are
listed so a good-faith report does not go to waste:

- **Running more than one worker.** The panel refuses to start with
  `WEB_CONCURRENCY>1` on purpose: its rate limiters, locks, settings cache and
  node monitor live in process memory, so a second worker multiplies every
  limit and can interleave restores. See `_enforce_single_worker` in
  `main.py`. `ZEFIRA_ALLOW_MULTI_WORKER=1` overrides it, at the operator's own
  risk.
- **SQLite write serialisation.** One writer at a time is a property of SQLite,
  not a bug in this panel. It is why the panel refuses to scale with workers
  and why the rate limiters are per-process.
- **No HSM or KMS.** `instance/secret.key` protects the encrypted settings and
  the per-customer credential bundles. There is no hardware-backed key.
- **The AI assistant sends operator-written prompts to the configured
  provider.** It is an LLM the operator points at a host they choose. See "The
  AI assistant, and what it sends" above.

## Scope notes

- Change your admin password immediately if you suspect exposure;
  logout and password change invalidate all other sessions.
- Never share backup JSON files: they contain password hashes and secrets.
- Back up `instance/secret.key` offline — without it, encrypted data
  (tunnel tokens, REALITY keys, Telegram/AI credentials) is unrecoverable.
  If the file exists but is shorter than 32 characters the panel now refuses
  to start instead of silently generating a new one, because that would
  invalidate every session and make every encrypted setting undecryptable.
- **A backup file is untrusted input.** Restoring one deliberately does NOT
  import admin passwords, API tokens, or the public origin
  (`public_url` / `domain`): a crafted file could otherwise install a
  credential its author knows, or repoint every customer's subscription link
  and QR at an attacker's host. Change those in Settings after a migration,
  and re-create any integration tokens the restored customers need.
- Dependencies install from `requirements.lock` (every artifact pinned with
  its sha256) via `pip install --require-hashes --no-deps`, never from a
  floating resolution of `requirements.txt`.
- The in-panel updater refuses any incoming commit that adds runtime state
  (`instance/`, `.env`, database/key files), binds the install to the exact
  commit the Update card showed, requires a GitHub-verified signature by
  default, and will not run while the systemd unit is unsafe (running as root
  or carrying a privileged `ExecStartPre=+`).
- One panel = one reseller trust domain: any `bot`-scoped API token can
  list all users and renew anyone's plan (by design for a single
  reseller). Never give bot tokens to two independent resellers on the
  same panel.
