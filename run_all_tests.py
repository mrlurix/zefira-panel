"""Run every suite back-to-back on one panel, restarting between them.

Proves the suites are order-independent (no hidden state carried over) and
that the security fixes hold under the live adversarial probes too.
Usage: .venv\\Scripts\\python run_all_tests.py [admin] [password]
"""
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
# Per-run panel logs, outside the repo so a failing run never leaves untracked
# files in the tree the pre-push gate inspects.
LOG_DIR = os.path.join(tempfile.gettempdir(), "zefira-suite-logs")
os.makedirs(LOG_DIR, exist_ok=True)
ADMIN = sys.argv[1] if len(sys.argv) > 1 else "admin"
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else "YOUR_PASSWORD"
HOST, PORT = "127.0.0.1", "8011"
BASE = f"http://{HOST}:{PORT}"
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
if not os.path.exists(PY):
    PY = sys.executable

SUITES = [
    ("feature_test.py", "feature coverage"),
    ("security_test.py", "security / abuse"),
    ("functional_test.py", "functional flows"),
    ("attack_test.py", "live attack probes"),
    ("attack_quota_test.py", "quota / schema boundaries"),
    ("attack_paths_test.py", "operator paths / restore"),
    ("frontend_bugs_test.py", "front-end regressions"),
    ("panel_sections_test.py", "panel sections end-to-end"),
    # SECURITY.md must not restate a coverage figure: it said thirty-five
    # suites and seven per-suite check counts when the runner had 42. A
    # document that overstates its own coverage is worse than one that
    # says nothing, so the numbers were removed and this fails if one
    # reappears. Also covers the bug-bounty section. 18 checks, 5 mutations.
    ("security_doc_test.py", "the security policy stays honest"),
    # The migration list, executed rather than read. It exists because
    # a helper landed between @staticmethod and def _add_column, which
    # ast.parse cannot see: the file parsed, the names did not resolve,
    # and every migration raised on the first step. 13 checks, 4 mutations.
    ("migration_run_test.py", "the migration list actually runs"),
    # Six defects an agent sweep found on 2026-10-16, each measured before
    # it was fixed: a restore that answered ok:true after deleting every
    # customer, a validator that caught one spelling of a field and not the
    # other, two serialisers that 500 on a bytes or NULL column, a missing
    # index on the anonymous subscription lookup, and the access log
    # carrying that same credential. 28 checks, 7 mutations.
    ("reliability_guards_test.py", "agent-sweep defects stay fixed"),
    # Reads, changes, reads back and restores EVERY settings card. Cards whose
    # action reaches outside the panel (a real certificate, a real chat, provider
    # quota) are probed with input rejected before the side effect, so this
    # exercises them without issuing anything.
    ("settings_cards_test.py", "every settings card end-to-end"),
    ("security_audit_test.py", "security audit round 1"),
    ("mcp_routes_test.py", "the MCP panel routes, end to end"),
    # LIVE, not static: this one starts its own panel and compares the
    # response shapes docs/api.html publishes against what the API
    # actually returns. A static check could only compare the
    # documentation with itself and would pass forever.
    ("api_response_shapes_test.py", "API reference matches reality"),
    # The real SDK, mcp==2.3.0, as a real client over both transports. It
    # installs into a throwaway virtualenv OUTSIDE the repository so the
    # panel installs no new dependency, and it exits 2 - never 0 - when
    # that environment cannot be prepared, because a suite that could not
    # run must never be reported as a pass.
    ("mcp_conformance_test.py", "MCP conformance, real SDK, both transports"),
    # LIVE: it starts its own panel with ZEFIRA_LOG_FORMAT=json and reads
    # what the panel actually wrote, so it cannot pass by comparing the
    # formatter with itself.
    ("logging_format_test.py", "the log format, plain and JSON"),
]
# Suites that need no running panel: static guards over the installer, which
# is only ever executed on a Linux VPS (never here), and the docs site.
OFFLINE_SUITES = [
    ("installer_test.py", "installer CLI"),
    # Runs public_base_url() against a genuinely fresh database with
    # ZEFIRA_DOMAIN= (what install.sh writes when the operator pressed Enter at
    # the domain prompt). No server, no suite state. This is the check that was
    # missing when every fresh install handed the customer a port-less link and
    # the customer got nginx's 404.
    ("dashboard_link_test.py", "customer dashboard link"),
    # client_ip() and request_scheme() disagreed on what a trusted peer is, so
    # a panel behind a local reverse proxy believed the scheme but not the
    # address - every visitor collapsed onto one rate-limit key and a flood
    # locked the operator out of login. DB-free; trusted_networks() is stubbed
    # to the EMPTY case, because stubbing it to a loopback network makes the
    # configured and unconfigured cases identical and hides the whole defect.
    ("proxy_trust_test.py", "proxy trust + client IP"),
    # ss/hysteria2/REALITY interpolated the remark raw while vless/trojan
    # percent-encoded it, so a name carrying "#" split the link into three
    # fragments and the client showed "a". Runs the real builders, offline.
    ("link_encoding_test.py", "share-link remark encoding"),
    # The updater's runtime-intrusion guard, over a real `git ls-tree`. It used
    # to feed globs ("*.db") to str.startswith, which matches nothing, and to
    # apply ".env" as a prefix - which flagged the shipped .env.example and so
    # refused EVERY update, on every release since v1.0.0. No test covered it.
    ("update_guard_test.py", "updater intrusion guard"),
    # Migration steps, one transaction each. Section 3 documents a failure the
    # fix addresses and cannot detect here (pysqlite commits DDL outside the
    # transaction - measured), so it is the transaction-boundary checks in
    # section 5 that do the guarding.
    ("migration_guard_test.py", "schema migration steps"),
    # The installer ran as root and appended to a .env that a compromised
    # panel (it owns /opt/zefira) can replace with a symlink. Derives the chown
    # that makes the symlink plantable, then asserts no unguarded append.
    ("env_symlink_guard_test.py", "installer env symlink"),
    # docs/bump_assets.py wrote its argv version straight into a regex REPLACEMENT,
    # so one backslash corrupted every asset URL in the site. Runs against a COPY.
    ("bump_assets_guard_test.py", "docs asset bump inputs"),
    # install.sh ran its own prose as root: backticks inside an UNQUOTED
    # systemd heredoc were executed as commands. Runs the real heredoc.
    ("installer_unit_test.py", "installer heredoc safety"),
    # secret_data holds the WireGuard private key, the OpenVPN client keypair
    # and the L2TP PSK. It was bare json.dumps in a TEXT column, so reading the
    # SQLite file - or an unencrypted backup - read every customer credential.
    ("secret_at_rest_test.py", "customer secrets encrypted at rest"),
    ("security_hardening_test.py", "audit hardening: secret disclosure budgets, fail-closed scopes"),
    ("subscription_token_test.py", "the subscription bearer token is not readable at rest"),
    ("operability_test.py", "single-worker refusal, request correlation, annotation coverage"),
    # /api/update/status held its request for 12 s on a slow link, because
    # the route made up to three 10 s GitHub calls inline and the panel is
    # single-worker. Measured against a live panel: 12.00 s before, 0.23 s
    # cold and 0.025 s warm after, with the GitHub half on a daemon thread.
    ("update_status_latency_test.py", "update page never waits on GitHub"),
    # The panel pinned BackPack v1.8.2 while upstream shipped v1.8.3,
    # v1.8.4 and v1.8.5, and the setup guide still described the wizard
    # those releases retired. 99 checks over the pin, the sni carrier, the
    # four per-tunnel options and every guide line, each proved red.
    ("backpack_tunnel_test.py", "BackPack v1.8.5 tunnel capabilities"),
    # The AI fetch validates eff_base, pins its IP and strips the key for
    # local targets, then fetches a `url` it built separately. The safety
    # rests on the two agreeing, and only reading enforced that. Measured:
    # all four providers agree today; this fails when a fifth does not.
    ("ai_url_guard_test.py", "AI fetch URL matches its validated base"),
    ("installer_guard_test.py", "installer symlink + banner guards"),
    # The four READMEs, compared rather than eyeballed: a translation that drops
    # a number, an address or a code fence is worse than none, because the reader
    # cannot tell which part to trust.
    ("readme_i18n_test.py", "README translations"),
    # The API reference was copied out of the source by hand, so it fell
    # behind: 33 of 67 /api routes were undocumented, among them the three
    # that hand back a tunnel token. This parses main.py the way FastAPI
    # registers it and fails when a route is added without being documented.
    ("api_coverage_test.py", "API reference covers every route"),
    # Telegram returns one description for four unrelated mistakes, and "chat not\n    # found" was passed through verbatim. Pure string mapping, offline.
    ("telegram_hint_test.py", "telegram error hints"),
    # The docs promise a least-privilege `bot` token that the create form could
    # not produce, so every token an operator minted was a `full` credential.
    # Each assertion is checked against a mutated copy of the real files too.
    ("api_scope_test.py", "API token scope control"),
    # Two guards that read as protection and are not: a port check that only
    # proved the value was a number, and an empty catch that let the download
    # proceed after the pre-check failed.
    ("settings_guard_test.py", "settings + download guards"),
    # A restore replaces the customer table, and the backup format permits an
    # empty users list. Also: a silent snapshot failure and a token cap that
    # counts expired tokens.
    ("restore_guard_test.py", "restore + snapshot + token cap guards"),
    # Three silent harness faults that each produced "17/26 suites passed"
    # with a wall of 401s, and looked like nine broken suites.
    ("harness_login_test.py", "harness can reach its admin"),
    # The site assistant answered "what is new?" with a release eleven versions
    # old, and linked to a changelog that disagreed with it.
    ("release_notes_test.py", "assistant not stale"),
    # The settings section is grouped by subject. The first attempt at this
    # grouping dropped 25 controls, so the count is asserted, not just the shape.
    ("settings_groups_test.py", "settings grouped, nothing lost"),
    ("i18n_test.py", "docs i18n dictionaries"),
    # Reads the route table out of main.py, the sidebar out of app.js and the
    # setting keys out of protocols.py, then requires a real mention in the
    # real HTML. Written because the docs covered every feature in prose and
    # still shipped five endpoints and seventeen setting names nowhere.
    ("docs_coverage_test.py", "docs cover the panel"),
    # Runs the shipped i18n.js and reads the resulting object, so a key that is
    # missing or empty in one language is a failure. Loading the file caught
    # six empty translations on its first run, in three languages.
    ("__NODE__ i18n_dict_check.js", "docs i18n coverage"),
    ("__NODE__ i18n_render_check.js", "docs i18n renderer safety"),
    ("mcp_tools_test.py", "the MCP tool table"),
    ("mcp_exec_test.py", "MCP call building and the HTTP executor"),
    ("mcp_asgi_exec_test.py", "the in-panel MCP executor"),
    ("mcp_protocol_test.py", "MCP JSON-RPC dispatch"),
    ("mcp_stdio_test.py", "the MCP stdio transport"),
    # One guard per defect the bug hunt found, so none of them can come
    # back quietly. mcp_guards_mutation.py proves all thirteen of these
    # can fail by re-introducing the original defect.
    ("mcp_guards_test.py", "MCP bug-hunt regression guards"),
    # Reads the audit retention out of main.py and the MCP budget out of
    # the schema, then fails if SECURITY.md states anything else. A figure
    # in a document that has drifted from the code is worse than no figure,
    # and this repository shipped several of those.
    ("audit_retention_test.py", "audit retention figure matches the code"),

    # Keeps the annotation coverage from regressing. The MCP modules were
    # 0/34 when they shipped; main.py may not gain a new unannotated
    # top-level function. The allowance list names four functions rather
    # than counting, so it cannot be widened from inside the guard.
    ("type_hints_test.py", "type annotations do not regress"),
    # The sidebar order is decided in three places - the server's
    # MENU_SECTIONS, the front end's MENU_IDS and the nav buttons in
    # panel.html - and only the server's is stored. They disagreed once
    # and nothing compared them, so this compares all three.
    ("menu_order_test.py", "the three menu orders agree"),
    # STATIC: it copies the application and the instance directory to a
    # temporary directory and works on the COPY, so the real instance is
    # never at risk, and it starts its own panel on its own port.
    ("key_loss_test.py", "a missing master key cannot be silent"),
    # STATIC: it copies the application and the instance directory to a
    # temporary directory and works on the COPY, so the real instance is
    # never at risk, and it starts its own panel on its own port.
    ("restore_report_test.py", "the restore report says what was lost"),
]


def wait_up(timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(BASE + "/api/me", timeout=2)
            return True
        except urllib.error.HTTPError:
            return True  # 401 means the app is up
        except Exception:
            time.sleep(0.5)
    return False


def stop(proc):
    if proc and proc.poll() is None:
        try:
            os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
        except Exception:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
            # After kill() the old code returned immediately, so the next
            # suite's uvicorn started while the previous one was still tearing
            # its threads down. Four runs in a row stopped mid-suite with no
            # traceback in either log, and this machine only has ~2.7 GB free
            # of 8 GB while a suite is running: starting the next panel on top
            # of a dying one is what tipped it over. Give it a moment to
            # release the port and its memory, and reap the process so no
            # zombie is left holding the database.
            try:
                proc.wait(timeout=15)
            except Exception:
                pass
    # Belt and braces: a moment of quiet between suites, so the port is
    # actually free before the next panel binds it.
    time.sleep(1.5)


RESET_SQL = (
    "import sqlite3;"
    "c=sqlite3.connect('instance/zefira.db');"
    "[c.execute('delete from '+t) for t in "
    "('vpn_users','inbounds','server_nodes','tunnel_nodes','user_templates',"
    "'api_tokens','blocked_sites')];"
    # block_direct_ip must NEVER survive into a suite: with it on, the panel
    # (correctly) refuses every request that arrives on 127.0.0.1, and the
    # whole suite talks to 127.0.0.1.
    "c.execute(\"update settings set value='0' where key='block_direct_ip'\");"
    "c.execute(\"update settings set value='' where key in "
    "('tg_bot_token','tg_chat_id','ai_api_key_enc')\");"
    "c.execute(\"update settings set value='0' where key='ai_enabled'\");"
    # trusted_proxies is the key of every per-IP rate limiter, and
    # ai_base_url/ai_extra steer the assistant: a suite that plants either (the
    # security one does, on purpose) must not hand it to the next suite.
    "c.execute(\"update settings set value='' where key='trusted_proxies'\");"
    "c.execute(\"update settings set value='' where key in "
    "('ai_base_url','ai_extra')\");"
    # The admin row must go too, and this cost a whole run to find: main.py only
    # adopts ZEFIRA_ADMIN_PASSWORD when the admins table is EMPTY, so an admin
    # left over from an earlier run keeps whatever password that run ended on,
    # and every suite then gets 401 on login - which reads as nine broken suites
    # rather than one stale credential. Two suites legitimately change the
    # password mid-run, so a run interrupted between the change and the revert
    # leaves the harness unable to log in at all. Deleting the row makes the
    # panel re-bootstrap the admin from the environment on its next start.
    "c.execute('delete from admins');"
    "c.commit()"
)


def reset_db(when):
    try:
        subprocess.check_call([PY, "-c", RESET_SQL], cwd=ROOT, stdout=subprocess.DEVNULL)
    except Exception as exc:
        print(f"[warn] db reset {when} failed: {exc}")


results = []

# When this harness's output is REDIRECTED to a file, the child's writes go
# straight to the shared fd while the parent's own stdout stays block-buffered,
# so the two interleave and the transcript stops being a faithful record. It
# cost real time here: frontend_bugs_test.py's "130/130 passed" line vanished
# from the captured log, which made the run look like 902 checks across eight
# counted suites when it is 1032 across nine, and sent me attributing another
# suite's count to the wrong file. Unbuffer the parent and the children, so the
# transcript is ordered and complete.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
# The panel creates its first admin only when the admins table is empty, and it
# takes the password from ZEFIRA_ADMIN_PASSWORD. Without these two the panel
# generated a random one, so every suite's login failed with 401 and the whole
# harness looked broken. The admin row is deleted in RESET_SQL above, so this
# is the path that actually provisions the account the suites log in with.
CHILD_ENV = dict(
    os.environ,
    PYTHONUNBUFFERED="1",
    ZEFIRA_ADMIN_USERNAME=ADMIN,
    ZEFIRA_ADMIN_PASSWORD=PASSWORD,
)

for script, label in SUITES:
    # Reset BEFORE each suite too: a dirty workdir (leftovers from manual
    # testing) must never decide a suite's result.
    reset_db(f"before {label}")
    # The panel's own output used to go to DEVNULL. A suite that failed with
    # `status 0` on one endpoint - which is what a crashed or wedged worker
    # looks like from the client side - left nothing behind to explain it, and
    # the only honest answer was "could not reproduce". Keep the log, and print
    # its tail when the suite fails, so a server-side fault is attributable to
    # a traceback instead of guessed at.
    log_path = os.path.join(LOG_DIR, re.sub(r"[^A-Za-z0-9_.-]", "_", script) + ".log")
    log_fh = open(log_path, "wb")
    proc = subprocess.Popen(
        [PY, "-m", "uvicorn", "main:app", "--host", HOST, "--port", str(PORT),
         "--no-server-header", "--no-proxy-headers", "--no-access-log"],
        cwd=ROOT, stdout=log_fh, stderr=subprocess.STDOUT,
        env=CHILD_ENV,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    if not wait_up():
        print(f"[FAIL] {label}: server did not start")
        log_fh.close()
        stop(proc)
        sys.exit(1)
    print(f"\n===== {label} ({script}) =====")
    sys.stdout.flush()   # the header must land before the child's first line
    rc = subprocess.call([PY, script, BASE, ADMIN, PASSWORD], cwd=ROOT,
                         env=CHILD_ENV)
    results.append((label, rc))
    stop(proc)
    log_fh.close()
    if rc != 0:
        # Only on failure: a 40-line traceback in a passing transcript is noise
        # that trains people to skip the output.
        try:
            with open(log_path, "rb") as fh:
                tail = fh.read()[-6000:].decode("utf-8", "replace")
        except OSError:
            tail = ""
        interesting = [ln for ln in tail.splitlines()
                       if ln.strip() and "Traceback" in ln or "Error" in ln
                       or "Exception" in ln or "CRITICAL" in ln]
        if interesting:
            print(f"----- panel log for {label} ({log_path}) -----")
            for ln in interesting[-25:]:
                print("  " + ln[:160])
        else:
            print(f"----- panel log for {label}: no traceback in {log_path} -----")
    time.sleep(1)
    # Each suite gets a clean slate: rows the previous one intentionally left
    # (password-change token revocations, restored admins…) must not decide
    # the next suite's result.
    reset_db(f"after {label}")

print("\n===== ALL SUITES =====")
for script, label in OFFLINE_SUITES:
    print(f"\n===== {label} ({script}) =====")
    sys.stdout.flush()   # the header must land before the child's first line
    # "__NODE__ foo.js" runs a harness under node instead of the interpreter.
    # A missing node is recorded as a FAILURE, not skipped: i18n_test.py already
    # shells out to `node --check`, so node is a hard requirement of this suite
    # anyway, and a guard that quietly did not run is worse than no guard.
    if script.startswith("__NODE__ "):
        target = script[len("__NODE__ "):]
        node = shutil.which("node")
        if not node:
            print(f"[FAIL] {label}: node is not on PATH, so {target} did not run")
            results.append((label, 1))
            continue
        rc = subprocess.call([node, target], cwd=ROOT)
    else:
        rc = subprocess.call([PY, script], cwd=ROOT, env=CHILD_ENV)
    results.append((label, rc))

bad = 0
for label, rc in results:
    print(f"{'PASS' if rc == 0 else 'FAIL'}  {label}")
    if rc != 0:
        bad += 1
print(f"\n{len(results) - bad}/{len(results)} suites passed")
sys.exit(1 if bad else 0)
