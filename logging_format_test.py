"""The panel's logging: plain by default, structured on request, never broken.

The assessment said the logging was "not structured enough for production
troubleshooting". That was half right, and the half that was wrong is worth
saying: the panel already mints a request id, echoes it on the response and
writes it into the access log, and the code says why - "so 'what happened at
14:03 for this customer' becomes one grep instead of a correlation argument
across every subsystem".

What was missing is the other half: the log lines a HANDLER emits had no way
to be tied back to a request. The id was on the response and in the access
log, and everything in between was unattributable. This release carries the
id into those lines, and adds a JSON mode for a log shipper.

Both are opt-in, so an existing install behaves exactly as before:

    ZEFIRA_LOG_FORMAT=json   one JSON object per line
    ZEFIRA_LOG_LEVEL=DEBUG   the level (default INFO)

The formatter NEVER raises. A logging bug that takes the panel's logs down
with it is much worse than a malformed line, so anything unexpected falls back
to the plain format - and this suite checks that, because the fallback is the
part nobody would notice if it did not work.
"""

import io
import json
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ok = []


def check(name, cond, detail=""):
    ok.append((name, bool(cond)))
    print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  -> " + str(detail)[:190])
                         if (detail and not cond) else ""))


PANEL_PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")

# ------------------------------------------------------- the formatter itself
import main as panel  # noqa: E402

fmt = panel._JsonLogFormatter()
rec = logging.LogRecord("zefira", logging.WARNING, "main.py", 10,
                         "a message with %s", ("an argument",), None)
line = fmt.format(rec)
try:
    obj = json.loads(line)
except Exception as exc:
    obj = {}
    check("a log line is valid JSON", False, "%s: %r" % (exc, line[:120]))

check("a log line is valid JSON", bool(obj), line[:120])
check("...and carries the level, the logger and the message",
      obj.get("level") == "WARNING" and obj.get("logger") == "zefira"
      and obj.get("msg") == "a message with an argument",
      str(obj)[:150])
check("...and a UTC timestamp", str(obj.get("ts", "")).endswith("+00:00"),
      str(obj.get("ts")))
check("...and no request id when there is no request",
      "request_id" not in obj, str(obj)[:150])

# the request id rides on the context variable
panel._CURRENT_REQUEST_ID.set("abc12345")
try:
    obj2 = json.loads(fmt.format(rec))
    check("...and the request id when the line was written inside a request",
          obj2.get("request_id") == "abc12345", str(obj2)[:150])
finally:
    panel._CURRENT_REQUEST_ID.set(None)

# a caller's own fields survive
rec2 = logging.LogRecord("zefira", logging.ERROR, "main.py", 11, "boom", None,
                          None)
rec2.zefira_customer = "buyer1"
obj3 = json.loads(fmt.format(rec2))
check("...and a caller's own extra field is merged in",
      obj3.get("customer") == "buyer1", str(obj3)[:150])

# an exception is recorded, not swallowed
try:
    raise ValueError("the original problem")
except ValueError:
    rec3 = logging.LogRecord("zefira", logging.ERROR, "main.py", 12, "failed",
                              None, sys.exc_info())
obj4 = json.loads(fmt.format(rec3))
check("...and an exception is recorded with its type and message",
      "ValueError" in (obj4.get("exc") or "")
      and "the original problem" in (obj4.get("exc") or ""),
      str(obj4.get("exc"))[:150])

# THE FALLBACK: a formatter that raises must not take the log down
class _Boom(logging.LogRecord):
    def getMessage(self):
        raise RuntimeError("the formatter is broken")


rec4 = _Boom("zefira", logging.ERROR, "main.py", 13, "x", None, None)
try:
    out = fmt.format(rec4)
    check("a broken record falls back to a plain line instead of raising",
          "ERROR" in out and "Traceback" not in out, repr(out)[:150])
except Exception as exc:
    check("a broken record falls back to a plain line instead of raising",
          False, "the formatter raised: %r" % (exc,))

# ------------------------------------------------------------- the defaults
check("the default format is the plain one, unchanged",
      panel._LOG_FORMAT != "json", repr(panel._LOG_FORMAT))
check("the default level is INFO", panel._LOG_LEVEL_NUM == logging.INFO,
      panel._LOG_LEVEL_NUM)

# --------------------------------------------------------- the live panel
PORT = 8190
BASE = "http://127.0.0.1:%d" % PORT
LOG = os.path.join(os.environ.get("TEMP", "."), "zefira_json_log.txt")

env = dict(os.environ, ZEFIRA_LOG_FORMAT="json", ZEFIRA_LOG_LEVEL="DEBUG")
lfh = open(LOG, "wb")
proc = subprocess.Popen(
    [PANEL_PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
     "--port", str(PORT), "--no-server-header", "--no-proxy-headers"],
    cwd=ROOT, stdout=lfh, stderr=subprocess.STDOUT, env=env)
try:
    up = False
    for _ in range(280):
        time.sleep(0.25)
        try:
            urllib.request.urlopen(BASE + "/login", timeout=2).read()
            up = True
            break
        except urllib.error.HTTPError:
            up = True
            break
        except Exception:
            continue
    check("the panel starts with ZEFIRA_LOG_FORMAT=json", up)

    if up:
        # a request that produces a log line INSIDE the handler
        rid = "TESTREQID1234"
        req = urllib.request.Request(
            BASE + "/api/login",
            data=json.dumps({"username": "no-such-user",
                             "password": "wrong"}).encode(),
            headers={"Content-Type": "application/json",
                     "X-Requested-With": "XMLHttpRequest",
                     "X-Request-Id": rid},
            method="POST")
        try:
            urllib.request.urlopen(req, timeout=20).read()
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass
        time.sleep(1.0)
        lfh.flush()
        raw = io.open(LOG, encoding="utf-8", errors="replace").read()
        lines = [l for l in raw.split("\n") if l.strip().startswith("{")]
        check("the panel wrote JSON log lines", bool(lines),
              "the log had %d bytes and no JSON line" % len(raw))
        parsed = []
        bad = 0
        for l in lines:
            try:
                parsed.append(json.loads(l))
            except Exception:
                bad += 1
        check("every one of them parses as JSON", bad == 0,
              "%d of %d did not parse" % (bad, len(lines)))
        check("...and they carry the standard fields",
              all({"ts", "level", "logger", "msg"} <= set(p) for p in parsed),
              str(parsed[0])[:150] if parsed else "none")
        with_rid = [p for p in parsed if p.get("request_id") == rid]
        check("...and a line written inside a request carries that request's id",
              bool(with_rid),
              "no line carried %r; the ids seen were %s"
              % (rid, sorted({p.get("request_id") for p in parsed
                              if p.get("request_id")})[:5]))
finally:
    proc.terminate()
    try:
        proc.wait(timeout=25)
    except Exception:
        proc.kill()
    lfh.close()

n = sum(1 for _k, v in ok if v)
print()
print("=== %d/%d ===" % (n, len(ok)))
sys.exit(0 if n == len(ok) else 1)