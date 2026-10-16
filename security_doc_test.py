"""Make SECURITY.md's suite inventory derive from run_all_tests.py.

The document said "thirty-five test suites" and listed seven by hand. The
runner now has 42. A hand-written count drifts the moment a suite is added, and
the day it is forgotten the document reports a coverage that does not exist -
which is worse than saying nothing, because a reader trusts it.

So: derive the total and the per-suite check counts at test time, and keep the
prose free of any figure that would need editing.

    .venv\\Scripts\\python.exe security_doc_test.py
"""
import ast
import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SEC = os.path.join(ROOT, "SECURITY.md")
RUNNER = os.path.join(ROOT, "run_all_tests.py")
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", name,
                         ("  -> " + detail) if detail and not ok else ""))


sec = io.open(SEC, encoding="utf-8", errors="replace").read()

# ------------------------------------------------------------------ inventory
tree = ast.parse(io.open(RUNNER, encoding="utf-8").read())
counts = {}
for n in tree.body:
    if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") in (
            "SUITES", "OFFLINE_SUITES"):
        counts[n.targets[0].id] = len(n.value.elts)
TOTAL = counts.get("SUITES", 0) + counts.get("OFFLINE_SUITES", 0)
print("  runner: %d online + %d offline = %d suites"
      % (counts.get("SUITES", 0), counts.get("OFFLINE_SUITES", 0), TOTAL))
print()

# ---------------------------------------------------------------- 1. no drift
# Written-out numbers in prose are the defect. N/N must never appear.
written = re.findall(
    r"\b(?:thirty-five|thirty|thirty-six|thirty-seven|thirty-eight|thirty-nine|"
    r"forty|forty-one|forty-two|forty-three)\b", sec)
check("SECURITY.md states no suite total in words", not written,
      "found %s" % written)

ratios = re.findall(r"\b(\d{2,3})\s+penetration|\((\d{2,3})\s", sec)
check("SECURITY.md states no check counts that can go stale", not ratios,
      "found %s" % ratios[:4])

check("the inventory sentence points at the runner instead of a number",
      "run_all_tests.py" in sec or "test suites" in sec)

# ------------------------------------------------- 2. the bounty basics, present
check("the bug bounty section exists", "## Bug bounty" in sec)
check("it promises no cash, because none is funded",
      re.search(r"no cash is promised", sec, re.I) is not None)
check("and it does not name a figure",
      "$" not in sec and "USD" not in sec and "€" not in sec)
check("safe harbour is present and grants permission",
      "Safe harbour" in sec and "permission to research" in sec)
check("safe harbour states what is out of scope",
      "Out of scope" in sec)
check("the report channel is the private advisory, not a public issue",
      "security/advisories/new" in sec)
check("and it says a public issue is not the way",
      re.search(r"do NOT open a public issue", sec, re.I) is not None)
check("the disclosure window is stated",
      re.search(r"\d+\s*days", sec) is not None)
check("the four severities are defined",
      all(s in sec for s in ("Critical", "High", "Medium", "Low")))

# ------------------------------------------- 3. known trade-offs are not silent
for trade, needle in (("single worker", "_enforce_single_worker"),
                      ("SQLite serialisation", "SQLite"),
                      ("no HSM/KMS", "HSM"),
                      ("AI assistant egress", "provider")):
    check("the known trade-off is named: %s" % trade, needle in sec)

# -------------------------------------------- 4. the report path is real
# A policy that says "report privately" and points at a channel that does not
# exist sends the researcher to the public issue it just warned them off.
readme = io.open(os.path.join(ROOT, "README.md"), encoding="utf-8",
                 errors="replace").read()
check("the README links the security policy", "SECURITY.md" in readme)
check("and SECURITY.md sits at the repository root so GitHub finds it",
      os.path.isfile(SEC))

# ------------------------------------------------------------------- report
n = sum(1 for _k, ok in results if ok)
print()
print("=== %d/%d ===" % (n, len(results)))

# The child spawned per mutation must not recurse into this section.
if os.environ.get("ZEFIRA_SECURITY_DOC_CHILD") == "1":
    sys.exit(0 if n == len(results) else 1)

# ---------------------------------------------------------------------------
# A guard nobody saw fail is a comment with an exit code. Each mutation below
# restores a defect this document actually had, so the red is a past failure
# rather than a shape invented here.
print()
print("== each of these can fail ==")
MUTATIONS = [
    ("put the stale suite total back",
     ("a test suite that runs against a live panel. Run it with:",
      "thirty-five test suites that run against a live panel: "
      "`security_test.py` (120 penetration checks). Run it with:")),
    ("delete the safe harbour",
     ("## Safe harbour", "## Reporting tips")),
    ("promise money that is not funded",
     ("**No cash is promised, because none is funded.**",
      "We pay $250 for a critical finding.")),
    ("drop the disclosure window",
     ("90 days have\n  passed since the report", "a while has\n  passed since the report")),
    ("drop a known trade-off",
     ("- **No HSM or KMS.**", "- **No hardware key store.**")),
]
mut_ok = True
raw = io.open(SEC, "rb").read()
saved = []
for label, (old, new) in MUTATIONS:
    if old not in raw.decode("utf-8"):
        print("[FAIL] goes red: %s  -> the mutation did not apply" % label)
        mut_ok = False
        continue
    io.open(SEC, "wb").write(raw.decode("utf-8").replace(old, new, 1).encode("utf-8"))
    try:
        r = subprocess.run([sys.executable, os.path.abspath(__file__)],
                           capture_output=True, text=True, timeout=300,
                           encoding="utf-8", errors="replace",
                           env=dict(os.environ, ZEFIRA_SECURITY_DOC_CHILD="1"))
        went_red = r.returncode != 0
        lines = [l.strip() for l in (r.stdout or "").splitlines()
                 if l.startswith("[FAIL]")]
        print("[%s] goes red: %s%s"
              % ("PASS" if went_red else "FAIL", label,
                 "" if went_red else "  -> child rc=0 and printed %s" % (lines or "nothing")))
        if not went_red:
            mut_ok = False
    finally:
        io.open(SEC, "wb").write(raw)
        assert io.open(SEC, "rb").read() == raw, "SECURITY.md was not restored"

print()
print("=== %d/%d checks, %d/%d mutations proved red ==="
      % (n, len(results), 5 if mut_ok else 0, 5))
sys.exit(0 if (n == len(results) and mut_ok) else 1)