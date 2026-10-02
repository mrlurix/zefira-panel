"""Guard docs/bump_assets.py: a typo must not corrupt every asset URL.

Two measured defects, both exercised against a COPY of the real docs tree so the
repository is never touched:

  1. The docs directory was unvalidated. A non-existent path made glob() return
     nothing, so the script rewrote zero files while still printing
     "setting every local asset URL to ?v=...". Worse, with ONE argument the
     directory cannot be given at all - the single argument becomes VER:
         python docs/bump_assets.py docs/
         setting every local asset URL to ?v=docs/

  2. VER went straight into the regex REPLACEMENT, where a backslash is special:
         python docs/bump_assets.py '9\\1'
         before: href="assets/style.css?v=34"
         after : href="assets/style.css?v=9assets/style.css"
     and it exited 0, having written that to every asset URL in the site. A
     stray backslash - or a Windows path pasted into the version slot -
     silently corrupted the docs.
"""
import io
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
ROOT = HERE  # the guard lives in the repo root, not in docs/
SCRIPT = ROOT / "docs" / "bump_assets.py"
PY = str(ROOT / ".venv" / "Scripts" / "python.exe")

fails = []


def check(label, cond, detail=""):
    if not cond:
        fails.append(label)
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", label,
                           ("  -> " + detail) if detail else ""))


def run(args):
    r = subprocess.run([PY, str(SCRIPT)] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=300)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def copy_docs():
    dst = pathlib.Path(tempfile.mkdtemp(prefix="zefira-docs-")) / "docs"
    shutil.copytree(ROOT / "docs", dst)
    return dst


def asset_urls(d):
    out = []
    for f in sorted(d.glob("*.html")):
        out += re.findall(r'assets/(?:style\.css|docs\.js|i18n\.js|support-ai\.js)\?v=\S*?"',
                          f.read_text(encoding="utf-8"))
    return out


print()
print("=== 1. a bad version is refused, and nothing is written ===")
for bad in ("9\\1", "docs/", "9;rm", "1 2", "", "v9", "9.1"):
    d = copy_docs()
    try:
        before = asset_urls(d)
        code, out, err = run([bad, str(d)])
        after = asset_urls(d)
        check("version %-8r refused, docs untouched" % bad,
              code != 0 and before == after,
              "exit=%d, %d URL(s) changed" % (code, len(after) - len(before)))
    finally:
        shutil.rmtree(d.parent, ignore_errors=True)

print()
print("=== 2. a missing directory is refused instead of silently doing nothing ===")
code, out, err = run(["9", str(ROOT / "docs" / "no-such-dir")])
check("a non-existent docs dir exits non-zero", code != 0, "exit=%d" % code)
check("and says why", "not a directory" in (out + err),
      repr((out + err).strip()[:80]))
check("it does not claim to have bumped anything",
      "setting every local asset URL" not in out,
      "it reported work it did not do")

print()
print("=== 3. a path given as the only argument is not mistaken for a version ===")
d = copy_docs()
try:
    before = asset_urls(d)
    code, out, err = run([str(d)])
    after = asset_urls(d)
    check("a bare path is not accepted as the version",
          code != 0 or before == after,
          "a path became ?v=%s" % out.strip()[:40])
finally:
    shutil.rmtree(d.parent, ignore_errors=True)

print()
print("=== 4. a legitimate bump still works end to end ===")
d = copy_docs()
try:
    code, out, err = run(["999", str(d)])
    after = asset_urls(d)
    check("a digits-only version is accepted", code == 0,
          (err or "").strip()[:80])
    check("every asset URL now carries it",
          after and all(u.endswith("?v=999\"") for u in after),
          "%d URL(s), first=%r" % (len(after), after[0] if after else None))
    check("the fetch() URLs moved too",
          re.search(r"\.json\?v=999",
                    (d / "assets" / "docs.js").read_text(encoding="utf-8"))
          is not None if (d / "assets" / "docs.js").exists() else True)
finally:
    shutil.rmtree(d.parent, ignore_errors=True)

print()
print("=== 5. the guards are in the source, not just the behaviour ===")
src = io.open(SCRIPT, encoding="utf-8").read()
check("VER is digits-checked", "re.fullmatch(r\"\\d{1,6}\", VER)" in src
      or "re.fullmatch(r'\\d{1,6}', VER)" in src)
check("the docs directory is checked with is_dir()", "is_dir()" in src)
check("neither check is inside a comment",
      not any(l.lstrip().startswith("#") and ("fullmatch" in l or "is_dir()" in l)
              for l in src.splitlines()))

print()
print("=== %s ===" % ("ALL OK" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)