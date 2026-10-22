"""Check the four READMEs line up before they ship.

A translation that is short, has a broken code fence, or is missing a fact the
English one states is worse than no translation: the reader cannot tell which
part to trust. So this compares them against the English file rather than
eyeballing.
"""
import io
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
FILES = {"en": "README.md", "fa": "README.fa.md", "zh": "README.zh.md",
         "ru": "README.ru.md"}
fails = []


def check(label, cond, detail=""):
    if not cond:
        fails.append(label)
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", label,
                           ("  -> " + detail) if detail else ""))


# Facts that must survive translation. Each is a number or a hash a reader could
# act on, so a dropped one is a real defect rather than a stylistic difference.
# Derived, never frozen. This entry used to be the literal "v1.15.16", and the
# four READMEs used to say v1.15.16, so the check and the staleness agreed with
# each other for twenty-four releases and the suite stayed green the whole time.
# A fact that has to be retyped by hand is a fact that will silently stop
# meaning anything; this one is the shipped version or it is a defect.
_SHIPPED = "v" + io.open("VERSION", encoding="utf-8").read().strip()

FACTS = [
    (_SHIPPED, "the pinned release in the read-before-you-run example"),
    ("129%2F129", "the pentest badge"),
    ("instance/first-run-credentials.txt", "where first-run credentials land"),
    ("instance/secret.key", "the encryption key path"),
    ("0x4caF4EfDe83784351ED81e39f56e5dB49FE8FE18", "the donation address"),
    ("--require-hashes --no-deps -r requirements.lock", "the install command"),
    ("ZEFIRA_EXPECTED_SHA", "the commit pin"),
    ("### OpenVPN ###", "the marker the old feed used"),
    ("422", "what a file-only plan answers"),
    ("xtls-rprx-vision", "the REALITY flow"),
]

texts = {}
print()
for loc, f in FILES.items():
    try:
        texts[loc] = io.open(f, encoding="utf-8").read()
    except OSError as exc:
        check("%s README exists" % loc, False, str(exc)[:70])

print("  %-3s %6s %8s %8s %7s %7s" % ("loc", "lines", "bytes", "fences",
                                      "links", "bad"))
for loc in ("en", "fa", "zh", "ru"):
    s = texts[loc]
    fences = s.count("```")
    links = sum(1 for x in FILES.values() if x in s)
    bad = s.count("\ufffd")
    print("  %-3s %6d %8d %8d %7d %7d"
          % (loc, len(s.splitlines()), len(s), fences, links, bad))
    check("%s has balanced code fences" % loc, fences % 2 == 0,
          "%d fences" % fences)
    check("%s has no mojibake" % loc, bad == 0, "%d replacement char(s)" % bad)
    # Each README links to the OTHER three, not to itself - linking a file to
    # itself is noise. My first version expected four and so failed all four
    # files for the right reason on three of them and the wrong reason on one:
    # the English file had no language line at all.
    # FILES[loc], not `f` - `f` is the loop variable of the earlier loop and is
    # still whatever the last iteration left behind, so `others` was always
    # relative to README.ru.md. A leaked loop variable computing the very thing
    # under test is the same shape as the guards fixed earlier this session.
    others = [x for k, x in FILES.items() if k != loc]
    want = sum(1 for x in others if x in s)
    check("%s links to the other three READMEs" % loc, want == 3,
          "%d of 3 (%s absent)" % (want, ", ".join(x for x in others if x not in s)))

print()
print("  facts that must survive translation:")
for fact, what in FACTS:
    missing = [loc for loc in ("fa", "zh", "ru") if fact not in texts[loc]]
    check("%-52s %s" % (what, fact[:34]), not missing,
          "absent from %s" % ", ".join(missing))

print()
print("  every command the English file tells a reader to run is in the "
      "translation too:")
#
# This replaced a check on the NUMBER of fenced blocks, which passed by
# accident: all three translations carried a duplicated copy of the test block
# spliced into "Install on a server" - between the "one-liner:" lead-in and the
# very curl command it introduces, followed by an orphan empty fence - and
# those extra blocks brought the count up to the English one. Removing the
# duplicate, which is the fix for a section that read like that, exposed that
# the count had been measuring the accident: en has 12 blocks, fa/zh/ru have
# 10, and always did. The commands, measured, are identical in all four.
_CMD = re.compile(r"^\s*(curl|python3?|node|git|pip|bash|sh|systemctl|sudo|"
                  r"nginx|docker|make|apt|dnf|yum)\b")


def _commands(text):
    out, inb = [], False
    for line in text.split("\n"):
        if line.strip().startswith("```"):
            inb = not inb
            continue
        if inb:
            m = _CMD.match(line)
            if m:
                out.append(m.group(1))
    return out


_base = set(_commands(texts["en"]))
for loc in ("fa", "zh", "ru"):
    got = set(_commands(texts[loc]))
    check("%s names every command en does (%d)" % (loc, len(_base)),
          _base <= got,
          "absent: %s" % ", ".join(sorted(_base - got)))
    check("%s invents no command en does not" % loc, got <= _base,
          "extra: %s" % ", ".join(sorted(got - _base)))

print()
print("  fenced-block shape (informational: the four documents group their "
      "examples differently, and always did):")
for loc in ("en", "fa", "zh", "ru"):
    print("    %-3s %d blocks, %d distinct commands"
          % (loc, texts[loc].count("```") // 2, len(set(_commands(texts[loc])))))

# --- the suite lists must agree with the runner ---------------------------
#
# The lists had already drifted twice before this check existed: README.md said
# "36 test suites" and "all 35" in consecutive lines, and the translations had
# been two releases behind because nothing compared them to run_all_tests.py.
# So this reads the runner rather than trusting any number written down.

import ast

_runner = ast.parse(io.open("run_all_tests.py", encoding="utf-8").read())
_counts = {}
for _n in _runner.body:
    if isinstance(_n, ast.Assign) and getattr(_n.targets[0], "id", "") in (
            "SUITES", "OFFLINE_SUITES"):
        _counts[_n.targets[0].id] = len(_n.value.elts)
TOTAL = _counts["SUITES"] + _counts["OFFLINE_SUITES"]
ONLINE = _counts["SUITES"]
OFFLINE = _counts["OFFLINE_SUITES"]
TOTAL_FOR_PROOF = TOTAL
PINS = {}
VERSION = _SHIPPED[1:]
RUNNER = set(re.findall(r'\("(\w+_test\.py)",',
                        io.open("run_all_tests.py", encoding="utf-8").read()))

print()
print("  suite lists against run_all_tests.py (%d suites: %d live, %d static):"
      % (TOTAL, ONLINE, OFFLINE))
for loc in ("en", "fa", "zh", "ru"):
    body = texts[loc]
    named = set(re.findall(r"^python (\w+_test\.py)\b", body, re.M))
    check("%s lists every suite the runner runs" % loc, named >= RUNNER,
          "missing %s" % ", ".join(sorted(RUNNER - named)))
    check("%s names no suite the runner does not run" % loc, named <= RUNNER,
          "invented %s" % ", ".join(sorted(named - RUNNER)))
    # A total written down that is not the runner's is the defect that shipped:
    # "36 ... all 35" in one file, "35 / 25" in three others.
    totals = {int(x) for x in re.findall(
        r"(\d+)\s*(?:test suites|مجموعهٔ تست|套测试|набор\w*\s+тест\w*)", body)}
    check("%s states a total equal to the runner's" % loc,
          totals and totals <= {TOTAL},
          "says %s, runner has %d" % (sorted(totals), TOTAL))
    # The split matters as much as the total: the README says 17 hit the
    # running panel and 44 are static, and a reader deciding what to run
    # first is reading exactly those two numbers.
    #
    # The SET of numbers in the paragraph, not the presence of the three.
    # "There are 61 test suites ... One command runs all 61" states the total
    # twice, so a check that only asks whether "61" appears still passes when
    # the first mention has gone stale and the second has not - which is the
    # mutation the guard has to catch.
    _want = {ONLINE, OFFLINE, TOTAL}
    _sets = [set(int(x) for x in re.findall(r"\d+", p))
             for p in re.split(r"\n\s*\n", body) if p.strip()]
    check("%s states the live/static split the runner has" % loc,
          _want in _sets,
          "no paragraph carries exactly %s" % sorted(_want))
    # The feature_test.py sentence used to claim a route count and a section
    # count: 67 across 11 in two languages, 77 across 11 in the other two,
    # and feature_test.py's own docstring said 62 across 10. Measured: the
    # panel registers 55 distinct /api paths across 12 sections, and
    # feature_test.py touches 41 of them. None of the numbers was true, and
    # the four files disagreed with each other. These READMEs say further
    # down that a stale number is worse than no number - so the sentence
    # carries no digits at all, and that is what is checked.
    _i = body.find("`feature_test.py`")
    _j = body.find("`attack_test.py`", _i)
    if _j < 0:
        _j = body.find("\n", _i)
    _sent = body[_i:_j] if _i >= 0 else ""
    check("%s states no route count for feature_test.py" % loc,
          _i >= 0 and not re.search(r"\d", _sent),
          "the sentence carries a number: %r" % _sent[:60])
    # The suite list belongs in the test section, not inside the install one.
    inst = body.find("install.sh | sudo bash")
    head = min((body.find(h) for h in ("### Running the tests",
                                       "\u0627\u062c\u0631\u0627\u06cc \u062a\u0633\u062a",
                                       "\u8fd0\u884c\u6d4b\u8bd5",
                                       "\u0417\u0430\u043f\u0443\u0441\u043a \u0442\u0435\u0441\u0442\u043e\u0432")
                    if h in body), default=-1)
    check("%s introduces its install one-liner before the test section" % loc,
          inst > 0 and head > inst,
          "install at %d, test heading at %d" % (inst, head))

    # The pin the README tells you to use when you want to review the installer
    # before running it as root. It was v1.15.16 while VERSION was 1.15.40: the
    # safer of the two documented install paths installed 24 releases of old code,
    # and the sentence under it called the tag a guarantee. Nothing compared this
    # copy of the version to install.sh:ZEFIRA_PINNED, which the release process
    # does bump - same disease as the changelog heading that displayed v1.15.38.
    _tag = _SHIPPED
    _pin = re.findall(r"/(v[\d.]+)/install\.sh", body)
    _prose_pin = re.findall(r"`(v[\d.]+)`[^\n]{0,40}pin|`(v[\d.]+)`", body)
    _seen = set(_pin) | {x for pair in _prose_pin for x in pair if x}
    check("%s pins the installer at the shipped version" % loc,
          _seen == {_tag},
          "pins %s, shipped is %s" % (sorted(_seen), _tag))
    PINS[loc] = _pin[0] if _pin else None



# --------------------------------------------------------------------------
check("all four READMEs pin the same installer tag",
      len(set(PINS.values())) == 1,
      "pinned %s" % {k: v for k, v in PINS.items() if v})


# Prove each of the new checks fails when the thing it guards is broken.
#
# A guard nobody saw fail is a comment with an exit code. Every mutation here
# is a defect that actually shipped in this repository, or the exact opposite
# of one.

if os.environ.get("ZEFIRA_README_CHILD") != "1":
    import os
    import shutil
    import subprocess
    import tempfile

    _ROOT = os.path.dirname(os.path.abspath(__file__))
    _FILES = ["README.md", "README.fa.md", "README.zh.md", "README.ru.md"]
    _bk = tempfile.mkdtemp(prefix="readme-mut-")
    for _f in _FILES:
        shutil.copyfile(os.path.join(_ROOT, _f), os.path.join(_bk, _f))

    def _read(_p):
        return io.open(_p, encoding="utf-8", newline="").read()

    def _child():
        r = subprocess.run(
            [sys.executable, os.path.abspath(__file__)],
            capture_output=True, timeout=180,
            cwd=_ROOT,
            env=dict(os.environ, ZEFIRA_README_CHILD="1"))
        # The child writes UTF-8 - it reconfigures its own stdout - and this
        # machine's locale encoding is cp1252, which cannot decode the
        # Chinese and Russian sentences these checks quote. With text=True
        # the reader thread died on the first byte it could not decode and
        # r.stdout came back None, so the proof reported a TypeError instead
        # of the thing it was proving.
        return r.stdout.decode("utf-8", "replace")

    def _prove(label, expect, fname, fn):
        path = os.path.join(_ROOT, fname)
        original = _read(path)
        broken = fn(original)
        if broken == original:
            check(label, False, "the mutation did not apply, so it proves nothing")
            return
        io.open(path, "w", encoding="utf-8", newline="").write(broken)
        try:
            out = _child()
            check(label, expect in out)
        finally:
            io.open(path, "w", encoding="utf-8", newline="").write(original)

    def _drop_node(text):
        for script in ("node i18n_dict_check.js", "node i18n_render_check.js"):
            text = re.sub(r"^\s*%s.*\n" % re.escape(script), "", text,
                          count=1, flags=re.M)
        return text

    def _splice_install(text):
        i = text.index("### اجرای تست‌ها")
        head = text[:i]
        j = head.index("یک‌خطی:")
        j = head.index("\n", j) + 1
        first = text[i:].split("\n", 1)[0][:110]
        return head[:j] + first + "\n" + head[j:] + text[i:]

    print()
    print("  --- proving each new check fails when its fix is removed ---")
    _prove("goes red without this fix: a suite dropped from a README",
           "[FAIL] fa lists every suite the runner runs", "README.fa.md",
           lambda t: re.sub(r"^python operability_test\.py.*\n", "", t,
                            count=1, flags=re.M))
    _prove("goes red without this fix: a suite invented in a README",
           "[FAIL] en names no suite the runner does not run", "README.md",
           lambda t: t.replace("python installer_test.py  ",
                               "python not_a_real_suite_test.py  ", 1))
    # The stale tag is a constant on purpose - it is the WRONG value, and the
    # point is to move away from it. The value being moved FROM is derived, so
    # this proof cannot freeze at one release and then quietly stop applying,
    # which is exactly what happened to it once.
    _STALE = "v1.15.16"
    assert _STALE != _SHIPPED, "the stale tag must differ from the shipped one"
    _prove("goes red without this fix: a stale installer pin, as shipped",
           "[FAIL] en pins the installer at the shipped version", "README.md",
           lambda t: t.replace("/%s/install.sh" % _SHIPPED,
                               "/%s/install.sh" % _STALE, 1))
    _prove("goes red without this fix: a stale total, as shipped",
           "[FAIL] en states a total equal to the runner's", "README.md",
           lambda t: t.replace("There are %d test suites." % TOTAL,
                               "There are %d test suites." % (TOTAL - 1), 1))
    # The split, not the total: the total is stated twice in the paragraph,
    # so a mutation that ages one mention still leaves the other.
    _prove("goes red without this fix: a stale live/static split",
           "[FAIL] en states the live/static split the runner has",
           "README.md",
           lambda t: t.replace("17 hit the running panel",
                               "18 hit the running panel", 1))
    # The route count, which is the number that was wrong in three
    # different ways at once.
    _prove("goes red without this fix: a route count for feature_test.py",
           "[FAIL] ru states no route count for feature_test.py",
           "README.ru.md",
           lambda t: t.replace("обходит "
                               "возможности "
                               "панели",
                               "обходит все 77 "
                               "маршрутов API", 1))
    _prove("goes red without this fix: the test block in the install section",
           "[FAIL] fa introduces its install one-liner before the test section",
           "README.fa.md", _splice_install)
    _prove("goes red without this fix: a command removed from a translation",
           "[FAIL] ru names every command en does", "README.ru.md", _drop_node)
    check("all four READMEs restored byte-for-byte after mutation",
          all(_read(os.path.join(_ROOT, f))
              == io.open(os.path.join(_bk, f), encoding="utf-8",
                         newline="").read() for f in _FILES))
    shutil.rmtree(_bk, ignore_errors=True)


print()
print("=== %s ===" % ("ALL OK" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)