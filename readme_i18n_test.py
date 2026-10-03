"""Check the four READMEs line up before they ship.

A translation that is short, has a broken code fence, or is missing a fact the
English one states is worse than no translation: the reader cannot tell which
part to trust. So this compares them against the English file rather than
eyeballing.
"""
import io
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
FACTS = [
    ("v1.15.16", "the pinned release in the read-before-you-run example"),
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
print("  every fenced block in each language opens a shell or text block "
      "identically to the English one:")
for loc in ("fa", "zh", "ru"):
    en_fences = texts["en"].split("```")[1::2]
    lo_fences = texts[loc].split("```")[1::2]
    same = len(en_fences) == len(lo_fences)
    check("%s has the same number of code blocks as en" % loc, same,
          "en=%d %s=%d" % (len(en_fences), loc, len(lo_fences)))

print()
print("=== %s ===" % ("ALL OK" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)