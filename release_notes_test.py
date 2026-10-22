r"""The public site assistant must not tell visitors about an old release.

docs/assets/site-knowledge.json answered "what is new?" with v1.13.3 while the
panel was on v1.15.23 - twenty-one releases of security work that the assistant
would confidently not mention - and it linked to changelog.html, whose newest
entry was v1.15.2, so a visitor got three mutually inconsistent answers.

That file is hand-maintained, which is why it drifted. This suite makes the
drift loud instead of silent: the assistant's newest version must equal the
repository VERSION, in every locale it is written in. docs/release_notes.py
prints the same gap and the commit subjects needed to close it.

Each assertion is also checked against a mutated copy of the real file, so a
guard that cannot go red is reported rather than trusted.

It also reads the changelog the way a reader does. It used to extract
<h2 id="v(\d+)>, so it was confident about an id nobody sees: v1.15.39
shipped a heading displaying v1.15.38, the only duplicated version number
in 41, and eleven ascending inversions buried the shipped release 12th of
41. And "every locale is non-empty" let seven U+FFFD through the same file.
"""
import io
import json
import os
import re
import subprocess
import importlib.util

ROOT = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE = os.path.join(ROOT, "docs", "assets", "site-knowledge.json")
CHANGELOG = os.path.join(ROOT, "docs", "changelog.html")
CHANGELOG_MD = os.path.join(ROOT, "CHANGELOG.md")
GEN_CHANGELOG = os.path.join(ROOT, "docs", "gen_changelog.py")
VERSION = os.path.join(ROOT, "VERSION")
RELEASE_NOTES = os.path.join(ROOT, "docs", "release_notes.py")
LOCALES = ("text", "fa", "zh", "ru")


def read_json(path):
    with io.open(path, encoding="utf-8") as fh:
        return json.load(fh)


def entry(kb):
    return next((e for e in kb if e.get("id") == "changelog"), None)


def newest_version(text):
    """The newest vX.Y.Z mentioned, with the leading `v`.

    Returns it prefixed, and `checks()` compares against a prefixed VERSION -
    the VERSION file holds bare digits, so comparing the two unprefixed would
    report every locale as stale.
    """
    found = re.findall(r"v(\d+\.\d+\.\d+)", text or "")
    return "v" + found[0] if found else None


def cur_head_section(changelog, cur):
    """The whole section (h2 + its <ul>) whose heading SHOWS `cur`.

    Not re.search over the file: that returns the first versioned section,
    v1.15.28, and every ordering mutation then talks about the wrong entry.
    """
    m = re.search(r'<h2 id="v\d+"><span>%s</span>.*?</ul>(?:\r\n|\r|\n){2}'
                  % re.escape(cur), changelog, re.S)
    assert m, "the shipped version %s has no complete section" % cur
    return m.group(0)


def _descending(shown):
    """True when the shown version numbers only ever get OLDER down the list.

    Newest first, so each heading must be older than the one above it. The
    comparison is `key(shown[i]) < key(shown[i - 1])` - written the other way
    round it asserts ASCENDING order, which is exactly the misordering this
    check exists to catch, so it would have passed the bug and failed the fix.

    An inversion is a heading that is NEWER than the one above it, so a reader
    scrolling meets an older release after a newer one. v1.15.39 shipped at
    position 12 of 41 because twelve releases stacked above a hardcoded anchor
    instead of above the newest heading.
    """
    def key(v):
        a, b, c = v[1:].split(".")
        return (int(a), int(b), int(c))
    return bool(shown) and all(key(shown[i]) < key(shown[i - 1])
                               for i in range(1, len(shown)))


def render_expected():
    """The markdown docs/gen_changelog.py would produce for the page.

    Loaded by path rather than imported by name, so this suite does not put
    docs/ on sys.path for the whole run.
    """
    spec = importlib.util.spec_from_file_location("gen_changelog_under_test",
                                                  GEN_CHANGELOG)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with io.open(CHANGELOG, encoding="utf-8") as fh:
        return mod.render_changelog(fh.read())


def changelog_md_checks(on_disk, expected):
    """Is the repository's CHANGELOG.md the generated one?"""
    out = {}
    out["the repository has a CHANGELOG.md"] = on_disk is not None
    out["CHANGELOG.md is what the generator produces"] = (
        on_disk is not None and on_disk == expected)
    return out


def checks(kb, version, changelog):
    e = entry(kb)
    cur = "v" + version.strip()   # VERSION holds bare digits, the entry has "v"
    out = {}
    for loc in LOCALES:
        out["assistant mentions the shipped version (%s)" % loc] = (
            e is not None and newest_version(e.get(loc)) == cur)
    out["the entry still exists"] = e is not None
    out["every locale is non-empty"] = e is not None and all(
        e.get(loc) for loc in LOCALES)
    # NOT enough on its own. Seven U+FFFD shipped through the check above,
    # because a string made entirely of replacement characters is non-empty.
    # These are the assistant's own sentences, read by every visitor in those
    # locales, so "it is a string" is not the property anyone depends on.
    out["every locale decodes without a replacement character"] = (
        e is not None and all("\ufffd" not in (e.get(loc) or "")
                              for loc in LOCALES))
    out["the full changelog is still linked"] = (
        e is not None and any(l.get("href") == "changelog.html" for l in (e.get("links") or [])))
    # The site also has a real changelog page; the assistant must not claim to
    # cover releases the page does not list without the gap being visible.
    page = set(re.findall(r'<h2 id="v(\d+)">', changelog))
    out["changelog.html has versioned entries"] = len(page) >= 7

    # Everything above this line reads the h2 ID. A reader reads the number in
    # the <span>, and those two disagreed: v1.15.39 shipped a heading displaying
    # v1.15.38, the only duplicated version number in the file. The ID was
    # checked and the label was not, so the guard was green over a wrong page.
    shown = re.findall(r'<h2 id="v\d+"><span>(v\d+\.\d+\.\d+)</span>', changelog)
    counts = {}
    for v in shown:
        counts[v] = counts.get(v, 0) + 1
    out["no two changelog headings show the same version"] = (
        bool(shown) and all(c == 1 for c in counts.values()))
    # NOT "shown[0] == cur": measured, the headings do not run newest-first
    # (the 1.15.28..1.15.39 block is ascending), so that assertion is false of
    # the real file. Asserting it would be writing the bug into the guard.
    out["the shipped version has a changelog heading of its own"] = cur in shown
    out["the changelog runs newest first"] = _descending(shown)
    out["every changelog heading shows a version number"] = (
        len(shown) == len(re.findall(r'<h2 id="v\d+">', changelog)))
    # The id has to BE the version it displays. It is what a reader copies
    # into a link, what the search index points at, and what the gap tool
    # matches against a release tag. Three headings were hand-typed one digit
    # short - v1127, v1128, v1129 for v1.15.27, v1.15.28 and v1.15.29 - so
    # the natural anchor for those three reached nothing, and the tool that
    # reports undocumented releases could not see them.
    _bad_ids = [(a, b) for a, b in re.findall(
        r'<h2 id="(v\d+)"><span>(v[\d.]+)</span>', changelog)
        if a != "v" + b[1:].replace(".", "")]
    out["every changelog heading's id is the version it shows"] = not _bad_ids
    return out


def main():
    kb = read_json(KNOWLEDGE)
    with io.open(VERSION, encoding="utf-8") as fh:
        version = fh.read()
    with io.open(CHANGELOG, encoding="utf-8") as fh:
        changelog = fh.read()

    base = checks(kb, version, changelog)
    failures = []

    print("== 1. the assistant is not stale ==")
    for name, ok in sorted(base.items()):
        print("   %-46s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2. the repository's CHANGELOG.md is the generated one ==")
    expected = render_expected()
    on_disk = None
    if os.path.exists(CHANGELOG_MD):
        with io.open(CHANGELOG_MD, encoding="utf-8") as fh:
            on_disk = fh.read()
    for name, ok in sorted(changelog_md_checks(on_disk, expected).items()):
        print("   %-46s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2b. every release the public never heard of ==")
    # A tool that PRINTS a gap does not make anyone close it: the gap was
    # open for twenty-seven releases while the tool sat in the repository
    # naming every one of them. This makes it fail the suite instead.
    _tags = [t.strip() for t in subprocess.run(
        ["git", "tag", "--list", "v*", "--sort=-v:refname"],
        capture_output=True, text=True, encoding="utf-8").stdout.splitlines()
        if re.match(r"^v\d+\.\d+\.\d+$", t.strip())]
    _present = set(re.findall(r'<h2 id="v(\d+)">', changelog))
    _missing = [t for t in _tags if t[1:].replace(".", "") not in _present]
    _name = "every release tag has a changelog entry (%d tag(s))" % len(_tags)
    _ok = not _missing
    print("   %-46s %s" % (_name, "ok" if _ok else "FAIL"))
    if not _ok:
        failures.append(_name)
        print("      %d release(s) shipped with no public entry: %s"
              % (len(_missing), ", ".join(_missing[:8])))
    print()
    print("== 3. the gap is reportable, so it can be closed ==")
    ok = os.path.exists(RELEASE_NOTES)
    print("   %-46s %s" % ("docs/release_notes.py exists", "ok" if ok else "FAIL"))
    if not ok:
        failures.append("no tool to list the undocumented releases")
    else:
        out = subprocess.run(["git", "tag", "--list", "v*", "--sort=-v:refname"],
                             cwd=ROOT, capture_output=True, text=True,
                             encoding="utf-8").stdout
        tags = [t.strip() for t in out.splitlines()
                if re.match(r"^v\d+\.\d+\.\d+$", t.strip())]
        print("   %-46s %s" % ("repository has release tags", "%d found" % len(tags)))
        if not tags:
            failures.append("no tags to compare against")

    print()
    print("== 4. each assertion can fail: roll the file back, it must go red ==")
    # Five mutations, all on copies: the two knowledge-base ones, and three
    # that relabel a heading the way a reader would notice.
    import copy
    mutations = []

    stale = copy.deepcopy(kb)
    se = entry(stale)
    se["text"] = re.sub(r"v1\.\d+\.\d+", "v1.13.3", se["text"], count=1)
    mutations.append(("age the English entry", stale, changelog,
                      ["assistant mentions the shipped version (text)"]))

    unlinked = copy.deepcopy(kb)
    entry(unlinked)["links"] = []
    mutations.append(("drop the changelog link", unlinked, changelog,
                      ["the full changelog is still linked"]))

    # The failure that actually shipped. A replacement character is invisible in
    # a diff unless you count them, and non-empty to every other assertion -
    # which is the point, so "every locale is non-empty" is deliberately NOT
    # listed as something that must go red. It is reported alongside instead,
    # because "this check still passes while the page is corrupt" is the
    # finding, not a test failure.
    for loc in ("fa", "zh"):
        c = copy.deepcopy(kb)
        t = entry(c)[loc]
        entry(c)[loc] = t[:40] + "\ufffd\ufffd" + t[40:]
        mutations.append((
            "ship U+FFFD in %s" % loc, c, changelog,
            ["every locale decodes without a replacement character"]))

    # Headings are read by eye, so the mutations have to be too. The first
    # reproduces the shipped bug exactly: the newest heading wearing the
    # previous release's number.
    cur = "v" + version.strip()
    newest = re.search(r'<h2 id="(v\d+)"><span>%s</span>' % re.escape(cur), changelog)
    assert newest, "the shipped version has no heading to mutate"
    newer_id, shown_now = newest.group(1), cur

    def relabel(text, old_id, old_shown, new_shown):
        before = '<h2 id="%s"><span>%s</span>' % (old_id, old_shown)
        assert text.count(before) == 1, "relabel anchor not unique"
        return text.replace(before, '<h2 id="%s"><span>%s</span>'
                            % (old_id, new_shown), 1)

    back = relabel(changelog, newer_id, shown_now, "v1.15.0")
    mutations.append(("ship the v1.15.38 bug again", kb, back,
                      ["no two changelog headings show the same version",
                       "the shipped version has a changelog heading of its own"]))

    # Not a duplicate: a wrong label that no count would catch. Proves the
    # shipped-version check is not merely a duplicate detector.
    ahead = relabel(changelog, newer_id, shown_now, "v9.9.9")
    mutations.append(("label it v9.9.9", kb, ahead,
                      ["the shipped version has a changelog heading of its own"]))

    # The ordering itself. Swap the shipped heading with the one directly above
    # it, which is exactly what the hardcoded anchor produced for twelve
    # releases, and nothing about labels or counts changes.
    sect = cur_head_section(changelog, cur)
    i = changelog.index(sect)
    # Swap with ONE neighbouring section so the move is exactly one position and
    # nothing about labels or counts changes. Which neighbour depends on where
    # the shipped heading already sits: today it is first, so it has to go
    # below the next one. Assuming a section exists above it only worked while
    # the file was still misordered.
    SECP = r'<h2 id="v\d+">.*?</ul>(?:\r\n|\r|\n){2}'
    above = list(re.finditer(SECP, changelog[:i], re.S))
    below = list(re.finditer(SECP, changelog[i + len(sect):], re.S))
    assert above or below, "the shipped heading has no neighbour to swap with"
    if above:
        p, q = above[-1], None
        swapped = (changelog[:p.start()] + sect + changelog[p.end():i]
                   + p.group(0) + changelog[i + len(sect):])
    else:
        n = below[0]
        s2 = changelog[i + len(sect):]
        swapped = (changelog[:i] + n.group(0) + sect + s2[n.end():])
    assert swapped != changelog
    assert len(swapped) == len(changelog), "the swap changed the byte length"
    assert sorted(re.findall(r"<span>(v[\d.]+)</span>", swapped)) == sorted(
        re.findall(r"<span>(v[\d.]+)</span>", changelog)), "the swap lost a label"
    mutations.append(("bury the shipped release", kb, swapped,
                      ["the changelog runs newest first"]))

    # Strip the label entirely: the reader sees no version at all.
    bare = relabel(changelog, newer_id, shown_now, "")
    bare = bare.replace('<h2 id="%s"><span></span>' % newer_id,
                        '<h2 id="%s">' % newer_id, 1)
    mutations.append(("leave the newest heading unlabelled", kb, bare,
                      ["every changelog heading shows a version number"]))

    # The generated file is only honest if something checks it. Mutate it the
    # way a stale file actually goes stale - the page gains a release and
    # nobody re-ran the generator - and the check must notice.
    if on_disk is not None:
        _newest = re.search(r"^## (v[\d.]+)", on_disk, re.M)
        assert _newest, "the CHANGELOG.md has no version heading"
        # The heading the file starts with, so the mutation follows the
        # newest release instead of a version frozen into the test.
        _head = "## " + _newest.group(1)
        stale = on_disk.replace(_head, _head + " ", 1)
        assert stale != on_disk, "the CHANGELOG.md mutation did not apply"
        assert stale != on_disk, "the CHANGELOG.md mutation did not apply"
        after = changelog_md_checks(stale, expected)
        must = "CHANGELOG.md is what the generator produces"
        if after[must]:
            print("   %-30s FAIL (stayed green)" % "let CHANGELOG.md go stale")
            failures.append("let CHANGELOG.md go stale: cannot fail")
        else:
            print("   %-30s ok (goes red: %s)"
                  % ("let CHANGELOG.md go stale", must))

    for name, mutated, mutated_changelog, must_go_red in mutations:
        after = checks(mutated, version, mutated_changelog)
        still = [g for g in must_go_red if after[g]]
        if still:
            print("   %-30s FAIL (stayed green: %s)" % (name, ", ".join(still)))
            failures.append(name + ": cannot fail")
        else:
            print("   %-30s ok (goes red: %s)" % (name, ", ".join(must_go_red)))

    print()
    if failures:
        print("FAIL: %d problem(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("PASS: the assistant and the shipped version agree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())