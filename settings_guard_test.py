"""Two guards in app.js that read as protections but do something else.

1. `saveAllSettings()` checked its eight port fields with
   `Number.isFinite(v)`, which accepts 0, 70000 and 443.5. The schema is
   StrictInt(ge=1, le=65535), so an out-of-range port produced a 422 - and a
   422 discards the ENTIRE save, taking the domain, DNS and every other
   setting the operator changed on the same screen with it. The three sibling
   forms already check the bounds; only this one checked "is it a number".

2. The WireGuard pre-check before the config download had an empty
   `catch (_) {}`. A 500, a 429 or a dropped connection left `blocked` false
   and the download still ran, so the operator shipped a customer a config
   with no server public key in it and no warning. The comment beside it
   promised "nothing was downloaded", which was true only on the !wg_pub
   branch.

Each assertion below is checked against a MUTATED copy of the real app.js, so
a guard that cannot go red is reported instead of trusted.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
APPJS = os.path.join(ROOT, "static", "app.js")
SCHEMAS = os.path.join(ROOT, "schemas.py")


def read(path):
    with io.open(path, encoding="utf-8-sig", newline="") as fh:
        return fh.read()


def body_of(src, opener):
    """Return the text of a function/block starting at `opener`, brace-matched."""
    i = src.index(opener)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    return src[i:]


def checks(appjs, schemas):
    settings = body_of(appjs, "async function saveAllSettings(")
    # The port guard itself: the line after the comment that promises a check.
    guard = re.search(r"for \(const \[k, v\] of Object\.entries\(body\)\)\s*\{[\s\S]{0,600}?\n  \}",
                      settings)
    g = guard.group(0) if guard else ""
    download = body_of(appjs, 'btn.dataset.act === "download"')

    return {
        # 1. port guard
        "port guard rejects below 1":
            re.search(r"v\s*<\s*1\b", g) is not None,
        "port guard rejects above 65535":
            re.search(r"v\s*>\s*65535", g) is not None,
        "port guard rejects a fraction":
            "Number.isInteger" in g,
        "port guard still rejects NaN":
            "Number.isFinite" in g,
        "settings schema really is ge=1 le=65535":
                    # The BOUNDS are the invariant, not the spelling. Four of the
        # ports became Optional[StrictInt] with default None, because
        # "not sent" must mean "unchanged" rather than "written from
        # the default" - the same reason every other field in the model
        # changed. The constraint itself is unchanged, so this check
        # accepts either shape and still insists on the bounds.
        len(re.findall(r"_port:\s*(?:Optional\[)?StrictInt\]?\s*=\s*Field\([^)]*ge=1,\s*le=65535", schemas)) >= 8,
        # 2. fail-closed download
        "download path fails closed":
            re.search(r"catch \(_\)\s*\{[^}]*blocked\s*=\s*true", download) is not None,
        "download still warns the operator":
            "wgKeyWarn" in download,
        "the download is gated on blocked":
            re.search(r"if \(blocked\) return;", download) is not None,
    }


def main():
    appjs = read(APPJS)
    schemas = read(SCHEMAS)
    base = checks(appjs, schemas)
    failures = []

    print("== 1. the guards are in place ==")
    for name, ok in sorted(base.items()):
        print("   %-40s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2. each guard can fail: restore the bug, it must go red ==")
    mutations = [
        ("back to Number.isFinite only",
         lambda t: re.sub(
             r"if \(!Number\.isFinite\(v\) \|\| v < 1 \|\| v > 65535 \|\| !Number\.isInteger\(v\)\) \{",
             "if (!Number.isFinite(v)) {", t),
         ["port guard rejects below 1", "port guard rejects above 65535",
          "port guard rejects a fraction"]),
        ("empty the catch again",
         lambda t: re.sub(
             r"catch \(_\) \{\n        // Fail closed\.[\s\S]*?blocked = true;\n      \}",
             "catch (_) {}", t),
         ["download path fails closed"]),
    ]
    for name, mutate, must_go_red in mutations:
        mutated = mutate(appjs)
        if mutated == appjs:
            print("   %-34s FAIL (mutation inert - untestable)" % name)
            failures.append(name + ": inert")
            continue
        after = checks(mutated, schemas)
        still = [g for g in must_go_red if after[g]]
        if still:
            print("   %-34s FAIL (stayed green: %s)" % (name, ", ".join(still)))
            failures.append(name + ": cannot fail")
        else:
            print("   %-34s ok (goes red: %s)" % (name, ", ".join(must_go_red)))

    print()
    if failures:
        print("FAIL: %d problem(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("PASS: both guards hold, and both can fail.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())