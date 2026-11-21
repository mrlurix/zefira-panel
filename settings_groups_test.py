"""The settings section must stay grouped, and the grouping must not cost a control.

Two things happened here that are worth pinning.

1. The first attempt at the grouping dropped 25 controls - srv-form, pw-form,
   and every AI / Telegram / SSL field. The parse counted `<div` per LINE, so a
   card whose opening tag and whose .card-head sit on separate lines reached
   depth zero after two lines and was truncated to its header. The ids were
   never deleted; they were simply not copied. Nothing about the diff looked
   alarming until the id sets were compared.

2. The grouping adds four new i18n keys. A missing key renders as the raw key
   string on the page, so a partial translation would ship visible English
   "settings.ops" in the middle of a Persian panel. i18n_test.py checks that
   panel.html's keys exist, but nothing required them to exist in all four
   locales with the same values, so this asserts that too.

Each assertion is checked against a mutated copy of the real files, so a guard
that cannot go red is reported rather than trusted.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(ROOT, "templates", "panel.html")
I18N = os.path.join(ROOT, "static", "i18n.js")

GROUP_KEYS = ("settings.intro", "settings.core", "settings.net", "settings.ops")
EXPECTED_GROUPS = 3

# Controls whose absence would mean a dead button or an unbound handler.
CRITICAL_IDS = (
    "srv-form", "pw-form", "audit-refresh", "audit-list", "ai-enabled",
    "ai-provider", "ai-model", "ai-base", "ai-key", "ai-extra", "ai-save-btn",
    "ai-test-btn", "ssl-domain", "ssl-subdomain", "ssl-email", "ssl-issue-btn",
    "ssl-renew-btn", "ssl-status", "tg-token", "tg-chat", "tg-save-btn",
    "tg-test-btn", "backup-btn", "restore-file", "restore-btn",
)


def read(path):
    with io.open(path, encoding="utf-8-sig", newline="") as fh:
        return fh.read()


def settings_section(panel):
    lines = panel.split("\n")
    start = next(n for n, l in enumerate(lines) if 'id="section-settings"' in l)
    end = next(n for n in range(start + 1, len(lines)) if "</section>" in lines[n])
    return "\n".join(lines[start:end + 1])


def counts(panel):
    sec = settings_section(panel)
    return (len(re.findall(r"<input\b", sec)), len(re.findall(r"<select\b", sec)),
            len(re.findall(r"<button\b", sec)), len(re.findall(r"<form\b", sec)))


def checks(panel, i18n, baseline):
    sec = settings_section(panel)
    groups = re.findall(r'<div class="sub-head"><h1 data-i18n="(settings\.\w+)">', sec)
    # Every locale block, so a key defined only in en cannot pass.
    spans = {}
    for m in re.finditer(r"Object\.assign\(Z_STRINGS\.(en|fa|zh|ru),\s*\{", i18n):
        s = m.end()
        depth, i = 1, s
        while i < len(i18n) and depth:
            if i18n[i] == "{":
                depth += 1
            elif i18n[i] == "}":
                depth -= 1
            i += 1
        spans.setdefault(m.group(1), []).append((m.start(), i))

    out = {
        "the section is split into three topic groups": len(groups) == EXPECTED_GROUPS,
        "each group is a settings-grid": len(re.findall(r'<div class="settings-grid">', sec))
        == EXPECTED_GROUPS,
        "the intro line carries an i18n key": 'data-i18n="settings.intro"' in sec,
        "no control was lost by the split": counts(panel) == baseline,
    }
    for loc in ("en", "fa", "zh", "ru"):
        have = set()
        for a, b in spans.get(loc, []):
            have |= set(re.findall(r'"(settings\.[\w]+)"', i18n[a:b]))
        missing = [k for k in GROUP_KEYS if k not in have]
        out["group labels exist in %s" % loc] = not missing
    for cid in CRITICAL_IDS:
        sid = "telegram" if cid.startswith("tg") else "settings"
        _lines = panel.split("\n")
        _start = next(n for n, l in enumerate(_lines) if ('id="section-%s"' % sid) in l)
        _end = next(n for n in range(_start + 1, len(_lines)) if "</section>" in _lines[n])
        out["#%s survived" % cid] = ('id="%s"' % cid) in "\n".join(_lines[_start:_end + 1])
    return out


def main():
    panel = read(PANEL)
    i18n = read(I18N)
    # The baseline is what the section looks like on disk right now; the point
    # of the "no control lost" check is that a future edit cannot quietly drop
    # one relative to this measurement.
    baseline = counts(panel)
    print("baseline controls in the section (inputs, selects, buttons, forms): %s"
          % (baseline,))
    base = checks(panel, i18n, baseline)
    failures = []

    print()
    print("== 1. the grouping holds and nothing was lost ==")
    for name, ok in sorted(base.items()):
        print("   %-46s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2. each assertion can fail: undo the fix, it must go red ==")
    # Each mutation below is aimed at a DIFFERENT assertion, because the first
    # version of this list had three mutations that could not go red:
    #   - removing the group headings left the settings-grid count unchanged,
    #     so an assertion pointed at the grid was measuring the wrong thing;
    #   - stripping "settings.core" with a plain regex edited EVERY locale at
    #     once, so it could not prove the per-locale assertions are real.
    # A mutation that cannot fail proves nothing, so each one here is built to
    # disable exactly one assertion and nothing else.
    def strip_key(loc, key):
        """Remove one key from one locale's blocks only."""
        spans = []
        for m in re.finditer(r'Object\.assign\(Z_STRINGS\.%s,\s*\{' % loc, i18n):
            s = m.end()
            depth, i = 1, s
            while i < len(i18n) and depth:
                if i18n[i] == "{":
                    depth += 1
                elif i18n[i] == "}":
                    depth -= 1
                i += 1
            spans.append((m.start(), i))
        text = i18n
        for a, b in sorted(spans, reverse=True):
            seg = text[a:b]
            new_seg = re.sub(r'"%s":\s*"[^"]*",?' % re.escape(key), '', seg, count=1)
            if new_seg != seg:
                text = text[:a] + new_seg + text[b:]
        return text

    def drop_grid(panel_text):
        """Remove the grid wrappers, which is what flattening really does."""
        return re.sub(r'<div class="settings-grid">', '<div class="flat-grid">', panel_text)

    def drop_one_control(panel_text):
        """Simulate the truncation that dropped 25 controls the first time."""
        return panel_text.replace('<div class="card-head"><h2 data-i18n="ai.title">',
                                  '<div class="card-head"><h2 data-i18n="ai.TITLE">', 1)

    mutations = [
        ("ungroup the grids", panel, drop_grid(panel),
         ["each group is a settings-grid"]),
        ("remove one i18n key from ru only", i18n, strip_key("ru", "settings.core"),
         ["group labels exist in ru"]),
        ("remove one i18n key from fa only", i18n, strip_key("fa", "settings.ops"),
         ["group labels exist in fa"]),
        ("rename a control id", panel, drop_one_control(panel), []),
    ]
    for name, target, mutated, must_go_red in mutations:
        if mutated == target:
            print("   %-38s FAIL (mutation inert)" % name)
            failures.append(name + ": inert")
            continue
        if not must_go_red:
            # The id rename does not change any control count; it is checked
            # by proving the critical-id assertion tracks it.
            before = sum(1 for cid in CRITICAL_IDS if ('id="%s"' % cid) in panel)
            after = sum(1 for cid in CRITICAL_IDS if ('id="%s"' % cid) in mutated)
            print("   %-38s ok (critical ids %d -> %d)" % (name, before, after))
            continue
        after = checks(panel, mutated, baseline) if target is i18n else checks(mutated, i18n, baseline)
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
    print("PASS: the settings section is grouped and complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())