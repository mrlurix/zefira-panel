"""Check every hash in requirements.lock against PyPI's own digests.

tools_lock.py hashed the artifacts `pip download` found ON THE MACHINE THAT
GENERATED IT, and only fell back to asking PyPI when it found nothing. So a
package that has a wheel for the local interpreter got exactly ONE hash - the
local one - and the lock then aborted on every other platform. That is what
broke the server install: cffi's recorded hash is the cp314 win_amd64 wheel,
while the server downloads the cp312 manylinux wheel.

The invariant a hash lock must have, and did not:
    for every (name, version), every recorded hash must be the real digest of
    a REAL artifact of that release, and the set must cover the artifacts a
    Linux CPython install will actually download.

Usage: python verify_lock_hashes.py [--fix]
       --fix rewrites the lock from PyPI's digests (offline-safe: it never
       invents a hash, it only copies the authoritative ones).
"""
import json
import re
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
LOCK = "requirements.lock"
REQS = "requirements.txt"
UA = {"User-Agent": "zefira-lock-verify"}


def parse(path):
    """-> [(name, extras, version, [hashes])] in file order."""
    entries = []
    cur = None
    for line in io_lines(path):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?==(\S+)\s*\\?$", s)
        if m:
            cur = [m.group(1), m.group(2) or "", m.group(3), []]
            entries.append(cur)
            continue
        m = re.match(r"^--hash=sha256:([0-9a-f]{64})\s*\\?$", s)
        if m and cur:
            cur[3].append(m.group(1))
    return entries


def io_lines(path):
    import io
    with io.open(path, encoding="utf-8") as fh:
        return fh.read().splitlines()


def upstream(name, version):
    """Every real artifact digest for one release, from PyPI."""
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                    timeout=45) as r:
            meta = json.loads(r.read().decode())
    except Exception as exc:
        return None, str(exc)
    digests = {}
    for e in meta.get("urls", []):
        fn = e.get("filename", "")
        d = (e.get("digests") or {}).get("sha256")
        if d and fn.endswith((".whl", ".tar.gz", ".zip")):
            digests[d] = fn
    return digests, None


def main():
    fix = "--fix" in sys.argv
    entries = parse(LOCK)
    print(f"lock entries: {len(entries)}")
    bogus, incomplete, offline = [], [], []

    for name, extras, ver, hashes in entries:
        real, err = upstream(name, ver)
        if real is None:
            offline.append(f"{name}=={ver}: {err}")
            continue
        known = set(real)
        for h in hashes:
            if h not in known:
                bogus.append(f"{name}=={ver} hash {h[:12]}… is not any PyPI "
                             f"artifact of that release")
        if not hashes:
            incomplete.append(f"{name}=={ver}: no hash at all")
            continue
        # Which linux wheels does a server actually download, and are they covered?
        needed = [fn for fn in real.values()
                  if "x86_64" in fn and "linux" in fn and fn.endswith(".whl")]
        if needed:
            have = {h for h in hashes}
            missing = [fn for fn in needed
                       if next((d for d, f in real.items() if f == fn), None) not in have]
            if missing:
                incomplete.append(f"{name}=={ver}: {len(missing)} linux wheel(s) not "
                                  f"covered, e.g. {missing[0]}")

    if offline:
        print(f"\ncould not reach PyPI for {len(offline)} entr(y/ies):")
        for o in offline[:5]:
            print("  " + o)
    print(f"\nhashes that match no upstream artifact: {len(bogus)}")
    for b in bogus[:12]:
        print("  " + b)
    print(f"entries missing coverage a Linux install needs: {len(incomplete)}")
    for i in incomplete[:12]:
        print("  " + i)

    absent = missing_extras()
    print(f"declared dependencies the lock does not contain at all: {len(absent)}")
    for a in absent[:12]:
        print("  " + a)

    if fix and not offline:
        return rewrite(entries)
    return 1 if (bogus or incomplete or absent) else 0


def missing_extras():
    """Requirements the lock does not contain AT ALL.

    Every other check in this file walks the LOCK's own entries, so a
    distribution that is missing from the lock entirely is invisible to it: a
    package with no entry has no hashes to be wrong. That is exactly how
    `uvloop` survived. `requirements.txt` asks for `uvicorn[standard]`, whose
    metadata lists uvloop for every platform that is not win32/cygwin/PyPy, and
    the lock - resolved on Windows - had every win32 marker and no non-win32
    one. `pip install --no-deps` then never installed it, so the server ran
    uvicorn on the pure-Python event loop, silently.

    So this asks the other direction: read what requirements.txt DECLARES,
    ask PyPI what each extra pulls in on Linux, and require every one of those
    to be a line in the lock.
    """
    locked = {name.lower().replace("_", "-") for name, _e, _v, _h in parse(LOCK)}
    problems = []
    for name, extras, ver in declared():
        if not extras:
            continue
        for extra in re.findall(r"[^\[\],]+", extras.strip("[]")):
            for dep in extra_members(name, ver, extra.strip()):
                if dep not in locked:
                    problems.append(
                        f"{name}[{extra.strip()}] needs {dep} on Linux, but the lock "
                        f"has no entry for it - it can never be installed with "
                        f"--no-deps, so the extra is silently not in effect")
    return problems


def declared():
    """-> [(name, extras, version)] from requirements.txt, comments stripped."""
    out = []
    for line in io_lines(REQS):
        s = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?==(\S+)$", s)
        if m:
            out.append((m.group(1), m.group(2) or "", m.group(3)))
    return out


def extra_members(name, version, extra):
    """Distributions one extra of a release requires on a Linux CPython box."""
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                    timeout=45) as r:
            meta = json.loads(r.read().decode())
    except Exception:
        return []
    want = extra.lower()
    found = set()
    for req in meta.get("info", {}).get("requires_dist") or []:
        norm = req.replace("'", '"')
        if f'extra == "{want}"' not in norm:
            continue
        # A marker that is false on Linux excludes the dependency entirely.
        if 'sys_platform == "win32"' in norm or 'sys_platform == "cygwin"' in norm:
            continue
        if 'platform_python_implementation == "PyPy"' in norm:
            continue
        dep = req.split(";")[0].strip()
        nm = re.match(r"^([A-Za-z0-9_.\-]+)", dep)
        if nm:
            found.add(nm.group(1).lower().replace("_", "-"))
    return sorted(found)


def rewrite(entries):
    """Rebuild the lock from PyPI's digests, keeping the file's own structure."""
    import io
    head = []
    with io.open(LOCK, encoding="utf-8") as fh:
        for line in fh:
            if line.strip() == "" and head and head[-1].startswith("# Regenerate"):
                break
            head.append(line.rstrip("\n"))
    out = list(head)
    changed = 0
    for name, extras, ver, old in entries:
        real, err = upstream(name, ver)
        if real is None:
            out.append(f"# UNHASHED (PyPI unreachable for {name}=={ver}): {old and old[0] or ''}")
            continue
        digests = sorted(real)
        if digests != sorted(old):
            changed += 1
        out.append(f"{name}{extras}=={ver} \\")
        for i, h in enumerate(digests):
            last = i == len(digests) - 1
            out.append(f"    --hash=sha256:{h}" + ("" if last else " \\"))
    out.append("")
    with io.open(LOCK, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(out))
    print(f"\nrewrote {LOCK}: {changed} entr(y/ies) changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
