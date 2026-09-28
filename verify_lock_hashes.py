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

    if fix and not offline:
        return rewrite(entries)
    return 1 if (bogus or incomplete) else 0


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
