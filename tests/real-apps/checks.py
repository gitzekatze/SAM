#!/usr/bin/env python3
"""One line per app from a real-app run (tests/real-apps/run.sh), and with a
baseline only the lines that changed, so a run is read in seconds.

    python3 tests/real-apps/checks.py WORK [BASELINE_WORK]

Columns: did the test start succeed; how many windows appeared after 20 s,
and whether a title reads like an error dialog; whether the recommendation
was the same twice; D-Bus calls without an answer; leftover launch folders
after closing; and, when run with CHECKS=..., the start without network
and sound, the second start, and the start in German.
"""
import glob
import json
import os
import re
import sys

ERROR_WORDS = re.compile(r"error|fehler|failed|crash|exception|cannot|could not|not supported", re.I)


def load(p):
    try:
        d = json.load(open(p))
        return d.get("data", d) if isinstance(d, dict) else d
    except Exception:
        return {}


def line(base):
    name = os.path.basename(base)
    checks = {}
    for l in open(base + ".checks", errors="replace").read().splitlines() if os.path.exists(base + ".checks") else []:
        k, _, v = l.partition(" ")
        checks[k] = v.strip()
    st = load(base + ".selftest0.json")
    res = (st.get("results") or [{}])[0] if isinstance(st, dict) else {}
    started = res.get("status") == "ok"
    for r in range(1, 4):
        s = load(f"{base}.selftest{r}.json")
        if isinstance(s, dict) and (s.get("results") or [{}])[0].get("status") == "ok":
            started = f"after repair {r}"
    wins = [l[len("window "):] for l in open(base + ".windows", errors="replace").read().splitlines()] if os.path.exists(base + ".windows") else []
    err = [w for w in wins if ERROR_WORDS.search(w)]
    m = re.search(r"(\d+) got no answer", checks.get("dbus", ""))
    cols = [
        "start=" + ("ok" if started is True else (started if started else "FAIL")),
        f"windows={len(wins)}" + (f" ERROR-TITLE={err[0][:40]!r}" if err else ""),
        "stable=" + checks.get("stable", "?"),
        "dbus-unanswered=" + (m.group(1) if m else "?"),
        "leftovers=" + checks.get("leftovers", "?"),
    ]
    for k in ("netoff", "second", "lang"):
        if k in checks:
            cols.append(f"{k}={checks[k]}")
    return name, "  ".join(cols)


def lines(work):
    return dict(line(t[:-4]) for t in sorted(glob.glob(f"{work}/results/*.txt")) if not t.endswith((".add.txt", "session.txt")))


def main():
    cur = lines(sys.argv[1])
    if len(sys.argv) > 2:
        base = lines(sys.argv[2])
        changed = {n: l for n, l in cur.items() if base.get(n) != l}
        print(f"{len(cur)} apps, {len(changed)} changed since the baseline")
        for n, l in changed.items():
            print(f"{n}\n  now:    {l}\n  before: {base.get(n, '(not in the baseline)')}")
    else:
        for n, l in cur.items():
            print(f"{n:60.60}  {l}")
        bad = sum(1 for l in cur.values() if "start=FAIL" in l or "ERROR-TITLE" in l or "stable=no" in l or not l.split("leftovers=")[1].startswith("0"))
        print(f"\n{len(cur)} apps, {bad} with something to look at")


if __name__ == "__main__":
    main()
