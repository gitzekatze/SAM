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
    # Start time: the first window KWin reported after the start began.
    start_ms = None
    try:
        t0 = int(open(base + ".t0").read().strip())
        app_id = load(base + ".info.json").get("entry", {}).get("id", "")
        log = open(os.path.join(os.path.dirname(os.path.dirname(base)), "kwin.log"), errors="replace").read()
        added = [int(t) for t in re.findall(rf"SAMADD {re.escape(app_id)} (\d+)", log) if int(t) >= t0]
        start_ms = min(added) - t0 if added else None
    except (OSError, ValueError):
        pass
    memf = dict(l.split(" ", 1) for l in open(base + ".mem").read().splitlines() if " " in l) if os.path.exists(base + ".mem") else {}
    mem = memf.get("memory", "?")
    cols = [
        "start=" + ("ok" if started is True else (started if started else "FAIL")),
        f"windows={len(wins)}" + (f" ERROR-TITLE={err[0][:40]!r}" if err else ""),
        "stable=" + checks.get("stable", "?"),
        "dbus-unanswered=" + (m.group(1) if m else "?"),
        "leftovers=" + checks.get("leftovers", "?"),
    ]
    # Timing and memory change from run to run: shown, but kept out of the
    # comparison with a baseline unless they change a lot (see main).
    extra = f"first-window={start_ms / 1000:.1f}s" if start_ms is not None else "first-window=none"
    # (Whether the GPU is in use cannot be seen from outside: sandboxed
    # processes are not dumpable, so their open files are hidden.)
    extra += f"  memory={mem}MiB"
    extra += f"  tray={checks.get('tray', '?')}  portals={checks.get('portals') or '-'}"
    for k in ("netoff", "second", "lang", "scale", "missing"):
        if k in checks:
            cols.append(f"{k}={checks[k]}")
    return name, "  ".join(cols), extra


def lines(work):
    out = {}
    for t in sorted(glob.glob(f"{work}/results/*.txt")):
        if not t.endswith((".add.txt", "session.txt")):
            name, cols, extra = line(t[:-4])
            out[name] = (cols, extra)
    return out


def number(extra, key):
    m = re.search(rf"{key}=([\d.]+)", extra)
    return float(m.group(1)) if m else None


def main():
    cur = lines(sys.argv[1])
    if len(sys.argv) > 2:
        base = lines(sys.argv[2])
        changed = {}
        for n, (cols, extra) in cur.items():
            b = base.get(n)
            # Start time or memory count as changed only at +50 % and more.
            grew = b and any(
                (x := number(extra, k)) and (y := number(b[1], k)) and x > y * 1.5 and x - y > (2 if k == "first-window" else 50)
                for k in ("first-window", "memory")
            )
            if b is None or b[0] != cols or grew:
                changed[n] = (cols, extra)
        print(f"{len(cur)} apps, {len(changed)} changed since the baseline")
        for n, (cols, extra) in changed.items():
            b = base.get(n)
            print(f"{n}\n  now:    {cols}  {extra}\n  before: {b[0] + '  ' + b[1] if b else '(not in the baseline)'}")
    else:
        for n, (cols, extra) in cur.items():
            print(f"{n:52.52}  {cols}  {extra}")
        bad = sum(1 for cols, _ in cur.values() if "start=FAIL" in cols or "ERROR-TITLE" in cols or "stable=no" in cols or not cols.split("leftovers=")[1].startswith("0"))
        print(f"\n{len(cur)} apps, {bad} with something to look at")


if __name__ == "__main__":
    main()
