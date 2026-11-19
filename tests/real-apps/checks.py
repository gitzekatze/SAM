#!/usr/bin/env python3
"""One line per app from a real-app run (tests/real-apps/run.sh), and with a
baseline only the lines that changed, so a run is read in seconds.

    python3 tests/real-apps/checks.py WORK [BASELINE_WORK]

Columns: did the test start succeed; how many windows appeared after 20 s,
and whether a title reads like an error dialog; whether the recommendation
was the same twice; D-Bus calls without an answer; leftover launch folders
after closing; and, when run with CHECKS=..., the start without network
and sound, the second start, and the start in German. "use=" says per
permission whether what SAM allowed was really used (GPU, sound, network).
"""
import glob
import json
import shutil
import subprocess
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


def use(base):
    """Whether what SAM allowed is really used (level 2), from the
    observation during the first start (every 2 s for its 25 s): per
    permission "works" (allowed and used), "unused" (allowed, not used during
    the start: no failure, many apps play no sound or go online only when
    asked), "-" (not allowed), "local" (network for this computer only:
    nothing may leave, nothing to measure) or "n/a" (not measurable here:
    the GPU check needs NVIDIA's driver, the network check a run started
    with Delegate=yes)."""
    seen = {}
    if os.path.exists(base + ".observe"):
        for l in open(base + ".observe", errors="replace").read().splitlines():
            k, _, v = l.partition(" ")
            seen[k] = v.strip()
    perms = (load(base + ".info.json").get("entry", {}).get("profile", {}) or {}).get("permissions", {}) or {}
    allowed = {
        "gpu": bool((perms.get("devices") or {}).get("gpu")),
        "sound": bool((perms.get("audio") or {}).get("enabled")),
        "net": (perms.get("network") or {}).get("mode") == "full",
    }
    local = (perms.get("network") or {}).get("mode") == "localhost"
    out = []
    for k in ("gpu", "sound", "net"):
        v = seen.get(k)
        if k == "net" and local:
            out.append("net:local")
        elif not allowed[k]:
            out.append(f"{k}:-")
        elif v in (None, "n/a"):
            out.append(f"{k}:n/a")
        elif v == "yes" or (k == "net" and v.isdigit() and int(v) > 0):
            out.append(f"{k}:works")
        else:
            out.append(f"{k}:unused")
    return ",".join(out)


# What an app printed during its first start, sorted into what usually
# matters: a crash, a missing library, something the sandbox refused. Lines
# about what SAM never gives (the system bus without permission, the
# accessibility bus of the hidden session) are left out: expected.
MESSAGES = {
    "crash": re.compile(r"segmentation fault|core dumped|SIGSEGV|SIGABRT|Traceback \(most recent call last\)"
                        r"|panicked at|terminate called|Fatal Python error|\bAborted\b", re.I),
    "library": re.compile(r"cannot open shared object|error while loading shared libraries|undefined symbol"
                          r"|GLIBC_[0-9.]+' not found|ModuleNotFoundError|ImportError", re.I),
    "denied": re.compile(r"permission denied|operation not permitted|read-only file system|EACCES|EPERM|EROFS"),
}
EXPECTED = re.compile(r"system_bus_socket|accessibility bus|org\.a11y|/run/dbus/", re.I)


def messages(base):
    """Counts per kind in the log of the first start, and the first line of
    each kind (for the report)."""
    app_id = (load(base + ".info.json").get("entry") or {}).get("id", "")
    logs = sorted(glob.glob(os.path.join(os.path.dirname(os.path.dirname(base)), "sam", "config", "logs", app_id, "launch-*.log")))
    found = {}
    if app_id and logs:
        for l in open(logs[0], errors="replace").read().splitlines():
            if l.startswith("#") or EXPECTED.search(l):
                continue
            for kind, rx in MESSAGES.items():
                if rx.search(l):
                    found.setdefault(kind, [0, l.strip()[:120]])[0] += 1
    return found


def screen(base):
    """What the screenshots of the first start show inside the app's largest
    window: "content" or "blank" (one or two colours: an empty window),
    whether it changed between 12 s and 20 s, and error words read from it
    (text recognition, tesseract). Each part "?" when it cannot be told."""
    out = {"window": "none", "changed": "?", "text": ""}
    geo = []
    if os.path.exists(base + ".geometry"):
        for l in open(base + ".geometry").read().splitlines():
            try:
                x, y, w, h = (int(v) for v in l.split()[:4])
                geo.append((w * h, (x, y, x + w, y + h)))
            except ValueError:
                pass
    if not geo or not os.path.exists(base + ".shot0.png"):
        return out
    box = max(geo)[1]
    try:
        from PIL import Image, ImageChops
    except ImportError:
        out["window"] = "?"
        return out
    try:
        shot = Image.open(base + ".shot0.png").convert("RGB").crop(box)
    except Exception:
        out["window"] = "?"
        return out
    small = shot.resize((max(1, shot.width // 4), max(1, shot.height // 4)))
    colours = small.getcolors(maxcolors=64)
    out["window"] = "blank" if colours is not None and len(colours) <= 2 else "content"
    if os.path.exists(base + ".shotA0.png"):
        try:
            early = Image.open(base + ".shotA0.png").convert("RGB").crop(box)
            out["changed"] = "yes" if ImageChops.difference(early, shot).getbbox() else "no"
        except Exception:  # noqa: S110 -- no early screenshot to compare: "changed" stays unknown
            pass
    if shutil.which("tesseract") and out["window"] == "content":
        crop = base + ".window.png"
        shot.save(crop)
        r = subprocess.run(["tesseract", crop, "-", "-l", "eng"], capture_output=True, text=True, timeout=60)
        os.remove(crop)
        for l in r.stdout.splitlines():
            if ERROR_WORDS.search(l):
                out["text"] = " ".join(l.split())[:80]
                break
    return out


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
    extra += f"  memory={mem}MiB"
    extra += "  use=" + use(base)
    extra += f"  tray={checks.get('tray', '?')}  portals={checks.get('portals') or '-'}"
    for k in ("netoff", "second", "lang", "scale", "missing"):
        if k in checks:
            cols.append(f"{k}={checks[k]}")
    # Used like a person would (test-one.sh, usecheck): the sample file read,
    # the app closed with its close button.
    if "file" in checks:
        cols.append("file=" + checks["file"].split(" ")[0])
    if "close" in checks:
        c = checks["close"].split(" ")
        cols.append("close=" + c[0] + ("" if c[-1] in ("ok", c[0]) else "-" + c[-1])
                    + (f" ({checks['closed-windows'][:40]})" if c[0] == "hung" and "closed-windows" in checks else ""))
    sc = screen(base)
    cols.append(f"screen={sc['window']}" + (f" SCREEN-ERROR={sc['text']!r}" if sc["text"] else ""))
    msg = messages(base)
    cols.append("messages=" + (",".join(f"{k}:{v[0]}" for k, v in sorted(msg.items())) or "clean"))
    extra += f"  changed={sc['changed']}"
    if "left-running" in checks:
        cols.append("left-running=" + checks["left-running"])
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
