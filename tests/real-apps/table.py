"""One row per AppImage from a tests/real-apps run, plus totals.

    python3 -I tests/real-apps/table.py WORK [kinds.txt]

Outcome: OK (works with SAM's recommendation), OK+N (after N repair steps),
FAIL (does not start), ADD (no sandbox could be created). Window: a window
was on screen 20 s after the start (screenshot bigger than an empty desktop).
kinds.txt: optional "file-name kind" lines to group the totals.
"""
import glob
import json
import os
import sys

R = os.path.abspath(sys.argv[1])
kinds = {}
if len(sys.argv) > 2:
    for line in open(sys.argv[2]):
        parts = line.split()
        if len(parts) >= 2:
            kinds[parts[0]] = parts[1]

EMPTY_SHOT = 8000  # bytes: an empty virtual desktop saves as about 3 KB


def load(p):
    try:
        d = json.load(open(p))
        return d.get("data", d) if isinstance(d, dict) else d
    except Exception:
        return None


def start_result(base, n):
    d = load(f"{base}.selftest{n}.json")
    if not isinstance(d, dict) or not d.get("results"):
        return None
    return d["results"][0]


rows = []
for txt in sorted(glob.glob(f"{R}/results/*.txt")):
    if txt.endswith(".add.txt"):
        continue
    base = txt[:-4]
    name = os.path.basename(base)
    info = load(base + ".info2.json") or {}
    e = info.get("entry") if isinstance(info, dict) else None
    if not e:
        add = open(base + ".add.txt").read() if os.path.exists(base + ".add.txt") else ""
        why = next((l.strip() for l in add.splitlines() if "error" in l.lower() or "failed" in l.lower()), add.strip()[-120:])
        rows.append((name, "ADD", "-", "-", why[:110]))
        continue
    outcome, why, rounds = None, "", 0
    for n in range(4):
        r = start_result(base, n)
        if r is None:
            break
        rounds = n
        if r.get("status") == "ok":
            outcome = "OK" if n == 0 else f"OK+{n}"
            break
        why = r.get("detail", "")
        f = [x.get("title") for x in r.get("findings", [])]
        if f:
            why += " | " + "; ".join(f[:2])
    if outcome is None:
        outcome = "FAIL"
    shot = f"{base}.shot{rounds}.png"
    size = os.path.getsize(shot) if os.path.exists(shot) else 0
    window = "yes" if size > EMPTY_SHOT else "no"
    ver = load(base + ".verify.json") or {}
    failed = (ver.get("record") or {}).get("failed") if isinstance(ver, dict) else None
    check = "ok" if failed == [] else ("FAIL " + ",".join(failed[:3]) if failed else "?")
    steps = []
    for n in range(1, 4):
        d = load(f"{base}.repair{n}.json")
        if isinstance(d, dict) and d.get("applied"):
            a = d["applied"]
            steps.append(a.get("title", str(a)) if isinstance(a, dict) else str(a))
    note = why if outcome == "FAIL" else ("repairs: " + "; ".join(steps) if steps else "")
    rows.append((name, outcome, window, check, note[:110]))

w = max(len(r[0]) for r in rows) if rows else 10
print(f"{'AppImage':<{w}}  outcome  window  check  note")
for r in rows:
    print(f"{r[0]:<{w}}  {r[1]:<7}  {r[2]:<6}  {r[3]:<5}  {r[4]}")
total = len(rows)
count = lambda pred: sum(1 for r in rows if pred(r))
print()
print(f"total {total}: OK {count(lambda r: r[1] == 'OK')}, OK after repair {count(lambda r: r[1].startswith('OK+'))}, "
      f"FAIL {count(lambda r: r[1] == 'FAIL')}, not added {count(lambda r: r[1] == 'ADD')}; "
      f"window seen {count(lambda r: r[2] == 'yes')}; check failed {count(lambda r: r[3].startswith('FAIL'))}")
if kinds:
    groups = {}
    for r in rows:
        k = kinds.get(r[0], "?").split("-")[0]
        groups.setdefault(k, []).append(r[1])
    for k, outs in sorted(groups.items()):
        ok = sum(1 for o in outs if o.startswith("OK"))
        print(f"  {k:<10} {ok}/{len(outs)} start")
