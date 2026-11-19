"""One row per AppImage from a tests/real-apps run, plus totals.

    python3 -I tests/real-apps/table.py WORK [kinds.txt]
    python3 -I tests/real-apps/table.py WORK kinds.txt --markdown DATE > docs/reports/real-apps-DATE.md

With --markdown it writes the report the website and README take their
numbers from (scripts/facts.py reads its "Total" line). Paths are reduced
to file names, so no folder of the test computer is published.

Outcome: OK (works with SAM's recommendation), OK+N (after N repair steps),
FAIL (does not start), ADD (no sandbox could be created). Window: a window
was on screen 20 s after the start (screenshot bigger than an empty desktop).
kinds.txt: optional "file-name kind" lines to group the totals.
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from checks import messages, screen, use  # noqa: E402  (what the app really did)

args = [a for a in sys.argv[1:]]
MARKDOWN = None
if "--markdown" in args:
    i = args.index("--markdown")
    MARKDOWN = args[i + 1]
    del args[i:i + 2]
R = os.path.abspath(args[0])
kinds = {}
if len(args) > 1:
    for line in open(args[1]):
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
        rows.append((name, "ADD", "-", "-", why, "", {}))
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
    checks = {}
    if os.path.exists(base + ".checks"):
        for l in open(base + ".checks", errors="replace").read().splitlines():
            k, _, v = l.partition(" ")
            checks[k] = v.strip()
    did = {"file": checks.get("file", ""), "close": checks.get("close", ""),
           "screen": screen(base), "messages": messages(base)}
    rows.append((name, outcome, window, check, note, use(base), did))

def markdown(date):
    """The published report: totals, results per kind of app, and every app."""
    import re
    clean = lambda t: re.sub(r"(?:/[^\s/|]+)+/([^\s/|]+)", r"\1", t).replace("|", "/")
    count = lambda pred: sum(1 for r in rows if pred(r))
    ok, rep = count(lambda r: r[1] == "OK"), count(lambda r: r[1].startswith("OK+"))
    fail, add = count(lambda r: r[1] == "FAIL"), count(lambda r: r[1] == "ADD")
    win = count(lambda r: r[2] == "yes")
    out = [f"# Real AppImages in SAM ({date})", "",
           "> **What this is:** every AppImage of SAM's test sets went through SAM's whole flow",
           "> in a hidden desktop session: SAM unpacked and analyzed it, created a sandbox with",
           "> its own recommendation, checked the sandbox from the inside, and started the app.",
           "> If the app did not start, SAM's repair steps were tried one at a time.",
           "> Made with `tests/real-apps/run.sh` and `tests/real-apps/table.py --markdown`.", "",
           f"**Total:** {len(rows)} AppImages; {ok} start with SAM's recommendation; {rep} start after one repair step; "
           f"{fail} do not start; {add} turned away (built for another processor); {win} showed a window within 20 seconds.", "",
           "A window can be missing for good reasons: tray-only apps, command-line tools and",
           "apps that wait for a first-run question show none in the hidden session.", ""]
    if kinds:
        groups = {}
        for r in rows:
            groups.setdefault(kinds.get(r[0], "?").split("-")[0], []).append(r[1])
        out += ["## By kind of app", "", "| Kind | Start | Of |", "|---|---|---|"]
        out += [f"| {k} | {sum(o.startswith('OK') for o in v)} | {len(v)} |" for k, v in sorted(groups.items())]
        out += [""]
    # Level 2: of the apps allowed each, how many really used it.
    used = {}
    for r in rows:
        for part in filter(None, r[5].split(",")):
            k, _, v = part.partition(":")
            used.setdefault(k, {}).setdefault(v, 0)
            used[k][v] += 1
    if any(used.values()):
        names = {"gpu": "Graphics card", "sound": "Sound", "net": "Network (leaving this computer)"}
        out += ["## What the apps really used", "",
                "Seen from outside during the 25-second start, every 2 seconds. *Unused* is no failure:",
                "many apps play no sound or go online only when asked. *Not measurable*: the graphics",
                "check needs NVIDIA's driver; the network check needs the run's own control groups.", "",
                "| Permission | Allowed and used | Allowed, unused | Not allowed | Not measurable |", "|---|---|---|---|---|"]
        for k in ("gpu", "sound", "net"):
            c = used.get(k, {})
            out.append(f"| {names[k]} | {c.get('works', 0)} | {c.get('unused', 0)} | "
                       f"{c.get('-', 0) + c.get('local', 0)} | {c.get('n/a', 0)} |")
        out += [""]
    # Used like a person would: a sample file, the close button, what the
    # window showed, what the app printed.
    did = [r[6] for r in rows if r[6]]
    if did:
        n = lambda pred: sum(1 for d in did if pred(d))
        with_file = n(lambda d: d["file"].split(" ")[0] in ("read", "not-read"))
        out += ["## Used like a person would", "",
                "Each app that started was started once more: with a small sample file of a type its",
                "menu entry says it opens, then closed with its windows' close buttons. Linux reports",
                "from outside whether the app read the file. The window is checked in the screenshot",
                "after 20 seconds, its text read for error messages, and the app's own messages for",
                "crashes, missing libraries and refused access.", "",
                "| Check | Apps |", "|---|---|",
                f"| Read the sample file it was given | {n(lambda d: d['file'].startswith('read'))} of {with_file} |",
                f"| Closed cleanly with its close button | {n(lambda d: d['close'].startswith('closed') and d['close'].endswith(' ok'))} |",
                f"| Closed, but with an error code or signal | {n(lambda d: d['close'].startswith('closed') and not d['close'].endswith(' ok'))} |",
                f"| Did not close within 10 seconds | {n(lambda d: d['close'].startswith('hung'))} |",
                f"| Ended by itself (command-line tools) | {n(lambda d: d['close'].startswith('ended-by-itself'))} |",
                f"| No window to close | {n(lambda d: d['close'].startswith('no-window'))} |",
                f"| Window empty (one or two colours) | {n(lambda d: d['screen']['window'] == 'blank')} |",
                f"| Error words on screen | {n(lambda d: bool(d['screen']['text']))} |",
                f"| Crash messages | {n(lambda d: 'crash' in d['messages'])} |",
                f"| Missing library messages | {n(lambda d: 'library' in d['messages'])} |",
                f"| Refused access messages | {n(lambda d: 'denied' in d['messages'])} |", ""]
    labels = {"OK": "starts", "FAIL": "does not start", "ADD": "turned away"}
    show = {"works": "used", "unused": "unused", "-": "-", "local": "local only", "n/a": "n/a"}
    out += ["## Every AppImage", "", "| AppImage | Result | Window | Sandbox check | Uses | Used like a person | Note |",
            "|---|---|---|---|---|---|---|"]
    for r in rows:
        res = labels.get(r[1], f"starts after {r[1][3:]} repair step")
        uses = ", ".join(f"{k} {show.get(v, v)}" for k, _, v in (p.partition(":") for p in r[5].split(",") if p)
                         if v in ("works", "unused"))
        d = r[6]
        person = []
        if d:
            f = d["file"].split(" ")
            if f[0] in ("read", "not-read") and len(f) > 1:
                person.append(f"{f[1]} {'read' if f[0] == 'read' else 'not read'}")
            if d["close"]:
                c = d["close"].split(" ")
                person.append(c[0].replace("-", " ") + (f" ({c[-1]})" if c[-1] not in ("ok", "?") and c[0] == "closed" else ""))
            if d["screen"]["window"] == "blank":
                person.append("empty window")
            if d["screen"]["text"]:
                person.append(f"on screen: {d['screen']['text'][:40]}")
            for k in sorted(d["messages"]):
                person.append(f"{k} message")
        out.append(f"| {r[0]} | {res} | {r[2]} | {r[3]} | {uses or '-'} | {', '.join(person) or '-'} | {clean(r[4])} |")
    print("\n".join(out))


if MARKDOWN:
    markdown(MARKDOWN)
    sys.exit(0)

w = max(len(r[0]) for r in rows) if rows else 10
print(f"{'AppImage':<{w}}  outcome  window  check  {'uses':<34}  note")
for r in rows:
    print(f"{r[0]:<{w}}  {r[1]:<7}  {r[2]:<6}  {r[3]:<5}  {r[5]:<34}  {r[4][:90]}")
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
