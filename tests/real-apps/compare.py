#!/usr/bin/env python3
"""Compares two runs of the real-app tests by group of apps, so a change in
SAM is reported as "Electron apps: 39 → 37 start; both lost: <reason>"
instead of a list of app names.

    python3 -I tests/real-apps/compare.py BEFORE AFTER [kinds.txt]

BEFORE and AFTER are outputs of tests/real-apps/table.py: the plain table,
or the published report (docs/reports/real-apps-*.md, from --markdown), so
a new run can be compared with the last published one. kinds.txt has "file-name kind" lines; the
kind before the first "-" is the group (electron-ai → electron). The exit
status is 1 when any group lost an app, so a script can stop on it.
"""
import sys
from collections import defaultdict


REPORT_RESULT = {"starts": "OK", "does not start": "FAIL", "turned away": "ADD"}


def read(path):
    """file name → (outcome, note) from a table.py output or report."""
    rows = {}
    for line in open(path):
        if line.startswith("| ") and ".appimage" in line.lower():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 5:
                result = REPORT_RESULT.get(cells[1], "OK+1" if cells[1].startswith("starts after") else "?")
                rows[cells[0]] = (result, cells[4])
            continue
        parts = line.rstrip("\n").split(None, 4)
        if len(parts) < 4 or parts[0] == "AppImage" or not parts[0].lower().endswith(".appimage"):
            continue
        rows[parts[0]] = (parts[1], parts[4] if len(parts) > 4 else "")
    return rows


def starts(outcome):
    return outcome.startswith("OK")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    before, after = read(sys.argv[1]), read(sys.argv[2])
    kinds = {}
    if len(sys.argv) > 3:
        for line in open(sys.argv[3]):
            p = line.split()
            if len(p) >= 2:
                kinds[p[0]] = p[1].split("-")[0]
    groups = defaultdict(list)
    for name in sorted(set(before) | set(after)):
        groups[kinds.get(name, "?")].append(name)
    lost_any = False
    lines = []
    for group, names in sorted(groups.items()):
        b = sum(starts(before[n][0]) for n in names if n in before)
        a = sum(starts(after[n][0]) for n in names if n in after)
        lost = [n for n in names if n in before and n in after and starts(before[n][0]) and not starts(after[n][0])]
        won = [n for n in names if n in before and n in after and not starts(before[n][0]) and starts(after[n][0])]
        if not lost and not won and b == a:
            continue
        lines.append(f"{group}: {b} → {a} of {len(names)} start")
        if lost:
            lost_any = True
            reasons = defaultdict(list)
            for n in lost:
                reasons[after[n][1].split(" | ")[0] or "no reason given"].append(n)
            for reason, apps in sorted(reasons.items(), key=lambda r: -len(r[1])):
                same = f"{len(apps)} apps, the same reason" if len(apps) > 1 else "1 app"
                lines.append(f"  lost ({same}): {reason}")
                lines += [f"    {n}" for n in apps]
        if won:
            lines.append(f"  now starting: {', '.join(won)}")
        only_before = [n for n in names if n not in after]
        only_after = [n for n in names if n not in before]
        if only_before:
            lines.append(f"  not in the new run: {', '.join(only_before)}")
        if only_after:
            lines.append(f"  new in this run: {', '.join(only_after)}")
    print("\n".join(lines) if lines else "No group changed.")
    sys.exit(1 if lost_any else 0)


if __name__ == "__main__":
    main()
