#!/usr/bin/env python3
"""What changed outside SAM between two runs: compares two records of
`sam-jail --json doctor --contracts` (for example the last green CI run and
the first red one) and lists the components whose version changed and the
contracts whose state changed. The answer to "it worked yesterday": a
newer Bubblewrap, a pasta that lost an option, a kernel without Landlock.

    scripts/contract-diff.py OLD.json NEW.json     Markdown, for a CI summary

Exits 0 either way; it explains, it does not judge.
"""
import json
import sys


def load(path):
    """The report inside a file written by `sam-jail --json ...` (the last
    JSON line, wrapped in {"data": ...}) or a bare report."""
    try:
        text = open(path, encoding="utf-8").read().strip().splitlines()
        v = json.loads(text[-1]) if text else {}
    except (OSError, ValueError):
        return None
    return v.get("data", v) if isinstance(v, dict) else None


def diff(old, new):
    lines = []
    ov = {c["id"]: c.get("version") for c in old.get("components", [])}
    nv = {c["id"]: c.get("version") for c in new.get("components", [])}
    names = {c["id"]: c.get("name", c["id"]) for c in new.get("components", []) + old.get("components", [])}
    changed = [(k, ov.get(k), nv.get(k)) for k in sorted(set(ov) | set(nv)) if ov.get(k) != nv.get(k)]
    lines.append("### What changed outside SAM")
    lines.append("")
    if changed:
        lines.append("| Component | Before | Now |")
        lines.append("|---|---|---|")
        for k, a, b in changed:
            lines.append(f"| {names.get(k, k)} | {a or 'not installed'} | {b or 'not installed'} |")
    else:
        lines.append("No component changed its version.")
    lines.append("")
    oc = {c["id"]: c for c in old.get("contracts", [])}
    moved = [c for c in new.get("contracts", []) if oc.get(c["id"], {}).get("state") != c.get("state")]
    if moved:
        lines.append("| Contract | Before | Now | Found |")
        lines.append("|---|---|---|---|")
        for c in moved:
            before = oc.get(c["id"], {}).get("state", "new")
            lines.append(f"| {c['id']} | {before} | {c['state']} | {c.get('detail', '')} |")
        lines.append("")
        for c in moved:
            if c["state"] == "broken":
                lines.append(f"- **{c['id']}:** {c.get('playbook', '')}")
    else:
        lines.append("No contract changed its state.")
    if not changed and not moved:
        lines.append("")
        lines.append("The outside world is the same as in the last good run: the cause is most likely in SAM's own change.")
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    old, new = load(sys.argv[1]), load(sys.argv[2])
    if old is None or new is None:
        print("### What changed outside SAM\n\nNo record of the last good run to compare with.")
        return
    print(diff(old, new), end="")


if __name__ == "__main__":
    main()
