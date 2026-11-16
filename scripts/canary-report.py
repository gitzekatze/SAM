#!/usr/bin/env python3
"""Turns the nightly early-warning results (tests/canary/in-container.sh)
into GitHub issues, so a contract that breaks on an upcoming distribution is
seen in time and nothing is reported twice:

  - one issue per distribution and problem ("Early warning: Fedora Rawhide:
    pasta-splice-only"), with what was found, the playbook, the component
    versions and what changed since the previous night;
  - an open issue is updated, not duplicated;
  - an issue closes itself when its problem is gone;
  - a distribution that could not be set up (a broken mirror or package)
    gets one issue of its own, never a contract issue.

    scripts/canary-report.py RESULTS [--previous PREVIOUS] [--dry-run]

RESULTS holds one folder per distribution (out-<name>/ with setup.txt,
contracts.json, tests.txt); PREVIOUS the same from the night before.
Needs the GitHub command line (gh) with a token that may write issues.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LABEL = "early-warning"
NAMES = {
    "rawhide": "Fedora Rawhide",
    "debian-testing": "Debian testing",
    "ubuntu-devel": "Ubuntu development release",
    "arch": "Arch Linux",
    "tumbleweed": "openSUSE Tumbleweed",
}

spec = importlib.util.spec_from_file_location("cdiff", ROOT / "scripts" / "contract-diff.py")
cdiff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cdiff)


def problems(out):
    """(key, details) for every problem in one distribution's results."""
    found = []
    if (out / "setup.txt").read_text().strip() != "ok" if (out / "setup.txt").exists() else True:
        log = (out / "setup.log").read_text()[-3000:] if (out / "setup.log").exists() else ""
        return [("setup", "The distribution could not be set up (packages or the mirror), so nothing was checked. "
                 "This is usually the distribution's own problem and passes by itself.\n\n```\n" + log + "\n```")]
    report = cdiff.load(out / "contracts.json") or {}
    for c in report.get("contracts", []):
        if c.get("state") == "broken":
            found.append((c["id"], f"**Found:** {c.get('detail', '')}\n\n**SAM assumes:** {c.get('assumes', '')}\n\n"
                          f"**When it breaks, SAM:** {c.get('on_break', '')}\n\n**Playbook:** {c.get('playbook', '')}"))
    tests = (out / "tests.txt").read_text().splitlines() if (out / "tests.txt").exists() else []
    log = (out / "tests.log").read_text() if (out / "tests.log").exists() else ""
    broken = {k for k, _ in found}
    for line in tests:
        if line.startswith("FAIL "):
            name = line.split(" ", 1)[1]
            hint = "\n".join(l for l in log.splitlines() if "CONTRACT BROKEN" in l or "SAM ERROR" in l or "panicked" in l)[-2000:]
            # A test stopped by a contract already reported belongs to that
            # contract's issue, not to an issue of its own.
            causes = {k for k in broken if f"CONTRACT BROKEN: {k} " in hint}
            if causes:
                found = [(k, d + f"\n\nIt also stopped the test group **{name}**." if k in causes else d) for k, d in found]
                continue
            found.append((f"tests {name}", f"The test group **{name}** failed twice.\n\n```\n{hint or log[-2000:]}\n```"))
    return found


def versions(out):
    report = cdiff.load(out / "contracts.json") or {}
    rows = [f"| {c.get('name', c['id'])} | {c.get('version') or 'not installed'} |" for c in report.get("components", [])]
    return "| Component | Version |\n|---|---|\n" + "\n".join(rows) if rows else ""


def gh(*args, dry):
    if dry:
        print("  gh", " ".join(a if len(a) < 60 else a[:57] + "..." for a in args))
        return ""
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def main():
    args = sys.argv[1:]
    dry = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    prev = None
    if "--previous" in args:
        i = args.index("--previous")
        prev = pathlib.Path(args[i + 1])
        del args[i:i + 2]
    results = pathlib.Path(args[0])
    gh("label", "create", LABEL, "--color", "D93F0B", "--force",
       "--description", "A contract broke on an upcoming distribution (nightly early warning)", dry=dry)
    listed = gh("issue", "list", "--label", LABEL, "--state", "open", "--limit", "300",
                "--json", "number,title", dry=dry)
    open_issues = {i["title"]: i["number"] for i in json.loads(listed)} if listed else {}
    for out in sorted(results.glob("out-*")):
        key = out.name[len("out-"):]
        distro = NAMES.get(key, key)
        found = problems(out)
        current = set()
        for what, details in found:
            title = f"Early warning: {distro}: {what}"
            current.add(title)
            body = f"{details}\n\n### Versions on {distro}\n\n{versions(out)}\n"
            if prev and (prev / out.name / "contracts.json").exists():
                old = cdiff.load(prev / out.name / "contracts.json")
                new = cdiff.load(out / "contracts.json")
                if old and new:
                    body += "\n" + cdiff.diff(old, new).replace("### What changed outside SAM", "### What changed since the night before")
            body += "\n_Opened by the nightly early-warning run (.github/workflows/canary.yml). It closes itself when the problem is gone._\n"
            if title in open_issues:
                gh("issue", "edit", str(open_issues[title]), "--body", body, dry=dry)
            else:
                gh("issue", "create", "--title", title, "--label", LABEL, "--body", body, dry=dry)
        prefix = f"Early warning: {distro}: "
        for title, number in open_issues.items():
            if title.startswith(prefix) and title not in current:
                gh("issue", "close", str(number), "--comment", "Green again in the nightly early-warning run.", dry=dry)
        print(f"{distro}: {len(found)} problem(s)" + "".join(f"\n  - {w}" for w, _ in found))


if __name__ == "__main__":
    main()
