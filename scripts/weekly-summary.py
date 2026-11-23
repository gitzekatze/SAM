#!/usr/bin/env python3
"""The weekly summary (AUTOMATION.md; the automation plan's section 8): one
GitHub issue, labelled "weekly-summary", updated every week instead of a new
one, so the owner sees in one place how SAM's upkeep stands:

  - what needs the owner, at the top (or "Nothing");
  - mutation testing of last week's code, by SAM function;
  - the long fuzz run;
  - whether the generated pages still match the code;
  - pull requests: open ones, and merges and reverts of the week;
  - the outside world: open early-warning and upstream-change issues;
  - the contract coverage; the kill switch.

When something needs the owner, a short comment is added too, so GitHub
notifies them; a quiet week only updates the issue. No AI is involved:
everything here is read from files, git and GitHub.

    scripts/weekly-summary.py RESULTS [--dry-run]

RESULTS holds mutants/ and fuzz/ (each `exit` and `report.txt`; no `exit`
means the part did not finish) and drift.txt (the generated pages that
differ, one per line; empty when none). Needs gh with a token that may
write issues, except with --dry-run.
"""
import datetime
import json
import os
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
LABEL = "weekly-summary"
TITLE = "Weekly summary"


def gh(*args, dry, read=False):
    """Runs gh; with --dry-run, reading still happens when gh works here."""
    if dry and not read:
        print("  gh", " ".join(a if len(a) < 60 else a[:57] + "..." for a in args))
        return ""
    r = subprocess.run(["gh", *args], check=False, capture_output=True, text=True)
    if r.returncode != 0:
        if dry:
            return ""
        raise SystemExit(f"gh {' '.join(args[:2])} failed: {r.stderr.strip()}")
    return r.stdout


def part(results, name):
    """(exit code or None when it did not finish, its report)."""
    d = results / name
    text = (d / "report.txt").read_text(errors="replace") if (d / "report.txt").exists() else ""
    code = (d / "exit").read_text().strip() if (d / "exit").exists() else None
    return (int(code or "1") if code is not None else None), text


def tail(text, n):
    lines = [l for l in text.splitlines() if l.strip()]
    return "\n".join(lines[-n:]) or "(no output)"


def mutation(results, attention):
    code, text = part(results, "mutants")
    if code is None:
        attention.append("The mutation run did not finish (time limit or a broken setup).")
        state = "did not finish"
    elif "NOT TRUE" in text or "unchanged code fails" in text:
        attention.append("The mutation run is not true: a test fails without any change. Make it pass first.")
        state = "not true"
    elif code != 0:
        attention.append(f"The mutation run ended with exit code {code}.")
        state = f"exit {code}"
    elif "No Rust code changed" in text:
        state = "no Rust code changed this week"
    elif "missed (" in text and " 0 missed (" not in text:
        attention.append("Last week's code has changes no test notices (each needs a test or a written reason).")
        state = "changes no test notices"
    else:
        state = "every change caught"
    return f"**{state}**\n\n```\n{tail(text, 40)}\n```"


def fuzz(results, attention):
    code, text = part(results, "fuzz")
    if code is None:
        attention.append("The long fuzz run did not finish.")
        state = "did not finish"
    elif code != 0:
        attention.append("The fuzzer found an input that crashes a parser (the input is in the run's artifact fuzz-crashes; make it a regression test).")
        state = "a crash"
    else:
        state = "no crash"
    first = text.splitlines()[0] if text.strip() else ""
    return f"**{state}** {first}\n\n```\n{tail(text, 12)}\n```"


def drift(results, attention):
    f = results / "drift.txt"
    if not f.exists():
        return "not checked"
    files = [l for l in f.read_text().splitlines() if l.strip()]
    if not files:
        return "up to date"
    attention.append("Generated pages no longer match the code: " + ", ".join(files) + " (run the generators, see CONTRIBUTING).")
    return "out of date: " + ", ".join(f"`{x}`" for x in files)


def pulls(dry):
    week_ago = (datetime.date.today() - datetime.timedelta(days=7)).isoformat()
    opened = json.loads(gh("pr", "list", "--state", "open", "--limit", "50", "--json", "number,title,author",
                           dry=dry, read=True) or "[]")
    merged = json.loads(gh("pr", "list", "--state", "merged", "--search", f"merged:>={week_ago}", "--limit", "50",
                           "--json", "number,title", dry=dry, read=True) or "[]")
    out = [f"Open: {len(opened)}"]
    out += [f"- #{p['number']} {p['title']} ({p['author']['login']})" for p in opened]
    out += [f"\nMerged in the last 7 days: {len(merged)}"]
    out += [f"- #{p['number']} {p['title']}" for p in merged]
    reverts = subprocess.run(["git", "-C", str(ROOT), "log", "--since=7.days", "--oneline", "--grep=^Revert"],
                             check=False, capture_output=True, text=True).stdout.strip()
    out += ["\nReverts on main in the last 7 days: " + (str(len(reverts.splitlines())) if reverts else "none")]
    return "\n".join(out)


def outside(attention, dry):
    lines = []
    for label, what in [("early-warning", "Early warning (upcoming distributions)"), ("upstream-change", "Upstream watch")]:
        issues = json.loads(gh("issue", "list", "--label", label, "--state", "open", "--limit", "50",
                               "--json", "number,title", dry=dry, read=True) or "[]")
        lines.append(f"{what}: {len(issues)} open" + "".join(f"\n- #{i['number']} {i['title']}" for i in issues))
        if issues:
            attention.append(f"{len(issues)} open {label} issue(s).")
    return "\n".join(lines)


def contracts():
    cs = tomllib.loads((ROOT / "docs/contracts.toml").read_text()).get("contract", [])
    full = sum(1 for c in cs if c.get("coverage") == "full")
    return f"{len(cs)} contracts: {full} fully tested, {len(cs) - full} partly (docs/contracts.md)"


def body(results, dry):
    attention = []
    week = datetime.date.today().isocalendar()
    sections = [
        ("Mutation testing of last week's code", mutation(results, attention)),
        ("Long fuzz run", fuzz(results, attention)),
        ("Generated pages", drift(results, attention)),
        ("Pull requests", pulls(dry)),
        ("The outside world", outside(attention, dry)),
        ("Contracts", contracts()),
        ("Kill switch", f"`SAM_AUTOMATION` = `{os.environ.get('SAM_AUTOMATION') or 'not set (like proposals)'}`"),
    ]
    text = f"# Week {week[1]} of {week[0]}\n\n## Needs your attention\n\n"
    text += "\n".join(f"- {a}" for a in attention) if attention else "Nothing."
    for title, content in sections:
        text += f"\n\n## {title}\n\n{content}"
    text += ("\n\n_Updated every week by .github/workflows/upkeep.yml (scripts/weekly-summary.py). "
             "Not collected yet: flaky tests and automation spending (they come with the proposal jobs after the beta)._\n")
    return text, attention


def main():
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    dry = "--dry-run" in sys.argv
    if not args:
        sys.exit(__doc__)
    text, attention = body(pathlib.Path(args[0]), dry)
    if dry:
        print(text)
    gh("label", "create", LABEL, "--color", "0E8A16", "--force",
       "--description", "SAM's weekly upkeep summary, updated every week", dry=dry)
    listed = gh("issue", "list", "--label", LABEL, "--state", "open", "--limit", "5", "--json", "number", dry=dry)
    existing = [i["number"] for i in json.loads(listed)] if listed else []
    if existing:
        gh("issue", "edit", str(existing[0]), "--body", text, dry=dry)
        number = str(existing[0])
    else:
        out = gh("issue", "create", "--title", TITLE, "--label", LABEL, "--body", text, dry=dry)
        number = out.strip().rsplit("/", 1)[-1] if out else "?"
    if attention:
        gh("issue", "comment", number, "--body",
           "This week needs your attention:\n\n" + "\n".join(f"- {a}" for a in attention), dry=dry)
    print(f"weekly summary: {len(attention)} item(s) need attention")


if __name__ == "__main__":
    main()
