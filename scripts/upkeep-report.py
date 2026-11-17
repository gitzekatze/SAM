#!/usr/bin/env python3
"""Turns the weekly upkeep results (.github/workflows/upkeep.yml) into
GitHub issues, only when something was found, so a finding names its part of
SAM and nothing is reported twice:

  - "Weekly upkeep: changes no test notices": the mutation run on last
    week's code found changes that no test catches, listed by SAM function;
  - "Weekly upkeep: the mutation run is not true": the unchanged code failed
    a test, or a test never passed, so no change could be judged;
  - "Weekly upkeep: the fuzzer found a crash": an input crashed a parser;
  - "Weekly upkeep: <part> did not finish": a job ran out of time or broke.

An open issue is updated, not duplicated, and closes itself when its finding
is gone.

    scripts/upkeep-report.py RESULTS [--dry-run]

RESULTS holds mutants/ and fuzz/, each with `exit` (the exit code) and
`report.txt` (the output). A part without `exit` did not finish.
Needs the GitHub command line (gh) with a token that may write issues.
"""
import json
import pathlib
import subprocess
import sys

LABEL = "weekly-upkeep"
FOOTER = "\n\n_Opened by the weekly upkeep run (.github/workflows/upkeep.yml). It closes itself when the finding is gone._\n"


def read(part):
    """(exit code or None when the part did not finish, its report)."""
    code = part / "exit"
    text = (part / "report.txt").read_text(errors="replace") if (part / "report.txt").exists() else ""
    if not code.exists():
        return None, text
    return int(code.read_text().strip() or "1"), text


def findings(results):
    """{title: body} of what this week's run found."""
    found = {}
    code, text = read(results / "mutants")
    tail = "\n".join(text.splitlines()[-60:])
    if code is None:
        found["Weekly upkeep: the mutation run did not finish"] = (
            "The mutation run on last week's code stopped before its report (time limit or a broken setup).\n\n"
            f"```\n{tail}\n```")
    elif "NOT TRUE" in text or "unchanged code fails" in text:
        found["Weekly upkeep: the mutation run is not true"] = (
            "A test fails without any change, so no change could be judged. Make the named test pass on the "
            f"unchanged code first.\n\n```\n{tail}\n```")
    elif code != 0:
        found["Weekly upkeep: the mutation run did not finish"] = f"The mutation run ended with exit code {code}.\n\n```\n{tail}\n```"
    elif "missed (" in text and " 0 missed (" not in text:
        found["Weekly upkeep: changes no test notices"] = (
            "Last week's code has changes that no test catches. Each needs a test, or a written reason in "
            f"docs/reports, for the SAM function it belongs to.\n\n```\n{tail}\n```")
    code, text = read(results / "fuzz")
    tail = "\n".join(text.splitlines()[-60:])
    if code is None:
        found["Weekly upkeep: the long fuzz run did not finish"] = f"The long fuzz run stopped before its end.\n\n```\n{tail}\n```"
    elif code != 0:
        found["Weekly upkeep: the fuzzer found a crash"] = (
            "An input crashed a parser of untrusted data. The input is in the run's artifact "
            "(fuzz-crashes); turn it into a regression test.\n\n"
            f"```\n{tail}\n```")
    return found


def gh(*args, dry):
    if dry:
        print("  gh", " ".join(a if len(a) < 60 else a[:57] + "..." for a in args))
        return ""
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def main():
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    dry = "--dry-run" in sys.argv
    if not args:
        sys.exit(__doc__)
    found = findings(pathlib.Path(args[0]))
    gh("label", "create", LABEL, "--color", "FBCA04", "--force",
       "--description", "Found by the weekly mutation and fuzz run", dry=dry)
    listed = gh("issue", "list", "--label", LABEL, "--state", "open", "--limit", "100", "--json", "number,title", dry=dry)
    open_issues = {i["title"]: i["number"] for i in json.loads(listed)} if listed else {}
    for title, body in found.items():
        if title in open_issues:
            gh("issue", "edit", str(open_issues[title]), "--body", body + FOOTER, dry=dry)
        else:
            gh("issue", "create", "--title", title, "--label", LABEL, "--body", body + FOOTER, dry=dry)
    for title, number in open_issues.items():
        if title not in found:
            gh("issue", "close", str(number), "--comment", "Gone in this week's upkeep run.", dry=dry)
    print(f"{len(found)} finding(s)" + "".join(f"\n  - {t}" for t in found))


if __name__ == "__main__":
    main()
