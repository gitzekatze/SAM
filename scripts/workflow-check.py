#!/usr/bin/env python3
"""Refuses the two known ways a GitHub workflow hands an attacker the
repository (AUTOMATION.md):

1. `pull_request_target` together with a checkout of the pull request's
   code: the workflow runs foreign code with the repository's secrets.
2. Text from issues, pull requests or comments (titles, bodies, branch
   names) written straight into a `run:` command with ${{ ... }}: the text
   becomes shell code. Such fields go through `env:` instead.

    scripts/workflow-check.py              check .github/workflows/
    scripts/workflow-check.py --self-test  check the rules on made-up workflows
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)"
    r"[^}]*\.(title|body|name|label|message|head_ref|ref|email)|head_ref)\s*\}\}")


def problems(name, text):
    errs = []
    if "pull_request_target" in text and re.search(
            r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", text):
        errs.append(f"{name}: pull_request_target checks out the pull request's code")
    in_run, indent = False, 0
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        cur = len(line) - len(stripped)
        if re.match(r"(- )?run:", stripped):
            in_run, indent = True, cur
            body = stripped.split("run:", 1)[1]
        elif in_run and stripped and cur <= indent:
            in_run = False
            body = ""
        else:
            body = line if in_run else ""
        if body and UNTRUSTED.search(body):
            errs.append(f"{name}:{n}: untrusted text inline in a run command; pass it through env:")
    return errs


def self_test():
    bad_target = "on: pull_request_target\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    bad_inline = "jobs:\n  x:\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\"\n"
    good_env = "jobs:\n  x:\n    steps:\n      - env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n"
    good_number = "jobs:\n  x:\n    steps:\n      - run: echo ${{ github.event.issue.number }}\n"
    cases = [(bad_target, 1), (bad_inline, 1), (good_env, 0), (good_number, 0)]
    wrong = [i for i, (t, want) in enumerate(cases) if len(problems(f"case{i}", t)) != want]
    print(f"workflow-check self-test: {len(cases) - len(wrong)} of {len(cases)} right")
    sys.exit(1 if wrong else 0)


def main():
    if "--self-test" in sys.argv:
        self_test()
    errs = []
    for f in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        errs += problems(str(f.relative_to(ROOT)), f.read_text())
    for e in errs:
        print(" ", e)
    print("workflows ok" if not errs else "Unsafe workflow patterns found.")
    sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
