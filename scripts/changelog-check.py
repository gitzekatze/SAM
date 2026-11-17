#!/usr/bin/env python3
"""Flags a change to SAM's behaviour without a line in CHANGELOG.md (the
automation plan's section 10). It only flags: a GitHub warning on the pull
request and a line in the run's summary, never a failure, because a pure
refactor or a test needs no changelog line and only a person can tell.

    scripts/changelog-check.py [BASE]      (default origin/main)
    scripts/changelog-check.py --self-test

Behaviour is the code SAM ships: crates/*/src, data/, po/ (translations).
Tests, documents, scripts and workflows are not.
"""
import os
import subprocess
import sys


def shipped(path):
    parts = path.split("/")
    return (path.startswith("crates/") and len(parts) > 2 and parts[2] == "src") \
        or path.startswith("data/") or path.startswith("po/")


def verdict(files):
    """(behaviour files, a note written: a file in changes/ or CHANGELOG.md)."""
    note = "CHANGELOG.md" in files or any(f.startswith("changes/") and f != "changes/README.md" for f in files)
    return [f for f in files if shipped(f)], note


def self_test():
    cases = [
        (["crates/sam-runner/src/launch.rs"], True),
        (["crates/sam-runner/src/launch.rs", "CHANGELOG.md"], False),
        (["crates/sam-runner/src/launch.rs", "changes/stop-button.md"], False),
        (["crates/sam-runner/src/launch.rs", "changes/README.md"], True),
        (["crates/sam-runner/tests/stop.rs", "docs/testing.md"], False),
        (["po/de.po"], True),
        (["scripts/site.py", ".github/workflows/ci.yml"], False),
    ]
    for files, flagged in cases:
        code, log = verdict(files)
        got = bool(code) and not log
        assert got == flagged, (files, got)
    print(f"changelog check: {len(cases)}/{len(cases)} cases right")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return
    base = next((a for a in sys.argv[1:] if not a.startswith("-")), "origin/main")
    files = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"], capture_output=True,
                           text=True, check=True).stdout.split()
    code, log = verdict(files)
    if code and not log:
        print(f"::warning title=No changelog line::This change touches what SAM ships ({len(code)} file(s), "
              f"e.g. {code[0]}) but adds no note. If users notice it, describe it in a new file in changes/.")
        summary = (f"No note in changes/, though {len(code)} shipped file(s) changed "
                   f"(e.g. `{code[0]}`). Fine for a refactor; otherwise add one.")
    else:
        summary = "A note for the change list." if log else "Nothing SAM ships changed."
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    if out:
        with open(out, "a") as f:
            f.write(f"### Changelog\n\n{summary}\n")
    else:
        print(summary)


if __name__ == "__main__":
    main()
