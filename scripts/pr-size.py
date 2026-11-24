#!/usr/bin/env python3
"""Warns when a pull request changes more lines than one review can cover
well (about 800), so it gets split before it is merged. It only warns: a
GitHub warning on the pull request and a line in the run's summary, never a
failure; the person who merges decides.

    scripts/pr-size.py [BASE]      (default origin/main)
    scripts/pr-size.py --self-test

Counted are the lines added and removed in files people write; a deleted
file counts too, as its removal is reviewed. Files the repository's
scripts write in full are left out (test library, function map, contract
map, third-party licences, the development dashboard, reports, man pages,
translation files, Cargo.lock), as they grow with the change without
needing a review of their own. README.md and docs/trust.md are counted:
scripts/facts.py rewrites only a few numbers in them.
"""
import os
import subprocess
import sys

LIMIT = 800

GENERATED = {
    "docs/test-library.md",
    "docs/functions.md",
    "docs/contracts.md",
    "THIRD-PARTY-LICENSES.md",
    "DEVELOPMENT.md",
    "Cargo.lock",
}


def generated(path):
    return path in GENERATED or path.startswith("data/man/") or path.startswith("docs/reports/") \
        or (path.startswith("po/") and (path.endswith(".po") or path.endswith(".pot")))


def entries(numstat):
    """(added, removed, [paths]) from `git diff --numstat -z`: a renamed
    file has an empty path field, then its old and new path."""
    fields = numstat.split("\0")
    i = 0
    while i < len(fields) and fields[i]:
        added, removed, path = fields[i].split("\t", 2)
        if path:
            i += 1
            yield added, removed, [path]
        else:
            yield added, removed, fields[i + 1:i + 3]
            i += 3


def count(numstat):
    """(lines changed in written files, the largest of them) from `git diff --numstat -z`."""
    total, files = 0, []
    for added, removed, paths in entries(numstat):
        # "-": a binary file. A renamed file is generated if either name is.
        if added == "-" or any(generated(p) for p in paths):
            continue
        path = paths[-1]
        n = int(added) + int(removed)
        total += n
        files.append((n, path))
    files.sort(reverse=True)
    return total, files[:3]


def self_test():
    generated_files = sorted(GENERATED) + [
        "docs/reports/version-1.0.json", "data/man/sam-jail.1", "po/de.po", "po/sam.pot"]
    cases = [
        ("10\t2\tcrates/sam-core/src/util.rs", 12, False),
        ("700\t0\tcrates/sam-core/src/util.rs\x00200\t5\tdocs/test-library.md", 700, False),
        ("700\t101\tcrates/sam-core/src/util.rs", 801, True),
        ("800\t0\tcrates/a.rs", 800, False),
        ("400\t0\tcrates/a.rs\x00401\t0\tREADME.md", 801, True),
        ("0\t900\tcrates/old.rs", 900, True),
        ("-\t-\tdata/icons/sam.png", 0, False),
        ("5\t1\t\x00crates/a.rs\x00crates/b.rs\x003\t0\tdocs/trust.md", 9, False),
        ("900\t0\t\x00docs/functions.md\x00docs/f.md", 0, False),
        ("2\t0\tpo/notes.txt", 2, False),
    ] + [(f"900\t900\t{f}", 0, False) for f in generated_files]
    for numstat, want, warned in cases:
        got, _ = count(numstat + "\x00")
        assert got == want, (numstat, got)
        assert (got > LIMIT) == warned, (numstat, got)
    print(f"pr size: {len(cases)}/{len(cases)} cases right")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return
    base = next((a for a in sys.argv[1:] if not a.startswith("-")), "origin/main")
    numstat = subprocess.run(["git", "diff", "--numstat", "-z", f"{base}...HEAD"], capture_output=True,
                             text=True, check=True).stdout
    total, largest = count(numstat)
    biggest = ", ".join(f"`{p}` ({n})" for n, p in largest)
    if total > LIMIT:
        print(f"::warning title=Large pull request::{total} lines changed in written files "
              f"(more than {LIMIT}); one review covers this badly. Consider splitting it. "
              f"Largest: {biggest}.")
        summary = (f"{total} lines changed in written files, more than {LIMIT}. "
                   f"Consider splitting it. Largest: {biggest}.")
    else:
        summary = f"{total} lines changed in written files (warning above {LIMIT})."
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    if out:
        with open(out, "a") as f:
            f.write(f"### Size\n\n{summary}\n")
    else:
        print(summary)


if __name__ == "__main__":
    main()
