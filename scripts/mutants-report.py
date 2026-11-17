#!/usr/bin/env python3
"""The result of a mutation run, by SAM function: which promises have
changes that no test notices (a gear without a warning light).

    python3 scripts/mutants-report.py MUTANTS_OUT [--markdown]

MUTANTS_OUT is cargo-mutants' output folder (with outcomes.json). Each
missed change is assigned to the functions whose code is in its file
(docs/functions.toml, `code`), so the report says "function 20 (the sandbox
check): 3 changes no test notices" instead of a file name.

It also refuses a result that cannot be true: a test that never passed in
any change's log fails without a change too, so its catches mean nothing.
"""
import json
import pathlib
import re
import sys
import tomllib
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent


def never_passed(out, data):
    """The tests that failed in several change logs and passed in none: such a
    test fails without any change too, and every change it "caught" means
    nothing. cargo-mutants' own baseline cannot run SAM's whole suite
    (scripts/mutants.sh), so this check stands in for it."""
    failed, passed = {}, set()
    for o in data.get("outcomes", []):
        log = out / (o.get("log_path") or "-")
        if not log.is_file():
            continue
        text = log.read_text(errors="replace")
        for name in re.findall(r"^test (\S+) \.\.\. FAILED$", text, re.M):
            failed[name] = failed.get(name, 0) + 1
        passed.update(re.findall(r"^test (\S+) \.\.\. ok$", text, re.M))
    return sorted(t for t, n in failed.items() if n >= 5 and t not in passed)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        sys.exit(__doc__)
    out = pathlib.Path(args[0])
    out = out / "mutants.out" if (out / "mutants.out").is_dir() else out
    data = json.loads((out / "outcomes.json").read_text())
    funcs = tomllib.loads((ROOT / "docs/functions.toml").read_text())["function"]
    by_file = defaultdict(list)
    for f in funcs:
        for c in f.get("code", []):
            by_file["crates/" + c].append(f)
    counts = defaultdict(int)
    missed = defaultdict(list)
    unmapped = []
    for o in data.get("outcomes", []):
        m = o.get("scenario", {})
        if not isinstance(m, dict) or "Mutant" not in m:
            continue
        mutant = m["Mutant"]
        summary = o.get("summary")
        counts[summary] += 1
        if summary != "MissedMutant":
            continue
        where = f"{mutant['file']}:{((mutant.get('span') or {}).get('start') or {}).get('line', '?')}"
        func = (mutant.get("function") or {}).get("function_name", "?")
        what = f"{where}: {mutant.get('replacement') or mutant.get('genre', '')} in {func}"
        owners = by_file.get(mutant["file"], [])
        if not owners:
            unmapped.append(what)
        for f in owners:
            missed[f["id"]].append(what)
    caught = counts["CaughtMutant"] + counts["Timeout"]
    buildable = caught + counts["MissedMutant"]
    md = "--markdown" in sys.argv
    lines = []
    total = sum(counts.values())
    pct = f"{100 * caught / buildable:.1f} %" if buildable else "n/a"
    lines.append(f"{total} changes: {counts['CaughtMutant']} caught by a test, {counts['Timeout']} by a timeout, "
                 f"{counts['Unviable']} not buildable, {counts['MissedMutant']} missed ({pct} of the buildable caught).")
    lines.append("")
    if md:
        lines += ["| Function | Missed | Example |", "|---|---|---|"]
    for f in sorted(funcs, key=lambda f: -len(missed[f["id"]])):
        n = len(missed[f["id"]])
        if not n:
            continue
        promise = f["promise"][:70] + ("…" if len(f["promise"]) > 70 else "")
        if md:
            lines.append(f"| {f['id']}. {promise} | {n} | `{missed[f['id']][0]}` |")
        else:
            lines.append(f"function {f['id']} ({promise}): {n} missed")
            lines += [f"    {w}" for w in missed[f["id"]][:5]]
    if not any(missed.values()):
        lines.append("No function has a change that the tests miss.")
    if unmapped:
        lines += ["", f"{len(unmapped)} missed changes are in files no function names (docs/functions.toml `code`):"]
        lines += [f"    {w}" for w in unmapped[:10]]
    broken = never_passed(out, data)
    if broken:
        lines = [f"NOT TRUE: {', '.join(broken)} never passed in this run, so it fails without any",
                 "change too and the changes it caught mean nothing. Make it pass on the unchanged code, then run again.",
                 ""] + lines
    print("\n".join(lines))
    if broken:
        sys.exit(1)


if __name__ == "__main__":
    main()
