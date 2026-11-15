#!/usr/bin/env python3
"""The summary of a change, for the CI run page: which of SAM's functions
the changed files touch, and how their tests did.

    scripts/push-summary.py BASE [HEAD]

BASE and HEAD are commits (HEAD defaults to the current one). The touched
functions come from docs/functions.toml (scripts/function-map.py), the
results from target/test-results.json (scripts/flaky-check.py). The
summary goes to $GITHUB_STEP_SUMMARY when set, otherwise to the terminal.
"""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location("function_map", ROOT / "scripts" / "function-map.py")
fmap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fmap)


def changed_files(base, head):
    p = subprocess.run(["git", "diff", "--name-only", f"{base}..{head}"], cwd=ROOT, text=True, capture_output=True)
    if p.returncode != 0:
        return None
    return [l for l in p.stdout.splitlines() if l]


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "HEAD~1"
    head = sys.argv[2] if len(sys.argv) > 2 else "HEAD"
    m = tomllib.loads(fmap.MAP.read_text())
    files = changed_files(base, head)
    res_file = ROOT / "target" / "test-results.json"
    res = json.loads(res_file.read_text()) if res_file.exists() else {"tests": [], "flaky": [], "failed": [], "runs": 0}
    by_name = {}
    for t in res["tests"]:
        by_name.setdefault(t["test"], []).append(t["results"])

    def state(name):
        rs = by_name.get(name)
        if not rs:
            return "–"
        flat = [x for r in rs for x in r]
        if all(x == "ok" for x in flat):
            return "✅"
        if all(x == "FAILED" for x in flat):
            return "❌"
        return "⚠️ flaky"

    L = ["## What this change touches", ""]
    if files is None:
        L += ["The changed files could not be determined (a new branch or a rewritten history), so every function is listed below.", ""]
        hit = m["function"]
    else:
        L += [f"{len(files)} changed files."]
        hit = fmap.touched(m, files)
    total = len(res["tests"])
    L += [
        f"Tests: {total} ran {res['runs']} times; {len(res['failed'])} failed, {len(res['flaky'])} gave different results between runs (flaky).",
        "",
    ]
    if not hit:
        L += ["No function of SAM is touched: the change is outside the code the function map names (documentation, scripts or CI).", ""]
    else:
        L += ["| Function | Its tests |", "|---|---|"]
        for f in hit:
            tests = f.get("tests", [])
            states = [state(t) for t in tests]
            if f.get("gap"):
                summary = "⚠️ gap: " + f["gap"].split(".")[0]
            elif not tests:
                summary = "no tests"
            elif all(s == "✅" for s in states):
                summary = "✅ its 1 test passes" if len(tests) == 1 else f"✅ all {len(tests)} pass"
            else:
                bad = [f"{t} {s}" for t, s in zip(tests, states) if s != "✅"]
                summary = "; ".join(bad)
            L.append(f"| {f['id']}. {f['promise']} | {summary} |")
        L.append("")
    for kind in ("flaky", "failed"):
        if res[kind]:
            L += [f"**{kind.capitalize()} tests:** " + ", ".join(f"`{t}`" for t in res[kind]), ""]
    text = "\n".join(L)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a") as fh:
            fh.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
