#!/usr/bin/env python3
"""Runs SAM's test suite several times and compares each test's results.

    scripts/flaky-check.py [--runs N] [-- extra cargo test arguments]

A test that passes in one run and fails in another is *flaky*: its result
depends on timing or on other tests, not only on the code, so it gives no
reliable answer. Both flaky and failing tests make this script fail. The
results are written to target/test-results.json (scripts/push-summary.py
reads them).
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "target" / "test-results.json"
RUNNING = re.compile(r"^\s*Running (?:unittests )?(\S+) \(target/[^)]*/deps/([A-Za-z0-9_]+?)-[0-9a-f]+\)")
RESULT = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)")


def one_run(extra):
    """{(binary, test): result} for one full run of the suite."""
    p = subprocess.run(
        ["cargo", "test", "--workspace", "--locked", "--no-fail-fast", *extra],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    sys.stdout.write(p.stdout)
    results, binary = {}, "?"
    for line in p.stdout.splitlines():
        m = RUNNING.match(line)
        if m:
            binary = m.group(2)
            continue
        m = RESULT.match(line)
        if m:
            results[(binary, m.group(1))] = m.group(2)
    return results


def main():
    args = sys.argv[1:]
    extra = args[args.index("--") + 1:] if "--" in args else []
    runs = int(args[args.index("--runs") + 1]) if "--runs" in args else 2
    all_runs = []
    for i in range(runs):
        print(f"\n===== test run {i + 1} of {runs} =====\n", flush=True)
        all_runs.append(one_run(extra))
    keys = sorted(set().union(*all_runs))
    flaky, failed = [], []
    for k in keys:
        seen = {r.get(k, "missing") for r in all_runs}
        if seen == {"FAILED"}:
            failed.append(k)
        elif len(seen - {"ignored"}) > 1:
            flaky.append(k)
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({
        "runs": runs,
        "tests": [{"binary": b, "test": t.rsplit("::", 1)[-1], "path": t, "results": [r.get((b, t), "missing") for r in all_runs]} for b, t in keys],
        "flaky": [f"{b} {t}" for b, t in flaky],
        "failed": [f"{b} {t}" for b, t in failed],
    }, indent=1))
    print(f"\n{len(keys)} tests, {runs} runs: {len(failed)} failed every time, {len(flaky)} flaky")
    for b, t in flaky:
        print(f"  FLAKY  {b} {t}: " + ", ".join(r.get((b, t), "missing") for r in all_runs))
    for b, t in failed:
        print(f"  FAILED {b} {t}")
    if not keys:
        print("no test results were found in the output")
        sys.exit(1)
    sys.exit(1 if flaky or failed else 0)


if __name__ == "__main__":
    main()
