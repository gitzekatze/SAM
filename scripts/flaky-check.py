#!/usr/bin/env python3
"""Runs SAM's test suite several times and compares each test's results.

    scripts/flaky-check.py [--runs N] [-- extra cargo test arguments]

A test that passes in one run and fails in another is *flaky*: its result
depends on timing or on other tests, not only on the code, so it gives no
reliable answer. Both flaky and failing tests make this script fail. So
does a test program that stops before its "test result" line (a crash, an
abort, a kill) and a cargo run that ends in an error without any failed
test (a build error, a crash after the last test): the per-test lines alone
would look green. The results are written to target/test-results.json
(scripts/push-summary.py reads them).

    scripts/flaky-check.py --self-test   checks the output reading
"""
import contextlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "target" / "test-results.json"
# The program's path in brackets: target/debug/deps/NAME-HASH (older cargo)
# or target/debug/build/PACKAGE/HASH/out/NAME-HASH (cargo 1.9x and later).
RUNNING = re.compile(r"^\s*Running (?:unittests )?(\S+) \((?:[^)]*/)?([A-Za-z0-9_]+?)-[0-9a-f]{16}\)")
RESULT = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)")
DOCTESTS = re.compile(r"^\s*Doc-tests (\S+)")
SUMMARY = re.compile(r"^test result: ")


def read_output(out, status):
    """({(binary, test): result}, [problems]) from one run's output.

    A problem is a test program that started but never printed its
    "test result" line, or a non-zero exit with no failed test to explain it.
    """
    results, problems, binary, open_ = {}, [], "?", None
    for line in out.splitlines():
        m = RUNNING.match(line) or DOCTESTS.match(line)
        if m:
            if open_:
                problems.append(f"{open_} stopped before its test result line")
            binary = m.group(2) if m.re is RUNNING else f"doc-{m.group(1)}"
            open_ = m.group(1) if m.re is RUNNING else f"Doc-tests {m.group(1)}"
            continue
        if SUMMARY.match(line):
            open_ = None
            continue
        m = RESULT.match(line)
        if m:
            results[(binary, m.group(1))] = m.group(2)
    if open_:
        problems.append(f"{open_} stopped before its test result line")
    if status != 0 and "FAILED" not in results.values() and not problems:
        problems.append(f"cargo test ended with status {status} but no test failed")
    return results, problems


def one_run(extra):
    """read_output() for one full run of the suite."""
    p = subprocess.run(
        ["cargo", "test", "--workspace", "--locked", "--no-fail-fast", *extra],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    sys.stdout.write(p.stdout)
    return read_output(p.stdout, p.returncode)


def judge(all_runs, problems):
    """(keys, flaky, failed, exit status) for the runs' results."""
    keys = sorted(set().union(*all_runs))
    flaky, failed = [], []
    for k in keys:
        seen = {r.get(k, "missing") for r in all_runs}
        if seen == {"FAILED"}:
            failed.append(k)
        elif len(seen - {"ignored"}) > 1:
            flaky.append(k)
    status = 1 if flaky or failed or problems or not keys else 0
    return keys, flaky, failed, status


def self_test():
    """Feeds made-up cargo output through read_output() and judge()."""
    head = "     Running tests/a.rs (target/debug/build/sam-core/0123456789abcdef/out/a-0123456789abcdef)\nrunning 2 tests\n"
    good = head + "test one ... ok\ntest two ... ok\ntest result: ok. 2 passed\n"
    other = good.replace("/a.rs", "/b.rs").replace("/a-", "/b-")
    # (name, output, cargo's status, number of results, the problems found
    # by their start, exit status of the whole run)
    cases = [
        ("all pass", good, 0, 2, [], 0),
        ("a test fails", head + "test one ... ok\ntest two ... FAILED\ntest result: FAILED.\n", 101, 2, [], 1),
        ("crash mid-run", head + "test one ... ok\nerror: test failed\n  process didn't exit successfully (signal: 11, SIGSEGV)\n", 101, 1, ["tests/a.rs stopped"], 1),
        ("crash, then the next program", head + "test one ... ok\n" + other, 101, 3, ["tests/a.rs stopped"], 1),
        ("crash in a run that says success", head + "test one ... ok\n", 0, 1, ["tests/a.rs stopped"], 1),
        ("error, no failed test", good, 101, 2, ["cargo test ended"], 1),
        ("build error, nothing ran", "error[E0425]: cannot find value\n", 101, 0, ["cargo test ended"], 1),
        ("nothing ran at all", "", 0, 0, [], 1),
        ("doc tests summed up", good + "   Doc-tests sam_core\nrunning 0 tests\ntest result: ok. 0 passed\n", 0, 2, [], 0),
        ("doc tests cut off", good + "   Doc-tests sam_core\nrunning 1 test\n", 0, 2, ["Doc-tests sam_core stopped"], 1),
        ("same test name in two programs", good + other, 0, 4, [], 0),
        ("older cargo layout", good.replace("build/sam-core/0123456789abcdef/out/", "deps/"), 0, 2, [], 0),
    ]
    bad = 0
    for name, out, status, n_results, starts, exit_status in cases:
        results, problems = read_output(out, status)
        got = judge([results], problems)[3]
        if (len(results), len(problems), got) != (n_results, len(starts), exit_status) or not all(
            p.startswith(s) for p, s in zip(problems, starts)
        ):
            bad += 1
            print(f"WRONG {name}: {len(results)} results, problems {problems}, exit {got}")
    # Across runs: passing once and failing once is flaky, failing every time
    # is failed, and a test missing from a run counts as a difference.
    ok, fail = {("a", "t"): "ok"}, {("a", "t"): "FAILED"}
    for name, runs, want in [
        ("flaky", [ok, fail], (1, 0, 1)),
        ("failed both times", [fail, fail], (0, 1, 1)),
        ("missing in one run", [ok, {("a", "u"): "ok"}], (2, 0, 1)),
        ("ignored once", [ok, {("a", "t"): "ignored"}], (0, 0, 0)),
    ]:
        cases.append(name)
        _, flaky, failed, got = judge(runs, [])
        if (len(flaky), len(failed), got) != want:
            bad += 1
            print(f"WRONG {name}: {len(flaky)} flaky, {len(failed)} failed, exit {got}")
    # The whole script, with a crash in the run instead of cargo.
    cases.append("the script's own exit status")
    global OUT
    real_run, real_out, real_argv = globals()["one_run"], OUT, sys.argv
    globals()["one_run"] = lambda extra: read_output(head + "test one ... ok\n", 0)
    OUT, sys.argv = pathlib.Path(tempfile.mkdtemp()) / "results.json", ["flaky-check.py", "--runs", "1"]
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            main()
        got = 0
    except SystemExit as e:
        got = e.code
    finally:
        globals()["one_run"], OUT, sys.argv = real_run, real_out, real_argv
    if got != 1:
        bad += 1
        print(f"WRONG the script's own exit status: {got} after a crash")
    print(f"{len(cases) - bad} of {len(cases)} cases right")
    sys.exit(1 if bad else 0)


def main():
    args = sys.argv[1:]
    if args[:1] == ["--self-test"]:
        self_test()
    extra = args[args.index("--") + 1:] if "--" in args else []
    runs = int(args[args.index("--runs") + 1]) if "--runs" in args else 2
    all_runs, problems = [], []
    for i in range(runs):
        print(f"\n===== test run {i + 1} of {runs} =====\n", flush=True)
        results, trouble = one_run(extra)
        all_runs.append(results)
        problems += [f"run {i + 1}: {p}" for p in trouble]
    keys, flaky, failed, status = judge(all_runs, problems)
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({
        "runs": runs,
        "tests": [{"binary": b, "test": t.rsplit("::", 1)[-1], "path": t, "results": [r.get((b, t), "missing") for r in all_runs]} for b, t in keys],
        "flaky": [f"{b} {t}" for b, t in flaky],
        "failed": [f"{b} {t}" for b, t in failed],
        "problems": problems,
    }, indent=1))
    print(f"\n{len(keys)} tests, {runs} runs: {len(failed)} failed every time, {len(flaky)} flaky")
    for b, t in flaky:
        print(f"  FLAKY  {b} {t}: " + ", ".join(r.get((b, t), "missing") for r in all_runs))
    for b, t in failed:
        print(f"  FAILED {b} {t}")
    for p in problems:
        print(f"  BROKEN {p}")
    if not keys:
        print("no test results were found in the output")
    sys.exit(status)


if __name__ == "__main__":
    main()
