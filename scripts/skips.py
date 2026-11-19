#!/usr/bin/env python3
"""Says which tests did not run, from the skip log `make test` and CI collect
($SAM_SKIP_LOG, one line per skipped test: "test: reason").

    python3 scripts/skips.py [LOG]
    python3 scripts/skips.py LOG --job NAME    (CI: Markdown for the job summary)
    python3 scripts/skips.py --self-test

With --job, the tests that said "not here" are compared with the list for
that job in tests/expected-not-here.toml. A test missing from the list fails
the job: a proof that stopped running on a CI machine would otherwise pass
without anyone seeing it (verification audit 2026-11-19). A listed test that
ran after all is only named, so the list can be shortened.
"""
import pathlib
import sys
import tomllib
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "tests" / "expected-not-here.toml"


def entries(lines):
    """[(test, reason)] from the log's lines."""
    out = []
    for line in lines:
        test, sep, reason = line.partition(": ")
        out.append((test.strip(), reason.strip()) if sep else (line.strip(), ""))
    return out


def judge(lines, expected):
    """(Markdown lines, whether the job passes) for one job's skip log."""
    seen = Counter(entries(lines))
    md, ok = ["### Tests that did not run on this machine", ""], True
    if not seen:
        md.append("Every test ran.")
    else:
        md += ["| Test | Why | Agreed |", "|---|---|---|"]
    for (test, reason), n in sorted(seen.items()):
        agreed = reason.startswith("not here:") and test in expected
        ok &= agreed
        times = f" ({n}×)" if n > 1 else ""
        md.append(f"| `{test}`{times} | {reason} | {'yes' if agreed else '**no**'} |")
    ran = sorted(set(expected) - {t for t, _ in seen})
    if ran:
        md += ["", "Ran here although listed as not here (the list in "
               "tests/expected-not-here.toml can lose them):"]
        md += [f"- `{t}`" for t in ran]
    if not ok:
        md += ["", "**A test did not run that should have.** Either the machine "
               "lacks something it had before (fix the job), or the test really "
               "cannot run here: then add it with the reason to "
               "tests/expected-not-here.toml, which needs the owner."]
    return md, ok


def self_test():
    exp = {"a": "pasta too old"}
    cases = [
        ("nothing skipped", [], True),
        ("an agreed not here", ["a: not here: no pasta"], True),
        ("the same twice (two runs)", ["a: not here: no pasta"] * 2, True),
        ("a new not here", ["b: not here: no pasta"], False),
        ("an agreed test, but skipped", ["a: no bubblewrap"], False),
        ("a line without a reason", ["a"], False),
    ]
    bad = 0
    for name, lines, want in cases:
        md, ok = judge(lines, exp)
        if ok != want:
            bad += 1
            print(f"WRONG {name}: {ok}\n" + "\n".join(md))
    md, _ = judge([], exp)
    if not any("`a`" in line for line in md):
        bad += 1
        print("WRONG a listed test that ran is not named")
    jobs = tomllib.loads(EXPECTED.read_text())
    if not all(isinstance(v, dict) and all(isinstance(r, str) and r for r in v.values()) for v in jobs.values()):
        bad += 1
        print("WRONG tests/expected-not-here.toml: every entry needs a reason")
    print(f"{len(cases) + 2 - bad} of {len(cases) + 2} cases right")
    sys.exit(1 if bad else 0)


def main():
    args = sys.argv[1:]
    if args[:1] == ["--self-test"]:
        self_test()
    job = args[args.index("--job") + 1] if "--job" in args else None
    rest = [a for i, a in enumerate(args) if a != "--job" and (i == 0 or args[i - 1] != "--job")]
    path = pathlib.Path(rest[0]) if rest else ROOT / "target" / "test-skips.log"
    lines = [line for line in path.read_text().splitlines() if line.strip()] if path.exists() else []
    if job:
        jobs = tomllib.loads(EXPECTED.read_text())
        if job not in jobs:
            print(f"no list for the job {job!r} in {EXPECTED.relative_to(ROOT)}")
            sys.exit(1)
        md, ok = judge(lines, jobs[job])
        print("\n".join(md))
        sys.exit(0 if ok else 1)
    if not lines:
        print("Every test ran.")
        sys.exit(0)
    print(f"{len(lines)} tests did not run here (they pass without checking anything):")
    for line, n in sorted(Counter(lines).items()):
        print(f"  {line}" + (f"  ({n}×)" if n > 1 else ""))
    print("CI runs them with SAM_REQUIRE_SANDBOX=1, where a test that cannot run fails.")


if __name__ == "__main__":
    main()
