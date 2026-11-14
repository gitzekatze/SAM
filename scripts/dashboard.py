#!/usr/bin/env python3
"""Writes DEVELOPMENT.md, the development dashboard: the current state of
SAM (CI, the latest version report), every test grouped by part, the
history of version reports, and the latest commits.

    scripts/dashboard.py

It is regenerated with every version report (scripts/version-report.py
calls it), so it shows the state at the end of the last phase of work.
"""
import datetime
import importlib.util
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPO = "https://github.com/gitzekatze/SAM"

# The test library's parser, to list the same tests with the same promises.
spec = importlib.util.spec_from_file_location("test_library", ROOT / "scripts" / "test-library.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True).stdout.strip()


def reports():
    out = []
    for p in (ROOT / "docs" / "reports").glob("*.json"):
        try:
            r = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        out.append((r.get("generated", ""), p, r))
    return [(p, r) for _, p, r in sorted(out, key=lambda x: x[0])]


def test_counts(r):
    tests = [t for t in r.get("tests", []) if "test" in t]
    return sum(t["result"] == "ok" for t in tests), sum(t["result"] == "FAILED" for t in tests)


def kind_of(path: pathlib.Path) -> str:
    return "integration" if "/tests/" in str(path) else "unit"


def main():
    version = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
    L = [
        "# SAM development dashboard",
        "",
        "The state of SAM for people who work on it: tests, results, history.",
        "For users, the front page is [README.md](README.md).",
        f"Generated {datetime.datetime.now().isoformat(timespec='minutes')} by `scripts/dashboard.py`",
        "(with every version report, `make report`).",
        "",
        "## Current state",
        "",
        f"[![CI]({REPO}/actions/workflows/ci.yml/badge.svg)]({REPO}/actions/workflows/ci.yml)",
        "",
        f"- **Version:** {version} (the number changes only when a version is published).",
        f"- **Latest commit:** `{git('log', '-1', '--format=%h %s')}`.",
    ]
    reps = reports()
    if reps:
        p, r = reps[-1]
        ok, failed = test_counts(r)
        L += [
            f"- **Latest version report:** [{p.stem}](docs/reports/{p.stem}.md), {r.get('generated', '')}:"
            f" {ok} tests pass, {failed} fail.",
            "",
            "| Part | Tests passing | Failing | Line coverage |",
            "|---|---|---|---|",
        ]
        by = {}
        for t in r.get("tests", []):
            if "test" in t:
                b = by.setdefault(t["part"], [0, 0])
                b[0 if t["result"] == "ok" else 1] += t["result"] in ("ok", "FAILED")
        for part in lib.PARTS:
            b = by.get(part, [0, 0])
            cov = r.get("coverage", {}).get(part, {})
            L.append(f"| {part} | {b[0]} | {b[1]} | {str(cov['percent']) + ' %' if cov else 'not measured'} |")
        if r.get("bench"):
            L += ["", "| Step | Fastest run |", "|---|---|"]
            for m in r["bench"]:
                v = m.get("best_ms", m.get("median_ms"))
                L.append(f"| {m['what']} | {f'{v:.3f} ms' if v is not None else 'not measured'} |")
    L += [
        "",
        "Line coverage is a gap finder, not a score: it shows code that no test runs.",
        "",
        "## Tests",
        "",
        "Every test keeps one promise, stated in a complete sentence; ⟲ marks a",
        "regression test, which guards against a bug that happened. The same list",
        "with links to the code is the [test library](docs/test-library.md).",
        "",
        "| Part | Unit tests | Integration tests | Regression tests | Total |",
        "|---|---|---|---|---|",
    ]
    all_rows = {}
    totals = [0, 0, 0]
    for part, what in lib.PARTS.items():
        rows = []
        for f in sorted((ROOT / "crates" / part).rglob("*.rs")):
            for name, promise, line, reg in lib.tests_in(f):
                rows.append((kind_of(f), reg, name, promise, f.relative_to(ROOT), line))
        if not rows:
            continue
        all_rows[part] = (what, rows)
        u = sum(k == "unit" for k, *_ in rows)
        i = sum(k == "integration" for k, *_ in rows)
        g = sum(1 for _, reg, *_ in rows if reg)
        totals = [totals[0] + u, totals[1] + i, totals[2] + g]
        L.append(f"| {part} | {u} | {i} | {g} | {len(rows)} |")
    L.append(f"| **all** | **{totals[0]}** | **{totals[1]}** | **{totals[2]}** | **{totals[0] + totals[1]}** |")
    L += ["", "Scripted checks of the window and of real AppImages:", ""]
    L += [f"- `{p}`: {t}" for p, t in lib.GUI_CHECKS]
    L += ["", "### Every test", ""]
    for part, (what, rows) in all_rows.items():
        L += [f"<details><summary><b>{part}</b>: {what} ({len(rows)} tests)</summary>", "", "| Kind | Promise | Test |", "|---|---|---|"]
        for kind, reg, name, promise, rel, line in rows:
            L.append(f"| {kind}{' ⟲' if reg else ''} | {promise} | [`{name}`]({rel}#L{line}) |")
        L += ["", "</details>", ""]
    L += ["## Version reports", "", "| Report | Generated | Tests passing | Failing |", "|---|---|---|---|"]
    for p, r in reversed(reps):
        ok, failed = test_counts(r)
        L.append(f"| [{p.stem}](docs/reports/{p.stem}.md) | {r.get('generated', '')} | {ok} | {failed} |")
    L += ["", "## Latest commits", "", "| Commit | Date | Change |", "|---|---|---|"]
    for line in git("log", "-30", "--format=%h%x09%ad%x09%s", "--date=short").splitlines():
        h, d, s = line.split("\t", 2)
        s = s.replace("|", "\\|")
        L.append(f"| [`{h}`]({REPO}/commit/{h}) | {d} | {s} |")
    L += ["", f"Full history: [{REPO}/commits/main]({REPO}/commits/main).", ""]
    (ROOT / "DEVELOPMENT.md").write_text("\n".join(L))
    print("wrote DEVELOPMENT.md")


if __name__ == "__main__":
    main()
