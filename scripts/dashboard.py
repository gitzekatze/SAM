#!/usr/bin/env python3
"""Writes DEVELOPMENT.md, the development dashboard: whether SAM is
healthy right now (CI, the latest version report), every test grouped by
part, the history of version reports, and the latest commits.

    scripts/dashboard.py

The version report (scripts/version-report.py, `make report`) calls it,
so the page shows the state at the end of the last phase of work. Each
section starts with a short note on what it shows and how to read it.
"""
import datetime
import importlib.util
import json
import pathlib
import re
import subprocess
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPO = "https://github.com/gitzekatze/SAM"

# The test library's parser, so both pages list the same tests and promises.
spec = importlib.util.spec_from_file_location("test_library", ROOT / "scripts" / "test-library.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)
# SAM's numbers, from the same source as README and website.
spec = importlib.util.spec_from_file_location("facts", ROOT / "scripts" / "facts.py")
facts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts)


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True).stdout.strip()


def reports():
    """All version reports, oldest first: (path, report)."""
    out = []
    for p in (ROOT / "docs" / "reports").glob("*.json"):
        try:
            out.append((p, json.loads(p.read_text())))
        except json.JSONDecodeError:
            continue
    return sorted(out, key=lambda x: x[1].get("generated", ""))


def test_counts(r):
    tests = [t for t in r.get("tests", []) if "test" in t]
    return sum(t["result"] == "ok" for t in tests), sum(t["result"] == "FAILED" for t in tests)


def bar(fraction, width=20):
    """A small bar chart made of characters (GitHub pages allow no styles)."""
    full = round(max(0.0, min(1.0, fraction)) * width)
    return "█" * full + "░" * (width - full)


def note(*lines):
    """The explanation above a section, as a quote block."""
    return [f"> {l}" if l else ">" for l in lines] + [""]


def kind_of(path: pathlib.Path) -> str:
    return "integration" if "/tests/" in str(path) else "unit"


def build():
    """The dashboard as Markdown; the website renders this same text."""
    version = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
    reps = reports()
    latest = reps[-1] if reps else None
    previous = reps[-2] if len(reps) > 1 else None
    ok, failed = test_counts(latest[1]) if latest else (0, 0)
    F = facts.compute()

    L = ["# SAM development dashboard", ""]
    L += note(
        "**What this page is:** the front page for people who work on SAM. It shows",
        "whether SAM is healthy right now, every test with the promise it keeps, how",
        "the version reports changed over time, and the latest commits. For people",
        "who use SAM, the front page is [README.md](README.md).",
        "",
        f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M')} by `scripts/dashboard.py`. The website",
        "builds this page again with every change to SAM; this file in the repository",
        "is renewed with every version report (`make report`).",
    )

    # ---- at a glance
    L += ["## At a glance", "", f"[![CI]({REPO}/actions/workflows/ci.yml/badge.svg)]({REPO}/actions/workflows/ci.yml)", ""]
    L += [
        "| | |",
        "|---|---|",
        f"| **Tests** | {'✅' if failed == 0 else '❌'} {ok} pass, {failed} fail in the latest version report |",
        f"| **Tests in the code** | {F['tests'][0]}, of which {F['regression_tests'][0]} guard against bugs that really happened |",
        f"| **Functions with proof** | {F['functions'][0]}, each with the tests that prove it |",
        *([f"| **Real AppImages** | {F['apps_start'][0]} of {F['apps_total'][0]} start in their sandbox ({F['apps_date'][0]}) |"] if "apps_total" in F else []),
        *([f"| **Mutation testing** | {F['mutants_caught_percent'][0]} of {F['mutants_tested'][0]} deliberate mistakes caught |"] if "mutants_tested" in F else []),
        f"| **Version** | {version} (the number changes only when a version is published) |",
        f"| **Latest commit** | `{git('log', '-1', '--format=%h')}` {git('log', '-1', '--format=%s').replace('|', '/')} |",
        f"| **Commits so far** | {git('rev-list', '--count', 'HEAD')} |",
        (f"| **Version reports** | {len(reps)}; the newest is [{latest[0].stem}](docs/reports/{latest[0].stem}.md) |" if latest else "| **Version reports** | none yet |"),
        "",
    ]
    L += note(
        "**How to read the badge:** it shows the last CI run on GitHub (unit,",
        "integration, sandbox and window tests on Ubuntu; sandbox tests on Fedora).",
        "Green means every test passed there; click it for the details.",
    )

    # ---- what the tests prove, area by area
    fm = tomllib.loads((ROOT / "docs/functions.toml").read_text())
    results = {t.get("test"): t.get("result") for t in (latest[1].get("tests", []) if latest else [])}
    L += ["## What the tests prove", ""]
    L += note(
        "**What you see:** SAM's promises, grouped into areas. Each function in an area",
        "has at least one test that proves it; the [function map](docs/functions.md) lists",
        "them one by one. *Newer than the report* counts tests added since the latest",
        "version report; they run in CI on every change.",
    )
    L += ["| Area | What it covers | Functions | Tests | Result |", "|---|---|---|---|---|"]
    for area in fm["area"]:
        fs = [x for x in fm["function"] if x["area"] == area["id"]]
        ts = sorted({t for x in fs for t in x.get("tests", [])})
        good = sum(results.get(t) == "ok" for t in ts)
        bad = sum(results.get(t) == "FAILED" for t in ts)
        new = len(ts) - good - bad
        state = (f"❌ {bad} failing" if bad else "✅ passing") + (f", {new} newer than the report" if new else "")
        L.append(f"| **{area['name']}** | {area.get('about', '')} | {len(fs)} | {len(ts)} | {state} |")
    L.append("")

    L += ["## The evidence", ""]
    L += note(
        "**What you see:** the larger checks behind SAM's promises, each with its full",
        "report. [How SAM is tested](docs/testing.md) explains every kind of test.",
    )
    if "apps_total" in F:
        L += [f"- **Real AppImages:** {F['apps_start'][0]} of {F['apps_total'][0]} start in their sandbox; "
              f"{F['apps_repaired'][0]} of them after one repair step, {F['apps_fail'][0]} fail for reasons inside the app, "
              f"and {F['apps_refused'][0]} built for another processor is turned away "
              f"([report]({F['apps_total'][1]}))."]
    if "mutants_tested" in F:
        L += [f"- **Mutation testing:** {F['mutants_tested'][0]} deliberate mistakes in the security code; "
              f"the tests caught {F['mutants_caught_percent'][0]} of those that could be built "
              f"([report]({F['mutants_tested'][1]}))."]
    L += ["- **Breakout and hostile-AppImage tests:** run inside a real sandbox on every change, "
          "on Ubuntu and Fedora ([threat model](docs/threat-model.md)).", ""]

    # ---- health of each part
    if latest:
        r = latest[1]
        L += ["## Health of each part", ""]
        L += note(
            "**What you see:** for each part of SAM, its tests in the latest version",
            "report, and how much of its code those tests run (line coverage, the bar).",
            "Low coverage hints where a regression test may be missing; it is not a",
            "grade. The window (sam-gtk) is mostly checked by the scripted window tests",
            "further down, which line coverage does not count.",
        )
        L += ["| Part | What it does | Tests | Line coverage |", "|---|---|---|---|"]
        by = {}
        for t in r.get("tests", []):
            if "test" in t:
                b = by.setdefault(t["part"], [0, 0])
                b[0] += t["result"] == "ok"
                b[1] += t["result"] == "FAILED"
        for part, what in lib.PARTS.items():
            b = by.get(part, [0, 0])
            cov = r.get("coverage", {}).get(part)
            covtxt = f"`{bar(cov['percent'] / 100)}` {cov['percent']} %" if cov else "not measured"
            state = "✅" if b[1] == 0 else f"❌ {b[1]} failing,"
            L.append(f"| **{part}** | {what} | {state} {b[0]} passing | {covtxt} |")
        L.append("")

        # ---- speed
        if r.get("bench"):
            L += ["## Speed", ""]
            L += note(
                "**What you see:** how long SAM's steps take, measured by `sam-jail dev bench`",
                "on a test AppImage with 2,000 files and on 120 sandboxed apps. Each step runs",
                "several times after a warm-up run; the fastest run is shown, because it is the",
                "one least disturbed by other programs. The last column compares with the",
                "previous report: 🔺 means more than 25 % slower, 🔻 more than 25 % faster.",
                "A busy computer can cause such a change, so measure twice before you believe it.",
            )
            pb = {m["key"]: m for m in (previous[1].get("bench", []) if previous else [])}
            L += ["| Step | Fastest run | Since the previous report |", "|---|---|---|"]
            for m in r["bench"]:
                v = m.get("best_ms", m.get("median_ms"))
                old = pb.get(m["key"], {}).get("best_ms")
                change = "first measurement"
                if v is not None and old:
                    pct = (v - old) / old * 100
                    change = f"{'🔺' if pct > 25 else ('🔻' if pct < -25 else '≈')} {pct:+.0f} %"
                L.append(f"| {m['what']} | {f'{v:.3f} ms' if v is not None else 'not measured here'} | {change} |")
            L.append("")

    # ---- tests
    L += ["## Tests", ""]
    L += note(
        "**What you see:** every automated test, counted per part. A **unit test** checks",
        "one piece of code on its own. An **integration test** runs the real program end",
        "to end, often inside a real sandbox. A **regression test** ⟲ guards against a bug",
        "that really happened, and fails without its fix. Every test keeps one promise,",
        "stated in a complete sentence. The same list with links to the code is the",
        "[test library](docs/test-library.md).",
    )
    groups = {}
    for part, what in lib.PARTS.items():
        rows = []
        for f in sorted((ROOT / "crates" / part).rglob("*.rs")):
            for name, promise, line, reg in lib.tests_in(f):
                rows.append((kind_of(f), reg, name, promise, f.relative_to(ROOT), line))
        if rows:
            groups[part] = (what, rows)
    most = max((len(rows) for _, rows in groups.values()), default=1)
    totals = [0, 0, 0]
    L += ["| Part | Unit | Integration | Regression ⟲ | Total | |", "|---|---|---|---|---|---|"]
    for part, (_, rows) in groups.items():
        u = sum(k == "unit" for k, *_ in rows)
        i = len(rows) - u
        g = sum(1 for _, reg, *_ in rows if reg)
        totals = [totals[0] + u, totals[1] + i, totals[2] + g]
        L.append(f"| **{part}** | {u} | {i} | {g} | {len(rows)} | `{bar(len(rows) / most, 15)}` |")
    L += [f"| **all parts** | **{totals[0]}** | **{totals[1]}** | **{totals[2]}** | **{totals[0] + totals[1]}** | |", ""]

    L += ["### Scripted checks of the window and of real AppImages", ""]
    L += note(
        "These run SAM's window or real AppImages in an invisible desktop session. The",
        "window smoke test runs in CI; the others are started by hand.",
    )
    L += [f"- `{p}` — {t}" for p, t in lib.GUI_CHECKS] + [""]

    L += ["### Every test", ""]
    L += note("Click a part to unfold its tests. The promise is the first sentence of the test's", "own comment; the name links to the code.")
    for part, (what, rows) in groups.items():
        L += [f"<details><summary><b>{part}</b> — {what} ({len(rows)} tests)</summary>", "", "| Kind | Promise | Test |", "|---|---|---|"]
        for kind, reg, name, promise, rel, line in rows:
            L.append(f"| {kind}{' ⟲' if reg else ''} | {promise} | [`{name}`]({rel}#L{line}) |")
        L += ["", "</details>", ""]

    # ---- version reports
    L += ["## Version reports", ""]
    L += note(
        "**What you see:** every version report, newest first. A report is made at the end",
        "of each phase of work and before each published version; it compares the tests,",
        "the coverage, the speed and the dependencies with the report before.",
    )
    L += ["| Report | Generated | Tests passing | Failing |", "|---|---|---|---|"]
    for p, r in reversed(reps):
        o, f = test_counts(r)
        L.append(f"| [{p.stem}](docs/reports/{p.stem}.md) | {r.get('generated', '').replace('T', ' ')} | {o} | {f} |")
    L.append("")

    # ---- commits
    L += ["## Latest commits", ""]
    L += note(
        "**What you see:** the 30 newest changes to SAM, newest first. Each commit message",
        "explains what changed and why; the hash links to the change on GitHub.",
    )
    L += ["| Commit | Date | Change |", "|---|---|---|"]
    for line in git("log", "-30", "--format=%h%x09%ad%x09%s", "--date=short").splitlines():
        h, d, s = line.split("\t", 2)
        L.append(f"| [`{h}`]({REPO}/commit/{h}) | {d} | {s.replace('|', '/')} |")
    L += ["", f"The full history is at [{REPO}/commits/main]({REPO}/commits/main).", ""]

    return "\n".join(L)


def main():
    (ROOT / "DEVELOPMENT.md").write_text(build())
    print("wrote DEVELOPMENT.md")


if __name__ == "__main__":
    main()
