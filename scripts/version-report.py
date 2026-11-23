#!/usr/bin/env python3
"""The version report: for each part of SAM, which tests pass, how much of
its code the tests run, how long its steps take, and which parts it depends
on; compared with the previous report.

    scripts/version-report.py [--no-coverage] [--no-bench] [--out DIR]
    scripts/version-report.py --recheck docs/reports/<version>-<commit>.json

Writes docs/reports/<version>-<commit>.json and .md (or into --out) and
prints the differences to the previous report in that folder. Build output
and coverage data go to ../claude (next to the repository) or $SAM_WORK.

Measuring coverage makes the code much slower and makes every program,
also SAM's helper inside a read-only sandbox, try to write a measurement
file. A test that fails then is run once more without the measurement:
if it passes there, the report says so instead of counting it as failing.
--recheck does that for a report already written (on the same code).

Line coverage is a gap finder, not a score: a part whose coverage drops, or
code no test runs, is a place to look for a missing regression test.
"""
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORK = pathlib.Path(os.environ.get("SAM_WORK", ROOT.parent / "claude")) / "version-report"
PARTS = ["sam-core", "sam-detect", "sam-intake", "sam-profile", "sam-sandbox", "sam-runner", "sam-storage", "sam-jail-cli", "sam-gtk"]
SLOWER = 1.25  # a step counts as slower when it takes 25 % longer ...
MIN_MS = 2.0  # ... and at least this much longer in absolute terms


def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=kw.pop("cwd", ROOT), text=True, check=False, capture_output=True, **kw)


def version_and_commit():
    v = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
    c = sh(["git", "rev-parse", "--short", "HEAD"]).stdout.strip() or "unknown"
    dirty = bool(sh(["git", "status", "--porcelain", "--untracked-files=no"]).stdout.strip())
    return v, c + ("-dirty" if dirty else "")


def dependencies():
    out = {}
    for d in sorted((ROOT / "crates").iterdir()):
        toml = d / "Cargo.toml"
        if not toml.exists():
            continue
        deps, on = [], False
        for line in toml.read_text().splitlines():
            l = line.strip()
            if l.startswith("["):
                on = l == "[dependencies]"
            elif on:
                name = re.split(r"[ .=]", l)[0]
                if name.startswith("sam-"):
                    deps.append(name)
        out[d.name] = sorted(deps)
    return out


def test_binaries(env):
    """Builds every test executable and returns (part, target, kind, path, package dir)."""
    r = sh(["cargo", "test", "--workspace", "--no-run", "--message-format=json"], env=env)
    if r.returncode != 0:
        sys.exit("building the tests failed:\n" + r.stderr[-3000:])
    bins = []
    for line in r.stdout.splitlines():
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("profile", {}).get("test"):
            part = m["package_id"].split("#")[0].rsplit("/", 1)[-1].split("@")[0]
            part = re.sub(r"[^a-z0-9-].*$", "", part) if part.startswith("sam-") else part
            pkgdir = pathlib.Path(m["manifest_path"]).parent
            bins.append((pkgdir.name, m["target"]["name"], m["target"]["kind"][0], m["executable"], pkgdir))
    return bins


def run_tests(bins, env):
    """Runs each test executable from its package folder; returns per-test results."""
    results = []
    for part, target, kind, exe, pkgdir in bins:
        t0 = datetime.datetime.now()
        r = subprocess.run([exe], cwd=pkgdir, env=env, text=True, check=False, capture_output=True)
        secs = (datetime.datetime.now() - t0).total_seconds()
        for m in re.finditer(r"^test (\S+) \.\.\. (ok|FAILED|ignored)", r.stdout, re.M):
            name = m.group(1).split("::")[-1]
            results.append({"part": part, "suite": target if kind != "lib" and kind != "bin" else "unit", "test": name, "result": m.group(2)})
        results.append({"part": part, "suite": target, "binary_seconds": round(secs, 2)})
    return results


def recheck(tests):
    """Runs each failed test once more without coverage measurement (its
    own build folder); one that passes there is marked as failing only
    while coverage is measured. Returns how many it rechecked."""
    failed = [t for t in tests if t.get("result") == "FAILED"]
    if not failed:
        return 0
    env = {k: v for k, v in os.environ.items() if k not in ("RUSTFLAGS", "LLVM_PROFILE_FILE")}
    env["CARGO_TARGET_DIR"] = str(WORK / "target-plain")
    env["TMPDIR"] = str(WORK / "tmp")
    env["PATH"] = f"{WORK / 'target-plain' / 'debug'}:{env['PATH']}"
    env["SAM_REQUIRE_SANDBOX"] = "1"
    print("rechecking the failed tests without coverage …", file=sys.stderr)
    # The tests start SAM's programs (the helper among them): build them once.
    sh(["cargo", "build", "--workspace", "--locked", "--bins"], env=env)
    for t in failed:
        targets = [["--lib"], ["--bins"]] if t["suite"] == "unit" else [["--test", t["suite"]]]
        for target in targets:
            r = sh(["cargo", "test", "--locked", "-p", t["part"], *target, "--", t["test"]], env=env)
            if re.search(rf"^test \S*\b{re.escape(t['test'])} \.\.\. ok$", r.stdout, re.M):
                t["result"] = "ok"
                t["fails_only_with_coverage"] = True
                break
    return len(failed)


def coverage(bins, profdir, env):
    raws = list(profdir.glob("*.profraw"))
    if not raws:
        return {}
    merged = profdir / "merged.profdata"
    sh(["llvm-profdata", "merge", "-sparse", *map(str, raws), "-o", str(merged)])
    objs = sorted({b[3] for b in bins})
    # The command-line binaries that integration tests start are instrumented too.
    for extra in ["sam-jail", "sam-jail-run", "sam-jail-gui"]:
        p = pathlib.Path(env["CARGO_TARGET_DIR"]) / "debug" / extra
        if p.exists():
            objs.append(str(p))
    args = ["llvm-cov", "export", "-summary-only", f"-instr-profile={merged}", objs[0]]
    for o in objs[1:]:
        args += ["-object", o]
    args += ["-ignore-filename-regex", r"(\.cargo/registry|/rustc/|/tests/|testkit\.rs)"]
    r = sh(args)
    if r.returncode != 0:
        print("coverage could not be read:", r.stderr[-500:], file=sys.stderr)
        return {}
    per = {}
    for f in json.loads(r.stdout)["data"][0]["files"]:
        m = re.search(r"/crates/([^/]+)/src/", f["filename"])
        if not m:
            continue
        s = f["summary"]["lines"]
        p = per.setdefault(m.group(1), {"lines": 0, "covered": 0, "untested_files": []})
        p["lines"] += s["count"]
        p["covered"] += s["covered"]
        if s["count"] > 20 and s["covered"] == 0:
            p["untested_files"].append(f["filename"].split("/crates/")[1])
    for p in per.values():
        p["percent"] = round(100.0 * p["covered"] / p["lines"], 1) if p["lines"] else 0.0
    return per


def bench():
    r = sh(["cargo", "build", "--release", "-q", "-p", "sam-jail-cli"])
    if r.returncode != 0:
        print("release build failed; no benchmarks", file=sys.stderr)
        return []
    tmp = WORK / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    r = sh(["target/release/sam-jail", "--json", "dev", "bench"], env={**os.environ, "TMPDIR": str(tmp)})
    try:
        v = json.loads(r.stdout)
        return v.get("data", v)
    except json.JSONDecodeError:
        print("benchmark failed:", r.stderr[-500:], file=sys.stderr)
        return []


def previous_report(outdir, current_name):
    reports = sorted((p for p in outdir.glob("*.json") if p.stem != current_name), key=lambda p: json.loads(p.read_text()).get("generated", ""))
    return json.loads(reports[-1].read_text()) if reports else None


def summarize(rep):
    tests = [t for t in rep["tests"] if "test" in t]
    by = {}
    for t in tests:
        b = by.setdefault(t["part"], {"ok": 0, "FAILED": 0, "ignored": 0})
        b[t["result"]] += 1
    return by, {(t["part"], t["suite"], t["test"]): t["result"] for t in tests}


def markdown(rep, prev):
    by, tests = summarize(rep)
    pby, ptests = summarize(prev) if prev else ({}, {})
    L = [f"# Version report {rep['version']} ({rep['commit']})", "", f"Generated {rep['generated']}."]
    L += [f"Compared with {prev['version']} ({prev['commit']}, {prev['generated']})." if prev else "This is the first report; there is nothing to compare with.", ""]
    failed = [k for k, v in tests.items() if v == "FAILED"]
    only_cov = sorted((t["part"], t["suite"], t["test"]) for t in rep["tests"] if t.get("fails_only_with_coverage"))
    new = sorted(set(tests) - set(ptests)) if prev else []
    gone = sorted(set(ptests) - set(tests)) if prev else []
    L += ["## Summary", ""]
    L += [f"- {sum(v == 'ok' for v in tests.values())} tests pass, {len(failed)} fail, {sum(v == 'ignored' for v in tests.values())} are skipped."]
    if only_cov:
        L += [f"- {len(only_cov)} of the passing tests fail only while coverage is measured, and pass without it (see the end of this report)."]
    if prev:
        L += [f"- {len(new)} tests are new and {len(gone)} were removed since the previous report."]
    L += [""]
    L += ["## Parts", "", "| Part | Tests passing | Failing | Line coverage | Change |", "|---|---|---|---|---|"]
    for p in PARTS:
        b = by.get(p, {"ok": 0, "FAILED": 0})
        cov = rep["coverage"].get(p, {})
        pcov = prev["coverage"].get(p, {}) if prev else {}
        pct = f"{cov['percent']} %" if cov else "not measured"
        delta = f"{cov['percent'] - pcov['percent']:+.1f} points" if cov and pcov else ""
        L.append(f"| {p} | {b['ok']} | {b['FAILED']} | {pct} | {delta} |")
    L += ["", "Line coverage is a gap finder: it shows code that no test runs, not how good the tests are.", ""]
    untested = [(p, f) for p, c in rep["coverage"].items() for f in c.get("untested_files", [])]
    if untested:
        L += ["Files with more than 20 lines that no test runs at all:", ""] + [f"- `{f}`" for _, f in sorted(untested)] + [""]
    L += ["## How long the steps take", "", "Each step runs several times after a warm-up run; the fastest run is compared, because it is the one least disturbed by other programs.", "", "| Step | Fastest | Median | Previous fastest | Change |", "|---|---|---|---|---|"]
    pb = {m["key"]: m for m in prev.get("bench", [])} if prev else {}
    for m in rep["bench"]:
        cur = m.get("best_ms", m["median_ms"])
        old = pb.get(m["key"], {}).get("best_ms")
        mark = "" if old is not None or not prev else "the previous report has no fastest run"
        if cur is not None and old:
            ch = (cur - old) / old * 100
            mark = f"{ch:+.0f} %" + (" ⚠ slower" if cur > old * SLOWER and cur - old > MIN_MS else "")
        fmt = lambda x: f"{x:.3f} ms" if x is not None else "not measured here"
        L.append(f"| {m['what']} | {fmt(cur)} | {fmt(m['median_ms'])} | {fmt(old) if old is not None else ''} | {mark} |")
    L += ["", "## Relations between the parts", ""]
    pdeps = prev["dependencies"] if prev else rep["dependencies"]
    changes = []
    for p, ds in rep["dependencies"].items():
        added = set(ds) - set(pdeps.get(p, []))
        removed = set(pdeps.get(p, [])) - set(ds)
        changes += [f"- {p} now depends on {d}." for d in sorted(added)] + [f"- {p} no longer depends on {d}." for d in sorted(removed)]
    L += changes or ["No dependency changed since the previous report."]
    L += ["", "| Part | Depends on |", "|---|---|"] + [f"| {p} | {', '.join(ds) or 'nothing'} |" for p, ds in rep["dependencies"].items()]
    if failed:
        L += ["", "## Failing tests", ""] + [f"- {p} / {s} / `{t}`" for p, s, t in failed]
    if only_cov:
        L += ["", "## Passing only without coverage measurement", "",
              "Measuring coverage makes the code much slower, and every program, SAM's helper inside a read-only sandbox too, tries to write a measurement file. These tests failed in the measured run and passed when run once more without the measurement, so they count as passing:", ""]
        L += [f"- {p} / {s} / `{t}`" for p, s, t in only_cov]
    if new:
        L += ["", "## New tests", ""] + [f"- {p} / {s} / `{t}`" for p, s, t in new]
    if gone:
        L += ["", "## Removed tests", ""] + [f"- {p} / {s} / `{t}`" for p, s, t in gone]
    return "\n".join(L) + "\n"


def main():
    args = sys.argv[1:]
    if "--recheck" in args:
        path = pathlib.Path(args[args.index("--recheck") + 1])
        rep = json.loads(path.read_text())
        WORK.mkdir(parents=True, exist_ok=True)
        (WORK / "tmp").mkdir(exist_ok=True)
        recheck(rep["tests"])
        path.write_text(json.dumps(rep, indent=1) + "\n")
        md = markdown(rep, previous_report(path.parent, path.stem))
        path.with_suffix(".md").write_text(md)
        print(md)
        return 1 if any(t.get("result") == "FAILED" for t in rep["tests"]) else 0
    outdir = pathlib.Path(args[args.index("--out") + 1]) if "--out" in args else ROOT / "docs" / "reports"
    outdir.mkdir(parents=True, exist_ok=True)
    version, commit = version_and_commit()
    name = f"{version}-{commit}"
    WORK.mkdir(parents=True, exist_ok=True)
    profdir = WORK / "profraw"
    shutil.rmtree(profdir, ignore_errors=True)
    profdir.mkdir(parents=True)
    env = {**os.environ, "CARGO_TARGET_DIR": str(WORK / "target"), "TMPDIR": str(WORK / "tmp"), "SAM_TEST_GPG": os.environ.get("SAM_TEST_GPG", ""),
           # A sandbox test that cannot run fails instead of counting as passed.
           "SAM_REQUIRE_SANDBOX": "1"}
    (WORK / "tmp").mkdir(exist_ok=True)
    if "--no-coverage" not in args:
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C instrument-coverage").strip()
        env["LLVM_PROFILE_FILE"] = str(profdir / "%p-%m.profraw")
    env["PATH"] = f"{WORK / 'target' / 'debug'}:{env['PATH']}"
    print("building and running the tests …", file=sys.stderr)
    bins = test_binaries(env)
    tests = run_tests(bins, env)
    cov = coverage(bins, profdir, env) if "--no-coverage" not in args else {}
    if "--no-coverage" not in args:
        recheck(tests)
    print("running the benchmarks …", file=sys.stderr)
    b = bench() if "--no-bench" not in args else []
    rep = {
        "version": version,
        "commit": commit,
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "tests": tests,
        "coverage": cov,
        "bench": b,
        "dependencies": dependencies(),
    }
    prev = previous_report(outdir, name)
    (outdir / f"{name}.json").write_text(json.dumps(rep, indent=1) + "\n")
    md = markdown(rep, prev)
    (outdir / f"{name}.md").write_text(md)
    print(md)
    print(f"wrote {outdir / name}.md and .json", file=sys.stderr)
    # The development dashboard shows the latest report.
    if outdir == ROOT / "docs" / "reports":
        sh(["python3", "-I", str(ROOT / "scripts" / "function-map.py")])
        sh(["python3", "-I", str(ROOT / "scripts" / "dashboard.py")])
    return 1 if any(t.get("result") == "FAILED" for t in tests) else 0


if __name__ == "__main__":
    sys.exit(main())
