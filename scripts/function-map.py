#!/usr/bin/env python3
"""SAM's function map: docs/functions.toml links each of SAM's functions to
the code that carries it and the tests that prove it.

    scripts/function-map.py            check the map and write docs/functions.md
    scripts/function-map.py --check    check only; fail if the map or the page is off
    scripts/function-map.py --touched FILE...
                                       the functions a change to these files touches

The check fails when a function has no test and no stated gap, when a test
in the code belongs to no function, or when the map names a test, file or
check that does not exist. The page shows, per function, its tests with
their latest result (from the newest version report), its code and its
scripted checks.
"""
import importlib.util
import json
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAP = ROOT / "docs" / "functions.toml"
PAGE = ROOT / "docs" / "functions.md"

spec = importlib.util.spec_from_file_location("test_library", ROOT / "scripts" / "test-library.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)


def all_tests():
    """name -> (file relative to the repository, line, promise, regression)."""
    out = {}
    for part in lib.PARTS:
        for f in sorted((ROOT / "crates" / part).rglob("*.rs")):
            for name, promise, line, reg in lib.tests_in(f):
                out[name] = (f.relative_to(ROOT), line, promise, reg)
    return out


def latest_results():
    """name -> "ok" / "FAILED" from the newest version report, if any."""
    reports = []
    for p in (ROOT / "docs" / "reports").glob("*.json"):
        try:
            reports.append(json.loads(p.read_text()))
        except json.JSONDecodeError:
            pass
    if not reports:
        return {}, None
    r = max(reports, key=lambda r: r.get("generated", ""))
    return {t["test"]: t["result"] for t in r.get("tests", []) if "test" in t}, r.get("generated", "")


def problems(m, tests):
    out = []
    named = set()
    ids = set()
    areas = {a["id"] for a in m.get("area", [])}
    for f in m.get("function", []):
        fid = f["id"]
        if fid in ids:
            out.append(f"function {fid} appears twice")
        ids.add(fid)
        if f.get("area") not in areas:
            out.append(f"function {fid}: unknown area {f.get('area')!r}")
        if not f.get("tests") and not f.get("gap"):
            out.append(f"function {fid} has no test and no stated gap")
        for t in f.get("tests", []):
            named.add(t)
            if t not in tests:
                out.append(f"function {fid} names the test {t}, which does not exist")
        for c in f.get("code", []):
            if not ((ROOT / "crates" / c).exists() or (ROOT / c).exists()):
                out.append(f"function {fid} names the file {c}, which does not exist")
        for c in f.get("checks", []):
            if not (ROOT / c).exists():
                out.append(f"function {fid} names the check {c}, which does not exist")
    for t in sorted(set(tests) - named):
        out.append(f"the test {t} ({tests[t][0]}) belongs to no function")
    return out


def touched(m, files):
    """Functions whose code, tests or checks live in one of `files`."""
    tests = all_tests()
    files = {pathlib.Path(f).as_posix() for f in files}
    hit = []
    for f in m["function"]:
        paths = {f"crates/{c}" if (ROOT / "crates" / c).exists() else c for c in f.get("code", [])}
        paths |= {tests[t][0].as_posix() for t in f.get("tests", []) if t in tests}
        paths |= set(f.get("checks", []))
        if paths & files:
            hit.append(f)
    return hit


def render(m, tests):
    results, generated = latest_results()
    areas = {a["id"]: a["name"] for a in m["area"]}
    funcs = m["function"]
    proven = [f for f in funcs if f.get("tests") and all(results.get(t) == "ok" for t in f["tests"])] if results else []
    gaps = [f for f in funcs if f.get("gap")]
    L = [
        "# SAM's functions and their proofs",
        "",
        "> **What this page is:** every function SAM promises, with the tests that",
        "> prove it, the code that carries it, and the scripted checks that try it on",
        "> real apps or in the window. A test may prove several functions. The page",
        "> is generated from [functions.toml](functions.toml) by",
        "> `scripts/function-map.py`; CI checks that every test belongs to a function",
        "> and every function has a test or a stated gap.",
        ">",
        f"> Test results are from the newest version report ({generated.replace('T', ' ') if generated else 'none yet'}).",
        "",
        f"**{len(funcs)} functions:** {len(proven)} proven by passing tests, {len(gaps)} with a gap, "
        f"{len(tests)} tests in all.",
        "",
        "| | Function | Tests | Result |",
        "|---|---|---|---|",
    ]
    for f in funcs:
        n = len(f.get("tests", []))
        if f.get("gap"):
            state = "⚠️ gap"
        elif not results:
            state = "not run yet"
        elif all(results.get(t) == "ok" for t in f["tests"]):
            state = "✅"
        else:
            state = "❌ " + ", ".join(t for t in f["tests"] if results.get(t) != "ok")
        L.append(f"| {f['id']} | [{f['promise']}](#{f['id']}) | {n} | {state} |")
    L.append("")
    current = None
    for f in funcs:
        if f["area"] != current:
            current = f["area"]
            L += [f"## {current}. {areas[current]}", ""]
        L += [f'<a id="{f["id"]}"></a>', f"### {f['id']}. {f['promise']}", ""]
        if f.get("internal"):
            L += ["*An internal guarantee: it keeps SAM maintainable and is not a feature users see.*", ""]
        if f.get("gap"):
            L += [f"**Gap:** {f['gap']}", ""]
        if f.get("tests"):
            L += ["| Test | Promise | Result |", "|---|---|---|"]
            for t in f["tests"]:
                path, line, promise, reg = tests[t]
                res = {"ok": "✅", "FAILED": "❌"}.get(results.get(t), "–")
                L.append(f"| [`{t}`](../{path}#L{line}){' ⟲' if reg else ''} | {promise} | {res} |")
            L.append("")
        code = ", ".join(f"[`{c}`](../{'crates/' if (ROOT / 'crates' / c).exists() else ''}{c})" for c in f.get("code", []))
        L += [f"**Code:** {code}", ""]
        if f.get("checks"):
            L += ["**Also tried by:** " + ", ".join(f"[`{c}`](../{c})" for c in f["checks"]), ""]
    L += ["⟲ marks a regression test: it guards against a bug that really happened.", ""]
    return "\n".join(L)


def main():
    m = tomllib.loads(MAP.read_text())
    if "--touched" in sys.argv:
        files = sys.argv[sys.argv.index("--touched") + 1:]
        for f in touched(m, files):
            print(f"{f['id']}. {f['promise']}")
        return
    tests = all_tests()
    found = problems(m, tests)
    if found:
        print("The function map is out of date:\n  " + "\n  ".join(found))
        sys.exit(1)
    page = render(m, tests)
    if "--check" in sys.argv:
        if not PAGE.exists() or PAGE.read_text() != page:
            print("docs/functions.md is out of date: run scripts/function-map.py")
            sys.exit(1)
        return
    PAGE.write_text(page)
    print(f"wrote {PAGE.relative_to(ROOT)}: {len(m['function'])} functions, {len(tests)} tests, all assigned")


if __name__ == "__main__":
    main()
