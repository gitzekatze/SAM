#!/usr/bin/env python3
"""SAM's numbers, computed from the repository, and kept current in the
documents that quote them.

    python3 scripts/facts.py            write the numbers into the documents
    python3 scripts/facts.py --check    fail if a document quotes an old number
    python3 scripts/facts.py --list     print every number and where it comes from

A document quotes a number as  <!-- fact:NAME -->VALUE<!-- /fact -->.
GitHub shows only VALUE, and the website renders the same text, so README,
docs and website always agree. A number is never typed by hand: when its
source changes, this script (and CI with --check) brings every quote along.

Sources:
  tests, regression_tests   the test functions in crates/ (scripts/test-library.py)
  functions                 docs/functions.toml
  languages                 po/LINGUAS, plus English
  apps_*                    the newest docs/reports/real-apps-*.md (its "Total" line)
  mutants_*                 the newest docs/reports/mutants-*.md (its result table)
"""
import importlib.util
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Documents that may quote facts. Generated documents get their numbers from
# their own generators, which import this module.
DOCUMENTS = ["README.md", "CONTRIBUTING.md", "SECURITY.md", *sorted(str(p.relative_to(ROOT)) for p in (ROOT / "docs").rglob("*.md")
                                                                if "reports" not in p.parts)]
FACT = re.compile(r"(<!-- fact:([a-z_]+) -->)(.*?)(<!-- /fact -->)", re.S)

spec = importlib.util.spec_from_file_location("test_library", ROOT / "scripts" / "test-library.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)


def newest(pattern):
    found = sorted((ROOT / "docs" / "reports").glob(pattern))
    return found[-1] if found else None


def number(text):
    return int(text.replace(",", "").replace(" ", ""))


def fmt(n):
    return f"{n:,}"


def compute():
    """Every fact as (value, source)."""
    f = {}
    tests = regression = 0
    for crate in lib.PARTS:
        for p in sorted((ROOT / "crates" / crate).rglob("*.rs")):
            for _name, _promise, _line, reg in lib.tests_in(p):
                tests += 1
                regression += bool(reg)
    f["tests"] = (fmt(tests), "test functions in crates/")
    f["regression_tests"] = (fmt(regression), "tests marked as regression tests")
    funcs = tomllib.loads((ROOT / "docs/functions.toml").read_text())["function"]
    f["functions"] = (fmt(len(funcs)), "docs/functions.toml")
    f["languages"] = (str(len((ROOT / "po/LINGUAS").read_text().split()) + 1), "po/LINGUAS plus English")

    apps = newest("real-apps-*.md")
    if apps:
        line = re.search(r"^\*\*Total:\*\*(.*)$", apps.read_text(), re.M).group(1)
        get = lambda label: number(re.search(rf"(\d[\d,]*) {label}", line).group(1))
        total, ok, repaired, failed, refused = (get("AppImages"), get("start with SAM's recommendation"),
                                                get("start after one repair step"), get("do not start"),
                                                get("turned away"))
        src = str(apps.relative_to(ROOT))
        f["apps_total"] = (fmt(total), src)
        f["apps_start"] = (fmt(ok + repaired), src)
        f["apps_start_unchanged"] = (fmt(ok), src)
        f["apps_repaired"] = (fmt(repaired), src)
        f["apps_fail"] = (fmt(failed), src)
        f["apps_refused"] = (fmt(refused), src)
        f["apps_date"] = (re.search(r"(\d{4}-\d\d-\d\d)", apps.name).group(1), src)

    mut = newest("mutants-*.md")
    if mut:
        text = mut.read_text()
        row = lambda label: number(re.search(rf"^\| {label}[^|]*\| ([\d,]+) \|", text, re.M).group(1))
        total, missed = row("Mutants in the four crates"), row("Missed")
        src = str(mut.relative_to(ROOT))
        f["mutants_tested"] = (fmt(total), src)
        f["mutants_missed"] = (fmt(missed), src)
        f["mutants_missed_percent"] = (f"{100 * missed / total:.1f} %", src)
        stated = re.search(r"\*\*([\d.]+ %) of the buildable changes were caught", text)
        if stated:
            f["mutants_caught_percent"] = (stated.group(1), src)
        f["mutants_report"] = (mut.name.removesuffix(".md"), src)
    return f


def update(text, facts, where):
    """The document with every quoted fact set to its current value."""
    def put(m):
        name = m.group(2)
        if name not in facts:
            sys.exit(f"{where}: unknown fact '{name}' (known: {', '.join(sorted(facts))})")
        return f"{m.group(1)}{facts[name][0]}{m.group(4)}"
    return FACT.sub(put, text)


def main():
    facts = compute()
    if "--list" in sys.argv:
        for name, (value, src) in sorted(facts.items()):
            print(f"{name:26} {value:>10}  {src}")
        return 0
    stale = []
    for doc in DOCUMENTS:
        path = ROOT / doc
        if not path.exists():
            continue
        old = path.read_text()
        for n, line in enumerate(old.splitlines(), 1):
            if line.lstrip().startswith("<!-- fact:"):
                sys.exit(f"{doc}:{n}: a line must not start with a fact; Markdown would end the paragraph or list there")
        new = update(old, facts, doc)
        if new != old:
            stale.append(doc)
            if "--check" not in sys.argv:
                path.write_text(new)
    if "--check" in sys.argv and stale:
        print("These documents quote old numbers; run python3 scripts/facts.py:")
        for doc in stale:
            print(f"  {doc}")
        return 1
    if stale:
        print("updated: " + ", ".join(stale))
    return 0


if __name__ == "__main__":
    sys.exit(main())
