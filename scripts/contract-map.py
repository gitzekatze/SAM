#!/usr/bin/env python3
"""SAM's contract map: docs/contracts.toml lists every assumption SAM makes
about the world outside it (programs and their options, kernel features,
paths, sockets, variables, desktop services, file formats), what SAM does
when one breaks, and how each is checked.

    scripts/contract-map.py              check the map and write docs/contracts.md
    scripts/contract-map.py --check      check only; fail if the map or the page is off
    scripts/contract-map.py --inventory  list what the code assumes, and which contract covers it

The check fails when the code uses an outside program, an option, a host
path, a variable, a D-Bus name, a syscall or a Wayland protocol that no
contract covers (so a new assumption cannot slip in unnoticed), when a
contract names a function, test or component that does not exist, or when
a contract lacks what to do when it breaks.
"""
import fnmatch
import importlib.util
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAP = ROOT / "docs" / "contracts.toml"
PAGE = ROOT / "docs" / "contracts.md"

# Code that only tests use is not an assumption of SAM itself.
_KEEP = tomllib.loads((ROOT / "keeper.toml").read_text())["contracts"]
TEST_ONLY = set(_KEEP["test_only"])
OWN_CLI_CALLERS = _KEEP["own_cli_callers"]

PATTERNS = {
    "program": [r'Command::new\("([^"/][^"]*|/[^"]+)"\)', r'which\("([^"]+)"\)'],
    "option": [r'"(--[a-z][a-z0-9-]*=?)"', r'"(-[A-Za-z])"', r'format!\("(--[a-z][a-z0-9-]*=)'],
    "path": [r'"(/(?:etc|run|sys|proc|dev|usr|tmp|var|opt|media|mnt|lib|lib64|bin|sbin)(?:/[^"{} ]*)?)"',
             # Paths built at runtime: the fixed part before the first {} counts.
             r'format!\(\s*"(/(?:etc|run|sys|proc|dev|usr|tmp|var|opt|media|mnt|lib|lib64|bin|sbin)/[^"{} ]*)\{'],
    "env": [r'env::var(?:_os)?\("([A-Z][A-Z0-9_]*)"\)', r'\benv\("([A-Z][A-Z0-9_]*)"\)'],
    "dbus": [r'"((?:org|com|ca|net)\.[A-Za-z0-9_.*]+[A-Za-z0-9_*])"'],
    "syscall": [r"libc::SYS_([a-z0-9_]+)"],
    "wayland": [r'"((?:wp|wl|xdg|zwp|ext)_[a-z0-9_]+_v\d+)"'],
}


def code_lines(path):
    """The lines of a Rust file outside its #[cfg(test)] modules."""
    lines = path.read_text().splitlines()
    out, in_test, depth = [], False, 0
    for i, line in enumerate(lines):
        if not in_test and line.strip() == "#[cfg(test)]":
            nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if nxt.endswith("{"):
                in_test, depth = True, 0
                continue
        if in_test:
            depth += line.count("{") - line.count("}")
            if depth <= 0 and "}" in line:
                in_test = False
            continue
        if line.strip().startswith("//"):
            continue
        out.append((i + 1, line))
    return out


def inventory():
    """(kind, value) -> first place it appears, from SAM's own code."""
    found = {}
    for f in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        rel = str(f.relative_to(ROOT))
        if rel in TEST_ONLY:
            continue
        for n, line in code_lines(f):
            for kind, pats in PATTERNS.items():
                # The window calls SAM's own command line: its options are not outside assumptions.
                if kind == "option" and any(rel.startswith(d) for d in OWN_CLI_CALLERS):
                    continue
                for p in pats:
                    for m in re.finditer(p, line):
                        found.setdefault((kind, m.group(1)), f"{rel}:{n}")
    return found


def covered(item, patterns):
    kind, value = item
    return any(fnmatch.fnmatchcase(f"{kind}:{value}", p) for p in patterns)


ON_BREAK = {
    "refuse": "SAM does not start the sandbox and says why",
    "safer": "SAM falls back to less access",
    "warn": "the start goes ahead with a visible warning",
    "feature": "one feature is unavailable; the sandbox is unaffected",
    "none": "nothing breaks: the assumption only ever narrows access",
}
KINDS = {"refuse": "Refuses", "safer": "Falls back to less", "warn": "Warns", "feature": "Loses a feature", "none": "Nothing breaks"}


def load():
    return tomllib.loads(MAP.read_text())


def problems(m, inv):
    errs = []
    funcs = {f["id"] for f in tomllib.loads((ROOT / "docs/functions.toml").read_text())["function"]}
    spec = importlib.util.spec_from_file_location("fm", ROOT / "scripts" / "function-map.py")
    fm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fm)
    tests = fm.all_tests()
    comps = {c["id"] for c in m["component"]}
    ids = set()
    for c in m["contract"]:
        cid = c.get("id", "?")
        if cid in ids:
            errs.append(f"contract {cid} appears twice")
        ids.add(cid)
        for key in ("component", "assumes", "on_break", "playbook", "probe", "tests"):
            if not c.get(key):
                errs.append(f"contract {cid} has no {key}")
        if c.get("component") not in comps:
            errs.append(f"contract {cid}: unknown component {c.get('component')}")
        if c.get("coverage") not in ("full", "partial"):
            errs.append(f"contract {cid}: coverage must be full or partial")
        if c.get("coverage") == "partial" and not c.get("gaps"):
            errs.append(f"contract {cid}: a partly tested contract says what is not tested (gaps)")
        if c.get("on_break") not in ON_BREAK:
            errs.append(f"contract {cid}: on_break must be one of {', '.join(ON_BREAK)}")
        for f in c.get("functions", []):
            if f not in funcs:
                errs.append(f"contract {cid}: no function {f}")
        for t in c.get("tests", []) + ([c["on_break_test"]] if c.get("on_break_test") else []):
            if t not in tests:
                errs.append(f"contract {cid}: no test {t}")
    for where, gid in guards():
        if gid not in ids:
            errs.append(f"{where}: the test guards an unknown contract {gid}")
    patterns = [p for c in m["contract"] for p in c.get("covers", [])]
    own = [p for o in m.get("own", []) for p in o["covers"]]
    for item, where in sorted(inv.items()):
        if not covered(item, patterns + own):
            errs.append(f"{item[0]} {item[1]} ({where}) is covered by no contract")
    for p in patterns + own:
        kind = p.split(":", 1)[0]
        if kind not in PATTERNS:
            errs.append(f"unknown kind in pattern {p}")
    return errs


def guards():
    """(place, contract id) for every contract a test checks first with
    sam_runner::contracts::guard(&[...])."""
    out = []
    for f in sorted((ROOT / "crates").glob("*/tests/*.rs")):
        text = f.read_text()
        for mt in re.finditer(r"contracts::guard\(\s*&\[([^\]]*)\]", text):
            line = text[: mt.start()].count("\n") + 1
            for gid in re.findall(r'"([a-z0-9-]+)"', mt.group(1)):
                out.append((f"{f.relative_to(ROOT)}:{line}", gid))
    return out


def page(m):
    comps = {c["id"]: c for c in m["component"]}
    out = [
        "# SAM's contracts with the outside world",
        "",
        "> Generated by `scripts/contract-map.py` from `docs/contracts.toml`; do not edit by hand.",
        "",
        "SAM builds on programs, the kernel and the desktop it does not control. Every",
        "assumption it makes about them is written down here, with what SAM does when",
        "it breaks and how it is checked. CI fails when the code uses something",
        "outside SAM that no contract covers, so the list cannot fall behind the code.",
        "",
        "What the check cannot see: names joined to a folder at runtime, such as",
        "`pipewire-0` or `pulse/native` under the runtime folder. They are found in",
        "one place (`probe_sockets` in sam-core `host.rs`) and named in the",
        "contracts by hand; a new one there needs a contract entry too.",
        "",
        "When something stops working after an update, `sam-jail doctor --contracts`",
        "names the contract that broke and the versions involved; its playbook says",
        "where to look.",
        "",
        "| Contract | Component | When it breaks | Tested |",
        "|---|---|---|---|",
    ]
    for c in m["contract"]:
        out.append(f"| [{c['id']}](#{c['id']}) | {comps[c['component']]['name']} | {KINDS[c['on_break']]} | {'fully' if c['coverage'] == 'full' else 'partly'} |")
    n = sum(c["coverage"] == "full" for c in m["contract"])
    out += ["", f"{n} of {len(m['contract'])} contracts are tested fully; for the others the entry says what is not tested, mostly because CI machines have no sound, GPU, Wayland session or desktop services. The quick checks and the early-warning runs cover part of that."]
    out.append("")
    for c in m["contract"]:
        comp = comps[c["component"]]
        out += [f"## {c['id']}", "", c["assumes"], ""]
        out.append(f"- **Component:** {comp['name']}" + (f" ([releases]({comp['upstream']}))" if comp.get("upstream") else ""))
        out.append(f"- **When it breaks:** {ON_BREAK[c['on_break']]}." + (f" Proven by `{c['on_break_test']}`." if c.get("on_break_test") else ""))
        if c.get("functions"):
            out.append("- **SAM functions that rely on it:** " + ", ".join(f"[{f}](functions.md#{f})" for f in c["functions"]))
        out.append(f"- **Quick check:** `{c['probe']}`" if c["probe"] != "none" else "- **Quick check:** none (only the tests below)")
        out.append("- **Tests:** " + ", ".join(f"`{t}`" for t in c["tests"]) + (" (fully)" if c["coverage"] == "full" else f" (partly: {c['gaps']})"))
        guarded = sorted({w.split(":")[0].split("/")[-1] for w, g in guards() if g == c["id"]})
        if guarded:
            out.append("- **Checked first by:** " + ", ".join(f"`{g}`" for g in guarded) + " (a broken contract stops these tests with its name)")
        if c.get("covers"):
            out.append("- **Covers:** " + ", ".join(f"`{x}`" for x in c["covers"]))
        out += [f"- **If it breaks:** {c['playbook']}", ""]
    return "\n".join(out) + "\n"


def main():
    args = sys.argv[1:]
    m = load()
    inv = inventory()
    if "--inventory" in args:
        own = [p for o in m.get("own", []) for p in o["covers"]]
        for item, where in sorted(inv.items()):
            who = next((c["id"] for c in m["contract"] if covered(item, c.get("covers", []))), "own" if covered(item, own) else "UNCOVERED")
            print(f"{item[0]:8} {item[1]:45} {who:24} {where}")
        return
    errs = problems(m, inv)
    text = page(m)
    if "--check" in args:
        if PAGE.read_text() != text if PAGE.exists() else True:
            errs.append("docs/contracts.md is out of date: run scripts/contract-map.py")
    else:
        PAGE.write_text(text)
    for e in errs:
        print(" ", e)
    if errs:
        print("The contract map is not complete.")
        sys.exit(1)
    print(f"wrote docs/contracts.md: {len(m['contract'])} contracts covering {len(inv)} assumptions" if "--check" not in args else "contract map ok")


if __name__ == "__main__":
    main()
