#!/usr/bin/env python3
"""The contract verifier (AUTOMATION.md): compares a change with its base and
finds every weakening of a security promise. A weakening needs the owner:
it passes only with the pull request label `owner-approved`, which only
maintainers can set. Strengthening and evidence-only changes (new tests,
new contracts, versions, regenerated pages) pass.

    scripts/contract-verifier.py [BASE] [--approved]
    scripts/contract-verifier.py --self-test

Weakening means:
  contracts.toml   a contract or a covered item removed; `assumes` or
                   `playbook` changed; `on_break` moved toward less safe
                   (refuse, safer, warn, feature, none); `coverage` from
                   full to partial; a test removed; a quick check removed
  functions.toml   a function removed; its promise changed; a test removed
  syscalls         a syscall refused less than before (blocked > blocked unless
                   nested sandboxes > limited > blocked by the strict filter > allowed)
  threat model     a row of a table removed or changed
  code lists       an entry removed from NEVER_FORWARD_FROM_APP,
                   DANGEROUS_BUS_NAMES, SENSITIVE_PATHS, PROTECTED_RO or
                   SENSITIVE_DOTFILES
  protected tests  a protected test file deleted, or any line in it
                   removed or changed (it may only gain lines)
  dependencies     a crate new in Cargo.lock

Verdict: PASS, NEEDS-OWNER (exit 1 without --approved), FAIL (exit 2:
something could not be read; the safe answer is no).
"""
import pathlib
import re
import subprocess
import sys
import tomllib

SAFETY = ["refuse", "safer", "warn", "feature", "none"]
ROOT = pathlib.Path(__file__).resolve().parent.parent
CFG = tomllib.loads((ROOT / "keeper.toml").read_text())["verifier"]
# Safety lists in the code (keeper.toml): removing an entry is a weakening.
LISTS = {l["file"]: l["names"] for l in CFG["lists"]}


def contracts(old, new):
    out = []
    o = {c["id"]: c for c in tomllib.loads(old).get("contract", [])}
    n = {c["id"]: c for c in tomllib.loads(new).get("contract", [])}
    for cid, oc in o.items():
        nc = n.get(cid)
        if nc is None:
            out.append(f"contract {cid} removed")
            continue
        for p in set(oc.get("covers", [])) - set(nc.get("covers", [])):
            out.append(f"contract {cid}: no longer covers {p}")
        for key in ("assumes", "playbook"):
            if oc.get(key) != nc.get(key):
                out.append(f"contract {cid}: {key} changed")
        a, b = oc.get("on_break"), nc.get("on_break")
        if a in SAFETY and b in SAFETY and SAFETY.index(b) > SAFETY.index(a):
            out.append(f"contract {cid}: on_break {a} -> {b}")
        if oc.get("coverage") == "full" and nc.get("coverage") != "full":
            out.append(f"contract {cid}: coverage full -> {nc.get('coverage')}")
        for t in set(oc.get("tests", [])) - set(nc.get("tests", [])):
            out.append(f"contract {cid}: test {t} removed")
        if oc.get("probe", "none") != "none" and nc.get("probe", "none") == "none":
            out.append(f"contract {cid}: quick check removed")
    return out


def functions(old, new):
    out = []
    o = {f["id"]: f for f in tomllib.loads(old).get("function", [])}
    n = {f["id"]: f for f in tomllib.loads(new).get("function", [])}
    for fid, of in o.items():
        nf = n.get(fid)
        if nf is None:
            out.append(f"function {fid} removed")
            continue
        if of.get("promise") != nf.get("promise"):
            out.append(f"function {fid}: promise changed")
        for t in set(of.get("tests", [])) - set(nf.get("tests", [])):
            out.append(f"function {fid}: test {t} removed")
    return out


# How strongly the filter refuses a call, by the review list's status: a
# step down (or a call that disappears) weakens the filter.
SYSCALL_STRENGTH = {
    "blocked": 4,
    "blocked unless nested sandboxes": 3,
    "limited": 2,
    "blocked by the strict filter": 1,
    "allowed": 0,
}


def syscalls(old, new):
    def statuses(t):
        return dict(l.split("\t", 1) for l in t.splitlines() if "\t" in l and not l.startswith("#"))
    o, n = statuses(old), statuses(new)
    out = []
    for name in sorted(o):
        before, after = o[name], n.get(name, "allowed")
        if SYSCALL_STRENGTH.get(after, 0) < SYSCALL_STRENGTH.get(before, 0):
            out.append(f"syscall {name}: {before} -> {after}")
    return out


def threat_model(old, new):
    rows = lambda t: {l.strip() for l in t.splitlines() if l.strip().startswith("|") and not set(l.strip()) <= set("|-: ")}
    return [f"threat model row removed or changed: {r[:80]}" for r in sorted(rows(old) - rows(new))]


def code_lists(path, old, new):
    out = []
    for name in LISTS[path]:
        def entries(t):
            m = re.search(rf"{name}[^=]*=\s*&?\[(.*?)\];", t, re.S)
            return set(re.findall(r'"([^"]*)"', m.group(1))) if m else set()
        for e in sorted(entries(old) - entries(new)):
            out.append(f"{name}: entry {e} removed")
    return out


# The tests that prove the security promises (keeper.toml): automation may
# add to them, never remove, skip or weaken them.
PROTECTED = CFG["protected_tests"]


def protected(path, old, new):
    """A protected test file may only gain lines: any line removed or
    changed (whitespace aside) could weaken a test, for example
    assert!(x) becoming assert!(x || true), and needs the owner."""
    if not old:
        return []
    if not new:
        return [f"protected test file {path} deleted"]
    from collections import Counter
    lines = lambda t: Counter(" ".join(l.split()) for l in t.splitlines() if l.strip())
    out = []
    if new.count("#[ignore") > old.count("#[ignore"):
        out.append(f"{path}: a test is switched off (#[ignore] added)")
    gone = lines(old) - lines(new)
    if not gone:
        return out
    sample = "; ".join(list(gone)[:3])
    return out + [f"{path}: {sum(gone.values())} line(s) removed or changed (protected tests may only gain lines): {sample[:160]}"]


def dependencies(old, new):
    names = lambda t: set(re.findall(r'^name = "([^"]+)"', t, re.M))
    return [f"new dependency {d} (needs review: purpose, maintenance, license)" for d in sorted(names(new) - names(old))]


def keeper(old, new):
    """keeper.toml decides what is critical, protected and watched: removing
    anything from those lists is a weakening."""
    out = []
    o, n = tomllib.loads(old), tomllib.loads(new)
    for section, key in [("risk", "critical"), ("verifier", "protected_tests")]:
        for e in sorted(set(o.get(section, {}).get(key, [])) - set(n.get(section, {}).get(key, []))):
            out.append(f"keeper.toml: {e} removed from {section}.{key}")
    nl = {(l["file"], x) for l in n.get("verifier", {}).get("lists", []) for x in l["names"]}
    for l in o.get("verifier", {}).get("lists", []):
        for x in l["names"]:
            if (l["file"], x) not in nl:
                out.append(f"keeper.toml: the safety list {x} in {l['file']} is no longer watched")
    for key in ("contracts", "functions", "syscalls", "threat_model"):
        if o.get("verifier", {}).get(key) and o["verifier"][key] != n.get("verifier", {}).get(key):
            out.append(f"keeper.toml: the watched {key} document changed")
    return out


CHECKS = {
    CFG["contracts"]: contracts,
    CFG["functions"]: functions,
    CFG["syscalls"]: syscalls,
    CFG["threat_model"]: threat_model,
    "keeper.toml": keeper,
}


def weakenings(path, old, new):
    if path in CHECKS:
        return CHECKS[path](old, new)
    if path in LISTS:
        return code_lists(path, old, new)
    if path in PROTECTED:
        return protected(path, old, new)
    if path == CFG["lockfile"]:
        return dependencies(old, new)
    return []


def show(ref, path):
    r = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def self_test():
    base_c = '[[contract]]\nid = "a"\nassumes = "x"\nplaybook = "p"\non_break = "refuse"\ncoverage = "full"\nprobe = "userns"\ncovers = ["path:/a", "path:/b"]\ntests = ["t1", "t2"]\n'
    cases = [
        ("docs/contracts.toml", base_c, base_c.replace('"refuse"', '"warn"'), 1),
        ("docs/contracts.toml", base_c, base_c.replace('"full"', '"partial"'), 1),
        ("docs/contracts.toml", base_c, base_c.replace(', "t2"', ''), 1),
        ("docs/contracts.toml", base_c, base_c.replace(', "path:/b"', ''), 1),
        ("docs/contracts.toml", base_c, base_c.replace('"x"', '"y"'), 1),
        ("docs/contracts.toml", base_c, base_c.replace('"userns"', '"none"'), 1),
        ("docs/contracts.toml", base_c, "", 1),
        ("docs/contracts.toml", base_c, base_c.replace('"t2"]', '"t2", "t3"]'), 0),
        ("docs/contracts.toml", base_c, base_c.replace('"warn"', '"refuse"'), 0),
        ("docs/functions.toml", '[[function]]\nid = 1\npromise = "p"\ntests = ["a"]\n', '[[function]]\nid = 1\npromise = "q"\ntests = ["a"]\n', 1),
        ("docs/functions.toml", '[[function]]\nid = 1\npromise = "p"\ntests = ["a"]\n', '[[function]]\nid = 1\npromise = "p"\ntests = []\n', 1),
        ("docs/syscalls-reviewed.txt", "mount\tblocked\nread\tallowed\n", "mount\tallowed\nread\tallowed\n", 1),
        ("docs/syscalls-reviewed.txt", "read\tallowed\n", "read\tblocked\n", 0),
        ("docs/syscalls-reviewed.txt", "mount\tblocked unless nested sandboxes\n", "mount\tallowed\n", 1),
        ("docs/syscalls-reviewed.txt", "ptrace\tblocked\n", "ptrace\tblocked by the strict filter\n", 1),
        ("docs/syscalls-reviewed.txt", "ioctl\tlimited\n", "ioctl\tblocked\n", 0),
        ("docs/syscalls-reviewed.txt", "mount\tblocked\n", "", 1),
        ("docs/threat-model.md", "| A | B |\n|---|---|\n| x | `t` |\n", "| A | B |\n|---|---|\n", 1),
        ("crates/sam-runner/src/netns.rs", 'const NEVER_FORWARD_FROM_APP: &[&str] = &[\n    "~1-1023", "~11434",\n];', 'const NEVER_FORWARD_FROM_APP: &[&str] = &[\n    "~1-1023",\n];', 1),
        ("crates/sam-runner/src/netns.rs", 'const NEVER_FORWARD_FROM_APP: &[&str] = &["~1"];', 'const NEVER_FORWARD_FROM_APP: &[&str] = &["~1", "~2"];', 0),
        ("README.md", "a", "b", 0),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() { assert!(x); }\n#[test]\nfn b() { assert!(y); }", "#[test]\nfn a() { assert!(x); }", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() { assert!(x); assert!(y); }", "#[test]\nfn a() { assert!(x); }", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() { assert!(x); }", "#[test]\n#[ignore]\nfn a() { assert!(x); }", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() { assert!(x); }", "", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n    assert!(x);\n    assert!(z);\n}", 0),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n    assert!(x || true);\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n        assert!(x);\n}", 0),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n    assert!(x);\n}\n#[test]\nfn b() {\n    assert!(y);\n}", 0),
        ("Cargo.lock", 'name = "serde"\n', 'name = "serde"\nname = "evil-crate"\n', 1),
        ("Cargo.lock", 'name = "serde"\nname = "old"\n', 'name = "serde"\n', 0),
        ("keeper.toml", '[risk]\ncritical = ["a", "b"]\n', '[risk]\ncritical = ["a"]\n', 1),
        ("keeper.toml", '[verifier]\nprotected_tests = ["t.rs"]\n', '[verifier]\nprotected_tests = []\n', 1),
        ("keeper.toml", '[verifier]\nlists = [{ file = "f", names = ["A", "B"] }]\n', '[verifier]\nlists = [{ file = "f", names = ["A"] }]\n', 1),
        ("keeper.toml", '[risk]\ncritical = ["a"]\n', '[risk]\ncritical = ["a", "b"]\n', 0),
    ]
    wrong = 0
    for path, old, new, want in cases:
        got = len(weakenings(path, old, new))
        if (got > 0) != (want > 0):
            wrong += 1
            print(f"FAIL {path}: {got} weakening(s), expected {'some' if want else 'none'}")
    print(f"contract-verifier self-test: {len(cases) - wrong} of {len(cases)} right")
    sys.exit(1 if wrong else 0)


def main():
    if "--self-test" in sys.argv:
        self_test()
    approved = "--approved" in sys.argv
    base = next((a for a in sys.argv[1:] if not a.startswith("-")), "origin/main")
    try:
        files = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"], capture_output=True,
                               text=True, check=True).stdout.split()
        found = []
        for f in files:
            if f in CHECKS or f in LISTS or f in PROTECTED or f == CFG["lockfile"]:
                found += weakenings(f, show(base, f), show("HEAD", f))
    except Exception as e:
        print(f"### Contract verifier: FAIL\n\nCould not compare with {base}: {e}. The safe answer is no.")
        sys.exit(2)
    if not found:
        print("### Contract verifier: PASS\n\nNo security promise is weakened.")
        return
    print("### Contract verifier: " + ("PASS (owner-approved)" if approved else "NEEDS-OWNER") + "\n")
    print("This change weakens security promises:\n")
    for w in found:
        print(f"- {w}")
    if not approved:
        print("\nIt passes only when the owner sets the label `owner-approved` (AUTOMATION.md).")
        sys.exit(1)


if __name__ == "__main__":
    main()
