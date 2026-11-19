#!/usr/bin/env python3
"""The contract verifier (AUTOMATION.md): compares a change with its base and
finds every weakening of a security promise. A weakening needs the owner:
it passes only with the pull request label `owner-approved`, which only
maintainers can set. Strengthening and evidence-only changes (new tests,
new contracts, versions, regenerated pages) pass.

    scripts/contract-verifier.py [BASE] [--head REF] [--approved]
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
                   removed or changed (it may only gain lines); added lines
                   that switch tests off (`cfg(`, `ignore`, `should_panic`
                   anywhere, `return`, `if false`, `exit(` inside a
                   function that was there before)
  dependencies     a crate new in Cargo.lock, an older version of one, or
                   the same version from another source or with another
                   checksum
  the gate itself  any change to the files that make up this check
                   (keeper.toml `verifier.gate`): CI runs the checker from
                   the base branch, and the next change would run the new one

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


def functions_in(text):
    """{name: body lines} of every `fn` in a Rust file, by brace matching
    (strings and comments with braces are rare in tests; a mismatch only
    makes a body longer)."""
    out = {}
    for m in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]", text):
        start = text.find("{", m.end())
        if start < 0:
            continue
        depth, i = 0, start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.setdefault(m.group(1), text[start:i + 1].splitlines())
    return out


# Added lines that can switch a test off without removing anything:
# anywhere in the file, and inside a function that was there before.
# `cfg(` and `cfg_attr` can leave a test out or mark it ignored;
# `macro_rules!` or `use … as assert` can make every check a no-op
# (`macro_rules! assert { … => {} }`): both shown to work, add-only, in the
# verification audit of 2026-11-19.
OFF_ANYWHERE = re.compile(
    r"cfg\(|cfg_attr|#\[\s*ignore|should_panic|macro_rules!"
    r"|\bas\s+(assert|assert_eq|assert_ne|debug_assert|panic|unreachable)\b"
)
OFF_INSIDE = re.compile(r"\breturn\b|\bif\s+false\b|\bexit\(|catch_unwind|\bloop\s*\{")


def protected(path, old, new):
    """A protected test file may only gain lines: any line removed or
    changed (whitespace aside) could weaken a test, for example
    assert!(x) becoming assert!(x || true), and needs the owner. Added
    lines can switch tests off too (audit P4): `#[cfg(any())]` above a
    test or `#![cfg(...)]` on the file, `#[ignore]`, or an early `return`
    or `if false` in a test or helper that was there before."""
    if not old:
        return []
    if not new:
        return [f"protected test file {path} deleted"]
    from collections import Counter
    norm = lambda l: " ".join(l.split())
    lines = lambda t: Counter(norm(l) for l in t.splitlines() if l.strip())
    out = []
    added = lines(new) - lines(old)
    for l in sorted(added):
        if OFF_ANYWHERE.search(l):
            out.append(f"{path}: an added line can switch tests off: {l[:120]}")
    of, nf = functions_in(old), functions_in(new)
    for name, body in sorted(of.items()):
        more = Counter(norm(l) for l in nf.get(name, []) if l.strip()) - Counter(norm(l) for l in body if l.strip())
        for l in sorted(more):
            if OFF_INSIDE.search(l) and not OFF_ANYWHERE.search(l):
                out.append(f"{path}: fn {name} gained a line that can skip its checks: {l[:120]}")
    gone = lines(old) - lines(new)
    if not gone:
        return out
    sample = "; ".join(list(gone)[:3])
    return out + [f"{path}: {sum(gone.values())} line(s) removed or changed (protected tests may only gain lines): {sample[:160]}"]


def packages(lock):
    """{name: {version: (source, checksum)}} of a Cargo.lock."""
    out = {}
    try:
        for p in tomllib.loads(lock).get("package", []):
            out.setdefault(p["name"], {})[p.get("version", "")] = (p.get("source"), p.get("checksum"))
    except tomllib.TOMLDecodeError:
        # Not a whole lock file (the self-test's short examples): names only.
        for n in re.findall(r'^name = "([^"]+)"', lock, re.M):
            out.setdefault(n, {})
    return out


def version_key(v):
    return [int(x) if x.isdigit() else x for x in re.split(r"[.+-]", v)]


def dependencies(old, new):
    """A new crate, an older version of one (it may bring back a known
    hole), or the same version from another source or with another
    checksum (another crate under a known name) needs the owner (audit
    P9). A newer version passes: `cargo deny` checks it for advisories."""
    o, n = packages(old), packages(new)
    out = [f"new dependency {d} (needs review: purpose, maintenance, license)" for d in sorted(set(n) - set(o))]
    for name in sorted(set(n) & set(o)):
        for v, what in n[name].items():
            if v in o[name] and o[name][v] != what:
                out.append(f"dependency {name} {v}: another source or checksum than before")
        if o[name] and n[name]:
            newest_old = max(o[name], key=version_key)
            newest_new = max(n[name], key=version_key)
            if version_key(newest_new) < version_key(newest_old):
                out.append(f"dependency {name}: older version {newest_new} instead of {newest_old}")
    return out


def gate(path, old, new):
    """The files that make up this check: CI runs them from the base
    branch, so a change here takes effect only for the next pull requests,
    and the owner decides about it (audit P2)."""
    return [f"{path}: the approval check itself changes"] if old != new else []


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


GATE = CFG.get("gate", [])


def weakenings(path, old, new):
    found = gate(path, old, new) if path in GATE else []
    if path in CHECKS:
        return found + CHECKS[path](old, new)
    if path in LISTS:
        return found + code_lists(path, old, new)
    if path in PROTECTED:
        return found + protected(path, old, new)
    if path == CFG["lockfile"]:
        return found + dependencies(old, new)
    return found


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
        ("scripts/contract-verifier.py", "old checker", "new checker", 1),
        (".github/workflows/approval.yml", "on: pull_request", "on: push", 1),
        ("scripts/contract-verifier.py", "same", "same", 0),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() { assert!(x); }\n#[test]\nfn b() { assert!(y); }", "#[test]\nfn a() { assert!(x); }", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() { assert!(x); assert!(y); }", "#[test]\nfn a() { assert!(x); }", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() { assert!(x); }", "#[test]\n#[ignore]\nfn a() { assert!(x); }", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() { assert!(x); }", "", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n    assert!(x);\n    assert!(z);\n}", 0),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n    assert!(x || true);\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n        assert!(x);\n}", 0),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n    assert!(x);\n}\n#[test]\nfn b() {\n    assert!(y);\n}", 0),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[cfg(any())]\n#[test]\nfn a() {\n    assert!(x);\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#![cfg(feature = \"never\")]\n#[test]\nfn a() {\n    assert!(x);\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n    return;\n    assert!(x);\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n    if false {\n    assert!(x);\n    }\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "fn helper() -> u8 {\n    1\n}", "fn helper() -> u8 {\n    if std::env::var(\"X\").is_err() { return 0; }\n    1\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\n#[should_panic]\nfn a() {\n    assert!(x);\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\nfn a() {\n    assert!(x);\n}\n#[test]\nfn b() {\n    if !ok() {\n        return;\n    }\n    assert!(y);\n}", 0),
        ("crates/sam-runner/tests/breakout.rs", "fn helper(c: &mut C) {\n    c.env(\"A\", 1);\n}", "fn helper(c: &mut C) {\n    c.env(\"A\", 1);\n    c.env(\"B\", 2);\n}", 0),
        ("crates/sam-runner/tests/breakout.rs", "fn a() {\n    x();\n}", "fn a() {\n    // hidden files are ignored here\n    x();\n}", 0),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "#[test]\n#[cfg_attr(all(), ignore)]\nfn a() {\n    assert!(x);\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "#[test]\nfn a() {\n    assert!(x);\n}", "macro_rules! assert { ($($t:tt)*) => {}; }\n#[test]\nfn a() {\n    assert!(x);\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "use std::fs;\n#[test]\nfn a() {\n    assert!(x);\n}", "use std::fs;\nuse crate::noop as assert;\n#[test]\nfn a() {\n    assert!(x);\n}", 1),
        ("crates/sam-runner/tests/breakout.rs", "#![allow(clippy::unwrap_used)]\n#[test]\nfn a() {\n    assert!(x);\n}", "#![allow(clippy::unwrap_used)]\n#![allow(clippy::disallowed_macros)]\n#[test]\nfn a() {\n    assert!(x);\n}", 0),
        ("Cargo.lock", 'name = "serde"\n', 'name = "serde"\nname = "evil-crate"\n', 1),
        ("Cargo.lock", '[[package]]\nname = "a"\nversion = "1.2.0"\nsource = "s"\nchecksum = "c1"\n', '[[package]]\nname = "a"\nversion = "1.1.0"\nsource = "s"\nchecksum = "c0"\n', 1),
        ("Cargo.lock", '[[package]]\nname = "a"\nversion = "1.2.0"\nsource = "s"\nchecksum = "c1"\n', '[[package]]\nname = "a"\nversion = "1.2.0"\nsource = "s"\nchecksum = "c9"\n', 1),
        ("Cargo.lock", '[[package]]\nname = "a"\nversion = "1.2.0"\nsource = "s"\nchecksum = "c1"\n', '[[package]]\nname = "a"\nversion = "1.2.0"\nsource = "git+evil"\nchecksum = "c1"\n', 1),
        ("Cargo.lock", '[[package]]\nname = "a"\nversion = "1.2.0"\nsource = "s"\nchecksum = "c1"\n', '[[package]]\nname = "a"\nversion = "1.10.0"\nsource = "s"\nchecksum = "c2"\n', 0),
        ("Cargo.lock", 'name = "serde"\nname = "old"\n', 'name = "serde"\n', 0),
        ("keeper.toml", '[risk]\ncritical = ["a", "b"]\n', '[risk]\ncritical = ["a"]\n', 1),
        ("keeper.toml", '[verifier]\nprotected_tests = ["t.rs"]\n', '[verifier]\nprotected_tests = []\n', 1),
        ("keeper.toml", '[verifier]\nlists = [{ file = "f", names = ["A", "B"] }]\n', '[verifier]\nlists = [{ file = "f", names = ["A"] }]\n', 1),
        # keeper.toml is part of the gate: even an addition needs the owner.
        ("keeper.toml", '[risk]\ncritical = ["a"]\n', '[risk]\ncritical = ["a", "b"]\n', 1),
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
    args = sys.argv[1:]
    head = "HEAD"
    if "--head" in args:
        i = args.index("--head")
        head = args[i + 1]
        del args[i:i + 2]
    base = next((a for a in args if not a.startswith("-")), "origin/main")
    try:
        files = subprocess.run(["git", "diff", "--name-only", f"{base}...{head}"], capture_output=True,
                               text=True, check=True).stdout.split()
        found = []
        for f in files:
            if f in CHECKS or f in LISTS or f in PROTECTED or f == CFG["lockfile"] or f in GATE:
                found += weakenings(f, show(base, f), show(head, f))
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
