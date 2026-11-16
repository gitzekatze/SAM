#!/usr/bin/env python3
"""The risk class of a change (AUTOMATION.md): low, medium, high or critical,
computed from the files it touches and from what it adds. The highest file
wins. The class decides what automation may do with a change and who must
merge it; it is never lowered by automation.

    scripts/risk-class.py [BASE]        class of the changes since BASE
                                        (default origin/main), Markdown
    scripts/risk-class.py --self-test   checks the rules with made-up changes

Rules (from keeper.toml, [risk]), first match per file:
  critical  sandbox, launch, network, D-Bus proxy, terminal relay, kernel
            layers, Wayland context, updates, signatures, release keys,
            unpacking, permissions and risk, the contract and security
            documents, release scripts, automation itself; and any added
            `unsafe`
  high      workflows, build files, packaging, storage formats
  medium    the rest of the code, translations (their wording carries
            security meaning, too)
  low       website, handbook, generated pages, other documents
"""
import fnmatch
import pathlib
import subprocess
import sys
import tomllib

ORDER = ["low", "medium", "high", "critical"]

ROOT = pathlib.Path(__file__).resolve().parent.parent
_cfg = tomllib.loads((ROOT / "keeper.toml").read_text())["risk"]
# keeper.toml decides what is critical, so it is critical itself.
RULES = [("critical", _cfg["critical"] + ["keeper.toml"]), ("high", _cfg["high"]),
         ("medium", _cfg["medium"]), ("low", ["*"])]


def class_of(path):
    for cls, pats in RULES:
        if any(fnmatch.fnmatchcase(path, p) for p in pats):
            return cls
    return "low"


def added_unsafe(diff):
    """Files whose added lines contain `unsafe` code."""
    out, current = set(), None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith("+") and not line.startswith("+++") and current and current.endswith(".rs"):
            code = line[1:].split("//")[0]
            if "unsafe " in code or "unsafe{" in code:
                out.add(current)
    return out


def classify(files, diff=""):
    """(class, {file: class}) for a change."""
    per = {f: class_of(f) for f in files}
    for f in added_unsafe(diff):
        per[f] = "critical"
    top = max(per.values(), key=ORDER.index) if per else "low"
    return top, per


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def self_test():
    cases = [
        (["docs/handbook/tips.md"], "", "low"),
        (["docs/handbook/tips.md", "crates/sam-gtk/src/window.rs"], "", "medium"),
        (["po/de.po"], "", "medium"),
        ([".github/workflows/ci.yml"], "", "high"),
        (["Cargo.lock"], "", "high"),
        (["docs/threat-model.md"], "", "critical"),
        (["docs/syscalls-reviewed.txt", "README.md"], "", "critical"),
        (["crates/sam-sandbox/src/lib.rs"], "", "critical"),
        (["crates/sam-gtk/src/main.rs"], "+++ b/crates/sam-gtk/src/main.rs\n+    unsafe { libc::getuid() };\n", "critical"),
        (["crates/sam-gtk/src/main.rs"], "+++ b/crates/sam-gtk/src/main.rs\n+    // no unsafe here\n", "medium"),
    ]
    bad = 0
    for files, diff, want in cases:
        got, _ = classify(files, diff)
        if got != want:
            bad += 1
            print(f"FAIL {files}: {got}, expected {want}")
    print(f"risk-class self-test: {len(cases) - bad} of {len(cases)} right")
    sys.exit(1 if bad else 0)


def main():
    if "--self-test" in sys.argv:
        self_test()
    base = next((a for a in sys.argv[1:] if not a.startswith("-")), "origin/main")
    files = [f for f in git("diff", "--name-only", f"{base}...HEAD").splitlines() if f]
    diff = git("diff", "-U0", f"{base}...HEAD")
    top, per = classify(files, diff)
    print(f"### Risk class: **{top}**\n")
    print("| File | Class |\n|---|---|")
    for f, c in sorted(per.items(), key=lambda kv: (-ORDER.index(kv[1]), kv[0])):
        print(f"| `{f}` | {c} |")
    print("\nWhat each class allows: AUTOMATION.md.")


if __name__ == "__main__":
    main()
