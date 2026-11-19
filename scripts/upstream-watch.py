#!/usr/bin/env python3
"""Watches the projects SAM builds on for changes that could break a
contract, before they reach any distribution:

  - asks Repology (a public database of package versions across
    distributions) for each component's newest version;
  - reads the release notes of components hosted on GitHub and looks for
    the options SAM uses (from docs/contracts.toml) and for words like
    "deprecated", "removed" or "renamed";
  - opens one issue per component and version when the notes mention
    something SAM relies on. A plain new version needs no issue: the
    nightly early-warning run tests it as soon as it reaches Rawhide or Arch.

    scripts/upstream-watch.py [--dry-run]

Sends nothing about the user or the project except the generic user agent
Repology asks automated clients to set. Needs gh for the issues.
"""
import json
import pathlib
import re
import subprocess
import sys
import time
import tomllib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
LABEL = "upstream-change"
AGENT = "SAM-contract-watch/1 (+https://github.com/gitzekatze/SAM)"
WORDS = re.compile(r"deprecat|remov|renam|no longer|breaking|incompatib|drop(ped)? support", re.I)


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def newest(repology):
    """The newest version Repology knows for a project, or None."""
    try:
        pkgs = get(f"https://repology.org/api/v1/project/{repology}")
    except Exception as e:  # network trouble is not a contract problem
        print(f"  {repology}: Repology not reachable ({e})")
        return None
    versions = [p["version"] for p in pkgs if p.get("status") == "newest"]
    return versions[0] if versions else None


def release_notes(upstream):
    """(tag, notes) of the latest GitHub release, for GitHub-hosted projects."""
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)/releases", upstream or "")
    if not m:
        return None, ""
    try:
        r = get(f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}/releases/latest")
    except Exception:
        return None, ""
    return r.get("tag_name"), r.get("body") or ""


def quoted(text, limit=300):
    """Text from another project (a line of its release notes, its tag) as
    inline code, cut to `limit`: GitHub turns nothing in it into a mention
    of a person, a link or formatting (audit P15)."""
    flat = " ".join(str(text).split()).replace("`", "'")
    if len(flat) > limit:
        flat = flat[:limit] + "…"
    return f"`{flat}`" if flat else "``"


def self_test():
    cases = [
        ("@alice fixed --splice-only", "`@alice fixed --splice-only`"),
        ("see [here](https://evil.example) `x`", "`see [here](https://evil.example) 'x'`"),
        ("a\n\tb", "`a b`"),
        ("x" * 400, "`" + "x" * 300 + "…`"),
    ]
    wrong = [(i, quoted(i), o) for i, o in cases if quoted(i) != o]
    for i, got, want in wrong:
        print(f"FAIL {i[:30]!r}: {got!r} != {want!r}")
    print(f"upstream-watch self-test: {len(cases) - len(wrong)} of {len(cases)} right")
    sys.exit(1 if wrong else 0)


def gh(*args, dry):
    if dry:
        print("  gh", " ".join(a if len(a) < 70 else a[:67] + "..." for a in args))
        return "[]" if "list" in args else ""
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def main():
    if "--self-test" in sys.argv:
        self_test()
    dry = "--dry-run" in sys.argv
    m = tomllib.loads((ROOT / "docs" / "contracts.toml").read_text())
    gh("label", "create", LABEL, "--color", "FBCA04", "--force",
       "--description", "A project SAM builds on changed something SAM relies on", dry=dry)
    seen = {i["title"] for i in json.loads(gh("issue", "list", "--label", LABEL, "--state", "all",
                                              "--limit", "500", "--json", "title", dry=dry) or "[]")}
    for comp in m["component"]:
        if not comp.get("repology"):
            continue
        version = newest(comp["repology"])
        time.sleep(1.1)  # Repology asks for at most one request per second
        contracts = [c for c in m["contract"] if c["component"] == comp["id"]]
        options = sorted({p.split(":", 1)[1] for c in contracts for p in c.get("covers", [])
                          if p.startswith("option:") and len(p) > len("option:--")})
        tag, notes = release_notes(comp.get("upstream"))
        hits = []
        for line in notes.splitlines():
            if any(re.search(rf"(?<![\w-]){re.escape(o)}(?![\w-])", line) for o in options) or WORDS.search(line):
                hits.append(line.strip())
        label = (tag or version or "?")[:60]
        print(f"{comp['name']}: newest {version or 'unknown'}" + (f", release {tag}" if tag else "")
              + (f", {len(hits)} line(s) worth a look" if hits else ""))
        title = f"Upstream: {comp['name']} {label}"
        if not hits or title in seen:
            continue
        body = (f"The release notes of **{comp['name']}** {quoted(label, 60)} mention something SAM relies on "
                f"or a removal. Check the lines below against the contracts.\n\n"
                + "\n".join(f"- {quoted(h)}" for h in hits[:30]) + "\n\n"
                + "**Contracts with this component:** " + ", ".join(f"`{c['id']}`" for c in contracts) + "\n\n"
                + f"**Release notes:** {comp.get('upstream')}\n\n"
                + "**Next step:** run the early-warning workflow (Actions → Early warning → Run workflow) "
                  "once the version reaches Fedora Rawhide or Arch, and read the contracts' playbooks "
                  "(docs/contracts.md).\n\n_Opened by the weekly upstream watch (.github/workflows/upstream-watch.yml)._\n")
        gh("issue", "create", "--title", title, "--label", LABEL, "--body", body, dry=dry)


if __name__ == "__main__":
    main()
