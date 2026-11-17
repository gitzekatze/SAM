#!/usr/bin/env python3
"""The notes of changes not yet released: one small file per change in
changes/, instead of every pull request writing at the top of CHANGELOG.md.
Two pull requests then never edit the same lines, so merging one never makes
the other conflict.

    scripts/changes.py list         the note files, newest first
    scripts/changes.py merged       CHANGELOG.md with the notes under Unreleased
                                    (what the website shows as "What's new")
    scripts/changes.py has-notes    exit 0 when there is anything to release
    scripts/changes.py collect      move the notes into CHANGELOG.md under
                                    Unreleased and delete their files (the
                                    release does this before it reads the notes)
    scripts/changes.py --self-test

A note file is Markdown: a "### " heading saying what changed for the user,
then bullet points, as in CHANGELOG.md (see changes/README.md).
"""
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def note_files(root):
    """The note files, newest first: by the time git first saw them (a new,
    uncommitted one counts as newest), then by name."""
    files = [p for p in (root / "changes").glob("*.md") if p.name != "README.md"]

    def added(p):
        r = subprocess.run(["git", "-C", str(root), "log", "--diff-filter=A", "--format=%ct", "--", str(p.relative_to(root))],
                           capture_output=True, text=True)
        stamps = r.stdout.split()
        return int(stamps[-1]) if r.returncode == 0 and stamps else 2**62

    return sorted(files, key=lambda p: (-added(p), p.name))


def merged(root):
    """CHANGELOG.md with every note inserted at the top of Unreleased."""
    text = (root / "CHANGELOG.md").read_text()
    notes = "".join(p.read_text().strip() + "\n\n" for p in note_files(root))
    if not notes:
        return text
    m = re.search(r"^## Unreleased[^\n]*\n(\n*)", text, re.M)
    if not m:
        raise SystemExit("CHANGELOG.md has no '## Unreleased' heading")
    return text[:m.end()] + notes + text[m.end():]


def has_notes(root):
    text = merged(root)
    m = re.search(r"^## Unreleased[^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    body = re.sub(r"<!--.*?-->", "", m.group(1), flags=re.S) if m else ""
    return bool(body.strip())


def collect(root):
    files = note_files(root)
    (root / "CHANGELOG.md").write_text(merged(root))
    for p in files:
        p.unlink()
    return len(files)


def self_test():
    with tempfile.TemporaryDirectory() as t:
        root = pathlib.Path(t)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / "changes").mkdir()
        (root / "changes" / "README.md").write_text("how to write a note\n")
        (root / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n### Old\n\n- old\n\n## 0.1.0 - 2026-01-01\n\n- first\n")
        assert not [p for p in note_files(root)], "README is not a note"
        assert has_notes(root)
        (root / "changes" / "a.md").write_text("### A\n\n- a\n")
        (root / "changes" / "b.md").write_text("### B\n\n- b\n")
        m = merged(root)
        assert m.index("### A") < m.index("### Old") and m.index("### B") < m.index("### Old"), m
        assert m.index("## 0.1.0") > m.index("### Old")
        assert collect(root) == 2
        assert not (root / "changes" / "a.md").exists() and (root / "changes" / "README.md").exists()
        assert "### A" in (root / "CHANGELOG.md").read_text()
        assert collect(root) == 0, "nothing twice"
        (root / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n<!-- notes go to changes/ -->\n\n## 0.1.0\n")
        assert not has_notes(root), "a comment is not a note"
        (root / "changes" / "c.md").write_text("### C\n\n- c\n")
        assert has_notes(root)
    print("changes: all 10 checks right")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "--self-test":
        self_test()
    elif cmd == "list":
        for p in note_files(ROOT):
            print(p.relative_to(ROOT))
    elif cmd == "merged":
        sys.stdout.write(merged(ROOT))
    elif cmd == "has-notes":
        sys.exit(0 if has_notes(ROOT) else 1)
    elif cmd == "collect":
        print(f"{collect(ROOT)} note(s) moved into CHANGELOG.md")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
