#!/usr/bin/env python3
"""The rules every GitHub workflow of SAM keeps (AUTOMATION.md). It runs in
the required test job, so a change that breaks one cannot be merged; the
lint job (zizmor, shellcheck, ruff) only warns.

Workflow safety:
1. `pull_request_target` together with a checkout of the pull request's
   code: the workflow runs foreign code with the repository's secrets.
2. Text from issues, pull requests or comments (titles, bodies, branch
   names), workflow inputs, other steps' or jobs' outputs, or a matrix
   computed at run time, written straight into a `run:` command with
   ${{ ... }}: the text becomes shell code. Such values go through `env:`
   instead (audit P10).
3. Every action is pinned to a full commit hash, never a tag a third party
   can move; every checkout keeps no token (`persist-credentials: false`)
   (audit P6).
4. Read-only by default: no workflow grants a write right to all its jobs,
   and only the jobs listed in WRITES may write, each only what it needs
   (audit P7).
5. A file a workflow downloads is checked against a fixed checksum in the
   same step (audit P8).

What the checks cover:
6. Every shell script in the repository is linted by shellcheck and parsed
   in CI, and every Python file is linted by ruff: the globs in ci.yml
   cover them all (audit P11, P12).
7. A document the code reads (include_str!, a path joined in a test)
   counts as code in CI's change filter, so a change to it alone still runs
   the tests (audit D-M11).
8. Every `cargo test` run by a workflow or a script runs with
   SAM_REQUIRE_SANDBOX=1: a sandbox test that cannot build its sandbox
   fails instead of passing without testing (audit D-M11).

    scripts/workflow-check.py              check the repository
    scripts/workflow-check.py --self-test  check the rules on made-up files
"""
import fnmatch
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
UNTRUSTED = re.compile(
    r"\$\{\{\s*(github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)"
    r"[^}]*\.(title|body|name|label|message|head_ref|ref|email)|head_ref|event\.inputs\.[^}]*)"
    r"|inputs\.[^}]*|(steps|needs)\.[^}]*\.outputs\.[^}]*)\s*\}\}")
MATRIX = re.compile(r"\$\{\{\s*matrix\.")
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")
# (workflow, job) -> the rights that job may write; everything else reads.
WRITES = {
    ("approval.yml", "forget-approval"): {"pull-requests"},
    ("release.yml", "appimage"): {"id-token", "attestations"},
    ("release.yml", "sbom-provenance"): {"id-token", "attestations"},
    ("release.yml", "draft"): {"contents"},
    ("pages.yml", "deploy"): {"pages", "id-token"},
    ("canary.yml", "report"): {"issues"},
    ("upkeep.yml", "report"): {"issues"},
    ("upstream-watch.yml", "watch"): {"issues"},
}


def indent(line):
    return len(line) - len(line.lstrip())


def block(lines, start):
    """The lines below lines[start] that are indented deeper (blank lines
    included), as (number, line) pairs."""
    out, base = [], indent(lines[start])
    for n in range(start + 1, len(lines)):
        if lines[n].strip() and indent(lines[n]) <= base:
            break
        out.append((n, lines[n]))
    return out


def jobs(lines):
    """{job name: (line number, its lines)} under the top-level `jobs:`."""
    out = {}
    for n, line in enumerate(lines):
        if line.rstrip() == "jobs:":
            for m, l in block(lines, n):
                if l.strip() and indent(l) == 2 and re.match(r"\s*[\w-]+:\s*$", l):
                    out[l.strip()[:-1]] = (m, [x for _, x in block(lines, m)])
    return out


def run_blocks(lines):
    """(first line number, text) of every `run:` command."""
    out = []
    for n, line in enumerate(lines):
        m = re.match(r"\s*(- )?run:(.*)$", line)
        if m:
            text = m.group(2) + "\n" + "\n".join(l for _, l in block(lines, n))
            out.append((n + 1, text))
    return out


def steps(lines):
    """Every step as its list of lines (the `- ` line first)."""
    out = []
    for n, line in enumerate(lines):
        if line.strip() == "steps:":
            items = block(lines, n)
            first = next((l for _, l in items if l.strip()), None)
            if first is None:
                continue
            k = indent(first)
            cur = None
            for _, l in items:
                if l.strip() and indent(l) == k and l.lstrip().startswith("- "):
                    cur = [l]
                    out.append(cur)
                elif cur is not None:
                    cur.append(l)
    return out


def unquote(s):
    return s.strip().strip("'\"").strip()


def permissions(lines):
    """{right: level} of the first `permissions:` in lines (or None): a
    block, a flow mapping (`{ contents: write }`) or one level for all
    (`write-all`), quoted or not."""
    for n, line in enumerate(lines):
        m = re.match(r"\s*permissions:\s*(.*?)\s*(#.*)?$", line)
        if m:
            value = m.group(1)
            if value.startswith("{"):
                pairs = value.strip("{}").split(",")
            elif value:
                return {"*": unquote(value)}
            else:
                pairs = [l.split("#")[0] for _, l in block(lines, n)]
            out = {}
            for pair in pairs:
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    out[unquote(k)] = unquote(v)
            return out
    return None


def workflow_problems(name, text):
    """Rules 1 to 5 for one workflow file."""
    errs = []
    lines = text.splitlines()
    base = name.rsplit("/", 1)[-1]
    if "pull_request_target" in text and re.search(
            r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", text):
        errs.append(f"{name}: pull_request_target checks out the pull request's code")
    the_jobs = jobs(lines)
    computed = set()
    for job, (_, jl) in the_jobs.items():
        for i, l in enumerate(jl):
            # Anywhere in the job's strategy: the matrix itself, or its
            # include list or one of its values.
            if re.match(r"\s*strategy:", l) and any(
                    "fromJSON(" in x for x in [l] + [y for _, y in block(jl, i)]):
                computed.add(job)
    for first, body in run_blocks(lines):
        job = next((j for j, (m, jl) in the_jobs.items() if m < first - 1 <= m + len(jl)), None)
        for k, l in enumerate(body.splitlines()):
            if UNTRUSTED.search(l):
                errs.append(f"{name}:{first + k}: untrusted text inline in a run command; pass it through env:")
            elif job in computed and MATRIX.search(l):
                errs.append(f"{name}:{first + k}: a matrix value computed at run time inline in a run command; pass it through env:")
    def pinned(uses):
        if not (uses.startswith("./") or PINNED.match(uses)
                or re.match(r"^docker://\S+@sha256:[0-9a-f]{64}$", uses)):
            errs.append(f"{name}: {uses} is not pinned to a full commit hash")
    # A job that calls another workflow (`uses:` on the job itself).
    for _, jl in the_jobs.values():
        keys = next((indent(l) for l in jl if l.strip()), None)
        for l in jl:
            m = re.match(r"\s*uses:\s*(\S+)", l)
            if m and indent(l) == keys:
                pinned(unquote(m.group(1)))
    for st in steps(lines):
        uses = next((re.match(r"\s*(- )?uses:\s*(\S+)", l).group(2) for l in st
                     if re.match(r"\s*(- )?uses:\s*\S", l)), None)
        if uses is None:
            continue
        pinned(uses)
        if uses.startswith("actions/checkout@") and not any(
                re.match(r"\s*persist-credentials:\s*false\s*$", l) for l in st):
            errs.append(f"{name}: a checkout keeps its token (persist-credentials: false is missing)")
    top = top_level(lines)
    if top is None:
        errs.append(f"{name}: no top-level permissions (they default to whatever the repository allows)")
    elif any(v in ("write", "write-all") for v in top.values()):
        errs.append(f"{name}: write rights for every job; give them to the job that needs them")
    for job, (_, jl) in the_jobs.items():
        p = permissions(jl) or {}
        for right, level in p.items():
            if level in ("write", "write-all") and right not in WRITES.get((base, job), set()):
                errs.append(f"{name}: job {job} may write {right}, which is not in workflow-check.py WRITES")
    for first, body in run_blocks(lines):
        if re.search(r"\b(curl|wget)\b", body) and not re.search(r"sha256sum -c|SHA256\b|_SHA256=", body):
            errs.append(f"{name}:{first}: a download without a fixed checksum in the same step")
    return errs


def top_level(lines):
    """The top-level `permissions:` block (indent 0) as permissions() reads it."""
    for n, line in enumerate(lines):
        if re.match(r"permissions:", line):
            return permissions(lines[n:n + 1 + len(block(lines, n))])
    return None


def lint_problems(ci, shell_files, python_files, exists):
    """Rule 6: the shellcheck, parse and ruff commands in ci.yml cover every
    shell and Python file. `exists(pattern)` lists the files a glob matches."""
    errs = []

    def globs(regex, what):
        m = re.search(regex, ci, re.M)
        if not m:
            errs.append(f"ci.yml: no {what} command found")
            return None
        return m.group(1).split()

    sc = globs(r"^\s*(?:- )?run: shellcheck(?: -\S+(?: \w+)?)* ((?:\S+\.sh ?)+)\s*$", "shellcheck")
    parse = globs(r"for f in ((?:\S+\.sh ?)+); do sh -n", "'sh -n' parse")
    ruff = globs(r"ruff[=\d.]* check ((?:[\w./-]+ ?)+)\s*$", "ruff")
    for what, pats in (("shellcheck", sc), ("the 'Shell scripts parse' step", parse)):
        if pats is None:
            continue
        covered = set().union(*(exists(p) for p in pats))
        for f in sorted(set(shell_files) - covered):
            errs.append(f"{f}: not covered by {what} in ci.yml")
    if ruff is not None:
        for f in sorted(python_files):
            if not any(f == d or f.startswith(d.rstrip("/") + "/") for d in ruff):
                errs.append(f"{f}: not covered by ruff in ci.yml")
    return errs


READ = re.compile(r"(?:include_str!|include_bytes!|\.join)\(\s*\"((?:\.\./)*[\w./-]+)\"")


def code_doc_problems(ci, sources, tracked):
    """Rule 7: `sources` is {path: text} of the Rust code, `tracked` the
    repository's files."""
    errs = []
    docs = re.search(r"^\s*docs='([^']+)'", ci, re.M)
    code = re.search(r"^\s*code_docs='([^']+)'", ci, re.M)
    if not (docs and code):
        return ["ci.yml: the change filter (docs=, code_docs=) was not found"]
    docs, code = re.compile(docs.group(1)), re.compile(code.group(1))
    for path, text in sorted(sources.items()):
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("//"):
                continue
            for m in READ.finditer(line):
                f = re.sub(r"^(\.\./)+", "", m.group(1))
                if f in tracked and docs.search(f) and not code.search(f):
                    errs.append(f"{path}:{n}: reads {f}, which ci.yml counts as a document only (add it to code_docs)")
    return errs


def sandbox_problems(name, text, workflow):
    """Rule 8 for one workflow (each run: command on its own, with its
    step's and the workflow's env:) or shell script (the whole file)."""
    errs = []
    lines = text.splitlines()
    if workflow:
        top = top_env = False
        for line in lines:
            if re.match(r"env:\s*$", line):
                top = True
            elif line.strip() and indent(line) == 0:
                top = False
            elif top and re.match(r"\s*SAM_REQUIRE_SANDBOX:\s*['\"]?1['\"]?\s*$", line):
                top_env = True
        parts = []
        for first, body in run_blocks(lines):
            step_env = False
            for j in range(first - 1, -1, -1):
                if re.match(r"\s*SAM_REQUIRE_SANDBOX:\s*['\"]?1['\"]?\s*$", lines[j]):
                    step_env = True
                if lines[j].lstrip().startswith("- "):
                    break
            parts.append((first, body.splitlines(), top_env or step_env))
    else:
        parts = [(1, lines, False)]
    for first, body, exported in parts:
        for n, line in enumerate(body):
            s = line.strip()
            if s.startswith("#"):
                continue
            if re.match(r"export\s.*\bSAM_REQUIRE_SANDBOX=1\b", s):
                exported = True
            if "cargo test" not in s:
                continue
            # The command: this line and the lines it continues.
            cmd, k = s, n
            while k > 0 and body[k - 1].rstrip().endswith("\\"):
                k -= 1
                cmd = body[k].strip() + " " + cmd
            if not (exported or re.search(r"\bSAM_REQUIRE_SANDBOX=1\b[^|;&]*cargo test", cmd)):
                errs.append(f"{name}:{first + n}: cargo test without SAM_REQUIRE_SANDBOX=1 (sandbox tests would pass without running)")
    return errs


def self_test():
    wf = ("on: push\npermissions:\n  contents: read\njobs:\n  x:\n    runs-on: u\n    steps:\n"
          "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n"
          "        with:\n          persist-credentials: false\n")
    bad_target = "on: pull_request_target\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    cases = [
        ("pull_request_target with the PR's code", bad_target, 4),
        ("untrusted title inline", wf + "      - run: |\n          echo \"${{ github.event.issue.title }}\"\n", 1),
        ("title through env", wf + "      - env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n", 0),
        ("a number inline", wf + "      - run: echo ${{ github.event.issue.number }}\n", 0),
        ("an input inline", wf + "      - run: echo ${{ inputs.since }}\n", 1),
        ("a step output inline", wf + "      - run: echo ${{ steps.a.outputs.b }}\n", 1),
        ("a computed matrix inline",
         wf.replace("    runs-on: u\n", "    strategy:\n      matrix: ${{ fromJSON(needs.a.outputs.m) }}\n    runs-on: u\n")
         + "      - run: echo ${{ matrix.name }}\n", 1),
        ("a matrix whose include list is computed",
         wf.replace("    runs-on: u\n", "    strategy:\n      matrix:\n        include: ${{ fromJSON(needs.a.outputs.m) }}\n    runs-on: u\n")
         + "      - run: echo ${{ matrix.name }}\n", 1),
        ("a fixed matrix inline",
         wf.replace("    runs-on: u\n", "    strategy:\n      matrix:\n        arch: [x86_64]\n    runs-on: u\n")
         + "      - run: echo ${{ matrix.arch }}\n", 0),
        ("an action on a tag", wf + "      - uses: someone/action@v2\n", 1),
        ("an action on a short hash", wf + "      - uses: someone/action@3d3c42e\n", 1),
        ("a checkout that keeps its token", wf.replace("        with:\n          persist-credentials: false\n", ""), 1),
        ("a checkout with persist-credentials: true", wf.replace("false", "true"), 1),
        ("no top-level permissions", wf.replace("permissions:\n  contents: read\n", ""), 1),
        ("top-level write", wf.replace("contents: read", "contents: write"), 1),
        ("a job writing what it may not", wf.replace("    runs-on: u\n", "    runs-on: u\n    permissions:\n      contents: write\n"), 1),
        ("a job writing through a flow mapping", wf.replace("    runs-on: u\n", "    runs-on: u\n    permissions: { contents: write }\n"), 1),
        ("a quoted write", wf.replace("    runs-on: u\n", "    runs-on: u\n    permissions:\n      contents: \"write\"\n"), 1),
        ("a quoted top-level write", wf.replace("contents: read", "contents: 'write'"), 1),
        ("write-all with a comment", wf.replace("    runs-on: u\n", "    runs-on: u\n    permissions: write-all # all\n"), 1),
        ("a reusable workflow on a tag", wf + "  y:\n    uses: someone/repo/.github/workflows/w.yml@v1\n", 1),
        ("a pinned reusable workflow",
         wf + "  y:\n    uses: someone/repo/.github/workflows/w.yml@3d3c42e5aac5ba805825da76410c181273ba90b1\n", 0),
        ("a download without a checksum", wf + "      - run: curl -fsSL -o f https://x/f\n", 1),
        ("a download with a checksum", wf + "      - run: |\n          curl -fsSL -o f https://x/f\n          echo \"abc  f\" | sha256sum -c -\n", 0),
    ]
    wrong = []
    for what, text, want in cases:
        got = workflow_problems("t.yml", text)
        if len(got) != want:
            wrong.append(f"{what}: {len(got)} problems, expected {want}: {got}")
    # Allowed writes are per workflow and job.
    allowed = wf.replace("  x:\n", "  draft:\n").replace("    runs-on: u\n", "    runs-on: u\n    permissions:\n      contents: write\n")
    if workflow_problems("release.yml", allowed) or not workflow_problems("other.yml", allowed):
        wrong.append("WRITES is not read per workflow and job")

    ci = ("      - run: shellcheck -S warning scripts/*.sh tests/*/*.sh\n      - run: pipx run ruff==0.17.5 check scripts tests\n"
          "        run: for f in scripts/*.sh tests/*/*.sh; do sh -n \"$f\" || exit 1; done\n"
          "          docs='^(docs/|[^/]+\\.md$)'\n          code_docs='^docs/(guide\\.md|contracts\\.toml)$'\n")
    files = ["scripts/a.sh", "tests/gui/b.sh"]

    def exists(p, files=files):
        return {f for f in files if fnmatch.fnmatch(f, p) and f.count("/") == p.count("/")}
    lint_cases = [
        ("all covered", ci, files, ["scripts/x.py"], 0),
        ("a script in a deeper folder", ci, files + ["tests/gui/lib/c.sh"], [], 2),
        ("shellcheck narrowed", ci.replace("shellcheck -S warning scripts/*.sh tests/*/*.sh", "shellcheck -S warning scripts/*.sh"), files, [], 1),
        ("a Python file outside ruff's folders", ci, files, ["packaging/x.py"], 1),
    ]
    for what, c, sh, py, want in lint_cases:
        got = lint_problems(c, sh, py, lambda p, sh=sh: exists(p, sh))
        if len(got) != want:
            wrong.append(f"lint coverage, {what}: {len(got)} problems, expected {want}: {got}")
    tracked = {"docs/guide.md", "docs/permissions.md", "docs/contracts.md"}
    doc_cases = [
        ("an included code doc", 'const G: &str = include_str!("../../../docs/guide.md");', 0),
        ("a test reading a plain doc", 'let t = root.join("../../docs/permissions.md");', 1),
        ("a doc named in a message", 'format!("see docs/contracts.md")', 0),
        ("a doc in a comment", '// root.join("docs/permissions.md")', 0),
    ]
    for what, src, want in doc_cases:
        got = code_doc_problems(ci, {"a.rs": src}, tracked)
        if len(got) != want:
            wrong.append(f"code docs, {what}: {len(got)} problems, expected {want}: {got}")
    sb_cases = [
        ("inline", "SAM_REQUIRE_SANDBOX=1 cargo test -p x\n", False, 0),
        ("exported", "export A=1 SAM_REQUIRE_SANDBOX=1\ncargo test -p x\n", False, 0),
        ("missing", "cargo test -p x\n", False, 1),
        ("set for another command", "SAM_REQUIRE_SANDBOX=1 true; cargo test -p x\n", False, 1),
        ("continued line", "SAM_REQUIRE_SANDBOX=1 X=2 \\\n  cargo test -p x\n", False, 0),
        ("a comment", "# cargo test -p x\n", False, 0),
        ("a workflow step's env", "    steps:\n      - name: t\n        env:\n          SAM_REQUIRE_SANDBOX: 1\n        run: cargo test\n", True, 0),
        ("another step's env", "    steps:\n      - env:\n          SAM_REQUIRE_SANDBOX: 1\n        run: true\n      - run: cargo test\n", True, 1),
    ]
    for what, text, workflow, want in sb_cases:
        got = sandbox_problems("t", text, workflow)
        if len(got) != want:
            wrong.append(f"required sandbox, {what}: {len(got)} problems, expected {want}: {got}")
    total = len(cases) + 1 + len(lint_cases) + len(doc_cases) + len(sb_cases)
    for w in wrong:
        print("  wrong:", w)
    print(f"workflow-check self-test: {total - len(wrong)} of {total} right")
    sys.exit(1 if wrong else 0)


def tracked_files():
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], check=True,
                         capture_output=True, text=True).stdout
    return [f for f in out.split("\0") if f and (ROOT / f).is_file()]


def is_shell(f):
    if f.endswith(".sh"):
        return True
    if "." in f.rsplit("/", 1)[-1]:
        return False
    with open(ROOT / f, "rb") as fh:
        first = fh.readline(80)
    return re.match(rb"#!\s*\S*/(env\s+)?(ba|da)?sh\b", first) is not None


def main():
    if "--self-test" in sys.argv:
        self_test()
    errs = []
    flows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    for f in flows:
        name = str(f.relative_to(ROOT))
        errs += workflow_problems(name, f.read_text())
        errs += sandbox_problems(name, f.read_text(), True)
    files = tracked_files()
    shell = [f for f in files if is_shell(f)]
    for f in shell:
        errs += sandbox_problems(f, (ROOT / f).read_text(), False)
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    def exists(p):
        return {str(x.relative_to(ROOT)) for x in ROOT.glob(p) if x.is_file()}
    errs += lint_problems(ci, shell, [f for f in files if f.endswith(".py")], exists)
    sources = {f: (ROOT / f).read_text() for f in files if f.startswith("crates/") and f.endswith(".rs")}
    errs += code_doc_problems(ci, sources, set(files))
    for e in errs:
        print(" ", e)
    print("workflows ok" if not errs else "Workflow rules broken.")
    sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
