#!/usr/bin/env python3
"""Builds SAM's website from the repository: the documents in docs/, the
function map, the test library and the version reports. Nothing on the site
is written by hand except the home page text below, so it never drifts from
the repository. The Pages workflow runs it on every change to main.

    python3 scripts/site.py [OUTDIR]        (default: target/site)

Needs the `markdown` package (python3-markdown, or pip install markdown). Links between documents
become links between pages; links to code go to GitHub. The site loads
nothing from other servers (privacy): no web fonts, no trackers, and the
diagram library, when present in OUTDIR/assets, is served by the site itself.
"""
import html
import json
import os
import pathlib
import re
import shutil
import sys
import tomllib

import markdown

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "site"
REPO = "https://github.com/gitzekatze/SAM"

# Section, page path on the site, source document, title in navigation.
PAGES = [
    ("use", "use/install.html", "README.md#installation", "Install"),
    ("use", "use/guide.html", "docs/guide.md", "User guide"),
    ("use", "use/permissions.html", "docs/permissions.md", "Permissions reference"),
    ("trust", "trust/security.html", "docs/security.md", "Security"),
    ("trust", "trust/threat-model.html", "docs/threat-model.md", "Threat model"),
    ("trust", "trust/functions.html", "docs/functions.md", "Functions and their tests"),
    ("trust", "trust/tests.html", "docs/test-library.md", "Test library"),
    ("trust", "trust/mutation-testing.html", "docs/reports/mutants-2026-11-15.md", "Mutation testing"),
    ("trust", "trust/security-review.html", "docs/reports/security-review-2026-11-10.md", "Security review"),
    ("maintain", "maintain/index.html", "docs/handbook/index.md", "Start here"),
    ("maintain", "maintain/github.html", "docs/handbook/github.md", "How GitHub works"),
    ("maintain", "maintain/workflow.html", "docs/handbook/workflow.md", "Everyday work"),
    ("maintain", "maintain/tools.html", "docs/handbook/tools.md", "Your tools"),
    ("maintain", "maintain/releasing.html", "docs/releasing.md", "Releasing"),
    ("maintain", "maintain/care.html", "docs/handbook/care.md", "Keeping SAM healthy"),
    ("maintain", "maintain/testing.html", "docs/testing.md", "Testing"),
    ("maintain", "maintain/translating.html", "docs/translating.md", "Translating"),
    ("maintain", "maintain/architecture.html", "docs/architecture.md", "Architecture"),
    ("maintain", "maintain/json-interface.html", "docs/json-interface.md", "JSON interface"),
    ("maintain", "maintain/packaging.html", "docs/packaging.md", "Packaging"),
    ("maintain", "maintain/contributing.html", "CONTRIBUTING.md", "Contributing"),
    ("maintain", "maintain/changelog.html", "CHANGELOG.md", "Changelog"),
]
SOURCE_TO_PAGE = {src.split("#")[0]: page for _, page, src, _ in PAGES}
SOURCE_TO_PAGE["README.md"] = "index.html"
SOURCE_TO_PAGE["DEVELOPMENT.md"] = "trust/dashboard.html"
SOURCE_TO_PAGE["SECURITY.md"] = "trust/security.html"
SECTIONS = [("index.html", "Home", None), ("use/install.html", "Use SAM", "use"),
            ("trust/index.html", "Trust SAM", "trust"), ("maintain/index.html", "Maintain SAM", "maintain")]


def rel(from_page, to_page):
    """A link from one site page to another."""
    return os.path.relpath(to_page, os.path.dirname(from_page) or ".")


def rewrite_links(body, source, page):
    """Links in a document point to site pages or to GitHub."""
    src_dir = os.path.dirname(source)

    def fix(m):
        attr, url = m.group(1), html.unescape(m.group(2))
        if re.match(r"^(https?:|mailto:|#)", url):
            return m.group(0)
        path, _, anchor = url.partition("#")
        target = os.path.normpath(os.path.join(src_dir, path)) if path else source
        if target in SOURCE_TO_PAGE:
            new = rel(page, SOURCE_TO_PAGE[target]) + (f"#{anchor}" if anchor else "")
        elif (ROOT / target).exists():
            kind = "tree" if (ROOT / target).is_dir() else "blob"
            new = f"{REPO}/{kind}/main/{target}" + (f"#{anchor}" if anchor else "")
        else:
            return m.group(0)
        return f'{attr}="{html.escape(new)}"'

    return re.sub(r'(href|src)="([^"]+)"', fix, body)


def render(text):
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"],
                           extension_configs={"toc": {"toc_depth": "2-3"}})
    body = md.convert(text)
    # Diagrams: drawn in the browser by the site's own copy of Mermaid.
    body = re.sub(r'<pre><code class="language-mermaid">(.*?)</code></pre>',
                  lambda m: f'<pre class="mermaid">{m.group(1)}</pre>', body, flags=re.S)
    return body, md.toc


def section_of_readme(name):
    """One `## name` section of the README, with its subsections."""
    text = (ROOT / "README.md").read_text()
    m = re.search(rf"^## {re.escape(name)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    return m.group(1) if m else ""


def shell(page, title, body, section=None, toc=None, source=None):
    nav = "".join(
        f'<a href="{rel(page, href)}"{" class=active" if sec and sec == section else ""}>{label}</a>'
        for href, label, sec in SECTIONS)
    side = ""
    if section in ("use", "trust", "maintain"):
        items = [(p, t) for s, p, _, t in PAGES if s == section]
        if section == "trust":
            items = [("trust/index.html", "Overview"), ("trust/dashboard.html", "Dashboard")] + items
        links = "".join(f'<li><a href="{rel(page, p)}">{html.escape(t)}</a></li>' for p, t in items)
        side = f'<nav class="toc" aria-label="Pages"><p>{dict((s, l) for _, l, s in SECTIONS)[section]}</p><ul>{links}</ul>'
        if toc and "<li>" in toc:
            side += f'<p style="margin-top:1.4rem">On this page</p>{toc}'
        side += "</nav>"
    edit = (f'<p class="edit">This page is made from <a href="{REPO}/blob/main/{source}">{source}</a>.</p>'
            if source else "")
    content = (f'<div class="wrap"><div class="page{" with-toc" if side else ""}"><article class="doc">{body}{edit}</article>{side}</div></div>'
               if section else body)
    mermaid = (f'<script src="{rel(page, "assets/mermaid.min.js")}"></script>'
               f'<script>mermaid.initialize({{startOnLoad:true,theme:matchMedia("(prefers-color-scheme: dark)").matches?"dark":"neutral"}})</script>'
               if 'class="mermaid"' in body and (OUT / "assets" / "mermaid.min.js").exists() else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · SAM</title>
<meta name="description" content="SAM - Sandboxed AppImage Manager: run AppImages in a sandbox with clear, per-app permissions.">
<link rel="icon" href="{rel(page, "assets/logo.svg")}">
<link rel="stylesheet" href="{rel(page, "assets/style.css")}">
</head><body>
<header class="top"><div class="top-inner">
<a class="brand" href="{rel(page, "index.html")}"><img src="{rel(page, "assets/logo.svg")}" alt="">SAM</a>
<nav class="nav" aria-label="Sections">{nav}<a href="{REPO}">GitHub</a></nav>
</div></header>
<main>{content}</main>
<footer><div class="wrap"><span>SAM - Sandboxed AppImage Manager · <a href="{REPO}/blob/main/LICENSE">GPL-3.0-or-later</a></span>
<span>No trackers, no cookies, no outside requests. Built from the <a href="{REPO}">repository</a>.</span></div></footer>
{mermaid}</body></html>
"""


def write(page, text):
    path = OUT / page
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def facts():
    """Numbers shown on the home page and dashboard, from the repository."""
    funcs = tomllib.loads((ROOT / "docs/functions.toml").read_text())["function"]
    tests = {t for f in funcs for t in f.get("tests", [])}
    reports = []
    for p in sorted((ROOT / "docs/reports").glob("*.json")):
        try:
            reports.append(json.loads(p.read_text()))
        except ValueError:
            pass
    reports.sort(key=lambda r: r.get("generated", ""))
    langs = len((ROOT / "po/LINGUAS").read_text().split()) + 1
    return {"functions": len(funcs), "tests": len(tests), "reports": reports, "languages": langs}


def home(f):
    page = "index.html"
    doors = [
        ("use/install.html", "🧭", "Use SAM", "Install SAM, sandbox your first AppImage in three clicks, and find every setting explained in plain language."),
        ("trust/index.html", "🛡️", "Trust SAM", "Every promise with the test that proves it: security, threat model, live test results, mutation testing."),
        ("maintain/index.html", "🛠️", "Maintain SAM", "The handbook: how SAM is built, tested and released, and how GitHub works, written for beginners."),
    ]
    columns = [
        ("📦", "Opens nearly anything", "Electron, Qt, GTK, games, Wine, Flutter: 117 of 120 real AppImages start in their sandbox, and the rest fail for reasons inside the app."),
        ("✨", "Simple on the surface", "Pick an AppImage, look over the access SAM recommends, press Create Sandbox. Every switch says what it costs."),
        ("🛡️", "Security you can check", "Bubblewrap, Landlock, a system-call filter, filtered desktop services. Each promise names the test that proves it."),
        ("🔒", "Private by design", "No telemetry, no accounts, network only when you ask. Bug reports hide your name, paths, addresses and secrets."),
        ("🔍", "Open and tested", f"{f['tests']} tests guard {f['functions']} functions; breakout attempts, fuzzing and mutation testing run against the code itself."),
    ]
    cards = lambda items: "".join(
        f'<a class="card" href="{href}"><div class="icon">{icon}</div><h3>{t}</h3><p>{d}</p><span class="more">Open →</span></a>'
        for href, icon, t, d in items)
    plain = lambda items: "".join(f'<div class="card"><div class="icon">{i}</div><h3>{t}</h3><p>{d}</p></div>' for i, t, d in items)
    body = f"""
<section class="hero"><div class="wrap">
<img class="logo" src="assets/logo.svg" alt="SAM's logo: a seal on a shield">
<h1>Every AppImage, in a <span>sandbox you control</span></h1>
<p class="lead">AppImages are handy: download, double-click, done. They also run with all your rights. SAM gives each one a sandbox with exactly the access you choose, explained in plain words, without the command line.</p>
<div class="buttons"><a class="btn primary" href="use/install.html">Get SAM</a><a class="btn ghost" href="trust/index.html">See the evidence</a></div>
</div></section>
<section class="band soft"><div class="wrap">
<h2>How it works</h2><p class="sub">Three steps from a downloaded file to an app that runs safely.</p>
<div class="grid steps">
<div class="card"><h3>Pick an AppImage</h3><p>SAM lists the AppImages in your folders and reads their name and icon without running anything.</p></div>
<div class="card"><h3>Look over the access</h3><p>SAM recommends the least access the app needs: its own window, maybe sound or the network. Change anything with a switch.</p></div>
<div class="card"><h3>Run it sandboxed</h3><p>The app starts in its sandbox, from SAM or your app menu. If it struggles, SAM says why and offers a fix you can undo.</p></div>
</div></div></section>
<section class="band"><div class="wrap">
<h2>What SAM stands for</h2><p class="sub">Five promises guide every change.</p>
<div class="grid">{plain(columns)}</div></div></section>
<section class="band soft"><div class="wrap">
<div class="stats">
<div class="stat"><b>{f['tests']}</b><span>tests</span></div>
<div class="stat"><b>{f['functions']}</b><span>functions, each proven</span></div>
<div class="stat"><b>120</b><span>real AppImages tried</span></div>
<div class="stat"><b>{f['languages']}</b><span>languages</span></div>
</div></div></section>
<section class="band"><div class="wrap">
<h2>Find your way</h2><p class="sub">Whether you want to use SAM, check it, or look after it.</p>
<div class="grid">{cards(doors)}</div></div></section>
<section class="band soft"><div class="wrap honest">
<h2>How SAM is made</h2>
<p>One person, one AI assistant, and a lot of proof. SAM is built with Claude as a coding assistant, and it shows its evidence instead of asking for trust. An outside security review is the next step before the first public beta.</p>
<p><a href="trust/index.html">See the evidence →</a></p>
</div></section>"""
    write(page, shell(page, "Sandboxed AppImage Manager", body))


def trust_index(f):
    page = "trust/index.html"
    items = [
        ("dashboard.html", "📊", "Dashboard", "Test results, coverage and speed from the newest version report."),
        ("security.html", "🛡️", "Security", "What the sandbox shows and hides, layer by layer, each promise with its test."),
        ("threat-model.html", "🎯", "Threat model", "Who SAM protects against, and just as clearly, what it does not."),
        ("functions.html", "🧩", "Functions and their tests", f"All {f['functions']} functions SAM promises, with the tests that prove each one."),
        ("tests.html", "🧪", "Test library", f"Every one of the {f['tests']} tests and the promise it keeps."),
        ("mutation-testing.html", "🧬", "Mutation testing", "2,821 deliberate mistakes in the security code, and how many the tests caught."),
        ("security-review.html", "📝", "Security review", "The review that checked every promise against a test."),
    ]
    cards = "".join(f'<a class="card" href="{h}"><div class="icon">{i}</div><h3>{t}</h3><p>{d}</p><span class="more">Open →</span></a>' for h, i, t, d in items)
    body = f"""<h1>Trust SAM</h1>
<p>SAM keeps people safe from programs they download, so it has to earn trust. Instead of asking for it, SAM shows its work: every promise, the test behind it, and the results.</p>
<div class="grid" style="margin-top:1.5rem">{cards}</div>
<h2>How SAM is made</h2>
<p>SAM is a one-person project, built with Claude, Anthropic's AI model, as a coding assistant. The maintainer decides what SAM does and how far each permission may go; Claude writes most of the code and tests, and every change has to pass them. An outside security review is planned before the first public beta. Found a way out of the sandbox? Please report it privately through <a href="{REPO}/security/advisories/new">GitHub's security tab</a>.</p>"""
    write(page, shell(page, "Trust SAM", body, section="trust"))


def dashboard(f):
    page = "trust/dashboard.html"
    reps = f["reports"]
    if not reps:
        write(page, shell(page, "Dashboard", "<h1>Dashboard</h1><p>No version report yet.</p>", section="trust"))
        return
    last = reps[-1]
    tests = last.get("tests", [])
    ok = sum(1 for t in tests if t.get("result") == "ok")
    failed = sum(1 for t in tests if t.get("result") == "FAILED")
    status = '<span class="pill ok">all passing</span>' if failed == 0 else f'<span class="pill bad">{failed} failing</span>'
    cov = "".join(
        f'<div class="bar"><span>{html.escape(part)}</span><div class="track"><div class="fill" style="width:{v.get("percent", 0)}%"></div></div><span>{v.get("percent", 0):.0f} %</span></div>'
        for part, v in sorted(last.get("coverage", {}).items()) if isinstance(v, dict))
    peak = max(len([t for t in r.get("tests", []) if t.get("result") == "ok"]) for r in reps) or 1
    hist = "".join(
        f'<div style="height:{100 * n / peak:.0f}%" title="{html.escape(r.get("generated", ""))}"><span>{n}</span></div>'
        for r in reps for n in [len([t for t in r.get("tests", []) if t.get("result") == "ok"])])
    bench = "".join(f"<tr><td>{html.escape(b.get('what', b.get('key', '')))}</td><td>{b['best_ms']:.3f} ms</td></tr>"
                    for b in last.get("bench", []) if isinstance(b.get("best_ms"), (int, float)))
    body = f"""<h1>Dashboard</h1>
<p>From the newest version report ({html.escape(last.get("generated", "").replace("T", " "))}). Reports are made before each version with <code>make report</code>.</p>
<div class="stats" style="margin:1.5rem 0">
<div class="stat"><b>{ok}</b><span>tests passed {status}</span></div>
<div class="stat"><b>{f['functions']}</b><span>functions</span></div>
<div class="stat"><b>{len(reps)}</b><span>version reports</span></div>
</div>
<h2>Passing tests, report by report</h2>
<div class="history" role="img" aria-label="Passing tests in each version report">{hist}</div>
<h2>Line coverage per part</h2>
<p>Coverage finds code no test runs; it does not say how good the tests are. The window is tested mostly by clicking through it, which coverage does not count.</p>
<div class="bars">{cov}</div>
<h2>Speed</h2>
<table><thead><tr><th>What</th><th>Best time</th></tr></thead><tbody>{bench}</tbody></table>"""
    write(page, shell(page, "Dashboard", body, section="trust"))


def documents():
    for section, page, source, title in PAGES:
        if "#" in source:
            path, _, name = source.partition("#")
            text = f"# {title}\n\n" + section_of_readme(name.title())
            src_file = path
        else:
            src_file = source
            text = (ROOT / source).read_text()
        body, toc = render(text)
        body = rewrite_links(body, src_file, page)
        write(page, shell(page, title, body, section=section, toc=toc, source=src_file))


def main():
    if OUT.exists():
        keep = OUT / "assets" / "mermaid.min.js"
        saved = keep.read_bytes() if keep.exists() else None
        shutil.rmtree(OUT)
    else:
        saved = None
    (OUT / "assets").mkdir(parents=True)
    if saved:
        (OUT / "assets" / "mermaid.min.js").write_bytes(saved)
    shutil.copy(ROOT / "docs/site/style.css", OUT / "assets/style.css")
    shutil.copy(ROOT / "data/io.github.gitzekatze.SAM.svg", OUT / "assets/logo.svg")
    f = facts()
    home(f)
    trust_index(f)
    dashboard(f)
    documents()
    (OUT / ".nojekyll").write_text("")
    broken = check_links()
    print(f"wrote {OUT}: {sum(1 for _ in OUT.rglob('*.html'))} pages, {len(broken)} broken links")
    for page, url in broken[:20]:
        print(f"  {page}: {url}")
    sys.exit(1 if broken else 0)


def check_links():
    """Every link inside the site leads to a page or file of the site."""
    broken = []
    for f in OUT.rglob("*.html"):
        for url in re.findall(r'(?:href|src)="([^"#][^"]*)"', f.read_text()):
            if url.startswith(("http:", "https:", "mailto:")):
                continue
            target = (f.parent / html.unescape(url).split("#")[0]).resolve()
            if not target.exists():
                broken.append((str(f.relative_to(OUT)), url))
    return broken


if __name__ == "__main__":
    main()
