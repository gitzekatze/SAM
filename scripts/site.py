#!/usr/bin/env python3
"""Builds SAM's website from the repository: the documents in docs/, the
function map, the test library and the version reports. Nothing on the site
is written by hand except the home page text below, so it never drifts from
the repository. The Pages workflow runs it on every change to main.

    python3 scripts/site.py [OUTDIR]        (default: target/site)

The website has three sections: Use SAM, Trust SAM and Maintain SAM (the
maintainer handbook).

Needs the `markdown` package (python3-markdown, or pip install markdown). Links between documents
become links between pages; links to code go to GitHub. The site loads
nothing from other servers (privacy): no web fonts, no trackers, and the
diagram library, when present in OUTDIR/assets, is served by the site itself.
"""
import hashlib
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
# A stamp of the stylesheet's content in its link: browsers keep a stylesheet
# for a while, and a new stamp makes them load a changed one at once.
STYLE_STAMP = hashlib.sha256((ROOT / "docs/site/style.css").read_bytes()).hexdigest()[:10]

# Section, page path on the site, source document, title in navigation.
PAGES = [
    ("use", "use/install.html", "docs/install.md", "Install SAM"),
    ("use", "use/guide.html", "docs/guide.md", "User guide"),
    ("use", "use/permissions.html", "docs/permissions.md", "Permissions reference"),
    ("trust", "trust/security.html", "docs/security.md", "Security"),
    ("trust", "trust/threat-model.html", "docs/threat-model.md", "Threat model"),
    ("trust", "trust/functions.html", "docs/functions.md", "Functions and their tests"),
    ("trust", "trust/tests.html", "docs/test-library.md", "Test library"),
    ("trust", "trust/mutation-testing.html", "docs/reports/mutants-2026-11-15.md", "Mutation testing"),
    ("trust", "trust/security-review.html", "docs/reports/security-review-2026-11-10.md", "Security review"),
    ("trust", "trust/testing.html", "docs/testing.md", "How SAM is tested"),
    ("trust", "trust/architecture.html", "docs/architecture.md", "Architecture"),
    ("use", "use/changelog.html", "CHANGELOG.md", "What's new"),
]
# The maintainer handbook.
HANDBOOK = [
    ("maintain", "maintain/index.html", "docs/handbook/index.md", "Start here"),
    ("maintain", "maintain/looks-after-itself.html", "docs/handbook/looks-after-itself.md", "How SAM looks after itself"),
    ("maintain", "maintain/github.html", "docs/handbook/github.md", "How GitHub works"),
    ("maintain", "maintain/workflow.html", "docs/handbook/workflow.md", "Everyday work"),
    ("maintain", "maintain/tips.html", "docs/handbook/tips.md", "Updating SAM and the repository"),
    ("maintain", "maintain/outside.html", "docs/handbook/outside.md", "When the outside changes"),
    ("maintain", "maintain/contracts.html", "docs/contracts.md", "Contracts"),
    ("maintain", "maintain/automation.html", "AUTOMATION.md", "Automation"),
    ("maintain", "maintain/tools.html", "docs/handbook/tools.md", "Your tools"),
    ("maintain", "maintain/releasing.html", "docs/releasing.md", "Releasing"),
    ("maintain", "maintain/care.html", "docs/handbook/care.md", "Keeping SAM healthy"),
    ("maintain", "maintain/translating.html", "docs/translating.md", "Translating"),
    ("maintain", "maintain/json-interface.html", "docs/json-interface.md", "JSON interface"),
    ("maintain", "maintain/packaging.html", "docs/packaging.md", "Packaging"),
    ("maintain", "maintain/contributing.html", "CONTRIBUTING.md", "Contributing"),
]
PAGES += HANDBOOK
SOURCE_TO_PAGE = {src: page for _, page, src, _ in PAGES}
SOURCE_TO_PAGE["README.md"] = "index.html"
SOURCE_TO_PAGE["DEVELOPMENT.md"] = "trust/dashboard.html"
SOURCE_TO_PAGE["SECURITY.md"] = "trust/security.html"
SECTION_NAMES = {"use": "Use SAM", "trust": "Trust SAM", "maintain": "Maintain SAM"}
OVERVIEWS = {"use": "use/index.html", "trust": "trust/index.html", "maintain": "maintain/index.html"}
# One icon per page, used wherever the page is linked. No two pages, and no
# two points on the home page, share an icon: claim() stops the build if they do.
PAGE_ICONS = {
    "use/index.html": "compass", "use/install.html": "download", "use/guide.html": "book", "use/permissions.html": "sliders",
    "use/changelog.html": "clock",
    "trust/index.html": "scale", "trust/dashboard.html": "chart", "trust/security.html": "shield", "trust/threat-model.html": "target",
    "trust/functions.html": "check", "trust/tests.html": "archive", "trust/mutation-testing.html": "bug",
    "trust/security-review.html": "badge", "trust/testing.html": "flask", "trust/architecture.html": "layers",
    "maintain/index.html": "wrench", "maintain/looks-after-itself.html": "cycle", "maintain/github.html": "branch",
    "maintain/workflow.html": "calendar", "maintain/tips.html": "update", "maintain/outside.html": "radar",
    "maintain/contracts.html": "pen", "maintain/automation.html": "cpu", "maintain/tools.html": "terminal",
    "maintain/releasing.html": "tag", "maintain/care.html": "heart",
    "maintain/translating.html": "globe", "maintain/json-interface.html": "code",
    "maintain/packaging.html": "box", "maintain/contributing.html": "users",
}
# Navigation glyphs (home, previous, next) are controls, not points, and may repeat.
NAV_ICONS = {"home", "left", "right"}
ICON_OWNER = {}
ICON_CLASH = []


def claim(name, meaning):
    """Records that an icon stands for one page or one point; a second meaning is a clash."""
    if name in NAV_ICONS:
        return
    owner = ICON_OWNER.setdefault(name, meaning)
    if owner != meaning and (name, owner, meaning) not in ICON_CLASH:
        ICON_CLASH.append((name, owner, meaning))


def section_pages(section):
    """The pages of a section in reading order, its overview first."""
    pages = [(p, t) for s, p, _, t in PAGES if s == section]
    extra = {"use": [("use/index.html", "Overview")],
             "trust": [("trust/index.html", "Overview"), ("trust/dashboard.html", "Dashboard")]}.get(section, [])
    return extra + [x for x in pages if x[0] not in dict(extra)]
SECTIONS = [("index.html", "Home", None), ("use/index.html", "Use SAM", "use"),
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
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists", "md_in_html"],
                           extension_configs={"toc": {"toc_depth": "2-3"}})
    body = md.convert(text)
    # Diagrams: drawn in the browser by the site's own copy of Mermaid.
    body = re.sub(r'<pre><code class="language-mermaid">(.*?)</code></pre>',
                  lambda m: f'<pre class="mermaid">{m.group(1)}</pre>', body, flags=re.S)
    return body, md.toc


def shell(page, title, body, section=None, toc=None, source=None):
    nav = "".join(
        f'<a href="{rel(page, href)}"{" class=active" if sec and sec == section else ""}>{label}</a>'
        for href, label, sec in SECTIONS)
    side = crumbs = pager = ""
    if section in SECTION_NAMES:
        order = section_pages(section)
        links = "".join(
            f'<li><a href="{rel(page, p)}"{" class=current" if p == page else ""}>{page_icon(p, "small")}{html.escape(t)}</a></li>'
            for p, t in order)
        side = f'<nav class="toc" aria-label="Pages"><p>{SECTION_NAMES[section]}</p><ul>{links}</ul>'
        if toc and "<li>" in toc:
            side += f'<p style="margin-top:1.4rem">On this page</p>{toc}'
        side += "</nav>"
        overview = OVERVIEWS[section]
        crumbs = (f'<nav class="crumbs" aria-label="You are here"><a href="{rel(page, "index.html")}">{icon("home", "small")}Home</a>'
                  f'<span>›</span><a href="{rel(page, overview)}">{SECTION_NAMES[section]}</a>'
                  + (f'<span>›</span><span aria-current="page">{html.escape(title)}</span>' if page != overview else "") + "</nav>")
        idx = [p for p, _ in order].index(page) if page in [p for p, _ in order] else 0
        prev_p, prev_t = order[idx - 1]
        next_p, next_t = order[(idx + 1) % len(order)]
        pager = (f'<nav class="pager" aria-label="More pages">'
                 f'<a class="prev" href="{rel(page, prev_p)}">{icon("left", "small")}<span><small>Previous</small>{html.escape(prev_t)}</span></a>'
                 f'<a class="next" href="{rel(page, next_p)}"><span><small>Next</small>{html.escape(next_t)}</span>{icon("right", "small")}</a></nav>'
                 + (f'<p class="back"><a href="{rel(page, overview)}">{icon("left", "small")}Back to {SECTION_NAMES[section]}</a></p>' if page != overview else ""))
    edit = (f'<p class="edit">This page is made from <a href="{REPO}/blob/main/{source}">{source}</a>.</p>'
            if source else "")
    content = (f'<div class="wrap"><div class="page{" with-toc" if side else ""}"><article class="doc">{crumbs}{body}{pager}{edit}</article>{side}</div></div>'
               if section else body)
    mermaid = (f'<script src="{rel(page, "assets/mermaid.min.js")}"></script>'
               f'<script>mermaid.initialize({{startOnLoad:true,theme:matchMedia("(prefers-color-scheme: dark)").matches?"dark":"neutral"}})</script>'
               if 'class="mermaid"' in body and (OUT / "assets" / "mermaid.min.js").exists() else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · SAM</title>
<meta name="description" content="SAM - Sandboxed AppImage Manager: run AppImages in a sandbox with clear, per-app permissions.">
<link rel="icon" href="{rel(page, "assets/logo.svg")}">
<link rel="stylesheet" href="{rel(page, "assets/style.css")}?v={STYLE_STAMP}">
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
    # Tables scroll on their own on narrow screens and use the full width otherwise.
    text = text.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")
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


# Line icons (24 × 24, stroked), drawn inline so the site loads nothing else.
ICONS = {
    # Pages
    "compass": "M12 3a9 9 0 100 18 9 9 0 000-18zM15.5 8.5l-2 5-5 2 2-5z",
    "download": "M12 4v11M7 10l5 5 5-5M5 20h14",
    "book": "M4 5.5A2.5 2.5 0 016.5 3H20v15H6.5A2.5 2.5 0 004 20.5zM4 20.5A2.5 2.5 0 016.5 18H20v3H6.5",
    "sliders": "M4 7h10M18 7h2M4 17h4M12 17h8M14 4v6M8 14v6",
    "clock": "M12 3a9 9 0 100 18 9 9 0 000-18zM12 7v5l3 2",
    "scale": "M12 3v18M7 21h10M4 7h16M7 7l-3 7h6zM17 7l-3 7h6z",
    "chart": "M4 20V11M10 20V5M16 20v-6M2.5 20h19",
    "shield": "M12 3l8 3v6c0 5-3.5 8.5-8 9.5C7.5 20.5 4 17 4 12V6l8-3zM9 12l2 2 4-4",
    "target": "M12 3a9 9 0 100 18 9 9 0 000-18zM12 8a4 4 0 100 8 4 4 0 000-8zM12 11.5v1",
    "check": "M9 4h6v3H9zM15 5.5h3V21H6V5.5h3M9 14l2 2 4-4",
    "archive": "M3 4h18v4H3zM5 8v12h14V8M10 12h4",
    "bug": "M8 10a4 4 0 018 0v4a4 4 0 01-8 0zM12 10v8M4 13h4M16 13h4M5 8l3 2M19 8l-3 2M5 19l3-2M19 19l-3-2M10 6L9 4M14 6l1-2",
    "badge": "M12 3a6 6 0 100 12 6 6 0 000-12zM9 14l-2 7 5-3 5 3-2-7",
    "flask": "M9 3h6M10 3v6l-5 9a2 2 0 001.8 3h10.4a2 2 0 001.8-3l-5-9V3M7.5 15h9",
    "layers": "M12 3l9 5-9 5-9-5zM3 13l9 5 9-5",
    "wrench": "M14.5 6.5a4 4 0 00-5.2 5.2L4 17l3 3 5.3-5.3a4 4 0 005.2-5.2l-2.3 2.3-2.5-.5-.5-2.5z",
    "cycle": "M20 11a8 8 0 00-14.3-4.9L4 8M4 4v4h4M4 13a8 8 0 0014.3 4.9L20 16M20 20v-4h-4",
    "branch": "M6 4v12M6 20a2 2 0 100-4 2 2 0 000 4zM18 8a2 2 0 100-4 2 2 0 000 4zM18 8c0 5-6 4-12 8",
    "calendar": "M4 6h16v14H4zM4 10h16M8 3v4M16 3v4",
    "update": "M12 3a9 9 0 100 18 9 9 0 000-18zM12 16V8M8.5 11.5L12 8l3.5 3.5",
    "radar": "M12 12l6-6M12 3a9 9 0 109 9M12 7a5 5 0 105 5M12 11a1 1 0 100 2 1 1 0 000-2z",
    "pen": "M4 20l4-1 11-11-3-3L5 16zM14 7l3 3M13 20h7",
    "cpu": "M7 7h10v10H7zM10 10h4v4h-4zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4",
    "terminal": "M4 5h16v14H4zM7 10l3 2-3 2M12 15h5",
    "tag": "M3 12V4h8l10 10-8 8zM7.5 7.5h.01",
    "heart": "M12 20s-7-4.5-7-10a4 4 0 017-2.6A4 4 0 0119 10c0 5.5-7 10-7 10z",
    "globe": "M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9",
    "code": "M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16",
    "box": "M21 8l-9-5-9 5v8l9 5 9-5V8zM3 8l9 5 9-5M12 13v8",
    "users": "M9 11a4 4 0 100-8 4 4 0 000 8zM2 21a7 7 0 0114 0M17 11a3 3 0 100-6M22 21a6 6 0 00-5-5.9",
    # Points on the home page
    "file": "M7 3h7l5 5v13H7zM14 3v5h5",
    "unlock": "M6 11h12v10H6zM8.5 11V7.5a3.5 3.5 0 016.8-1.2M12 15v2",
    "sandbox": "M3 3h18v18H3zM9 7h4l2 2v8H9z",
    "eye": "M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7S2.5 12 2.5 12zM12 9.5a2.5 2.5 0 100 5 2.5 2.5 0 000-5z",
    "lock": "M6 11h12v10H6zM8.5 11V7.5a3.5 3.5 0 017 0V11",
    "toggle": "M3 12a5 5 0 015-5h8a5 5 0 010 10H8a5 5 0 01-5-5zM16 9.5a2.5 2.5 0 100 5 2.5 2.5 0 000-5z",
    "lifebuoy": "M12 3a9 9 0 100 18 9 9 0 000-18zM12 8a4 4 0 100 8 4 4 0 000-8zM5.6 5.6l3.6 3.6M14.8 14.8l3.6 3.6M18.4 5.6l-3.6 3.6M9.2 14.8l-3.6 3.6",
    "menu": "M4 6h16M4 12h16M4 18h10",
    "bricks": "M3 5h18v6H3zM12 5v6M3 13h18v6H3zM8 13v6M16 13v6",
    "anchor": "M12 8a2 2 0 100-4 2 2 0 000 4zM12 8v13M8 11h8M5 14a7 7 0 0014 0",
    "feather": "M20.2 3.8a6 6 0 00-8.5 0L5 10.5V19h8.5l6.7-6.7a6 6 0 000-8.5zM16 8L2 22M17.5 15H9",
    "keyhole": "M12 3a9 9 0 100 18 9 9 0 000-18zM12 8a2 2 0 100 4 2 2 0 000-4zM12 12v4",
    "eyeoff": "M3 3l18 18M10.6 6.1A10 10 0 0112 6c6 0 9.5 6 9.5 6a17 17 0 01-2.9 3.6M6.6 6.6C3.9 8.4 2.5 12 2.5 12s3.5 6 9.5 6a9.6 9.6 0 004.4-1.1M9.9 9.9a3 3 0 004.2 4.2",
    "search": "M10.5 4a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM20 20l-4.8-4.8",
    # Navigation
    "home": "M4 11l8-7 8 7M6 9.5V20h12V9.5",
    "left": "M15 6l-6 6 6 6",
    "right": "M9 6l6 6-6 6",
}


def icon(name, size="", meaning=None):
    claim(name, meaning or name)
    return (f'<span class="icon{" " + size if size else ""}" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            f'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="{ICONS[name]}"/></svg></span>')


def page_icon(page, size=""):
    """A page's icon; every page must have its own (a missing one stops the build)."""
    return icon(PAGE_ICONS[page], size, meaning=page)


def cards(items, links=True, page=""):
    """Up to four items become cards side by side; longer lists become rows,
    which stay readable however many there are. Linked items carry the icon
    of the page they lead to."""
    rows = len(items) > 4
    out = []
    for item in items:
        href, ic, title, text = item if links else (None, *item)
        mark = (icon(PAGE_ICONS[target], meaning=target)
                if links and (target := os.path.normpath(os.path.join(os.path.dirname(page), href))) in PAGE_ICONS
                else icon(ic, meaning=title))
        inner = f"{mark}<div><h3>{title}</h3><p>{text}</p></div>"
        cls = "row" if rows else "card"
        out.append(f'<a class="{cls}" href="{href}">{inner}<span class="more" aria-hidden="true">{"→" if rows else "Open →"}</span></a>' if links
                   else f'<div class="{cls}">{inner}</div>')
    return f'<div class="{"rows" if rows else "grid"}">{"".join(out)}</div>'


def home(f):
    page = "index.html"
    flow = [
        ("file", "One file", "AppImages are the easiest way to get software on Linux: download one file and run it."),
        ("unlock", "All your rights", "That file then runs with all your rights. It can read your documents, keys and browser profiles."),
        ("sandbox", "Its own sandbox", "SAM gives each AppImage its own sandbox, with exactly the access you allow, in a window anyone can use."),
    ]
    why = [
        ("eye", "Nothing runs before you decide",
         "SAM reads an AppImage's name, icon and needs without running it, and unpacks it without running it. The app starts only when you press Launch."),
        ("lock", "Least access, chosen for each app",
         "Every app starts with a private home folder and its own window, nothing more. SAM adds only what this app shows it needs: sound for a player, the network for a browser."),
        ("toggle", "Every switch says what it costs",
         "Each permission is explained in a sentence and marked harmless, think twice or dangerous. No jargon, no hidden defaults."),
        ("lifebuoy", "When an app struggles, SAM finds out why",
         "After a failed start SAM reads what went wrong and offers the one change that helps, from mild to strong, each one reversible."),
        ("menu", "Fits into your desktop",
         "Sandboxed apps appear in your application menu and always start through SAM. Menu entries that would start an app without its sandbox are hidden."),
        ("bricks", "Built on proven parts",
         "Bubblewrap, the sandbox Flatpak uses, plus Landlock, a system-call filter and filtered desktop services. SAM adds no new privileged code."),
    ]
    columns = [
        ("anchor", "Reliable", "117 of 120 real AppImages, from Electron and Qt apps to games and Wine, start in their sandbox. The other three fail for reasons inside the app."),
        ("feather", "Simple", "Pick an AppImage, look over the access, press Create Sandbox. Settings for experts stay out of the way until you need them."),
        ("keyhole", "Secure", "A breakout test attacks every security promise from inside a real sandbox, and the threat model says just as clearly what SAM cannot stop."),
        ("eyeoff", "Private", "No telemetry, no account, no network unless you ask. Bug reports remove your name, folders, addresses and secrets."),
        ("search", "Auditable", f"Open source under the GPL. {f['tests']} tests guard {f['functions']} functions, and the results are published on this site."),
    ]
    doors = [
        ("use/index.html", None, "Use SAM", "How to install SAM, your first sandbox, and every setting explained."),
        ("trust/index.html", None, "Trust SAM", "The evidence: how the sandbox works, what it cannot do, and test results you can check."),
        ("maintain/index.html", None, "Maintain SAM", "The handbook: how to change, update and release SAM, and look after its repository."),
    ]
    flow_html = "".join(
        f'<li class="step s{i}">{icon(ic, meaning=title)}<h3>{title}</h3><p>{text}</p></li>'
        for i, (ic, title, text) in enumerate(flow, 1))
    promises = "".join(
        f'<div class="promise">{icon(ic, meaning=title)}<h3>{title}</h3><p>{text}</p></div>' for ic, title, text in columns)
    # An example of the app page, drawn with SAM's own words for permissions and risk.
    mock = """<figure class="mock" aria-label="Example: the permissions SAM shows for a music player">
<div class="mock-head"><span class="app" aria-hidden="true">♪</span><div><b>Music player</b><code>player-3.1-x86_64.AppImage</code></div><span class="tag">Sandboxed</span></div>
<ul>
<li><span>Network</span><em class="pill off">No network</em></li>
<li><span>Music folder</span><em class="pill">Read-only</em></li>
<li><span>Documents</span><em class="pill off">No access</em></li>
<li><span>Sound</span><i class="switch on" aria-label="on"></i></li>
<li><span>Camera</span><i class="switch" aria-label="off"></i></li>
</ul>
<div class="mock-foot"><span>Risk of these settings</span><em class="risk">Harmless</em></div>
<figcaption>An example of what SAM shows for a music player.</figcaption>
</figure>"""
    body = f"""
<section class="hero"><div class="wrap hero-grid">
<div class="hero-text">
<p class="eyebrow"><img src="assets/logo.svg" alt="">Sandboxed AppImage Manager</p>
<h1>Every AppImage, in a <span>sandbox you control</span></h1>
<p class="lead">SAM runs each AppImage sealed off from your files, keys and accounts, and shows what it may reach as plain switches.</p>
<div class="buttons"><a class="btn primary" href="use/install.html">Get SAM</a><a class="btn ghost" href="trust/index.html">See the evidence</a></div>
<p class="note">Free and open source · Linux · English, Deutsch, Español, Français</p>
</div>
{mock}
</div></section>

<section class="band"><div class="wrap">
<h2>Why AppImages need a sandbox</h2>
<ol class="flow">{flow_html}</ol>
</div></section>

<section class="band soft"><div class="wrap split">
<div class="split-head">
<h2>The gap SAM closes</h2>
<p>Flatpak apps come with a sandbox and tools like Flatseal to adjust it. AppImages have neither. Wrapping them by hand needs command-line tools and knowing which access each app needs. SAM does that work for you, and shows its reasoning.</p>
</div>
<ol class="how">
<li><h3>Pick an AppImage</h3><p>SAM lists the AppImages in your folders, sandboxed or not, and reads them without running them.</p></li>
<li><h3>Look over the access</h3><p>SAM recommends the least access this app needs, and explains every switch in plain words.</p></li>
<li><h3>Run it in its sandbox</h3><p>Launch it from SAM or your application menu. SAM can check from inside the sandbox that every setting holds.</p></li>
</ol>
</div></section>

<section class="band"><div class="wrap">
<h2>Why SAM</h2><p class="sub">What it does differently.</p>
{cards(why, links=False)}</div></section>

<section class="band soft"><div class="wrap">
<h2>What SAM stands for</h2><p class="sub">Five promises every change is checked against.</p>
<div class="promises">{promises}</div>
<div class="stats">
<div class="stat"><b>{f['tests']}</b><span>automated tests</span></div>
<div class="stat"><b>{f['functions']}</b><span>functions, each with proof</span></div>
<div class="stat"><b>120</b><span>real AppImages tried</span></div>
<div class="stat"><b>{f['languages']}</b><span>languages</span></div>
</div></div></section>

<section class="band"><div class="wrap">
<h2>Find your way</h2><p class="sub">Use SAM, check it, or look after it.</p>
{cards(doors, page=page)}</div></section>

<section class="band soft"><div class="wrap honest">
<h2>How SAM is made</h2>
<p>SAM is a one-person project built with Claude, Anthropic's AI model, as a coding assistant. That is why it asks to be checked rather than trusted: every promise is tied to a test, the tests run on every change, and the results are on this site. An outside security review is the next step before the first public beta.</p>
<p><a href="trust/index.html">See the evidence →</a></p>
</div></section>"""
    write(page, shell(page, "Sandboxed AppImage Manager", body))


def use_index(f):
    page = "use/index.html"
    items = [
        ("install.html", "download", "Install SAM", "What your computer needs, installing the AppImage, and your first sandbox."),
        ("guide.html", "book", "User guide", "The window, every setting group by group, and what to do when an app does not work."),
        ("permissions.html", "sliders", "Permissions reference", "For the command line: every permission key, preset files and changing several apps at once."),
        ("changelog.html", "clock", "What's new", "What changed in each version of SAM, newest first."),
    ]
    body = f"""<h1>Use SAM</h1>
<p>Everything you need to run your AppImages in a sandbox: getting SAM onto your computer, your first sandbox, and what each switch does. You never need the command line, but everything works there too.</p>
{cards(items, page=page)}
<h2>The short version</h2>
<ol>
<li>Install SAM and open it. It lists the AppImages in your usual folders.</li>
<li>Select an AppImage and look over the access SAM recommends.</li>
<li>Press <b>Create Sandbox</b>, then <b>Launch</b>.</li>
</ol>
<p>Not sure an app gets what it needs? <b>Test</b>, next to Launch, checks from inside the sandbox that every setting holds and that the app starts.</p>"""
    write(page, shell(page, "Use SAM", body, section="use"))


def trust_index(f):
    page = "trust/index.html"
    items = [
        ("dashboard.html", "chart", "Dashboard", "What the tests prove, area by area, how they work, and their newest results."),
        ("security.html", "shield", "Security", "What the sandbox shows and hides, layer by layer, and how it is built."),
        ("threat-model.html", "target", "Threat model", "Who SAM protects you from, and just as clearly, what it does not."),
        ("functions.html", "check", "Functions and their proof", f"All {f['functions']} functions SAM promises, each with the tests that prove it."),
        ("tests.html", "flask", "Test library", f"Every one of the {f['tests']} tests and the promise it keeps."),
        ("mutation-testing.html", "shuffle", "Mutation testing", "2,821 deliberate mistakes put into the security code, to see whether the tests notice."),
        ("security-review.html", "doc", "Security review", "The review that checked every security promise against a test."),
        ("testing.html", "flask", "How SAM is tested", "The kinds of tests, what each one proves, and how to run them yourself."),
        ("architecture.html", "layers", "Architecture", "SAM's parts, how they work together, and where the trust boundary runs."),
    ]
    body = f"""<h1>Trust SAM</h1>
<p>SAM protects you from programs you download, so it should not ask for blind trust. This section publishes what anyone needs to judge it: how the sandbox works, what it cannot do, and the tests that check every promise, with their results.</p>
{cards(items, page=page)}
<h2>How to check SAM yourself</h2>
<ul>
<li>The <a href="threat-model.html">threat model</a> lists each threat with what stops it and the test that proves it; every promise on the <a href="security.html">security page</a> is attacked by a breakout test from inside a real sandbox; the <a href="tests.html">test library</a> links each test to its code.</li>
<li>The tests run on every change on GitHub, on Ubuntu and Fedora; the results are public in the repository's <a href="{REPO}/actions">Actions</a> tab.</li>
<li>Releases are signed; <a href="{REPO}/blob/main/SECURITY.md#checking-a-download">SECURITY.md</a> shows how to check a download.</li>
<li>Linux keeps changing under SAM. Every assumption SAM makes about it is a <a href="../maintain/contracts.html">contract</a> with a test, and every night SAM is built and tested on the distributions that come next, so a change is noticed before it reaches you.</li>
<li>Found a way out of the sandbox? Report it privately through <a href="{REPO}/security/advisories/new">GitHub's security tab</a>.</li>
</ul>
<h2>How SAM is made</h2>
<p>SAM is a one-person project, built with Claude, Anthropic's AI model, as a coding assistant. The maintainer decides what SAM does and how far each permission may go; Claude writes most of the code and the tests, and a change goes in only when every test passes. No one outside the project has reviewed SAM yet; an outside security review is planned before the first public beta.</p>"""
    write(page, shell(page, "Trust SAM", body, section="trust"))


AREA_TEXT = {
    "A": "SAM finds AppImages, recognizes every format, unpacks them without running them, within limits, and survives damaged or hostile files.",
    "B": "SAM recommends the least access each app needs, explains every permission, and app output can never grant access on its own.",
    "C": "Inside the sandbox an app sees only what you allowed: files, network, desktop services, display, devices, and nothing that would let it out.",
    "D": "Every way of starting an app goes through its sandbox, the sandbox check confirms each setting from inside, and stopping leaves nothing behind.",
    "E": "When an app fails, SAM says why and offers fixes from mild to strong, each one reversible.",
    "F": "SAM notices settings changed behind its back and changed or moved AppImages, and updates come over HTTPS and are checked.",
    "G": "Removing an app or SAM deletes only what SAM made, and bug reports contain no personal data.",
    "H": "The window: overview, Permission Manager, translations, and use with keyboard and screen reader.",
    "I": "SAM's own files survive versions, and its parts stay cleanly separated.",
}

KINDS = [
    ("Logic tests", "Every rule in SAM, checked with known inputs and the exact expected result.", "every change, twice (a test whose result changes is flaky and fails the run)"),
    ("Real sandbox tests", "Start real Bubblewrap sandboxes and check from inside what an app can see, reach and change.", "every change, on Ubuntu and Fedora"),
    ("Attack tests", "Breakout attempts from inside a sandbox, deliberately hostile AppImages, and fuzzing: thousands of damaged files fed to SAM's readers.", "every change"),
    ("Update tests", "A local HTTPS server serves real updates; SAM must apply genuine ones and refuse damaged downloads and plain HTTP.", "every change"),
    ("Window tests", "A script clicks through the window like a person, through the accessibility interface screen readers use.", "every change"),
    ("Upgrade test", "Builds the previous version, creates apps and settings with it, and checks that the new version keeps them and still starts the apps.", "before every release"),
    ("Real AppImages", "120 real AppImages of every kind go through SAM's whole flow in a hidden session.", "before every release"),
    ("Mutation testing", "Puts thousands of small mistakes into the security code on purpose; a mistake the tests miss is a missing test.", "before every release"),
    ("Install tests", "The finished AppImage on fresh Ubuntu, Debian, Fedora, Arch and openSUSE systems.", "every release build"),
]


def dashboard(f):
    page = "trust/dashboard.html"
    reps = f["reports"]
    last = reps[-1] if reps else {}
    results = {t.get("test"): t.get("result") for t in last.get("tests", [])}
    funcs = tomllib.loads((ROOT / "docs/functions.toml").read_text())
    names = {a["id"]: a["name"] for a in funcs["area"]}
    rows = []
    total_ok = total_bad = total_new = 0
    for area in names:
        fs = [x for x in funcs["function"] if x["area"] == area]
        ts = sorted({t for x in fs for t in x.get("tests", [])})
        ok = sum(1 for t in ts if results.get(t) == "ok")
        bad = sum(1 for t in ts if results.get(t) == "FAILED")
        new = len(ts) - ok - bad
        total_ok, total_bad, total_new = total_ok + ok, total_bad + bad, total_new + new
        state = (f'<span class="pill bad">{bad} failing</span>' if bad else '<span class="pill ok">passing</span>')
        extra = f" · {new} newer than the report" if new else ""
        rows.append(f"<tr><td><b>{html.escape(names[area])}</b><br><span class=muted>{AREA_TEXT.get(area, '')}</span></td>"
                    f"<td>{len(fs)}</td><td>{len(ts)}</td><td>{state}<br><span class=muted>{ok} passed{extra}</span></td></tr>")
    when = html.escape(last.get("generated", "").replace("T", " ")[:16]) or "none yet"
    headline = (f"All {total_ok} tests in the newest report pass" if total_bad == 0 else f"{total_bad} tests fail")
    kinds = "".join(f"<tr><td><b>{k}</b></td><td>{d}</td><td>{w}</td></tr>" for k, d, w in KINDS)
    peak = max([len([t for t in r.get("tests", []) if t.get("result") == "ok"]) for r in reps] or [1])
    hist = "".join(
        f'<div style="height:{100 * n / peak:.0f}%" title="{html.escape(r.get("generated", "")[:10])}"><span>{n}</span></div>'
        for r in reps for n in [len([t for t in r.get("tests", []) if t.get("result") == "ok"])])
    bench = "".join(f"<tr><td>{html.escape(b.get('what', ''))}</td><td>{b['best_ms']:.2f} ms</td></tr>"
                    for b in last.get("bench", []) if isinstance(b.get("best_ms"), (int, float)) and b.get("what"))
    body = f"""<h1>Dashboard</h1>
<p class="lead-p"><b>{headline}.</b> The newest version report is from {when}. A version report runs the whole test suite and records the results before each version (<code>make report</code>); in between, the same tests run on GitHub with every change.</p>
<h2>What the tests prove</h2>
<p>SAM's promises are grouped into areas. Each function in an area has at least one test that proves it; the <a href="functions.html">function map</a> lists them one by one.</p>
<table><thead><tr><th>Area and what it covers</th><th>Functions</th><th>Tests</th><th>Result</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>How SAM is tested</h2>
<table><thead><tr><th>Kind</th><th>What it does</th><th>When</th></tr></thead><tbody>{kinds}</tbody></table>
<p>The latest <a href="mutation-testing.html">mutation testing</a> caught 88.5 % of 2,609 deliberate mistakes; the gaps that mattered got tests.</p>
<h2>Passing tests, report by report</h2>
<p>Each bar is one version report; the number is how many tests passed. It grows because every change comes with tests.</p>
<div class="history" role="img" aria-label="Passing tests in each version report">{hist}</div>
<h2>How fast SAM is</h2>
<p>Measured in the newest report on the maintainer's computer; the best of several runs.</p>
<table><thead><tr><th>What</th><th>Time</th></tr></thead><tbody>{bench}</tbody></table>"""
    write(page, shell(page, "Dashboard", body, section="trust"))


def documents():
    for section, page, source, title in PAGES:
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
    use_index(f)
    trust_index(f)
    dashboard(f)
    documents()
    (OUT / ".nojekyll").write_text("")
    broken = check_links()
    print(f"wrote {OUT}: {sum(1 for _ in OUT.rglob('*.html'))} pages, {len(broken)} broken links")
    for page, url in broken[:20]:
        print(f"  {page}: {url}")
    for name, first, second in ICON_CLASH:
        print(f"  icon '{name}' stands for both '{first}' and '{second}'; give one of them its own icon")
    sys.exit(1 if broken or ICON_CLASH else 0)


def check_links():
    """Every link inside the site leads to a page or file of the site."""
    broken = []
    for f in OUT.rglob("*.html"):
        for url in re.findall(r'(?:href|src)="([^"#][^"]*)"', f.read_text()):
            if url.startswith(("http:", "https:", "mailto:")):
                continue
            target = (f.parent / re.split(r"[?#]", html.unescape(url))[0]).resolve()
            if not target.exists():
                broken.append((str(f.relative_to(OUT)), url))
    return broken


if __name__ == "__main__":
    main()
