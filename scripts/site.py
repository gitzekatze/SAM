#!/usr/bin/env python3
"""Builds SAM's website from the repository's documents: README.md becomes
the front page, every document in docs/ a page, and the dashboard comes from
scripts/dashboard.py. This script writes no content of its own: it only lays
documents out, styles them and gives them icons, so the website changes
whenever the documents do. The Pages workflow runs it on every change to main.

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
import os
import pathlib
import re
import shutil
import sys

import importlib.util

import markdown

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "site"
REPO = "https://github.com/gitzekatze/SAM"
# A stamp of the stylesheet's content in its link: browsers keep a stylesheet
# for a while, and a new stamp makes them load a changed one at once.
# The dashboard's text comes from scripts/dashboard.py, built fresh for the site.
_spec = importlib.util.spec_from_file_location("dashboard", pathlib.Path(__file__).resolve().parent / "dashboard.py")
dashboard_md = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dashboard_md)
STYLE_STAMP = hashlib.sha256((ROOT / "docs/site/style.css").read_bytes()).hexdigest()[:10]

# Section, page path on the site, source document, title in navigation.
def newest(pattern):
    """The newest report of a kind; the site always shows the latest one."""
    return str(sorted((ROOT / "docs" / "reports").glob(pattern))[-1].relative_to(ROOT))


PAGES = [
    ("use", "use/index.html", "docs/use.md", "Overview"),
    ("use", "use/install.html", "docs/install.md", "Install SAM"),
    ("use", "use/guide.html", "docs/guide.md", "User guide"),
    ("use", "use/permissions.html", "docs/permissions.md", "Permissions reference"),
    ("trust", "trust/index.html", "docs/trust.md", "Overview"),
    ("trust", "trust/dashboard.html", "DEVELOPMENT.md", "Dashboard"),
    ("trust", "trust/security.html", "docs/security.md", "Security"),
    ("trust", "trust/threat-model.html", "docs/threat-model.md", "Threat model"),
    ("trust", "trust/functions.html", "docs/functions.md", "Functions and their tests"),
    ("trust", "trust/tests.html", "docs/test-library.md", "Test library"),
    ("trust", "trust/real-apps.html", newest("real-apps-*.md"), "Real AppImages"),
    ("trust", "trust/mutation-testing.html", newest("mutants-*.md"), "Mutation testing"),
    ("trust", "trust/security-review.html", "docs/reports/security-review-2026-11-10.md", "Security review"),
    ("trust", "trust/testing.html", "docs/testing.md", "How SAM is tested"),
    ("trust", "trust/architecture.html", "docs/architecture.md", "Architecture"),
    ("trust", "trust/reporting.html", "SECURITY.md", "Reporting a problem"),
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
# Pages whose lists and tables become cards, rows, flows and tiles (see showcase()).
SHOWCASE = {"use/index.html", "trust/index.html", "trust/dashboard.html"}
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
    "trust/real-apps.html": "rocket", "trust/reporting.html": "flag",
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
    return [(p, t) for s, p, _, t in PAGES if s == section]
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
    "eye": "M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7S2.5 12 2.5 12zM12 9.5a2.5 2.5 0 100 5 2.5 2.5 0 000-5z",
    "lock": "M6 11h12v10H6zM8.5 11V7.5a3.5 3.5 0 017 0V11M12 15v2",
    "funnel": "M3 5h18l-7 8v6l-4 2v-8z",
    "toggle": "M3 12a5 5 0 015-5h8a5 5 0 010 10H8a5 5 0 01-5-5zM16 9.5a2.5 2.5 0 100 5 2.5 2.5 0 000-5z",
    "lifebuoy": "M12 3a9 9 0 100 18 9 9 0 000-18zM12 8a4 4 0 100 8 4 4 0 000-8zM5.6 5.6l3.6 3.6M14.8 14.8l3.6 3.6M18.4 5.6l-3.6 3.6M9.2 14.8l-3.6 3.6",
    "menu": "M4 6h16M4 12h16M4 18h10",
    "bricks": "M3 5h18v6H3zM12 5v6M3 13h18v6H3zM8 13v6M16 13v6",
    "search": "M10.5 4a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM20 20l-4.8-4.8",
    "boxes": "M3 13h8v8H3zM13 13h8v8h-8zM8 3h8v8H8z",
    "grid": "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
    "zap": "M13 2L4 14h7l-1 8 9-12h-7z",
    "microscope": "M6 18h8M3 22h18M14 22a7 7 0 100-14h-1M9 14h2M9 12a2 2 0 01-2-2V6h6v4a2 2 0 01-2 2zM12 6V3a1 1 0 00-1-1H9a1 1 0 00-1 1v3",
    "shuffle": "M16 4h4v4M4 20L20 4M20 16v4h-4M14.5 14.5L20 20M4 4l5 5",
    "stamp": "M5 21h14M6 17h12v4H6zM10 17V10a2 2 0 114 0v7",
    "power": "M12 3v9M6.3 6.3a8 8 0 1011.4 0",
    "play": "M8 5v14l11-7z",
    "bookmark": "M6 3h12v18l-6-4-6 4z",
    "activity": "M3 12h4l3-8 4 16 3-8h4",
    "key": "M8 15a4 4 0 100-8 4 4 0 000 8zM11 11h10M18 11v3M15 11v2",
    "link": "M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1.5 1.5M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1.5-1.5",
    "mail": "M3 5h18v14H3zM3 6l9 7 9-7",
    "rocket": "M5 15c-1.5 1.5-2 5-2 5s3.5-.5 5-2M9 15l-3-3c1.5-4 5-8 12-9-1 7-5 10.5-9 12zM14 7.5a1.5 1.5 0 100 3 1.5 1.5 0 000-3z",
    "flag": "M5 21V4M5 4h11l-2 4 2 4H5",
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


# How a document's structure becomes the design. These rules work on any
# document, so writing a document in this shape is all it takes:
#   1. **Title.** text   in a numbered list of three   -> a flow with arrows
#   1. **Title.** text   in a longer numbered list     -> a numbered timeline
#   - **Title.** text    in a bullet list              -> cards (up to four) or rows
#   - **[Page](doc.md):** text                         -> a card or row that opens the page
#   a table whose first column holds only links        -> rows that open the pages
#   a table with an empty header and bold labels       -> tiles with the number large
#   > [!NOTE] / [!TIP] / [!IMPORTANT] / [!WARNING]     -> a callout box
#   `████░░░░` (a bar drawn with block characters)    -> a real bar
# Icons for points that are not links come from POINT_ICONS (design, keyed by
# the point's title with its numbers left out); a point without one is shown
# without an icon and named in the build output.
POINT_ICONS = {
    # README: why AppImages need a sandbox
    "simple": "file", "unprotected": "unlock", "sandboxed": "lock",
    # README: what SAM does differently
    "nothing runs before you decide": "eye", "each app gets the least access it needs": "funnel",
    "every switch says what it costs": "toggle", "sam finds out why an app struggles": "lifebuoy",
    "sandboxed apps fit into your desktop": "menu", "sam is built on proven parts": "bricks",
    # README: the evidence
    "# of # real appimages start in their sandbox": "boxes", "# automated tests guard # functions": "grid",
    "every security promise is attacked from inside a real sandbox": "zap",
    "the tests themselves are tested": "microscope", "sam's readers of untrusted files are fuzzed": "shuffle",
    "every release is tested and signed": "stamp",
    # Use SAM: the short version
    "install sam and open it": "power", "look over the access": "search", "create the sandbox and launch": "play",
    # Trust SAM: how to check SAM yourself
    "read the promises and their attacks": "bookmark", "watch the tests run": "activity",
    "check a download": "key", "see how sam keeps up with linux": "link", "report a way out": "mail",
    # Dashboard: the evidence
    "real appimages": "boxes", "mutation testing": "microscope", "breakout and hostile-appimage tests": "zap",
}
# Points that state the same thing in two documents share one meaning, so they share an icon.
SAME_POINT = {"real appimages": "# of # real appimages start in their sandbox",
              "mutation testing": "the tests themselves are tested",
              "breakout and hostile-appimage tests": "every security promise is attacked from inside a real sandbox"}
MISSING_ICONS = []


def plain(text):
    return re.sub(r"<[^>]+>", "", html.unescape(text)).strip()


def point_key(title):
    return re.sub(r"\d[\d,.]*", "#", plain(title).rstrip(".:").lower()).strip()


def bold_items(inner):
    """The items of a list whose every item starts with a bold title, or None."""
    items = []
    for li in re.findall(r"<li>(.*?)</li>", inner, re.S):
        m = re.match(r"\s*(?:<p>)?<strong>(.*?)</strong>\s*(.*?)\s*(?:</p>)?\s*$", li, re.S)
        if not m:
            return None
        title = re.sub(r"[.:]\s*$", "", m.group(1).strip())
        title = re.sub(r"(</a>)[.:]$", r"\1", title)
        rest = re.sub(r"^[.:]\s*", "", m.group(2).strip())
        items.append((title, rest))
    return items or None


def target_of(href, page):
    path = html.unescape(href).split("#")[0]
    return os.path.normpath(os.path.join(os.path.dirname(page), path)) if path and not path.startswith("http") else None


def point(title, text, page, kind):
    """One card, row or flow step; a linked title opens its page and carries the page's icon."""
    text = re.sub(r"^([a-z])", lambda m: m.group(1).upper(), text)  # "Title: text" -> "Text" under its own heading
    link = re.fullmatch(r'<a href="([^"]+)">(.*?)</a>', title)
    if link:
        target = target_of(link.group(1), page)
        mark = icon(PAGE_ICONS[target], meaning=target) if target in PAGE_ICONS else ""
        inner = f"{mark}<div><h3>{link.group(2)}</h3><p>{text}</p></div>"
        more = "→" if kind == "row" else "Open →"
        return f'<a class="{kind}" href="{link.group(1)}">{inner}<span class="more" aria-hidden="true">{more}</span></a>'
    key = point_key(title)
    name = POINT_ICONS.get(key)
    mark = icon(name, meaning=SAME_POINT.get(key, key)) if name else ""
    return f'<div class="{kind}">{mark}<div><h3>{title}</h3><p>{text}</p></div></div>'


def check_icons(items, page):
    """A list is either all icons or none: a list with some is missing one."""
    keys = [point_key(t) for t, _ in items if not t.startswith("<a ")]
    have = [k for k in keys if k in POINT_ICONS]
    if have and len(have) < len(keys):
        MISSING_ICONS.extend((page, k) for k in keys if k not in POINT_ICONS)


def showcase(body, page):
    """Turns a rendered document's structure into the site's design (rules above)."""
    def ordered(m):
        items = bold_items(m.group(1))
        if not items:
            return m.group(0)
        check_icons(items, page)
        if len(items) == 3:
            steps = "".join(f'<li class="step s{i}">{point(t, x, page, "flow-step")}</li>' for i, (t, x) in enumerate(items, 1))
            return f'<ol class="flow">{steps}</ol>'
        return '<ol class="how">' + "".join(f"<li><h3>{t}</h3><p>{x}</p></li>" for t, x in items) + "</ol>"

    def bullets(m):
        items = bold_items(m.group(1))
        if not items:
            return m.group(0)
        check_icons(items, page)
        kind = "row" if len(items) > 4 else "card"
        return f'<div class="{"rows" if kind == "row" else "grid"}">' + "".join(point(t, x, page, kind) for t, x in items) + "</div>"

    def link_table(m):
        if len(re.findall(r"<th>", m.group(0))) != 2:
            return m.group(0)
        rows = re.findall(r"<tr>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*</tr>", m.group(2), re.S)
        if not rows or not all(re.fullmatch(r'<a href="[^"]+">[^<]*</a>', a.strip()) for a, _ in rows):
            return m.group(0)
        return '<div class="rows">' + "".join(point(a.strip(), b, page, "row") for a, b in rows) + "</div>"

    def tiles(m):
        rows = re.findall(r"<tr>\s*<td><strong>(.*?)</strong></td>\s*<td>(.*?)</td>\s*</tr>", m.group(1), re.S)
        if not rows:
            return m.group(0)
        out = []
        for label, value in rows:
            # The large value is the entry's first word when that is a number,
            # a percentage or a version; a hash or a sentence stays small.
            num = re.match(r"[✅❌]?\s*(\d[\d,.]*(?:\s?%)?)(?=[\s,;(]|$)", plain(value))
            big = num.group(1).rstrip(",.") if num else ""
            out.append(f'<div class="tile"><span>{label}</span>' + (f"<b>{big}</b>" if big else "") + f"<p>{value}</p></div>")
        return '<div class="tiles">' + "".join(out) + "</div>"

    body = re.sub(r"<ol>\s*(.*?)</ol>", ordered, body, flags=re.S)
    body = re.sub(r"<ul>\s*(.*?)</ul>", bullets, body, flags=re.S)
    body = re.sub(r"<table>\s*<thead>\s*<tr>\s*<th>(.*?)</th>.*?</thead>\s*<tbody>(.*?)</tbody>\s*</table>", link_table, body, flags=re.S)
    body = re.sub(r"<table>\s*<thead>\s*<tr>\s*<th></th>\s*<th></th>\s*</tr>\s*</thead>\s*<tbody>(.*?)</tbody>\s*</table>", tiles, body, flags=re.S)
    return body


def callouts(body):
    """GitHub's alert boxes (> [!NOTE]) become callouts on every page."""
    def box(m):
        kind = m.group(1).lower()
        return f'<aside class="callout {kind}"><p class="callout-label">{kind.capitalize()}</p><p>{m.group(2)}'
    body = re.sub(r"<blockquote>\s*<p>\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*(.*?)(?=</p>)", box, body, flags=re.S)
    return re.sub(r'(<aside class="callout[^"]*">.*?)</blockquote>', r"\1</aside>", body, flags=re.S)


def meters(body):
    """Bars drawn with block characters become real bars."""
    def bar(m):
        full, empty = m.group(1).count("█"), m.group(1).count("░")
        pct = 100 * full / max(1, full + empty)
        return f'<span class="meter" role="img" aria-label="{pct:.0f} %"><i style="width:{pct:.0f}%"></i></span>'
    return re.sub(r"<code>([█░]+)</code>", bar, body)


def history_chart(body):
    """A table with a 'Tests passing' column also gets a column chart of it, oldest first."""
    def chart(m):
        heads = [plain(h) for h in re.findall(r"<th>(.*?)</th>", m.group(0))]
        if "Tests passing" not in heads:
            return m.group(0)
        col = heads.index("Tests passing")
        rows = [re.findall(r"<td>(.*?)</td>", r, re.S) for r in re.findall(r"<tr>(.*?)</tr>", m.group(0), re.S)[1:]]
        values = [(plain(r[0]), int(plain(r[col]))) for r in rows if len(r) > col and plain(r[col]).isdigit()][::-1]
        if len(values) < 2:
            return m.group(0)
        top = max(v for _, v in values)
        bars = "".join(f'<div style="height:{100 * v / top:.0f}%" title="{n}: {v}"><span>{v}</span></div>' for n, v in values)
        return f'<div class="history" role="img" aria-label="Tests passing in each version report, oldest first">{bars}</div>' + m.group(0)
    return re.sub(r"<table>.*?</table>", chart, body, flags=re.S)


def home():
    """The front page: README.md, with its first part as the opening and each
    section as a band of its own."""
    page, source = "index.html", "README.md"
    body, _ = render((ROOT / source).read_text())
    body = rewrite_links(body, source, page)
    body = re.sub(r"<p><strong>Website:</strong>.*?</p>", "", body, flags=re.S)  # the site itself
    body = re.sub(r"<hr\s*/?>", "", body)
    body = callouts(showcase(body, page))
    parts = re.split(r"(?=<h2[ >])", body)
    head, sections = parts[0], parts[1:]
    title = re.search(r"<h1[^>]*>(.*?)</h1>", head, re.S).group(1)
    name, _, subtitle = title.partition(" - ")
    # The bold line under the title is the headline; the paragraph after it the lead.
    tagline = re.search(r"<p><strong>(.*?)</strong></p>\s*<p>(.*?)</p>", head, re.S)
    headline, lead = (tagline.group(1), tagline.group(2)) if tagline else (title, "")
    hero = f"""<section class="hero"><div class="wrap hero-grid">
<p class="eyebrow"><img src="assets/logo.svg" alt="">{subtitle or name}</p>
<h1>{headline}</h1>
<p class="lead">{lead}</p>
<div class="buttons"><a class="btn primary" href="use/install.html">Get SAM</a><a class="btn ghost" href="trust/index.html">See the evidence</a></div>
</div></section>"""
    bands = "".join(f'<section class="band{" soft" if i % 2 else ""}"><div class="wrap prose-band">{s}</div></section>'
                    for i, s in enumerate(sections))
    write(page, shell(page, subtitle or name, hero + bands))


def documents():
    for section, page, source, title in PAGES:
        text = dashboard_md.build() if source == "DEVELOPMENT.md" else (ROOT / source).read_text()
        body, toc = render(text)
        body = rewrite_links(body, source, page)
        body = callouts(body)
        if page in SHOWCASE:
            body = history_chart(meters(showcase(body, page)))
        write(page, shell(page, title, body, section=section, toc=toc, source=source))


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
    home()
    documents()
    (OUT / ".nojekyll").write_text("")
    broken = check_links()
    print(f"wrote {OUT}: {sum(1 for _ in OUT.rglob('*.html'))} pages, {len(broken)} broken links")
    for page, url in broken[:20]:
        print(f"  {page}: {url}")
    for page, key in MISSING_ICONS:
        print(f"  '{key}' on {page} has no icon, while the other points of its list have one; add it to POINT_ICONS")
    for name, first, second in ICON_CLASH:
        print(f"  icon '{name}' stands for both '{first}' and '{second}'; give one of them its own icon")
    sys.exit(1 if broken or ICON_CLASH or MISSING_ICONS else 0)


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
