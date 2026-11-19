#!/usr/bin/env python3
"""SAM's translations: collects the texts marked for translation and checks
the language files.

    scripts/i18n.py extract    write po/sam.pot and update every po/*.po (needs msgmerge)
    scripts/i18n.py check      fail when po/sam.pot is out of date, German misses a
                               text, or any translation loses or adds a placeholder
    scripts/i18n.py stats      how complete each language is

Texts are marked in the code with tr("…"), trf("…", …) and trn("…", "…", …)
(sam_core::i18n), and the permission catalog's titles and explanations are
the 3rd and 4th argument of perm!(…). A small Rust string reader finds them,
so no gettext version with Rust support is needed.

German must always be complete (the maintainer can review it); other
languages may lag behind, and a missing text then appears in English.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PO = ROOT / "po"
POT = PO / "sam.pot"
COMPLETE = {"de", "es", "fr"}
PLACEHOLDER = re.compile(r"\{[a-z_]+\}")
# SAM addresses people informally (decided 2026-11-15): du, tú, tu. These
# catch the formal forms (Sie, usted, vous) in a translation.
_ES_IMPERATIVES = ("Vuelva|Compruebe|Pruebe|Intente|Consulte|Asegúrese|Elija|Indique|Instale|Active|Desactive|Permita|Muestre|"
                   "Abra|Seleccione|Escriba|Pulse|Haga|Revise|Guarde|Cree|Quite|Libere|Ejecute|Inicie|Conceda|Añada|Use|Dele|"
                   "Deje|Confirme|Descargue|Actualice|Cierre|Suba|Reinicie|Cambie|Borre|Elimine")
FORMAL = {
    "de": re.compile(r"\b\w+en Sie\b|(?:^|[.!?:;]\s+|\n)Sie (?:können|haben|müssen|sehen|finden|werden|möchten|sollten|dürfen|brauchen)\b"
                     r"|(?<![.!?:]\s)(?<!^)\b(?:Ihnen|Ihr|Ihre|Ihren|Ihrem|Ihrer|Ihres)\b"),
    "es": re.compile(r"\busted(?:es)?\b|(?:^|[.!?:;]\s+|\n)(?i:" + _ES_IMPERATIVES + r")\b"),
    "fr": re.compile(r"\b(?:vous|votre|vos)\b", re.I),
}


# ---- reading Rust source

def rust_string(src, i):
    """The Rust string literal starting at src[i] and the index after it, or None."""
    if src.startswith('r"', i) or src.startswith("r#", i):
        j = i + 1
        hashes = 0
        while src[j] == "#":
            hashes += 1
            j += 1
        if src[j] != '"':
            return None
        end = src.index('"' + "#" * hashes, j + 1)
        return src[j + 1:end], end + 1 + hashes
    if src[i] != '"':
        return None
    out, j = [], i + 1
    while True:
        c = src[j]
        if c == '"':
            return "".join(out), j + 1
        if c == "\\":
            n = src[j + 1]
            if n == "n":
                out.append("\n"); j += 2
            elif n == "t":
                out.append("\t"); j += 2
            elif n in '"\\\'':
                out.append(n); j += 2
            elif n == "u":
                k = src.index("}", j)
                out.append(chr(int(src[j + 3:k], 16))); j = k + 1
            elif n == "\n":
                j += 2
                while src[j] in " \t\n":
                    j += 1
            else:
                out.append(n); j += 2
        else:
            out.append(c); j += 1


def skip_space(src, i):
    while i < len(src) and src[i] in " \t\n\r":
        i += 1
    return i


# Calls whose arguments hold texts: name -> positions (1-based) of the
# texts; "p" after a position marks the plural of the text before it. Names
# that are common words only count in the file given.
CALLS = {
    "tr": ([1], None),
    "n_": ([1], None),
    "opt": ([2, 3], "crates/sam-gtk/src/perms.rs"),
    "trf": ([1], None),
    "trn": ([1, "p2"], None),
    "perm!": ([3, 4], None),
    "Warning::new": ([3, 4], None),
    "Warning::info": ([2, 3], None),
    "Warning::warn": ([2, 3], None),
    "Warning::danger": ([2, 3], None),
    "s": ([2, 3], "crates/sam-runner/src/repair.rs"),
    "no_sandbox": ([1], "crates/sam-runner/src/repair.rs"),
    "check": ([2, 4], "crates/sam-runner/src/doctor.rs"),
    "item": ([3], "crates/sam-core/src/risk.rs"),
    "c": ([2, 3], "crates/sam-runner/src/verify.rs"),
    "unsigned": ([1], "crates/sam-detect/src/signature.rs"),
    "pass": ([1], "crates/sam-runner/src/probe.rs"),
    "fail": ([1], "crates/sam-runner/src/probe.rs"),
    "skip": ([1], "crates/sam-runner/src/probe.rs"),
}
# A name counts on its own or after a path ("sam_core::i18n::trf"), but not
# as the end of a longer name ("detr(") or a method (".tr(").
CALL = re.compile(r"(?<![A-Za-z0-9_.])(?:[a-z_]+::)*(" + "|".join(re.escape(n) for n in sorted(CALLS, key=len, reverse=True)) + r")\(")


def split_args(src, i):
    """The top-level arguments of a call whose "(" ends at src[i-1]."""
    args, depth, j, start = [], 0, i, i
    while j < len(src):
        c = src[j]
        if c == '"' or (c == "r" and src[j + 1:j + 2] in ('"', "#") and not (src[j - 1].isalnum() or src[j - 1] == "_")):
            lit = rust_string(src, j)
            if lit is not None:
                j = lit[1]
                continue
        if c == "'" and j + 2 < len(src) and src[j + 2] == "'":
            j += 3
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                args.append(src[start:j])
                return args
            depth -= 1
        elif c == "," and depth == 0:
            args.append(src[start:j])
            start = j + 1
        j += 1
    return args


def literal(arg):
    """The text of an argument that is one string literal, else None."""
    a = arg.strip()
    lit = rust_string(a, 0) if a[:1] in ('"', "r") else None
    return lit[0] if lit and lit[1] == len(a) else None


def without_tests(src):
    """`src` without its test sections: each `#[cfg(test)]` up to the next
    line that is a lone `}` (where rustfmt ends a top-level item), with
    their lines kept as empty lines so line numbers stay right. Before,
    everything after the first test section was dropped, so texts below a
    test module in the middle of a file were never offered for translation.
    """
    out, i = [], 0
    while True:
        j = src.find("#[cfg(test)]", i)
        if j < 0:
            out.append(src[i:])
            return "".join(out)
        out.append(src[i:j])
        end = src.find("\n}\n", j)
        end = len(src) if end < 0 else end + 3
        out.append("\n" * src.count("\n", j, end))
        i = end


def messages():
    """[(msgid, plural or None, "file:line")] in source order."""
    found = []
    for f in sorted((ROOT / "crates").rglob("*.rs")):
        body = without_tests(f.read_text())
        rel = f.relative_to(ROOT).as_posix()
        for m in CALL.finditer(body):
            positions, only_in = CALLS[m.group(1)]
            if only_in and rel != only_in:
                continue
            line = body.count("\n", 0, m.start()) + 1
            args = split_args(body, m.end())
            k = 0
            while k < len(positions):
                pos = positions[k]
                text = literal(args[pos - 1]) if pos - 1 < len(args) else None
                plural = None
                if k + 1 < len(positions) and str(positions[k + 1]).startswith("p"):
                    ppos = int(positions[k + 1][1:])
                    plural = literal(args[ppos - 1]) if ppos - 1 < len(args) else None
                    k += 1
                if text:
                    found.append((text, plural, f"{rel}:{line}"))
                k += 1
    return found


# ---- PO files

def po_escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")


def po_unescape(s):
    return re.sub(r'\\(.)', lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), s)


def write_pot(found):
    entries = {}
    for msgid, plural, where in found:
        e = entries.setdefault((msgid, plural), [])
        e.append(where)
    L = [
        '# Texts of SAM - Sandboxed AppImage Manager, for translators.',
        '# Generated by scripts/i18n.py extract; do not edit by hand.',
        'msgid ""',
        'msgstr ""',
        '"Project-Id-Version: sam\\n"',
        '"Report-Msgid-Bugs-To: https://github.com/gitzekatze/SAM/issues\\n"',
        '"MIME-Version: 1.0\\n"',
        '"Content-Type: text/plain; charset=UTF-8\\n"',
        '"Content-Transfer-Encoding: 8bit\\n"',
        "",
    ]
    for (msgid, plural), wheres in entries.items():
        L.append("#: " + " ".join(wheres[:6]))
        if PLACEHOLDER.search(msgid):
            L.append("#. Keep the {placeholders}; their order may change.")
        L.append(f'msgid "{po_escape(msgid)}"')
        if plural is not None:
            L += [f'msgid_plural "{po_escape(plural)}"', 'msgstr[0] ""', 'msgstr[1] ""']
        else:
            L.append('msgstr ""')
        L.append("")
    return "\n".join(L)


def read_po(path):
    """{(msgid, plural): {"str": [msgstr…], "fuzzy": bool}} without the header."""
    out, cur, key, fuzzy = {}, None, None, False

    def flush():
        if cur is not None and cur["id"] != "":
            out[(cur["id"], cur.get("plural"))] = {"str": cur["str"], "fuzzy": cur["fuzzy"]}

    for raw in path.read_text().splitlines() + [""]:
        line = raw.strip()
        if line.startswith("#,") and "fuzzy" in line:
            fuzzy = True
        elif line.startswith("#~") or line.startswith("#"):
            continue
        elif line.startswith("msgid "):
            flush()
            cur = {"id": po_unescape(line[7:-1]), "str": [], "fuzzy": fuzzy}
            key, fuzzy = "id", False
        elif line.startswith("msgid_plural "):
            cur["plural"] = po_unescape(line[14:-1]); key = "plural"
        elif line.startswith("msgstr"):
            cur["str"].append(po_unescape(line[line.index('"') + 1:-1])); key = "str"
        elif line.startswith('"') and cur is not None:
            text = po_unescape(line[1:-1])
            if key == "id":
                cur["id"] += text
            elif key == "plural":
                cur["plural"] += text
            elif key == "str":
                cur["str"][-1] += text
        elif not line:
            flush(); cur = None
    flush()
    return out


def languages():
    return [l for l in (PO / "LINGUAS").read_text().split() if l]


def check():
    problems = []
    found = messages()
    expected = write_pot(found)
    if not POT.exists() or {k for k in read_po(POT)} != {(m, p) for m, p, _ in found}:
        problems.append("po/sam.pot is out of date: run scripts/i18n.py extract")
    wanted = {(m, p) for m, p, _ in found}
    for lang in languages():
        po = read_po(PO / f"{lang}.po")
        for key in wanted:
            e = po.get(key)
            done = e is not None and not e["fuzzy"] and all(e["str"]) and e["str"]
            if lang in COMPLETE and not done:
                problems.append(f"{lang}: no translation for {key[0][:70]!r}")
            if done and lang in FORMAL and any(FORMAL[lang].search(x) for x in e["str"]):
                problems.append(f"{lang}: formal address (SAM says du / tú / tu) in {key[0][:60]!r}")
            if done:
                want = set(PLACEHOLDER.findall(key[0] + (key[1] or "")))
                for s in e["str"]:
                    got = set(PLACEHOLDER.findall(s))
                    # A singular may leave out {n} ("one app"); nothing may be invented.
                    if got - want or (want - got) - {"{n}"}:
                        problems.append(f"{lang}: placeholders differ in {key[0][:60]!r}: {sorted(want)} vs {sorted(got)}")
    for p in problems[:80]:
        print(p)
    if len(problems) > 80:
        print(f"… and {len(problems) - 80} more")
    sys.exit(1 if problems else 0)


def stats():
    wanted = {(m, p) for m, p, _ in messages()}
    print(f"{len(wanted)} texts")
    for lang in languages():
        po = read_po(PO / f"{lang}.po")
        done = sum(1 for k in wanted if (e := po.get(k)) and not e["fuzzy"] and e["str"] and all(e["str"]))
        print(f"  {lang}: {done} translated ({done * 100 // max(1, len(wanted))} %)")


def extract():
    POT.write_text(write_pot(messages()))
    for lang in languages():
        subprocess.run(["msgmerge", "--quiet", "--update", "--backup=none", "--no-fuzzy-matching", str(PO / f"{lang}.po"), str(POT)], check=True)
    print(f"wrote po/sam.pot ({len({(m, p) for m, p, _ in messages()})} texts) and updated {', '.join(languages())}")


if __name__ == "__main__":
    {"extract": extract, "check": check, "stats": stats}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: print(__doc__))()
