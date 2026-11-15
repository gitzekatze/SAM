#!/usr/bin/python3 -I
"""Accessibility audit of one page of SAM's window through AT-SPI, the
interface screen readers use. Every visible, enabled control must have a
name a screen reader can say, and must accept keyboard focus.

    a11y-atspi.py PAGE      (run by a11y-atspi.sh while the window shows PAGE)

Prints one line per problem and "PAGE <name>: N controls, M problems".
Exit status 1 when there is a problem.
"""
import sys
import time

import gi
gi.require_version("Atspi", "2.0")
from gi.repository import Atspi

PAGE = sys.argv[1] if len(sys.argv) > 1 else "?"
R = Atspi.Role
CONTROLS = {
    R.PUSH_BUTTON, R.TOGGLE_BUTTON, R.CHECK_BOX, R.RADIO_BUTTON, R.COMBO_BOX,
    R.SPIN_BUTTON, R.SLIDER, R.LINK, R.MENU_ITEM, R.ENTRY, R.PASSWORD_TEXT,
}
SWITCH = getattr(R, "SWITCH", None)
if SWITCH is not None:
    CONTROLS.add(SWITCH)


def find_app(timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        d = Atspi.get_desktop(0)
        for i in range(d.get_child_count()):
            a = d.get_child_at_index(i)
            if a and ("sam-jail-gui" in (a.get_name() or "") or (a.get_name() or "") == "SAM"):
                return a
        time.sleep(0.5)
    return None


def walk(node, path, out):
    try:
        n = node.get_child_count()
        st = node.get_state_set()
    except Exception:
        return
    # Hidden parts (another page, a closed popover) are not on screen.
    if not st.contains(Atspi.StateType.SHOWING) and node.get_role() != R.APPLICATION:
        return
    out.append((node, path))
    name = (node.get_name() or "").strip()
    here = path + ([name[:30]] if name and node.get_role() in (R.FRAME, R.DIALOG, R.PANEL, R.LIST_ITEM, R.SECTION) else [])
    for i in range(n):
        c = node.get_child_at_index(i)
        if c is not None:
            walk(c, here, out)


def focusable(node):
    try:
        return node.get_state_set().contains(Atspi.StateType.FOCUSABLE)
    except Exception:
        return False


def reachable(node):
    """The keyboard reaches a control when it takes focus itself, or a part
    inside it does (GtkMenuButton's inner button), or the row it sits in
    does (libadwaita's combo and switch rows put focus on the row)."""
    if focusable(node):
        return True
    stack = [node]
    for _ in range(3):
        nxt = []
        for n in stack:
            try:
                for i in range(n.get_child_count()):
                    c = n.get_child_at_index(i)
                    if c is not None:
                        if focusable(c):
                            return True
                        nxt.append(c)
            except Exception:
                pass
        stack = nxt
    parent = node
    for _ in range(3):
        try:
            parent = parent.get_parent()
        except Exception:
            return False
        if parent is None:
            return False
        if focusable(parent) and parent.get_role() in (R.LIST_ITEM, R.TABLE_ROW, R.ROW_HEADER if hasattr(R, "ROW_HEADER") else R.LIST_ITEM):
            return True
    return False


def labelled(node):
    if (node.get_name() or "").strip() or (node.get_description() or "").strip():
        return True
    # A link inside a text label: screen readers read its words through the
    # label's text (GTK's hypertext interface), so the label's text counts.
    try:
        parent = node.get_parent()
        if node.get_role() == R.LINK and parent is not None and parent.get_role() == R.LABEL:
            text = parent.get_text_iface() if hasattr(parent, "get_text_iface") else None
            if (parent.get_name() or "").strip() or (text and text.get_character_count() > 0):
                return True
    except Exception:
        pass
    try:
        for rel in node.get_relation_set():
            if rel.get_relation_type() == Atspi.RelationType.LABELLED_BY and rel.get_n_targets() > 0:
                return True
    except Exception:
        pass
    return False


def main():
    app = find_app()
    if app is None:
        print(f"FAIL {PAGE}: SAM's window did not appear on the accessibility bus")
        sys.exit(1)
    time.sleep(6)   # the page fills in from `sam-jail --json` calls
    nodes = []
    walk(app, [], nodes)
    controls, problems = 0, []
    for node, path in nodes:
        role = node.get_role()
        if role not in CONTROLS:
            continue
        st = node.get_state_set()
        if not st.contains(Atspi.StateType.SENSITIVE):
            continue   # disabled controls are skipped by keyboard and readers alike
        controls += 1
        where = " > ".join(path[-3:]) or "window"
        what = node.get_role_name()
        if not labelled(node):
            problems.append(f"no name   {what} in {where}")
        if not reachable(node):
            problems.append(f"no focus  {what} '{(node.get_name() or '')[:40]}' in {where}")
    for p in problems:
        print(f"  {PAGE}: {p}")
    print(f"PAGE {PAGE}: {controls} controls, {len(problems)} problems")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
