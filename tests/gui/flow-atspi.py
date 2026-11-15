#!/usr/bin/python3 -I
"""SAM's main flow through AT-SPI, as a person clicks it: an AppImage
without a sandbox → Create Sandbox → its page → Launch. Then the window in
the chosen language. GTK 4 check and radio buttons offer no AT-SPI action,
so the language is chosen through the setting and ticking a choice stays a
manual check (docs/testing.md). Prints one line per check; the shell part
checks SAM's records."""
import sys, time
import gi
gi.require_version("Atspi", "2.0")
from gi.repository import Atspi

# Older accessibility stacks (Ubuntu 24.04) name some roles differently.
ROLE_ALIASES = {"button": {"button", "push button"}, "switch": {"switch", "toggle button", "check box"}}
def role_is(n, want):
    return n.get_role_name() in ROLE_ALIASES.get(want, {want})

ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  [{detail}]"), flush=True)

def walk(n, out):
    try:
        c = n.get_child_count()
    except Exception:
        return out
    out.append(n)
    for i in range(c):
        ch = n.get_child_at_index(i)
        if ch is not None:
            walk(ch, out)
    return out

def find(app, pred, role=None):
    for n in walk(app, []):
        try:
            if pred(n.get_name() or "") and (role is None or role_is(n, role)):
                return n
        except Exception:
            pass

def wait(f, t=20):
    end = time.time() + t
    while time.time() < end:
        r = f()
        if r:
            return r
        time.sleep(0.3)

def window():
    d = Atspi.get_desktop(0)
    for i in range(d.get_child_count()):
        a = d.get_child_at_index(i)
        if a and ("sam-jail-gui" in (a.get_name() or "") or "SAM" in (a.get_name() or "")):
            return a

def press(node):
    node.get_action_iface().do_action(0)

app = wait(window, 40)
check("window reachable through AT-SPI", app is not None)
if not app:
    sys.exit(1)

step = sys.argv[1] if len(sys.argv) > 1 else "flow"
if step == "flow":
    create = wait(lambda: find(app, lambda s: s == "Create Sandbox", "button"))
    check("an AppImage without a sandbox offers Create Sandbox", create is not None)
    if create:
        press(create)
        launch = wait(lambda: find(app, lambda s: s == "Launch", "button"), 90)
        check("after Create Sandbox the app page offers Launch", launch is not None)
        if launch:
            press(launch)
            time.sleep(4)
        trash = find(app, lambda s: s.startswith("Remove the sandbox"), "button")
        check("the app page offers removing the sandbox", trash is not None)
elif step in ("german", "english"):
    word = "Berechtigungsverwaltung" if step == "german" else "Permission Manager"
    check(f"the window shows “{word}”", wait(lambda: find(app, lambda s: s == word, "button"), 30) is not None)
    title = "Sprache von SAM" if step == "german" else "Language of SAM"
    check(f"the language page is titled “{title}”", wait(lambda: find(app, lambda s: s == title)) is not None)
print("RESULT " + ("pass" if ok else "fail"))
sys.exit(0 if ok else 1)
