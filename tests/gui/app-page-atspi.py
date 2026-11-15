#!/usr/bin/python3 -I
"""The app page through AT-SPI: the Test button and its state, the advice
group, the visible "Files This App Saved" row, and the remove dialog with
three choices of which none is preselected. Prints one line per check."""
import sys, time
import gi
gi.require_version("Atspi", "2.0")
from gi.repository import Atspi

# Older accessibility stacks (Ubuntu 24.04) name some roles differently.
ROLE_ALIASES = {"button": {"button", "push button"}, "switch": {"switch", "toggle button"}}
def role_is(n, want):
    return n.get_role_name() in ROLE_ALIASES.get(want, {want})

ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  [{detail}]"))

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
            nm = n.get_name() or ""
            if pred(nm) and (role is None or role_is(n, role)):
                return n
        except Exception:
            pass

def wait(f, t=15):
    end = time.time() + t
    while time.time() < end:
        r = f()
        if r:
            return r
        time.sleep(0.3)

app = None
for _ in range(60):
    d = Atspi.get_desktop(0)
    for i in range(d.get_child_count()):
        a = d.get_child_at_index(i)
        if a and ("sam-jail-gui" in (a.get_name() or "") or "SAM" in (a.get_name() or "")):
            app = a
    if app:
        break
    time.sleep(0.5)
check("window reachable through AT-SPI", app is not None)
if not app:
    sys.exit(1)
test = wait(lambda: find(app, lambda s: s == "Test", "button"))
check("the header has one Test button", test is not None)
check("there is no separate Check button", find(app, lambda s: s == "Check", "button") is None)
check("the test state is shown", wait(lambda: find(app, lambda s: s == "Not tested yet")) is not None)
check("advice is in one group", find(app, lambda s: s == "Advice") is not None and find(app, lambda s: s == "Worth Checking") is None)
check("Files This App Saved is visible on the page", find(app, lambda s: s == "Files This App Saved") is not None)
trash = find(app, lambda s: s.startswith("Remove the sandbox"), "button")
check("the trash button is named by its explanation", trash is not None)
launch = find(app, lambda s: s == "Launch", "button")
if trash and test and launch:
    hs = [b.get_component_iface().get_extents(Atspi.CoordType.WINDOW).height for b in (trash, test, launch)]
    check("the trash button, Test and Launch have the same height", len(set(hs)) == 1, hs)
if trash:
    trash.get_action_iface().do_action(0)
    apply = wait(lambda: find(app, lambda s: s == "Choose an option", "button"))
    check("the remove dialog's button asks for a choice first", apply is not None)
    if apply:
        check("…and cannot be pressed before a choice", not apply.get_state_set().contains(Atspi.StateType.SENSITIVE))
    for title in ["Only the unpacked copy", "The sandbox, but keep the app's settings and files", "Everything"]:
        b = find(app, lambda s, t=title: s == t, "check box") or find(app, lambda s, t=title: s == t, "radio button")
        check(f"choice “{title}” is offered and not preselected", b is not None and not b.get_state_set().contains(Atspi.StateType.CHECKED))
    cancel = find(app, lambda s: s == "Cancel", "button")
    if cancel:
        cancel.get_action_iface().do_action(0)
print("RESULT", "pass" if ok else "fail")
sys.exit(0 if ok else 1)
