#!/usr/bin/python3 -I
"""Drives SAM's Permissions page through AT-SPI and checks the stored
settings with the CLI. Prints one line per check."""
import json, os, subprocess, sys, time
import gi
gi.require_version("Atspi", "2.0")
from gi.repository import Atspi

# Older accessibility stacks (Ubuntu 24.04) name some roles differently.
ROLE_ALIASES = {"button": {"button", "push button"}, "switch": {"switch", "toggle button", "check box"}}
def role_is(n, want):
    return n.get_role_name() in ROLE_ALIASES.get(want, {want})

CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../target/debug/sam-jail")
ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  [{detail}]"))

def perms():
    out = subprocess.run([CLI, "--json", "group", "list"], capture_output=True, text=True).stdout
    data = json.loads(out)
    data = data.get("data", data)
    return {a["name"]: a for a in data}

def find_app(timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        d = Atspi.get_desktop(0)
        for i in range(d.get_child_count()):
            a = d.get_child_at_index(i)
            if a and ("sam-jail-gui" in (a.get_name() or "") or "SAM" in (a.get_name() or "")):
                return a
        time.sleep(0.5)
    return None

def walk(node, out):
    try:
        n = node.get_child_count()
    except Exception:
        return out
    out.append(node)
    for i in range(n):
        c = node.get_child_at_index(i)
        if c is not None:
            walk(c, out)
    return out

def nodes(app):
    return walk(app, [])

def by_name(app, pred, role=None):
    for n in nodes(app):
        try:
            nm = n.get_name() or ""
            if pred(nm) and (role is None or role_is(n, role)):
                return n
        except Exception:  # noqa: S110 -- an element that vanished while walking; one not found fails the check
            pass
    return None

def press(n):
    act = n.get_action_iface()
    act.do_action(0)

def wait(pred, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        r = pred()
        if r:
            return r
        time.sleep(0.3)
    return None

app = find_app()
check("window reachable through AT-SPI", app is not None)
if not app:
    sys.exit(1)
wait(lambda: by_name(app, lambda s: s.startswith("Select Browser")), 20)
before = perms()
for name in ["Browser", "Player", "Editor"]:
    cb = wait(lambda n=name: by_name(app, lambda s: s == f"Select {n}"))
    check(f"check box 'Select {name}' has a name", cb is not None)
    if cb:
        check(f"'Select {name}' is ticked", cb.get_state_set().contains(Atspi.StateType.CHECKED))
count = wait(lambda: by_name(app, lambda s: s == "3 apps selected"))
check("three apps selected", count is not None)
head = wait(lambda: by_name(app, lambda s: s == "3 Apps Selected"))
check("group switches shown for three apps", head is not None)
# A mini control per app with its accessible name.
dd = by_name(app, lambda s: s.startswith("Documents for "), "combo box") or by_name(app, lambda s: s.startswith("Documents for "))
check("drop-downs are named after permission and apps", dd is not None)
# The big switch of the row whose apps have sound on, found by its name:
# SAM's records say how many apps have sound (GTK versions report the
# switch's on state differently).
had_sound = sorted(k for k in ["Browser", "Player", "Editor"] if before[k]["permissions"]["audio"]["enabled"])
wanted = {"Sound for all selected apps", f"Sound for {len(had_sound)} apps"}
on = [n for n in nodes(app) if (n.get_name() or "") in wanted and role_is(n, "switch")]
check("big switch for the apps with sound on", bool(on), [(n.get_name(), n.get_role_name()) for n in nodes(app) if (n.get_name() or "").startswith("Sound for")])
if on:
    press(on[0])
    dlg = wait(lambda: by_name(app, lambda s: s == "Change All Apps" or s == "Change Anyway", "button"))
    warn = by_name(app, lambda s: "may stop working" in s)
    check("warning before an app loses sound it needs", dlg is not None and warn is not None)
    if dlg:
        press(dlg)
    time.sleep(2)
    after = perms()
    check("sound is off for every app that had it", all(not after[k]["permissions"]["audio"]["enabled"] for k in had_sound), had_sound)
    undo = wait(lambda: by_name(app, lambda s: s == "Undo", "button"))
    check("toast offers Undo", undo is not None)
    if undo:
        press(undo)
        time.sleep(2)
        restored = perms()
        check("Undo restores every app", all(restored[k]["permissions"] == before[k]["permissions"] for k in before))
# Turning on a permission rated Think twice for several apps asks first,
# as it does for one app (audit G-F2); Cancel changes nothing.
cam = [n for n in nodes(app) if (n.get_name() or "").startswith("Webcam for") and role_is(n, "switch")]
check("big switch for the webcam", bool(cam), [(n.get_name(), n.get_role_name()) for n in nodes(app) if (n.get_name() or "").startswith("Webcam")])
if cam:
    before_cam = perms()
    press(cam[0])
    allow = wait(lambda: by_name(app, lambda s: s == "Allow", "button"))
    asks = by_name(app, lambda s: s.startswith("Allow This for "))
    names = by_name(app, lambda s: "This adds:" in s and "Webcam" in s)
    check("the webcam for several apps asks first and names it", allow is not None and asks is not None and names is not None)
    cancel = by_name(app, lambda s: s == "Cancel", "button")
    if cancel:
        press(cancel)
    time.sleep(2)
    check("Cancel gives no app the webcam", all(perms()[k]["permissions"] == before_cam[k]["permissions"] for k in before_cam))
# Tag filter: click the first tag filter button and check the list shrinks or stays.
f = by_name(app, lambda s: s.startswith("Filter: click to show only"), "button")
check("tag filter buttons have names", f is not None)
if f:
    label = f.get_name()
    press(f)
    time.sleep(0.6)
    check("tag filter cycles to 'has'", by_name(app, lambda s: s.startswith("Filter on: the list shows only the apps that have")) is not None, label)
print("RESULT", "pass" if ok else "fail")
sys.exit(0 if ok else 1)
