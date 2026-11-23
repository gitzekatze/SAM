#!/usr/bin/python3 -I
"""The app page through AT-SPI: the Test button and its state, the advice
group, the visible "Files This App Saved" row, Confirm Settings for a record
changed outside SAM, a failed save, compatibility mode turned on
through its dialog, and the remove dialog with three choices of which none
is preselected. Prints one line per check."""
import json, os, subprocess, sys, time
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
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"  [{detail}]"))

def walk(n, out):
    try:
        c = n.get_child_count()
    except Exception:
        return out
    out.append(n)
    for i in range(c):
        try:
            ch = n.get_child_at_index(i)
        except Exception:  # noqa: S112 -- a child that vanished while walking; one not found fails the check
            continue
        if ch is not None:
            walk(ch, out)
    return out

def find(app, pred, role=None):
    for n in walk(app, []):
        try:
            nm = n.get_name() or ""
            if pred(nm) and (role is None or role_is(n, role)):
                return n
        except Exception:  # noqa: S110 -- an element that vanished while walking; one not found fails the check
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
if sys.argv[1:] == ["finding"]:
    # A finding from the last start applies its fix and starts the app
    # again; the row says so (audit G-F12/13: it started the app without
    # a word).
    row = wait(lambda: find(app, lambda s: s == "A library is not visible"), 20)
    check("the failed start shows its finding", row is not None)
    check("…which says it fixes and starts the app", wait(lambda: find(app, lambda s: s == "Fix and start")) is not None)
    print("RESULT", "pass" if ok else "fail")
    sys.exit(0 if ok else 1)
def entry():
    out = subprocess.run([os.environ["SAM_TEST_BIN"] + "/sam-jail", "--json", "info", os.environ["SAM_TEST_APP"]],
                         capture_output=True, text=True).stdout
    d = json.loads(out)
    return d.get("data", d)["entry"]
# The shell part turned X11 on in the record from outside SAM. "Confirm
# Settings" names what the settings allow before the app may start again,
# and Cancel keeps it blocked (audit G-F12/13: one click confirmed them).
confirm = wait(lambda: find(app, lambda s: s == "Confirm Settings", "button"))
check("a record changed outside SAM offers Confirm Settings", confirm is not None)
# The note of an update's needs confirms the settings too ("review"): it
# waits until they are confirmed, or its "Got It" would start the app
# without the question.
check("…and nothing else that confirms them (no Got It)", find(app, lambda s: s == "Got It", "button") is None)
if confirm:
    # Changed again while the page is open: the question names the
    # settings as they are now, not as the page read them.
    rec = os.path.join(os.environ["SAM_DATA_DIR"], "apps", os.environ["SAM_TEST_APP"] + ".json")
    with open(rec) as f:
        d = json.load(f)
    d["profile"]["permissions"]["devices"]["usb"] = True
    with open(rec, "w") as f:
        json.dump(d, f)
    confirm.get_action_iface().do_action(0)
    asks = wait(lambda: find(app, lambda s: s == "Confirm These Settings?"))
    check("Confirm Settings asks first", asks is not None)
    check("…and names X11, which the change added", find(app, lambda s: "These settings let the app use:" in s and "X11" in s) is not None)
    check("…and raw USB, added after the page was shown", find(app, lambda s: "These settings let the app use:" in s and "Raw USB" in s) is not None)
    cancel = find(app, lambda s: s == "Cancel", "button")
    if cancel:
        cancel.get_action_iface().do_action(0)
    time.sleep(1.5)
    check("…after Cancel the app stays blocked", entry().get("changed_outside") is True)
    confirm = find(app, lambda s: s == "Confirm Settings", "button")
    if confirm:
        confirm.get_action_iface().do_action(0)
        ok_button = wait(lambda: find(app, lambda s: s == "Confirm", "button"))
        if ok_button:
            ok_button.get_action_iface().do_action(0)
    check("…after Confirm it may start", wait(lambda: entry().get("changed_outside", False) is False) is True)
test = wait(lambda: find(app, lambda s: s == "Test", "button"))
check("the header has one Test button", test is not None)
check("there is no separate Check button", find(app, lambda s: s == "Check", "button") is None)
check("the test state is shown", wait(lambda: find(app, lambda s: s == "Not tested yet")) is not None)
check("advice is in one group", find(app, lambda s: s == "Advice") is not None and find(app, lambda s: s == "Worth Checking") is None)
check("Files This App Saved is visible on the page", find(app, lambda s: s == "Files This App Saved") is not None)
# A switch rated Think twice asks before it is granted, like every
# change that adds such a risk (audit G-F2: the webcam, X11 and the SSH
# agent did not ask); Cancel leaves the app without it.
def info():
    out = subprocess.run([os.environ["SAM_TEST_BIN"] + "/sam-jail", "--json", "info", os.environ["SAM_TEST_APP"]],
                         check=False, capture_output=True, text=True).stdout
    d = json.loads(out)
    return d.get("data", d)["entry"]["profile"]["permissions"]
cam = find(app, lambda s: s == "Webcam", "switch")
check("the webcam switch is on the page", cam is not None)
if cam:
    cam.get_action_iface().do_action(0)
    grant = wait(lambda: find(app, lambda s: s == "Grant", "button"))
    check("turning the webcam on asks first", grant is not None and find(app, lambda s: s == "Grant “Webcam”?") is not None)
    cancel = find(app, lambda s: s == "Cancel", "button")
    if cancel:
        cancel.get_action_iface().do_action(0)
    time.sleep(1.5)
    check("…and after Cancel the app has no webcam", info()["devices"]["webcam"] is False)
# A change made elsewhere while the page is open stays when a switch on
# the page is changed: the page sends only its own change (audit G-F4: it
# wrote back the whole set it had loaded).
subprocess.run([os.environ["SAM_TEST_BIN"] + "/sam-jail", "set", os.environ["SAM_TEST_APP"], "filesystem.music", "ro"],
               capture_output=True, check=True)
pads = find(app, lambda s: s == "Game controllers", "switch")
check("the game controllers switch is on the page", pads is not None)
if pads:
    pads.get_action_iface().do_action(0)
    check("…and the page saves it", wait(lambda: info()["devices"]["gamepads"] is True) is True)
    check("…and the change made elsewhere stays", info()["filesystem"]["music"] == "ro")
# A save that fails leaves the page showing the stored settings, not the
# switch as it was flipped (audit G-F3).
printing = find(app, lambda s: s == "Printing", "switch")
check("the printing switch is on the page, off", printing is not None and not printing.get_state_set().contains(Atspi.StateType.CHECKED))
if printing:
    apps = os.path.join(os.environ["SAM_DATA_DIR"], "apps")
    os.chmod(apps, 0o555)
    try:
        printing.get_action_iface().do_action(0)
        # The window reports the refused write, then shows the stored
        # settings again once they are read back.
        check("…the save fails and the window says so", wait(lambda: find(app, lambda s: "os error 13" in s)) is not None)
        check("…a failed save leaves the app without printing", info()["sockets"]["cups"] is False)
        def shown_off():
            again = find(app, lambda s: s == "Printing", "switch")
            return again is not None and not again.get_state_set().contains(Atspi.StateType.CHECKED)
        check("…and the page shows it off", wait(shown_off) is True)
    finally:
        os.chmod(apps, 0o755)
# Compatibility mode: the switch asks first, and after "Turn On" the app
# really has it (regression: the window called the command line without
# --yes, so turning it on failed after the person had confirmed).
def compat_on():
    out = subprocess.run([os.environ["SAM_TEST_BIN"] + "/sam-jail", "--json", "info", os.environ["SAM_TEST_APP"]],
                         check=False, capture_output=True, text=True).stdout
    try:
        d = json.loads(out)
        d = d.get("data", d)
        return d["entry"]["profile"]["compatibility_mode"] is True
    except Exception:
        return False
sw = find(app, lambda s: s == "Compatibility mode", "switch")
check("the compatibility mode switch is on the page", sw is not None)
if sw:
    sw.get_action_iface().do_action(0)
    turn_on = wait(lambda: find(app, lambda s: s == "Turn On", "button"))
    check("turning compatibility mode on asks first", turn_on is not None)
    check("…and says it is a way out", wait(lambda: find(app, lambda s: "way out" in s)) is not None)
    if turn_on:
        turn_on.get_action_iface().do_action(0)
        check("…and after Turn On the app has it", wait(compat_on) is True)
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
