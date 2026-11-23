#!/usr/bin/python3 -I
"""SAM's main flow through AT-SPI, as a person clicks it: an AppImage
without a sandbox → Create Sandbox → its page → Launch. Then the window in
the chosen language. GTK 4 check and radio buttons offer no AT-SPI action,
so the language is chosen through the setting and ticking a choice stays a
manual check (docs/testing.md). Prints one line per check; the shell part
checks SAM's records."""
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
        except Exception:  # noqa: S110 -- an element that vanished while walking; one not found fails the check
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
elif step == "preferences":
    # Turning a protection off for every app asks first, and Cancel keeps
    # it on (audit G-F11: the switch wrote the setting at once).
    def setting(key):
        out = subprocess.run([os.environ["SAM_TEST_BIN"] + "/sam-jail", "--json", "config", "show"],
                             capture_output=True, text=True).stdout.strip().splitlines()[-1]
        d = json.loads(out)
        d = d.get("data", d)
        for part in key.split("."):
            d = d[part]
        return d
    def is_on(n):
        return n.get_state_set().contains(Atspi.StateType.CHECKED)
    def switch(title):
        # A switch row shows up as the row and as its switch; the one
        # with an action is the one a person flips.
        for n in walk(app, []):
            try:
                if (n.get_name() or "") == title and role_is(n, "switch") \
                        and n.get_action_iface() is not None and n.get_action_iface().get_n_actions() > 0:
                    return n
            except Exception:  # noqa: S110 -- an element that vanished while walking; one not found fails the check
                pass
    ll = wait(lambda: switch("Landlock write protection"), 30)
    check("the Landlock switch is on the page and on", ll is not None and is_on(ll))
    if ll:
        press(ll)
        turn_off = wait(lambda: find(app, lambda s: s == "Turn Off", "button"))
        check("turning Landlock off for every app asks first",
              turn_off is not None and find(app, lambda s: s == "Turn Off Landlock for Every App?") is not None)
        cancel = find(app, lambda s: s == "Cancel", "button")
        if cancel:
            press(cancel)
        # The switch goes back once the answer is in; only then is a
        # save that Cancel should have stopped finished too.
        check("…after Cancel the switch shows it on", wait(lambda: is_on(ll)) is True)
        check("…and Landlock stays on", setting("security.experimental_landlock") is True)
        press(ll)
        turn_off = wait(lambda: find(app, lambda s: s == "Turn Off", "button"))
        if turn_off:
            press(turn_off)
        check("…after Turn Off it is off", wait(lambda: setting("security.experimental_landlock") is False) is True)
    # A save that fails leaves the switch where the setting is (audit
    # G-F15: it kept the new position although nothing was saved).
    sc = switch("Check the sandbox before each start")
    check("the start check switch is on the page and off", sc is not None and not is_on(sc))
    if sc:
        cfg = os.environ["SAM_CONFIG_DIR"]
        os.chmod(cfg, 0o555)
        try:
            press(sc)
            # The window reports the refused write; the switch then goes
            # back once the stored settings are read again.
            check("…the save fails and the window says so", wait(lambda: find(app, lambda s: "os error 13" in s)) is not None)
            check("…a failed save leaves it off", setting("security.check_before_launch") is False)
            check("…and the switch shows it off", wait(lambda: not is_on(sc)) is True)
        finally:
            os.chmod(cfg, 0o755)
print("RESULT " + ("pass" if ok else "fail"))
sys.exit(0 if ok else 1)
