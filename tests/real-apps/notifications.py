#!/usr/bin/env python3
"""A stand-in notification service for the test desktop: it answers like a
desktop's (org.freedesktop.Notifications) and writes each notification to
a log. Apps that wait for one at start (Plover) started in the night run
only without it (audit P13: an artefact of the test desktop).

    notifications.py LOGFILE
"""
import sys

from gi.repository import Gio, GLib

XML = """<node><interface name="org.freedesktop.Notifications">
<method name="Notify"><arg type="s" direction="in"/><arg type="u" direction="in"/>
<arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="s" direction="in"/>
<arg type="as" direction="in"/><arg type="a{sv}" direction="in"/><arg type="i" direction="in"/>
<arg type="u" direction="out"/></method>
<method name="CloseNotification"><arg type="u" direction="in"/></method>
<method name="GetCapabilities"><arg type="as" direction="out"/></method>
<method name="GetServerInformation"><arg type="s" direction="out"/><arg type="s" direction="out"/>
<arg type="s" direction="out"/><arg type="s" direction="out"/></method>
<signal name="NotificationClosed"><arg type="u"/><arg type="u"/></signal>
<signal name="ActionInvoked"><arg type="u"/><arg type="s"/></signal>
</interface></node>"""

log = open(sys.argv[1], "a", buffering=1)
count = [0]


def call(_conn, sender, _path, _iface, method, params, inv):
    if method == "Notify":
        app, _replaces, _icon, summary, body = params.unpack()[:5]
        count[0] += 1
        log.write(f"{count[0]}\t{sender}\t{app}\t{summary}\t{body[:200]!r}\n")
        inv.return_value(GLib.Variant("(u)", (count[0],)))
    elif method == "GetCapabilities":
        inv.return_value(GLib.Variant("(as)", (["body", "actions"],)))
    elif method == "GetServerInformation":
        inv.return_value(GLib.Variant("(ssss)", ("sam-test", "SAM", "1", "1.2")))
    else:
        inv.return_value(None)


def acquired(conn, _name):
    conn.register_object("/org/freedesktop/Notifications",
                         Gio.DBusNodeInfo.new_for_xml(XML).interfaces[0], call, None, None)


Gio.bus_own_name(Gio.BusType.SESSION, "org.freedesktop.Notifications",
                 Gio.BusNameOwnerFlags.NONE, acquired, None, lambda *_: sys.exit(1))
GLib.MainLoop().run()
