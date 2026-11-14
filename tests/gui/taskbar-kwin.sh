#!/bin/sh
# The taskbar icon of a sandboxed app, checked in an invisible KWin session:
# KWin must name the app's window after SAM's menu entry ("sam-<id>"), or
# the taskbar cannot find the entry and shows a generic icon. A KWin script
# prints what KWin knows about each window. Prints "RESULT pass" or "RESULT
# fail".
#
#   tests/gui/taskbar-kwin.sh OUTDIR
#
# Needs kwin_wayland, qdbus6 and zenity (for a small test window).
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
out=$(mkdir -p "${1:?usage: taskbar-kwin.sh OUTDIR}" && cd "$1" && pwd)
if [ "${INSIDE:-}" != 1 ]; then
    export QT_FORCE_STDERR_LOGGING=1 QT_LOGGING_RULES="js.debug=true"
    INSIDE=1 SAM_SESSION=kwin exec "$here/tests/gui/session.sh" "$out" "$0" "$out"
fi
bin="$here/target/debug"
rm -rf "$out/data"; mkdir -p "$out/data/config" "$out/data/apps-folder"
export SAM_CONFIG_DIR="$out/data/config" SAM_DATA_DIR="$out/data/data" SAM_APPLICATIONS_DIR="$out/data/apps"
printf '#!/bin/sh\nexec /usr/bin/zenity --info --text sandboxed\n' > "$out/apprun.sh"
"$bin/sam-jail" dev make-fixture --name Zen --categories "Utility;" --apprun "$out/apprun.sh" "$out/data/apps-folder/Zen.AppImage" >/dev/null
id=$("$bin/sam-jail" --json add "$out/data/apps-folder/Zen.AppImage" --accept | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data",d); print(d["entry"]["id"])')
"$bin/sam-jail" set "$id" advanced.host_runtime full >/dev/null
"$bin/sam-jail" run "$id" > "$out/run.log" 2>&1 & run=$!
sleep 6
cat > "$out/windows.js" <<'J'
for (const w of workspace.windowList()) { print("SAMWIN desktopFile=" + w.desktopFileName + " class=" + w.resourceClass); }
J
sid=$(qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.loadScript "$out/windows.js" samwin)
qdbus6 org.kde.KWin /Scripting/Script"$sid" org.kde.kwin.Script.run >/dev/null
sleep 2
"$bin/sam-jail" stop "$id" >/dev/null 2>&1 || true
kill $run 2>/dev/null || true
if grep -aq "SAMWIN desktopFile=sam-$id " "$out/kwin.log"; then
    echo "ok   the sandboxed window is named after SAM's menu entry (sam-$id)"; echo "RESULT pass"
else
    echo "FAIL the sandboxed window is not named after SAM's menu entry:"; grep -a SAMWIN "$out/kwin.log" || echo "(no window found)"; echo "RESULT fail"; exit 1
fi
