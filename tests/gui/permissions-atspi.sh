#!/bin/sh
# The Permissions page through the accessibility interface (AT-SPI), in an
# invisible KWin session: four test apps, three of them selected; the script
# checks the names of the controls, the warning before an app loses sound it
# needs, the group change, Undo, the question before a risky permission
# goes to several apps, and the tag filter; then the one-app editor after a
# save that failed. Prints one line per
# check and "RESULT pass" or "RESULT fail".
#
#   tests/gui/permissions-atspi.sh OUTDIR
#
# Needs kwin_wayland (or mutter, with SAM_SESSION=mutter), at-spi2-core and python3-gobject (Atspi).
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
out=$(mkdir -p "${1:?usage: permissions-atspi.sh OUTDIR}" && cd "$1" && pwd)
if [ "${INSIDE:-}" != 1 ]; then
    INSIDE=1 SAM_SESSION=${SAM_SESSION:-kwin} exec "$here/tests/gui/session.sh" "$out" "$0" "$out"
fi
bin="$here/target/debug"
rm -rf "$out/data-set"; mkdir -p "$out/data-set/apps-folder" "$out/data-set/config"
export SAM_CONFIG_DIR="$out/data-set/config" SAM_DATA_DIR="$out/data-set/data" SAM_APPLICATIONS_DIR="$out/data-set/apps"
printf '[general]\nscan_directories = ["%s"]\n' "$out/data-set/apps-folder" > "$SAM_CONFIG_DIR/config.toml"
for spec in "Browser:Network;WebBrowser;" "Player:AudioVideo;Audio;Player;" "Editor:Graphics;2DGraphics;" "Tool:Utility;"; do
    n=${spec%%:*}; c=${spec#*:}
    "$bin/sam-jail" dev make-fixture --name "$n" --categories "$c" "$out/data-set/apps-folder/$n-1.0-x86_64.AppImage" >/dev/null
    "$bin/sam-jail" add "$out/data-set/apps-folder/$n-1.0-x86_64.AppImage" --no-launcher --accept >/dev/null
done
ids=$("$bin/sam-jail" --json group list | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data",d); print(",".join(a["id"] for a in d if a["name"]!="Tool"))')
"${ATSPI_LAUNCHER:-/usr/lib/at-spi-bus-launcher}" --launch-immediately >/dev/null 2>&1 & launcher=$!
sleep 1
"${ATSPI_REGISTRY:-/usr/lib/at-spi2-registryd}" >/dev/null 2>&1 & registry=$!
"$bin/sam-jail-gui" --screenshot "$out/permissions.png" --size 1180x800 --delay 25000 --page permissions --app "$ids" > "$out/gui.log" 2>&1 & gui=$!
rc=0; python3 -I "$here/tests/gui/permissions-atspi.py" || rc=$?
wait $gui || true
# One app selected: its editor after a save that failed.
browser=$("$bin/sam-jail" --json group list | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data",d); print([a["id"] for a in d if a["name"]=="Browser"][0])')
"$bin/sam-jail-gui" --screenshot "$out/permissions-one.png" --size 1180x800 --delay 60000 --page permissions --app "$browser" > "$out/gui-one.log" 2>&1 & gui=$!
python3 -I "$here/tests/gui/permissions-atspi.py" single || rc=1
# The window stays open longer than the checks wait; it is closed here.
kill $gui 2>/dev/null || true; wait $gui 2>/dev/null || true
chmod 755 "$SAM_DATA_DIR/apps"
kill $registry $launcher 2>/dev/null || true
if grep -E 'CRITICAL|panicked' "$out/gui.log" "$out/gui-one.log"; then rc=1; fi
exit $rc
