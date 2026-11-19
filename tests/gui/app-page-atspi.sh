#!/bin/sh
# The app page through the accessibility interface (AT-SPI), in an
# invisible KWin session: one sandboxed test app; checks the Test button and
# its state, the advice group, "Files This App Saved", turning on
# compatibility mode through its dialog, and the remove dialog.
# Prints one line per check and "RESULT pass" or "RESULT fail".
#
#   tests/gui/app-page-atspi.sh OUTDIR
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
out=$(mkdir -p "${1:?usage: app-page-atspi.sh OUTDIR}" && cd "$1" && pwd)
if [ "${INSIDE:-}" != 1 ]; then
    INSIDE=1 SAM_SESSION=${SAM_SESSION:-kwin} exec "$here/tests/gui/session.sh" "$out" "$0" "$out"
fi
bin="$here/target/debug"
rm -rf "$out/data-set"; mkdir -p "$out/data-set/apps-folder" "$out/data-set/config"
export SAM_CONFIG_DIR="$out/data-set/config" SAM_DATA_DIR="$out/data-set/data" SAM_APPLICATIONS_DIR="$out/data-set/apps"
printf '[general]\nscan_directories = ["%s"]\n' "$out/data-set/apps-folder" > "$SAM_CONFIG_DIR/config.toml"
"$bin/sam-jail" dev make-fixture --name Tool "$out/data-set/apps-folder/Tool.AppImage" >/dev/null
id=$("$bin/sam-jail" --json add "$out/data-set/apps-folder/Tool.AppImage" --no-launcher --accept | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data",d); print(d["entry"]["id"])')
"${ATSPI_LAUNCHER:-/usr/lib/at-spi-bus-launcher}" --launch-immediately >/dev/null 2>&1 & launcher=$!
sleep 1
"${ATSPI_REGISTRY:-/usr/lib/at-spi2-registryd}" >/dev/null 2>&1 & registry=$!
"$bin/sam-jail-gui" --screenshot "$out/app-page.png" --size 1180x800 --delay 30000 --page app --app "$id" > "$out/gui.log" 2>&1 & gui=$!
rc=0; SAM_TEST_BIN="$bin" SAM_TEST_APP="$id" python3 -I "$here/tests/gui/app-page-atspi.py" || rc=$?
wait $gui || true
kill $registry $launcher 2>/dev/null || true
if grep -E 'CRITICAL|panicked' "$out/gui.log"; then rc=1; fi
exit $rc
