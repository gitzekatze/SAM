#!/bin/sh
# Accessibility audit of every page of SAM's window, in an invisible KWin
# session: each page is opened on its own and read through AT-SPI, the
# interface screen readers use. Every visible, enabled control must have a
# name a screen reader can say and must accept keyboard focus. Prints the
# problems per page and "RESULT pass" or "RESULT fail".
#
#   tests/gui/a11y-atspi.sh OUTDIR
#
# Needs kwin_wayland, at-spi2-core and python3-gobject (Atspi).
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
out=$(mkdir -p "${1:?usage: a11y-atspi.sh OUTDIR}" && cd "$1" && pwd)
if [ "${INSIDE:-}" != 1 ]; then
    INSIDE=1 SAM_SESSION=kwin exec "$here/tests/gui/session.sh" "$out" "$0" "$out"
fi
bin="$here/target/debug"
rm -rf "$out/data-set"; mkdir -p "$out/data-set/apps-folder" "$out/data-set/config"
export SAM_CONFIG_DIR="$out/data-set/config" SAM_DATA_DIR="$out/data-set/data" SAM_APPLICATIONS_DIR="$out/data-set/apps"
printf '[general]\nscan_directories = ["%s"]\n' "$out/data-set/apps-folder" > "$SAM_CONFIG_DIR/config.toml"
# Two sandboxed apps and one AppImage without a sandbox, so every page has content.
for spec in "Browser:Network;WebBrowser;" "Editor:Graphics;2DGraphics;"; do
    n=${spec%%:*}; c=${spec#*:}
    "$bin/sam-jail" dev make-fixture --name "$n" --categories "$c" "$out/data-set/apps-folder/$n-1.0-x86_64.AppImage" >/dev/null
    "$bin/sam-jail" add "$out/data-set/apps-folder/$n-1.0-x86_64.AppImage" --no-launcher --accept >/dev/null
done
"$bin/sam-jail" dev make-fixture --name Waiting "$out/data-set/apps-folder/Waiting-1.0-x86_64.AppImage" >/dev/null
first=$("$bin/sam-jail" --json list | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data",d); print(d[0]["id"])')

"${ATSPI_LAUNCHER:-/usr/lib/at-spi-bus-launcher}" --launch-immediately >/dev/null 2>&1 & launcher=$!
sleep 1
"${ATSPI_REGISTRY:-/usr/lib/at-spi2-registryd}" >/dev/null 2>&1 & registry=$!

rc=0
for page in overview app app-repair file permissions presets preferences diagnostics guide; do
    set -- --page "$page"
    case "$page" in
        overview) set -- ;;
        app|app-repair) set -- --page "$page" --app "$first" ;;
        file) set -- "$out/data-set/apps-folder/Waiting-1.0-x86_64.AppImage" --page file ;;
    esac
    "$bin/sam-jail-gui" --screenshot "$out/$page.png" --size 1180x800 --delay 14000 "$@" > "$out/$page.log" 2>&1 & gui=$!
    python3 -I "$here/tests/gui/a11y-atspi.py" "$page" || rc=1
    wait $gui || true
    if grep -E 'CRITICAL|panicked' "$out/$page.log"; then rc=1; fi
done
kill $registry $launcher 2>/dev/null || true
[ $rc = 0 ] && echo "RESULT pass" || echo "RESULT fail"
exit $rc
