#!/bin/sh
# Opens every page of SAM's window against a throwaway data set and fails on
# GTK criticals, warnings or a panic. Needs a display (Wayland, X11 or GTK's
# Broadway) and a session bus; CI runs it under gtk4-broadwayd.
#
#   tests/gui/smoke.sh OUTDIR        (screenshots and logs go to OUTDIR)
#
# Uses target/debug binaries and its own SAM_* folders; nothing outside
# OUTDIR is written.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
out=$(mkdir -p "${1:?usage: smoke.sh OUTDIR}" && cd "$1" && pwd)
bin="$here/target/debug"
export SAM_CONFIG_DIR="$out/config" SAM_DATA_DIR="$out/data" SAM_APPLICATIONS_DIR="$out/apps" TMPDIR="$out/tmp"
export GTK_A11Y=none NO_AT_BRIDGE=1
mkdir -p "$out/apps-folder" "$TMPDIR" "$SAM_CONFIG_DIR"
printf '[general]\nscan_directories = ["%s"]\n' "$out/apps-folder" > "$SAM_CONFIG_DIR/config.toml"

# Two AppImages: one gets a sandbox, one stays without.
"$bin/sam-jail" dev make-fixture --name Sandboxed "$out/apps-folder/Sandboxed-1.0-x86_64.AppImage" >/dev/null
"$bin/sam-jail" dev make-fixture --name Plain "$out/apps-folder/Plain-1.0-x86_64.AppImage" >/dev/null
"$bin/sam-jail" add "$out/apps-folder/Sandboxed-1.0-x86_64.AppImage" --no-launcher >/dev/null

fail=0
shot() {
    name=$1; shift
    "$bin/sam-jail-gui" --screenshot "$out/$name.png" --size 1180x800 --delay 2500 "$@" > "$out/$name.log" 2>&1 || {
        echo "FAIL $name: exited with $?"; tail -n 30 "$out/$name.log"; fail=1; return; }
    if [ ! -s "$out/$name.png" ]; then
        echo "FAIL $name: no screenshot"; fail=1
    fi
    # Criticals, warnings and panics; the accessibility bus is not there on purpose.
    if grep -E 'CRITICAL|WARNING|panicked' "$out/$name.log" | grep -v -e 'accessibility bus' -e 'org.a11y.Bus'; then
        echo "FAIL $name: see $out/$name.log"; fail=1
    else
        echo "ok   $name"
    fi
}
shot start
shot app --page app
shot file --page file
shot presets --page presets
shot preferences --page preferences
shot diagnostics --page diagnostics
shot guide --page guide
shot narrow --size 360x700
exit $fail
