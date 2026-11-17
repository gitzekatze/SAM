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
# The same window on every computer: its own home (no Downloads folder of
# the person running it) and no desktop settings (theme, fonts, scaling),
# as on CI's machine.
export HOME="$out/home" XDG_CONFIG_HOME="$out/xdg-config" GSETTINGS_BACKEND=memory
mkdir -p "$out/apps-folder" "$TMPDIR" "$SAM_CONFIG_DIR" "$HOME" "$XDG_CONFIG_HOME"
printf '[general]\nscan_directories = ["%s"]\n' "$out/apps-folder" > "$SAM_CONFIG_DIR/config.toml"

# One AppImage without a sandbox, and one sandboxed app in each state the
# app page shows differently: a page often breaks only in one state.
"$bin/sam-jail" dev make-fixture --name Plain "$out/apps-folder/Plain-1.0-x86_64.AppImage" >/dev/null
printf '#!/bin/sh\necho "error while loading shared libraries: libmissing.so.1: cannot open shared object file" >&2\nexit 127\n' > "$out/failing-apprun"
add() { # name [failing] -> the app's id
    if [ "${2:-}" = failing ]; then
        "$bin/sam-jail" dev make-fixture --name "$1" --apprun "$out/failing-apprun" "$out/apps-folder/$1-1.0-x86_64.AppImage" >/dev/null
    else
        "$bin/sam-jail" dev make-fixture --name "$1" "$out/apps-folder/$1-1.0-x86_64.AppImage" >/dev/null
    fi
    if [ "$1" = Review ]; then
        "$bin/sam-jail" add "$out/apps-folder/$1-1.0-x86_64.AppImage" --no-launcher >/dev/null
    else
        "$bin/sam-jail" add "$out/apps-folder/$1-1.0-x86_64.AppImage" --no-launcher --accept >/dev/null
    fi
    "$bin/sam-jail" --json list | tail -n1 | python3 -I -c 'import json,sys; print([a["id"] for a in json.load(sys.stdin)["data"] if a["name"] == sys.argv[1]][0])' "$1"
}
sandboxed=$(add Sandboxed)
review=$(add Review)
compat=$(add Compat)
"$bin/sam-jail" compat "$compat" on >/dev/null
broken=$(add Broken failing)
"$bin/sam-jail" run "$broken" >/dev/null 2>&1 || true
repaired=$(add Repaired failing)
"$bin/sam-jail" run "$repaired" >/dev/null 2>&1 || true
"$bin/sam-jail" repair "$repaired" --next >/dev/null 2>&1 || true
tampered=$(add Tampered)
# Something other than SAM changes the record: SAM shows "Changed outside SAM".
python3 -I -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["profile"]["permissions"]["network"]["mode"]="full"; json.dump(d,open(p,"w"))' "$SAM_DATA_DIR/apps/$tampered.json"

fail=0
# The states must really be there, or the pages below would only show the
# ordinary state again.
badge() { "$bin/sam-jail" --json list | tail -n1 | python3 -I -c 'import json,sys; print([a["badge"] for a in json.load(sys.stdin)["data"] if a["id"] == sys.argv[1]][0])' "$1"; }
for want in "$review needs-review" "$compat compatibility-mode" "$broken broken" "$tampered changed-outside"; do
    set -- $want
    got=$(badge "$1")
    if [ "$got" = "$2" ]; then echo "ok   state $2"; else echo "FAIL state: $1 should be $2, is $got"; fail=1; fi
done
shot() {
    name=$1; shift
    "$bin/sam-jail-gui" --screenshot "$out/$name.png" --size 1180x800 --delay "${DELAY:-2500}" "$@" > "$out/$name.log" 2>&1 || {
        echo "FAIL $name: exited with $?"; tail -n 30 "$out/$name.log"; fail=1; return; }
    if [ ! -s "$out/$name.png" ]; then
        echo "FAIL $name: no screenshot"; fail=1
    fi
    # Criticals, warnings and panics; the accessibility bus is not there on
    # purpose. Broadway's own frame clock (newer GTK) warns now and then about
    # its timing, whatever the page: that is GTK's, not SAM's.
    if grep -E 'CRITICAL|WARNING|panicked' "$out/$name.log" | grep -v -e 'accessibility bus' -e 'org.a11y.Bus' -e 'Duplicate call to gdk_frame_timings_submitted'; then
        echo "FAIL $name: see $out/$name.log"; fail=1
    else
        echo "ok   $name"
    fi
}
shot start
shot app --page app --app "$sandboxed"
shot app-review --page app --app "$review"
shot app-compat --page app --app "$compat"
# An app whose last start failed loads its advice first: its page needs
# longer than the others (2.5 s drew nothing at all on a debug build).
DELAY=6000 shot app-broken --page app --app "$broken"
DELAY=6000 shot app-repaired --page app --app "$repaired"
shot app-tampered --page app --app "$tampered"
shot file --page file
shot presets --page presets
DELAY=4000 shot permissions --page permissions
DELAY=4000 shot permissions-narrow --page permissions --size 360x700
shot preferences --page preferences
shot diagnostics --page diagnostics
shot guide --page guide
shot narrow --size 360x700
exit $fail
