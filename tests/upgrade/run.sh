#!/bin/sh
# Upgrade test: data made by an older SAM still works with this one.
#
#   tests/upgrade/run.sh [OLD_REF] WORKDIR     (OLD_REF defaults to v0.1.0)
#
# Builds this checkout's sam-jail first (into CARGO_TARGET_DIR when that is
# set, as cargo does, else target/), so the test never checks an older
# build left there. Builds the older version from git into WORKDIR, uses it
# to create two sandboxed apps, custom permissions, a preset and a setting,
# then checks with this checkout's build that all of it is still there and
# that the apps still pass the sandbox check and start. An app whose record
# the older version saved without SAM's checksum (0.1.0 saves none) must ask
# for one review, as SAM marks such records once; the test confirms it as a
# person does (`sam-jail review APP --seen FINGERPRINT`) before the sandbox
# check and the start. An app whose record has the checksum must not ask.
# Prints one line per check and "RESULT pass" or "RESULT fail". Needs bwrap
# and cargo; uses only WORKDIR (and its own SAM_* folders) for data.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
if [ $# -ge 2 ]; then ref=$1; shift; else ref=v0.1.0; fi
work=$(mkdir -p "${1:?usage: run.sh [OLD_REF] WORKDIR}" && cd "$1" && pwd)
# This checkout's sam-jail, built now: a build left in the build folder
# may come from another commit. A relative CARGO_TARGET_DIR counts from
# the checkout, where cargo runs here.
echo "== building this SAM"
(cd "$here" && cargo build -q --locked -p sam-jail-cli)
target=${CARGO_TARGET_DIR:-target}
case $target in /*) ;; *) target="$here/$target" ;; esac
new="$target/debug/sam-jail"
[ -x "$new" ] || { echo "the build left no $new"; exit 2; }

echo "== building SAM $ref"
rm -rf "$work/old" "$work/data" "$work/apps"
mkdir -p "$work/old" "$work/apps" "$work/tmp"
git -C "$here" archive "$ref" | tar -x -C "$work/old"
CARGO_TARGET_DIR="$work/target-old" cargo build -q --locked -p sam-jail-cli --manifest-path "$work/old/Cargo.toml"
old="$work/target-old/debug/sam-jail"

export SAM_CONFIG_DIR="$work/data/config" SAM_DATA_DIR="$work/data/data" SAM_APPLICATIONS_DIR="$work/data/apps" TMPDIR="$work/tmp"
# Nothing of the person running it: own home and runtime folder (short,
# for socket paths; never the real one), no desktop session, one language.
rt="$work/run"
[ -d "/run/user/$(id -u)" ] && [ -w "/run/user/$(id -u)" ] && rt="/run/user/$(id -u)/samupgrade-$$"
mkdir -p "$work/home" "$rt" && chmod 700 "$rt"
export HOME="$work/home" XDG_CONFIG_HOME="$work/home/.config" XDG_DATA_HOME="$work/home/.local/share" XDG_RUNTIME_DIR="$rt" LANG=C.UTF-8
unset WAYLAND_DISPLAY DISPLAY DBUS_SESSION_BUS_ADDRESS SSH_AUTH_SOCK LC_ALL LANGUAGE

echo "== creating data with SAM $ref"
"$old" dev make-fixture --name Writer "$work/apps/Writer-1.0-x86_64.AppImage" >/dev/null
"$old" dev make-fixture --name Player "$work/apps/Player-1.0-x86_64.AppImage" >/dev/null
"$old" add "$work/apps/Writer-1.0-x86_64.AppImage" --no-launcher --accept >/dev/null
"$old" add "$work/apps/Player-1.0-x86_64.AppImage" --no-launcher --accept >/dev/null
id_of() { "$1" --json list | python3 -c "import json,sys; d=json.loads(sys.stdin.read().splitlines()[-1])['data']; print([a['id'] for a in d if a.get('name','').startswith('$2') or '$2'.lower() in a['id']][0])"; }
writer=$(id_of "$old" Writer)
"$old" set "$writer" network.mode full >/dev/null
"$old" set "$writer" filesystem.documents rw >/dev/null
"$old" preset save "$writer" "Writer setup" >/dev/null
"$old" config set general.theme dark >/dev/null
# Which records the older version saved without SAM's checksum, read before
# this SAM loads them (this SAM's first save adds a checksum and keeps the
# mark until the review).
# The first line is the number of records read, so a scan of the wrong
# folder cannot pass for "none without a checksum".
scan=$(python3 -c "
import json, pathlib, sys
files = sorted(pathlib.Path(sys.argv[1]).glob('*.json'))
print(len(files))
for f in files:
    if 'integrity' not in json.loads(f.read_text()):
        print(f.stem)
" "$SAM_DATA_DIR/apps")
records=$(echo "$scan" | head -n1)
unsummed=$(echo "$scan" | tail -n +2)

echo "== checking with this SAM"
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected '$3', got '$2'"; fail=1; fi; }
data() { "$new" --json "$@" 2>/dev/null | tail -n1 | python3 -c "import json,sys; v=json.loads(sys.stdin.read()); print(json.dumps(v.get('data')) if v.get('ok') else 'ERROR: '+v.get('error',''))"; }
check "the older version's two app records are read" "$records" 2
check "both apps are listed" "$(data list | python3 -c "import json,sys; print(len(json.loads(sys.stdin.read())))")" 2
check "custom network setting kept" "$(data get "$writer" network.mode)" '"full"'
check "custom folder access kept" "$(data get "$writer" filesystem.documents)" '"rw"'
check "the preset is there" "$(data preset list | python3 -c "import json,sys; print(any(p.get('name')=='Writer setup' for p in json.loads(sys.stdin.read())))")" True
check "the setting is kept" "$(data config get general.theme)" '"dark"'
info() { "$new" --json info "$1" 2>/dev/null | tail -n1 | python3 -c "import json,sys; v=json.loads(sys.stdin.read()); d=v.get('data') or {}; print(d.get('review_fingerprint', '') if sys.argv[1] == 'fingerprint' else str(bool((d.get('entry') or {}).get('changed_outside'))).lower() if v.get('ok') else 'ERROR')" "$2"; }
for app in $("$new" --json list | tail -n1 | python3 -c "import json,sys; print(' '.join(a['id'] for a in json.loads(sys.stdin.read())['data']))"); do
    case " $(echo $unsummed) " in *" $app "*) want=true ;; *) want=false ;; esac
    marked=$(info "$app" mark)
    check "$app asks for one review exactly when its record has no checksum" "$marked" "$want"
    if [ "$marked" = true ]; then
        # Marked means the start waits for the review, not only a flag.
        if "$new" run "$app" >"$work/tmp/refused-$app.log" 2>&1; then refused=no
        elif grep -q 'changed outside SAM' "$work/tmp/refused-$app.log"; then refused=yes
        else refused="no, another error (see $work/tmp/refused-$app.log)"; fi
        check "$app does not start before the review" "$refused" yes
        reviewed=$(data review "$app" --seen "$(info "$app" fingerprint)")
        case $reviewed in ERROR*) ;; *) reviewed=accepted ;; esac
        check "$app's review is accepted" "$reviewed" accepted
        check "$app no longer asks after the review" "$(info "$app" mark)" false
    fi
    verdict=$("$new" --json verify "$app" 2>/dev/null | tail -n1 | python3 -c "import json,sys; v=json.loads(sys.stdin.read()); r=(v.get('data') or {}).get('record') or {}; print('pass' if v.get('ok') and r.get('passed', 0) > 0 and not r.get('failed') else 'fail')")
    check "$app passes the sandbox check" "$verdict" pass
    if "$new" run "$app" >"$work/tmp/run-$app.log" 2>&1; then started=yes; else started=no; fi
    check "$app starts" "$started" yes
done
if [ $fail = 0 ]; then echo "RESULT pass"; else echo "RESULT fail"; fi
exit $fail
