#!/bin/sh
# SAM's main flow and the language switch through the accessibility
# interface (AT-SPI), in an invisible KWin session: Create Sandbox, the app
# page, Launch; then the window in German and back in English.
# Prints one line per check and "RESULT pass" or "RESULT fail".
#
#   tests/gui/flow-atspi.sh OUTDIR
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
out=$(mkdir -p "${1:?usage: flow-atspi.sh OUTDIR}" && cd "$1" && pwd)
if [ "${INSIDE:-}" != 1 ]; then
    INSIDE=1 SAM_SESSION=kwin exec "$here/tests/gui/session.sh" "$out" "$0" "$out"
fi
bin="$here/target/debug"
rm -rf "$out/data-set"; mkdir -p "$out/data-set/apps-folder" "$out/data-set/config"
export SAM_CONFIG_DIR="$out/data-set/config" SAM_DATA_DIR="$out/data-set/data" SAM_APPLICATIONS_DIR="$out/data-set/apps"
printf '[general]\nscan_directories = ["%s"]\n' "$out/data-set/apps-folder" > "$SAM_CONFIG_DIR/config.toml"
"$bin/sam-jail" dev make-fixture --name Tool "$out/data-set/apps-folder/Tool.AppImage" >/dev/null
"$ATSPI_LAUNCHER" --launch-immediately >/dev/null 2>&1 & launcher=$!
sleep 1
"$ATSPI_REGISTRY" >/dev/null 2>&1 & registry=$!
count() { "$bin/sam-jail" --json list | tail -n1 | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)["data"]))'; }
rc=0

# The main flow, from the AppImage's page.
"$bin/sam-jail-gui" --screenshot "$out/flow.png" --size 1180x800 --delay 60000 --page file > "$out/flow.log" 2>&1 & gui=$!
python3 -I "$here/tests/gui/flow-atspi.py" flow || rc=1
kill $gui 2>/dev/null || true; wait $gui 2>/dev/null || true
id=$("$bin/sam-jail" --json list | tail -n1 | python3 -I -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d[0]["id"] if len(d) == 1 else "")')
started=$( [ -n "$id" ] && "$bin/sam-jail" --json info "$id" | tail -n1 | python3 -I -c 'import json,sys; e=json.load(sys.stdin)["data"]["entry"]; print(bool((e.get("last_launch") or {}).get("success")))' )
if [ "$started" = True ]; then echo "ok   the sandbox was created and the app started from the window"; else echo "FAIL no sandbox, or the app did not start ($started)"; rc=1; fi

# The language: gettext ignores a chosen language in the C locale, so the
# window gets a real one (CI runners default to C).
real=$(locale -a 2>/dev/null | grep -i '^en_' | head -n1)
[ -n "$real" ] || real=$(locale -a 2>/dev/null | grep -v -e '^C' -e '^POSIX' | head -n1)
[ -n "$real" ] && export LANG="$real" && unset LC_ALL LC_MESSAGES LANGUAGE
for lang in de ""; do
    "$bin/sam-jail" config set general.language "$lang" >/dev/null
    name=${lang:-en}
    "$bin/sam-jail-gui" --screenshot "$out/language-$name.png" --size 1180x800 --delay 25000 --page language > "$out/language-$name.log" 2>&1 & gui=$!
    python3 -I "$here/tests/gui/flow-atspi.py" "$( [ "$lang" = de ] && echo german || echo english )" || rc=1
    kill $gui 2>/dev/null || true; wait $gui 2>/dev/null || true
done

kill $registry $launcher 2>/dev/null || true
if grep -E 'CRITICAL|panicked' "$out"/flow.log "$out"/language-*.log; then rc=1; fi
[ $rc = 0 ] && echo "RESULT pass" || echo "RESULT fail"
exit $rc
