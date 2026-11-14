#!/bin/sh
# Full SAM flow for one AppImage; writes results/<name>.* files.
# Runs inside the invisible KWin session (WAYLAND_DISPLAY/DISPLAY set).
#
#   recommendation → Create Sandbox → sandbox check → test start (25 s, with
#   a screenshot after 20 s: first starts of Electron apps take a while) → if the start failed: up to three rounds of
#   "apply the next repair step, start again" → hints, repair list, info.
#
# Extra checks (one line each in results/<name>.checks, summarized by
# checks.py): always the D-Bus log of the first start, the windows after
# 20 s (does one appear, does its title read like an error), whether the
# recommendation is the same twice, and leftovers after closing. With
# CHECKS containing "netoff", "second" or "lang": a start without network
# and sound, a second start while the first runs, a start in German.
set -u
CHECKS=${CHECKS:-}
# What KWin shows: one line per window (title), via a KWin script.
windows() {
    printf 'for (const w of workspace.windowList()) { if (w.normalWindow || w.dialog) print("SAMWIN %s " + w.caption); }\n' "$id" > "$R/tmp/windows.js"
    sid=$(qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.loadScript "$R/tmp/windows.js" "samwin$1" 2>/dev/null)
    [ -n "$sid" ] && qdbus6 org.kde.KWin /Scripting/Script"$sid" org.kde.kwin.Script.run >/dev/null 2>&1
    sleep 1
    qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.unloadScript "samwin$1" >/dev/null 2>&1
}
img=$1; name=$(basename "$img"); out="$R/results/$name"
S=sam-jail
start() { # round
    ( sleep 20; spectacle -b -n -f -o "$out.shot$1.png" >/dev/null 2>&1; [ "$1" = 0 ] && windows "$1" ) &
    shot=$!
    $S --json selftest "$id" --seconds 25 > "$out.selftest$1.json" 2>&1
    echo "selftest$1 exit $?"
    wait "$shot" 2>/dev/null
}
ok() { grep -q '"ok":true' "$out.selftest$1.json" && python3 -I -c "import json,sys; d=json.load(open(sys.argv[1]))['data']['results']; sys.exit(0 if d and d[0].get('status') == 'ok' else 1)" "$out.selftest$1.json"; }
{
  echo "== $name"
  $S --json preview "$img" > "$out.preview.json" 2>&1
  # --allow-fallback stands for the consent a person gives in the window.
  $S add "$img" --accept --no-launcher --allow-fallback > "$out.add.txt" 2>&1; echo "add exit $?"
  id=$(sed -n 's/.* as \([a-z0-9-]*\).*/\1/p' "$out.add.txt" | head -1)
  echo "id $id"
  [ -n "$id" ] || exit 0
  $S --json info "$id" > "$out.info.json" 2>&1
  $S --json verify "$id" > "$out.verify.json" 2>&1; echo "verify exit $?"
  # The D-Bus log of the first start (calls without answer, blocked calls).
  : > "$out.dbus.log"
  export SAM_DBUS_LOG="$out.dbus.log"
  start 0
  unset SAM_DBUS_LOG
  round=0
  while ! ok "$round" && [ "$round" -lt 3 ]; do
      round=$((round + 1))
      $S --json repair "$id" --next > "$out.repair$round.json" 2>&1 || break
      start "$round"
  done
  ok "$round" && started=1 || started=0
  {
    # Recommendation stability: the same recommendation twice.
    $S --json preview "$img" > "$out.preview2.json" 2>&1
    python3 -I -c "import json,sys; a,b=(json.load(open(f))['data'].get('permissions') for f in sys.argv[1:3]); print('stable', 'yes' if a==b else 'no')" "$out.preview.json" "$out.preview2.json" 2>/dev/null || echo "stable unknown"
    python3 -I "$TOOLS/../../scripts/dbus-log-summary.py" "$out.dbus.log" 2>/dev/null | sed -n '1s/^/dbus /p'
    if [ "$started" = 1 ] && case "$CHECKS" in *netoff*) true;; *) false;; esac; then
        $S set "$id" network.mode none >/dev/null; $S set "$id" audio.enabled false >/dev/null
        $S --json selftest "$id" --seconds 15 > "$out.netoff.json" 2>&1
        grep -q '"status":"ok"' "$out.netoff.json" && echo "netoff ok" || echo "netoff crashed"
        $S --json profile reset "$id" >/dev/null 2>&1
    fi
    if [ "$started" = 1 ] && case "$CHECKS" in *second*) true;; *) false;; esac; then
        $S run "$id" > "$out.first.log" 2>&1 & first=$!
        sleep 10
        $S --json selftest "$id" --seconds 10 > "$out.second.json" 2>&1
        kill -0 "$first" 2>/dev/null && echo "second first-still-running" || echo "second first-ended"
        $S stop "$id" >/dev/null 2>&1; wait "$first" 2>/dev/null
    fi
    if [ "$started" = 1 ] && case "$CHECKS" in *lang*) true;; *) false;; esac; then
        LANG=de_DE.UTF-8 LC_ALL=de_DE.UTF-8 $S --json selftest "$id" --seconds 15 > "$out.lang.json" 2>&1
        grep -q '"status":"ok"' "$out.lang.json" && echo "lang ok" || echo "lang crashed"
    fi
  } > "$out.checks" 2>&1
  $S --json hints "$id" > "$out.hints.json" 2>&1
  $S --json repair "$id" > "$out.repair.json" 2>&1
  $S --json info "$id" > "$out.info2.json" 2>&1
  $S stop "$id" >/dev/null 2>&1
  # Leftovers after closing: launch folders or processes of this app.
  sleep 2
  left=$(ls -d "$XDG_RUNTIME_DIR/sam/$id"/launch-* 2>/dev/null | wc -l)
  echo "leftovers $left" >> "$out.checks"
} > "$out.txt" 2>&1
# Window titles seen after 20 s, from KWin's log.
grep -a "SAMWIN ${id:-none} " "$R/kwin.log" 2>/dev/null | sed "s/.*SAMWIN ${id:-none} /window /" | sort -u > "$out.windows" || true
