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
# CHECKS containing "netoff", "second", "lang" or "scale": a start without
# network and sound, a second start while the first runs, a start in
# German, a start with display scaling 2; "missing" adds a diagnostic run
# under strace (if installed) that lists files the app looked for in vain. Always: the start time (until the
# first window) and the memory of the app after 20 s.
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
appcg=""
if [ -n "${APPS_CG:-}" ] && mkdir "$APPS_CG/app-$$" 2>/dev/null; then appcg="$APPS_CG/app-$$"; fi
S=sam-jail
# Memory of everything the test start runs (the sandbox and the app), in MiB.
memory() {
    p=$(pgrep -f "selftest $id" | head -1); [ -n "$p" ] || return
    all="$p"; new="$p"
    while [ -n "$new" ]; do new=$(for q in $new; do pgrep -P "$q"; done); all="$all $new"; done
    echo "memory $(for q in $all; do ps -o rss= -p "$q" 2>/dev/null; done | awk '{s+=$1} END {printf "%d", s/1024}')" > "$out.mem"
}
# Level 2: whether what SAM allowed is really used, seen from outside while
# the first start runs (sandboxed processes are not dumpable, so nothing is
# read from inside them). Looked at every 2 s for the whole start, so a short
# connection or sound is not missed:
# - GPU: contexts the NVIDIA driver lists for the app's processes (n/a
#   without NVIDIA: other drivers show this to root only);
# - sound: clients of the session's own sound server (only one app runs at a
#   time, and its process numbers inside the sandbox differ from ours);
# - network: connections of the app's own control group (one per app, see
#   run.sh) that leave this computer, as `ss` lists them (n/a when the run's
#   scope cannot hold control groups of its own).
# One "key value" line each in $out.observe.
procs() {
    if [ -n "$appcg" ]; then cat "$appcg/cgroup.procs" 2>/dev/null; return; fi
    p=$(pgrep -f "selftest $id" | head -1); [ -n "$p" ] || return
    all="$p"; new="$p"
    while [ -n "$new" ]; do new=$(for q in $new; do pgrep -P "$q"; done); all="$all $new"; done
    echo $all
}
sound_client() {
    pw-dump 2>/dev/null | python3 -I -c '
import json, sys
own = {"pipewire", "pipewire-pulse", "pw-dump", "wireplumber"}
n = 0
for o in json.load(sys.stdin):
    if o.get("type") == "PipeWire:Interface:Client":
        pr = (o.get("info") or {}).get("props") or {}
        name = str(pr.get("application.name") or pr.get("application.process.binary") or "")
        if name and name.lower() not in own:
            n += 1
print("yes" if n else "no")' 2>/dev/null
}
observe() {
    gpu=n/a; sound=n/a; net=n/a
    command -v nvidia-smi >/dev/null && gpu=no
    command -v pw-dump >/dev/null && sound=no
    rel=""
    if [ -n "$appcg" ] && command -v ss >/dev/null; then net=0; rel=${appcg#/sys/fs/cgroup}; fi
    t=0
    while [ "$t" -lt 24 ]; do
        sleep 2; t=$((t + 2))
        if [ "$gpu" = no ]; then
            g=$(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null; nvidia-smi 2>/dev/null | awk '/ G | C\+G /{print $5}')
            for q in $(procs); do echo "$g" | grep -qx "$q" && gpu=yes; done
        fi
        [ "$sound" = no ] && [ "$(sound_client)" = yes ] && sound=yes
        if [ -n "$rel" ]; then
            # Peer addresses of established TCP and connected UDP sockets,
            # without this computer's own (loopback).
            n=$(ss -Htun state established cgroup "$rel" 2>/dev/null | awk '{print $5}' \
                | grep -cvE '^(127\.|\[::1\]|\[::ffff:127\.)')
            [ "$n" -gt "$net" ] && net=$n
        fi
    done
    printf 'gpu %s\nsound %s\nnet %s\n' "$gpu" "$sound" "$net" > "$out.observe"
}
# The first start runs in a control group of its own, when the run has one
# to give (APPS_CG, see run.sh): its network connections are then this app's.
in_own_group() {
    if [ -n "$appcg" ]; then
        sh -c 'echo $$ > "$0/cgroup.procs" && exec "$@"' "$appcg" "$@"
    else
        "$@"
    fi
}
start() { # round
    if [ "$1" = 0 ]; then
        # The moment the first window appears, for the start time.
        printf 'workspace.windowAdded.connect(function (w) { if (w.normalWindow || w.dialog) print("SAMADD %s " + Date.now()); });\n' "$id" > "$R/tmp/added.js"
        qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.loadScript "$R/tmp/added.js" samadd >/dev/null 2>&1
        qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.start >/dev/null 2>&1
        date +%s%3N > "$out.t0"
    fi
    ( sleep 20; spectacle -b -n -f -o "$out.shot$1.png" >/dev/null 2>&1; [ "$1" = 0 ] && { windows "$1"; memory; } ) &
    shot=$!
    watch=""
    if [ "$1" = 0 ]; then observe & watch=$!; fi
    if [ "$1" = 0 ]; then
        in_own_group $S --json selftest "$id" --seconds 25 > "$out.selftest$1.json" 2>&1
    else
        $S --json selftest "$id" --seconds 25 > "$out.selftest$1.json" 2>&1
    fi
    echo "selftest$1 exit $?"
    wait "$shot" 2>/dev/null
    [ -n "$watch" ] && wait "$watch" 2>/dev/null
    [ "$1" = 0 ] && qdbus6 org.kde.KWin /Scripting org.kde.kwin.Scripting.unloadScript samadd >/dev/null 2>&1
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
    # Tray icon and portals, seen in the D-Bus log of the first start.
    grep -q "RegisterStatusNotifierItem" "$out.dbus.log" 2>/dev/null && echo "tray yes" || echo "tray no"
    echo "portals $(grep -o '\-> org\.freedesktop\.portal\.Desktop call org\.freedesktop\.portal\.[A-Za-z]*' "$out.dbus.log" 2>/dev/null | sed 's/.*portal\.//' | sort -u | tr '\n' ',' | sed 's/,$//')"
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
    # Missing files: a diagnostic run under strace lists files and sockets
    # the app looked for in vain, for fixes that help whole groups.
    if case "$CHECKS" in *missing*) true;; *) false;; esac; then
        if command -v strace >/dev/null; then
            $S --json diagnose "$id" > "$out.missing.json" 2>&1
            echo "missing $(python3 -I -c "import json,sys; d=json.load(open(sys.argv[1])).get('data',{}); print(len(d.get('findings',[])))" "$out.missing.json" 2>/dev/null || echo error)"
        else
            echo "missing n/a"
        fi
    fi
    if [ "$started" = 1 ] && case "$CHECKS" in *scale*) true;; *) false;; esac; then
        GDK_SCALE=2 QT_SCALE_FACTOR=2 $S --json selftest "$id" --seconds 15 > "$out.scale.json" 2>&1
        grep -q '"status":"ok"' "$out.scale.json" && echo "scale ok" || echo "scale crashed"
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
# The app's control group is empty once it has closed; what is still in it
# kept running after SAM closed the app.
if [ -n "$appcg" ] && ! rmdir "$appcg" 2>/dev/null; then
    echo "left-running $(wc -l < "$appcg/cgroup.procs")" >> "$out.checks"
fi
