#!/bin/sh
# Full SAM flow for one AppImage; writes results/<name>.* files.
# Runs inside the invisible KWin session (WAYLAND_DISPLAY/DISPLAY set).
#
#   recommendation → Create Sandbox → sandbox check → test start (25 s, with
#   a screenshot after 20 s: first starts of Electron apps take a while) → if the start failed: up to three rounds of
#   "apply the next repair step, start again" → hints, repair list, info.
set -u
img=$1; name=$(basename "$img"); out="$R/results/$name"
S=sam-jail
start() { # round
    ( sleep 20; spectacle -b -n -f -o "$out.shot$1.png" >/dev/null 2>&1 ) &
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
  start 0
  round=0
  while ! ok "$round" && [ "$round" -lt 3 ]; do
      round=$((round + 1))
      $S --json repair "$id" --next > "$out.repair$round.json" 2>&1 || break
      start "$round"
  done
  $S --json hints "$id" > "$out.hints.json" 2>&1
  $S --json repair "$id" > "$out.repair.json" 2>&1
  $S --json info "$id" > "$out.info2.json" 2>&1
  $S stop "$id" >/dev/null 2>&1
} > "$out.txt" 2>&1
