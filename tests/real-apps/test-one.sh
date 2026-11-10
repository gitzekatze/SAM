#!/bin/sh
# Full SAM flow for one AppImage; writes results/<name>.json and .txt.
# Runs inside the invisible KWin session (WAYLAND_DISPLAY/DISPLAY set).
set -u
img=$1; name=$(basename "$img"); out="$R/results/$name"
S=sam-jail
{
  echo "== $name"
  $S --json preview "$img" > "$out.preview.json" 2>&1
  $S add "$img" --accept --no-launcher > "$out.add.txt" 2>&1; echo "add exit $?"
  id=$(sed -n 's/.* as \([a-z0-9-]*\).*/\1/p' "$out.add.txt" | head -1)
  echo "id $id"
  [ -n "$id" ] || exit 0
  $S --json info "$id" > "$out.info.json" 2>&1
  $S --json verify "$id" > "$out.verify.json" 2>&1; echo "verify exit $?"
  $S --json selftest "$id" --seconds 15 > "$out.selftest.json" 2>&1; echo "selftest exit $?"
  $S --json hints "$id" > "$out.hints.json" 2>&1
  $S --json repair "$id" > "$out.repair.json" 2>&1
  $S --json info "$id" > "$out.info2.json" 2>&1
} > "$out.txt" 2>&1
