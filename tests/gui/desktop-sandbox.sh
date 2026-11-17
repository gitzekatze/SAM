#!/bin/sh
# The sandbox tests inside a desktop session: a hidden KWin (Wayland) and,
# with SAM_TEST_AUDIO=1 (as in CI), PipeWire with its PulseAudio server, all
# in the session's own runtime folder. CI machines have no desktop, so the
# checks of the permission matrix, the sandbox check and the end-to-end test
# that need Wayland or sound never ran there; here they do, and the
# Wayland, security-context and sound contracts get a light on every change.
#
#   SAM_SESSION=kwin [SAM_TEST_AUDIO=1] tests/gui/desktop-sandbox.sh OUTDIR
#
# Fails when the session lacks Wayland (or sound, when asked for): a run
# without them would prove nothing. Only PipeWire itself and pipewire-pulse
# start, no session manager, so no sound card is opened.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
out=$(mkdir -p "${1:?usage: desktop-sandbox.sh OUTDIR}" && cd "$1" && pwd)
if [ "${INSIDE:-}" != 1 ]; then
    INSIDE=1 SAM_SESSION=${SAM_SESSION:-kwin} exec "$here/tests/gui/session.sh" "$out" "$0" "$out"
fi
pids=""
if [ "${SAM_TEST_AUDIO:-}" = 1 ]; then
    pipewire >"$out/pipewire.log" 2>&1 & pids="$pids $!"
    i=0; while [ ! -S "$XDG_RUNTIME_DIR/pipewire-0" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    pipewire-pulse >"$out/pipewire-pulse.log" 2>&1 & pids="$pids $!"
    i=0; while [ ! -S "$XDG_RUNTIME_DIR/pulse/native" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
fi
missing=""
[ -n "${WAYLAND_DISPLAY:-}" ] && [ -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ] || missing="$missing Wayland"
if [ "${SAM_TEST_AUDIO:-}" = 1 ]; then
    [ -S "$XDG_RUNTIME_DIR/pipewire-0" ] || missing="$missing PipeWire"
    [ -S "$XDG_RUNTIME_DIR/pulse/native" ] || missing="$missing PulseAudio"
fi
rc=0
if [ -n "$missing" ]; then
    echo "FAIL the session lacks:$missing (see $out/*.log)"
    rc=1
else
    echo "ok   the session has Wayland${SAM_TEST_AUDIO:+, PipeWire and PulseAudio}; bus $DBUS_SESSION_BUS_ADDRESS"
    # The D-Bus proxy's own log, kept with the session's logs.
    export SAM_DBUS_LOG="$out/dbus-proxy.log"
    cd "$here"
    # Inside this session the tests keep its display, bus and sound: they are
    # the test's own (SAM_TEST_SESSION=1, sam_runner::testenv).
    # The tests use SAM's helper of this build (never one from PATH).
    cargo build -q --bins
    # The matrix fails instead of skipping its display and sound checks.
    export SAM_REQUIRE_DESKTOP=1
    [ "${SAM_TEST_AUDIO:-}" = 1 ] && export SAM_REQUIRE_SOUND=1
    SAM_REQUIRE_SANDBOX=1 cargo test -q --no-fail-fast -p sam-runner \
        --test matrix --test verify --test sandbox --test breakout --test evil 2>&1 \
        | tee "$out/tests.log" | grep -E '^test result|panicked|CHECK FAIL' || true
    grep -q 'test result: FAILED\|panicked' "$out/tests.log" && rc=1
fi
for p in $pids; do kill "$p" 2>/dev/null || true; done
echo "RESULT $([ $rc = 0 ] && echo pass || echo fail)"
exit $rc
