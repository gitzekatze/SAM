#!/bin/sh
# Runs a command inside an invisible test session and removes the session
# afterwards. The session has its own runtime folder and its own session bus
# without service files, so no portal or other desktop service starts and the
# real desktop session is never touched.
#
#   tests/gui/session.sh OUTDIR CMD [ARGS…]
#
# SAM_SESSION=kwin uses a hidden nested KWin (KDE), SAM_SESSION=mutter a
# headless Mutter (GNOME); both are Wayland, which the accessibility
# interface needs (GTK offers it only on Wayland and X11). Otherwise GTK's
# Broadway backend. Home, settings (Adwaita icons), data and cache come from
# OUTDIR, unless REAL_XDG=1 keeps the user's own (then the compositor reads
# and may write the real ~/.config).
set -eu
out=$(mkdir -p "${1:?usage: session.sh OUTDIR CMD…}" && cd "$1" && pwd); shift
# Its own runtime folder, never the real one; below /run/user when that
# exists (short socket paths), else in OUTDIR (CI runners may have none).
if [ -d "/run/user/$(id -u)" ] && [ -w "/run/user/$(id -u)" ]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)/samtest-gui-$$"
else
    export XDG_RUNTIME_DIR="$out/run-$$"
fi
mkdir -p "$XDG_RUNTIME_DIR" "$out/empty-services" "$out/tmp" && chmod 700 "$XDG_RUNTIME_DIR"
cat > "$out/session.conf" <<C
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:tmpdir=$XDG_RUNTIME_DIR</listen><servicedir>$out/empty-services</servicedir>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>
C
unset WAYLAND_DISPLAY DISPLAY DBUS_SESSION_BUS_ADDRESS NO_AT_BRIDGE
# Nothing of the person running it, before anything starts: the compositor,
# GTK and the window read (and KWin writes) the home and XDG folders, so the
# session gets its own; and one language (scripts that check another set it).
if [ -z "${REAL_XDG:-}" ]; then
    # Rust's own folders stay where they are (build tools, not desktop
    # state): tests inside the session may run cargo.
    export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
    export HOME="$out/home" XDG_CONFIG_HOME="$out/xdg-config" XDG_DATA_HOME="$out/xdg-data" \
        XDG_CACHE_HOME="$out/xdg-cache" XDG_STATE_HOME="$out/xdg-state" GSETTINGS_BACKEND=memory
    mkdir -p "$HOME" "$XDG_CONFIG_HOME/gtk-4.0" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_STATE_HOME"
    printf '[Settings]\ngtk-icon-theme-name=Adwaita\n' > "$XDG_CONFIG_HOME/gtk-4.0/settings.ini"
fi
export LANG=C.UTF-8
# Tests inside may use this session's display and bus: it is their own
# (sam_runner::contracts::test_host).
export SAM_TEST_SESSION=1
unset LC_ALL LC_MESSAGES LANGUAGE
bus=$(dbus-daemon --config-file="$out/session.conf" --fork --print-address=1 --print-pid=1)
export DBUS_SESSION_BUS_ADDRESS=$(echo "$bus" | sed -n 1p); buspid=$(echo "$bus" | sed -n 2p)
if [ "${SAM_SESSION:-broadway}" = kwin ]; then
    kwin_wayland --virtual --no-lockscreen --no-global-shortcuts --socket samtest-wl --width 1180 --height 800 >"$out/kwin.log" 2>&1 & disp=$!
    # GL instead of Vulkan: Vulkan layers installed by the user print warnings.
    export WAYLAND_DISPLAY=samtest-wl GDK_BACKEND=wayland GSK_RENDERER=gl GDK_DISABLE=vulkan
elif [ "${SAM_SESSION:-broadway}" = mutter ]; then
    mutter --headless --wayland --no-x11 --virtual-monitor 1180x800 --wayland-display samtest-wl >"$out/mutter.log" 2>&1 & disp=$!
    export WAYLAND_DISPLAY=samtest-wl GDK_BACKEND=wayland GSK_RENDERER=gl GDK_DISABLE=vulkan
else
    # A display of its own run: two sessions at once (two checkouts) never meet.
    bwd=":$(( $$ % 900 + 100 ))"
    gtk4-broadwayd "$bwd" >/dev/null 2>&1 & disp=$!
    export GDK_BACKEND=broadway BROADWAY_DISPLAY="$bwd"
    sleep 1
fi
# Wait until the compositor accepts windows: a fixed pause was too short for
# Mutter's first start on a fresh machine (about 4.5 seconds).
if [ -n "${WAYLAND_DISPLAY:-}" ]; then
    i=0
    while [ ! -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
    [ -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ] || echo "session.sh: the compositor did not start within 30 seconds" >&2
    sleep 0.5
fi
export TMPDIR="$out/tmp"
# The accessibility services, wherever the distribution puts them.
atspi() {
    for d in /usr/lib /usr/libexec /usr/lib/at-spi2-core; do
        [ -x "$d/$1" ] && { echo "$d/$1"; return; }
    done
    echo "/usr/lib/$1"
}
export ATSPI_LAUNCHER=$(atspi at-spi-bus-launcher) ATSPI_REGISTRY=$(atspi at-spi2-registryd)
rc=0; "$@" || rc=$?
kill "$disp" "$buspid" 2>/dev/null || true
rm -rf "$XDG_RUNTIME_DIR"
exit $rc
