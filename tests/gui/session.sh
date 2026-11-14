#!/bin/sh
# Runs a command inside an invisible test session and removes the session
# afterwards. The session has its own runtime folder and its own session bus
# without service files, so no portal or other desktop service starts and the
# real desktop session is never touched.
#
#   tests/gui/session.sh OUTDIR CMD [ARGS…]
#
# SAM_SESSION=kwin uses a hidden nested KWin (Wayland; needed for the
# accessibility interface, which GTK offers only on Wayland and X11);
# otherwise GTK's Broadway backend. Adwaita icons and GTK settings come from
# OUTDIR, unless REAL_XDG=1 keeps the user's own settings.
set -eu
out=$(mkdir -p "${1:?usage: session.sh OUTDIR CMD…}" && cd "$1" && pwd); shift
export XDG_RUNTIME_DIR="/run/user/$(id -u)/samtest-gui-$$"
mkdir -p "$XDG_RUNTIME_DIR" "$out/empty-services" "$out/tmp" && chmod 700 "$XDG_RUNTIME_DIR"
cat > "$out/session.conf" <<C
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:tmpdir=$XDG_RUNTIME_DIR</listen><servicedir>$out/empty-services</servicedir>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>
C
unset WAYLAND_DISPLAY DISPLAY DBUS_SESSION_BUS_ADDRESS NO_AT_BRIDGE
bus=$(dbus-daemon --config-file="$out/session.conf" --fork --print-address=1 --print-pid=1)
export DBUS_SESSION_BUS_ADDRESS=$(echo "$bus" | sed -n 1p); buspid=$(echo "$bus" | sed -n 2p)
if [ "${SAM_SESSION:-broadway}" = kwin ]; then
    kwin_wayland --virtual --no-lockscreen --no-global-shortcuts --socket samtest-wl --width 1180 --height 800 >"$out/kwin.log" 2>&1 & disp=$!
    # GL instead of Vulkan: Vulkan layers installed by the user print warnings.
    export WAYLAND_DISPLAY=samtest-wl GDK_BACKEND=wayland GSK_RENDERER=gl GDK_DISABLE=vulkan
    sleep 3
else
    gtk4-broadwayd :17 >/dev/null 2>&1 & disp=$!
    export GDK_BACKEND=broadway BROADWAY_DISPLAY=:17
    sleep 1
fi
if [ -z "${REAL_XDG:-}" ]; then
    mkdir -p "$out/xdg-config/gtk-4.0"
    printf '[Settings]\ngtk-icon-theme-name=Adwaita\n' > "$out/xdg-config/gtk-4.0/settings.ini"
    export XDG_CONFIG_HOME="$out/xdg-config"
fi
export TMPDIR="$out/tmp"
rc=0; "$@" || rc=$?
kill "$disp" "$buspid" 2>/dev/null || true
rm -rf "$XDG_RUNTIME_DIR"
exit $rc
