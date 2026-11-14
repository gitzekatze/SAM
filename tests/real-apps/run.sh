#!/bin/sh
# Runs SAM's whole flow (recommendation, Create Sandbox, sandbox check,
# test start, hints, repair steps) on real AppImages, inside an invisible
# KWin session (virtual output + Xwayland) on a private D-Bus that starts
# no services, with a fake home. Nothing appears on the desktop and the
# real home, SAM config and sound server are not touched.
#
#   WORK=/path/to/scratch tests/real-apps/run.sh App1.AppImage App2.AppImage ...
#   python3 tests/real-apps/analyze.py "$WORK"
#
# Needs kwin_wayland, dbus-run-session and a built SAM (target/debug).
# Set SESSION_SCRIPT to run your own script in the session instead, and
# SESSION_TIMEOUT (seconds, default 3600) for long queues.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
: "${WORK:?set WORK to a scratch folder}"
mkdir -p "$WORK"
R=$(cd "$WORK" && pwd)
export R
mkdir -p "$R/home/.config" "$R/home/Documents" "$R/home/Downloads" "$R/home/Pictures" "$R/home/Music" "$R/home/Videos" "$R/results" "$R/empty-services" "$R/tmp"
printf '[Daemon]\nAutolock=false\nLockOnResume=false\nTimeout=0\n' > "$R/home/.config/kscreenlockerrc"
run=/run/user/$(id -u)/samtest
cat > "$R/session.conf" <<CONF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:tmpdir=$run</listen><servicedir>$R/empty-services</servicedir>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>
CONF
export HOME="$R/home" XDG_CONFIG_HOME="$R/home/.config" XDG_DATA_HOME="$R/home/.local/share" XDG_CACHE_HOME="$R/home/.cache"
export XDG_RUNTIME_DIR="$run"
export SAM_CONFIG_DIR="$R/sam/config" SAM_DATA_DIR="$R/sam/data" SAM_APPLICATIONS_DIR="$R/sam/apps" TMPDIR="$R/tmp"
export PATH="$here/../../target/debug:$PATH"
unset WAYLAND_DISPLAY DISPLAY DBUS_SESSION_BUS_ADDRESS XAUTHORITY
mkdir -p -m 700 "$XDG_RUNTIME_DIR"
for f in "$@"; do (cd "$(dirname "$f")" && printf '%s\n' "$(pwd)/$(basename "$f")"); done > "$R/queue.txt"
cat > "$run/queue" <<'Q'
#!/bin/sh
while IFS= read -r img; do [ -n "$img" ] && "$TEST_ONE" "$img" < /dev/null; done < "$R/queue.txt"
Q
chmod +x "$run/queue"
export TEST_ONE="$here/test-one.sh" TOOLS="$here" CHECKS="${CHECKS:-}"
# KWin script output (window titles) goes to kwin.log.
export QT_FORCE_STDERR_LOGGING=1 QT_LOGGING_RULES="js.debug=true"
# KWin splits the session command at spaces: start it through a link.
ln -sf "${SESSION_SCRIPT:-$run/queue}" "$run/start"
dbus-run-session --config-file="$R/session.conf" -- \
  timeout "${SESSION_TIMEOUT:-3600}" kwin_wayland --virtual --xwayland --socket sam-test --width 1280 --height 800 \
  --exit-with-session "$run/start" > "$R/kwin.log" 2>&1 || true
rm -rf "$run"
